// 接收回路：把 netlink socket 上到达的报文交给 Router 分派。
//
// 分层：transport 只负责字节收发，Router 是纯状态机（决定「谁收」，
// 不做 I/O），Reactor 只做 I/O（等可读、取报文、交给 Router）。三者共用同一 socket。
package kernel

import (
	"errors"
	"log/slog"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/runtime"
)

// PollInterval 是接收回路单次等待可读的上限。
//
// 取值决定的是「关停最坏要多久被发现」：Poll 现在是事件驱动的，报文一到即返回，不再
// 有空转唤醒，所以这里可以放大到 500ms 与 SO_RCVTIMEO 对齐，让空闲时每秒只醒两次。
// 旧实现里它同时也是轮询频率——那个版本不看 fd，每 100ms 硬排空一次。
const PollInterval = 500 * time.Millisecond

// Reactor 驱动内核接收回路。
//
// 它持 transport 与 router，循环「等可读 → 排空 → 分派」，直到关停令牌被置位或链路
// 断开。接收侧全进程唯一：同一 socket 同时只能有一个接收方。
type Reactor struct {
	transport *Transport
	router    *Router
	shutdown  *runtime.Shutdown
	logger    *slog.Logger
	// onLinkDown 在接收链路断开时调用一次；nil 时只记日志。
	onLinkDown func(error)
}

// ReactorOption 配置接收回路的可选行为。
type ReactorOption func(*Reactor)

// WithLinkDownHandler 注入链路断开回调。
//
// 接收回路自己只负责「发现断开」，不知道该如何处置：重启进程是组合根的决定。回调在
// Run 即将返回前调用一次，调用方据此记录致命错误并请求终止，使进程以非零码退出，
// 再由 systemd 的 Restart=on-failure 重新拉起并重新注册。
func WithLinkDownHandler(fn func(error)) ReactorOption {
	return func(r *Reactor) {
		if fn != nil {
			r.onLinkDown = fn
		}
	}
}

// NewReactor 装配接收回路。
//
// router 与 transport 由调用方持有并共享（客户端也在这二者之上工作）；shutdown 是本
// 回路专属的关停令牌。logger 为 nil 时退回 slog.Default。可变参数保持向后兼容：
// 不传 Option 时链路断开只记日志并返回。
func NewReactor(
	transport *Transport,
	router *Router,
	shutdown *runtime.Shutdown,
	logger *slog.Logger,
	opts ...ReactorOption,
) *Reactor {
	if logger == nil {
		logger = slog.Default()
	}
	r := &Reactor{
		transport: transport,
		router:    router,
		shutdown:  shutdown,
		logger:    logger,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

// errorBackoff 是 Poll 持续报错时的让出时长。
//
// 报错通常是 epoll 层失败（fd 被别处关掉），此时循环会立刻重试；不睡就是空转烧 CPU。
// 与 PollInterval 分开：后者可以为了关停响应而放大，这个不该跟着变。
const errorBackoff = 100 * time.Millisecond

// Run 阻塞执行接收回路，直到关停被请求或链路断开。
//
// 退出时关闭 router：把存活标志置死并清空在途
// 登记，使所有阻塞在 RecvTimeout 上的等待方立即拿到 ErrLinkDown，而不是白等到各自超时。
// 顺序要紧：Router.Close 内部先置死（此后新登记被拒）再清表（释放已等待的请求），
// 否则「置死与清表之间」到达的登记会插进空表然后干等。
func (r *Reactor) Run() {
	defer r.router.Close()

	for !r.shutdown.IsShutdown() {
		ready, err := r.transport.Poll(PollInterval, EventRx|EventLinkDown)
		if err != nil {
			r.logger.Error("netlink 轮询失败", "error", err)
			// 短暂让出，避免轮询持续报错时空转烧 CPU。
			time.Sleep(errorBackoff)
			continue
		}
		if ready.Has(EventLinkDown) {
			r.logger.Warn("与内核的 netlink 接收链路已断开")
			// 链路不会再恢复：内核模块卸载/重载后旧 socket 已死，继续运行只会让每次
			// 下发石沉大海。把处置权交给组合根（记录致命错误并请求终止），由 systemd
			// 重启本进程并重新注册，而不是在这里 os.Exit 绕过关停清理。
			if r.onLinkDown != nil {
				r.onLinkDown(ErrLinkDown)
			}
			return
		}
		// 只有真正确认过可读才排空：EventInterrupt 时无数据，TryRecv 会白等一轮接收超时。
		if ready.Has(EventRx) {
			r.drain()
		}
	}
}

// drain 排空当前可读的报文并逐条分派。
//
// 一次唤醒处理多帧：内核可能已把多条报文排进 socket 缓冲，逐条重进 Poll 会多出无谓
// 的系统调用。遇到错误或无数据即返回，下次唤醒再来。
func (r *Reactor) drain() {
	for {
		if r.shutdown.IsShutdown() {
			return
		}
		dg, ok, err := r.transport.TryRecv()
		if err != nil {
			r.logRecvError(err)
			return
		}
		if !ok {
			return
		}
		r.router.HandleDatagram(dg)
	}
}

// logRecvError 按错误性质分级：报文本体不合法是可丢弃的脏数据，只是告警；
// 其余（socket 层失败）视为真故障。
func (r *Reactor) logRecvError(err error) {
	if errors.Is(err, ErrTruncated) || errors.Is(err, ErrMalformedDatagram) {
		r.logger.Warn("netlink 报文不合法，已丢弃", "error", err)
		return
	}
	r.logger.Error("收取 netlink 报文失败", "error", err)
}

// NewEventChannel 建立内核事件通道及其路由器。
//
// capacity <= 0 时取 EventQueue。返回的 router 由调用方持有（客户端与接收回路共享
// 它），events 是内核推送的单向事件流。存活凭据即 router 自身的 Close，
// 无需额外的 Guard 类型。
func NewEventChannel(capacity int) (*Router, <-chan Incoming) {
	if capacity <= 0 {
		capacity = EventQueue
	}
	router := NewRouter(make(chan Incoming, capacity))
	return router, router.Events()
}
