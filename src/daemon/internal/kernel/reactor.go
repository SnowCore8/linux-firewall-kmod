// 接收回路：把 netlink socket 上到达的报文交给 Router 分派。
//
// 分层与 Rust 版一致：transport 只负责字节收发，Router 是纯状态机（决定「谁收」，
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
// 取 100ms 而非 recvTimeout：轮询超时决定的是关停响应延迟，越短越灵敏，但空转唤醒
// 也越频繁。100ms 是「关停足够快」与「空闲几乎不振」的折中。
const PollInterval = 100 * time.Millisecond

// Reactor 驱动内核接收回路。
//
// 它持 transport 与 router，循环「等可读 → 排空 → 分派」，直到关停令牌被置位或链路
// 断开。接收侧全进程唯一：同一 socket 同时只能有一个接收方。
type Reactor struct {
	transport *Transport
	router    *Router
	shutdown  *runtime.Shutdown
	logger    *slog.Logger
}

// NewReactor 装配接收回路。
//
// router 与 transport 由调用方持有并共享（客户端也在这二者之上工作）；shutdown 是本
// 回路专属的关停令牌。logger 为 nil 时退回 slog.Default。
func NewReactor(
	transport *Transport,
	router *Router,
	shutdown *runtime.Shutdown,
	logger *slog.Logger,
) *Reactor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reactor{
		transport: transport,
		router:    router,
		shutdown:  shutdown,
		logger:    logger,
	}
}

// Run 阻塞执行接收回路，直到关停被请求或链路断开。
//
// 退出时关闭 router：这等价于 Rust 版 LivenessGuard 的析构——把存活标志置死并清空在途
// 登记，使所有阻塞在 RecvTimeout 上的等待方立即拿到 ErrLinkDown，而不是白等到各自超时。
// 顺序要紧：Router.Close 内部先置死（此后新登记被拒）再清表（释放已等待的请求），
// 否则「置死与清表之间」到达的登记会插进空表然后干等。
func (r *Reactor) Run() {
	defer r.router.Close()

	for !r.shutdown.IsShutdown() {
		ready, err := r.transport.Poll(PollInterval, EventInterrupt|EventLinkDown)
		if err != nil {
			r.logger.Error("netlink 轮询失败", "error", err)
			// 短暂让出，避免轮询持续报错时空转烧 CPU。
			time.Sleep(PollInterval)
			continue
		}
		if ready.Has(EventLinkDown) {
			r.logger.Warn("与内核的 netlink 接收链路已断开")
			return
		}
		r.drain()
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
// 它），events 是内核推送的单向事件流。与 Rust 的 event_channel 工厂对应，只是 Go 的
// 存活凭据即 router 自身的 Close，无需额外的 Guard 类型。
func NewEventChannel(capacity int) (*Router, <-chan Incoming) {
	if capacity <= 0 {
		capacity = EventQueue
	}
	router := NewRouter(make(chan Incoming, capacity))
	return router, router.Events()
}
