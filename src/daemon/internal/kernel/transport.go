package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// netlinkProto 是契约固定的协议号：`NETLINK_USERSOCK`。
const netlinkProto = unix.NETLINK_USERSOCK

// netlinkGroup 是内核广播组号（契约固定为 1）。
const netlinkGroup = 1

// netlink 链路健康计数器的名字。
//
// 这四个名字是本进程 /metrics 的公开契约（集成测试 19 逐字断言其样本行存在），不随内部
// 反射改名。四个计数器都在 SetMetrics 时注册，因此空闲链路也各有一条 0 值样本行。
const (
	// CounterMessagesSentTotal 是成功投递到内核的 netlink 报文数。
	CounterMessagesSentTotal = "firewall_netlink_messages_sent_total"
	// CounterMessagesReceivedTotal 是从内核成功收取的 netlink 报文数（不含截断/畸形报文）。
	CounterMessagesReceivedTotal = "firewall_netlink_messages_received_total"
	// CounterSendErrorsTotal 是 sendto 失败的次数。
	CounterSendErrorsTotal = "firewall_netlink_send_errors_total"
	// CounterRecvErrorsTotal 是收取报文失败的次数（含截断与畸形报文）。
	CounterRecvErrorsTotal = "firewall_netlink_recv_errors_total"
)

// nlmsgHdrLen 是 `struct nlmsghdr` 的字节数。
const nlmsgHdrLen = 16

// RecvBuf 是接收缓冲区字节数。
//
// 契约用 u16 承载 msg_len，故单条自定义载荷最大 65535 字节，加 nlmsghdr 共 65551。
// 取 128 KiB 留出余量，同时让「报文超过缓冲区」只可能来自非契约行为，而非正常分页。
const RecvBuf = 128 * 1024

// recvTimeout 是接收侧单次阻塞等待的上限。
//
// 阻塞式 recvfrom 无法被 select 打断，故用 SO_RCVTIMEO 定时返回，让接收线程能周期性
// 检查关停标志。取值只影响关停的响应延迟与空闲唤醒频率，不影响正确性。
const recvTimeout = 500 * time.Millisecond

// ErrTruncated 表示内核发来的数据报超过接收缓冲，内容不完整。
var ErrTruncated = errors.New("netlink 数据报超过接收缓冲")

// ErrMalformedDatagram 表示 `nlmsghdr` 自相矛盾（长度不足一个头或超过实得字节数）。
var ErrMalformedDatagram = errors.New("nlmsghdr 声明的长度与实得字节数自相矛盾")

// EventType 是 Poll 返回的就绪事件位掩码。
type EventType uint8

// 就绪事件取值；可组合，用 Has 判定。
const (
	// EventTx 表示发送通道可写（上一次发送已完成）。
	EventTx EventType = 1 << iota
	// EventRx 表示 socket 上有可读报文（需调用方在 interesting 里显式索要）。
	EventRx
	// EventEvents 表示内核推送事件流有待取用的事件。
	EventEvents
	// EventLinkDown 表示接收侧已退出。
	EventLinkDown
	// EventAbandon 表示收到了「放弃在途请求」的通知。
	EventAbandon
	// EventBusy 表示在途请求表已满。
	EventBusy
	// EventDeadline 表示已到达调用方设定的截止时间。
	EventDeadline
	// EventInterrupt 表示轮询在超时内未观察到任何事件。
	EventInterrupt
)

// Has 报告掩码是否包含某个事件位。
func (t EventType) Has(want EventType) bool { return t&want != 0 }

// Datagram 是一条已剥离 `nlmsghdr` 的接收报文。
type Datagram struct {
	// PortID 是发送方的 netlink portid。内核为 0；非 0 表示本机其他进程，
	// 其内容不可信（内核侧要求 CAP_NET_ADMIN，但那不等于本进程可信）。
	PortID uint32
	// Payload 是自定义载荷，含 12 字节公共头。
	Payload []byte
}

// Abandon 是「放弃某个在途请求」的通知载荷（目标序号）。
type Abandon struct {
	Seq uint32
}

// Transport 是 netlink socket 的唯一所有者。
//
// 发送侧只有一把互斥锁，作用不是保护共享状态，而是保证每次 sendto 的数据报整体
// 原子（控制面与注册租约可能来自不同 goroutine，共用同一个 socket）。接收侧不取此锁。
type Transport struct {
	fd      int
	sendMu  sync.Mutex
	txPend  bool
	pending []Abandon

	deadlineMu sync.Mutex
	deadline   time.Time

	closed   bool
	closeMu  sync.Mutex
	linkDown chan struct{}

	// epoll 就绪观察对：epFd 同时监听 socket 与 wakeFd（见 Poll）。
	// 未建立时取 -1，Poll 退回纯定时语义。
	epFd   int
	wakeFd int

	// 健康计数句柄：SetMetrics 一次性填入，收发热路径只做一次非 nil 判定加一。
	// 必须在任何收发开始前写入，此后不再改写，因此无需加锁。
	sentCounter      CounterHandle
	receivedCounter  CounterHandle
	sendErrorCounter CounterHandle
	recvErrorCounter CounterHandle
}

// SetMetrics 接线 netlink 链路健康计数器。
//
// 必须在建立接收回路、启动 HTTP 之前调用一次（句柄此后再不改写）。传 nil 表示不计数，
// 单元测试里的零值 Transport 即按此处理。
func (t *Transport) SetMetrics(m Metrics) {
	if m == nil {
		return
	}
	t.sentCounter = m.Counter(CounterMessagesSentTotal)
	t.receivedCounter = m.Counter(CounterMessagesReceivedTotal)
	t.sendErrorCounter = m.Counter(CounterSendErrorsTotal)
	t.recvErrorCounter = m.Counter(CounterRecvErrorsTotal)
}

// bumpCounter 给一个可空的计数器句柄加一。
func bumpCounter(c CounterHandle) {
	if c != nil {
		c.Add(1)
	}
}

// OpenTransport 创建并绑定 netlink socket。
//
// `nl_pid = 0` 交由内核分配 portid，`nl_groups = 1` 订阅内核广播组。
func OpenTransport() (*Transport, error) { return openTransport(netlinkGroup) }

// openTransport 按给定广播组建链。
//
// 广播组单独成参数，是为了让就绪观察（epoll/eventfd 那一对）能在无特权的机器与 CI 上
// 被真正跑起来：订阅内核广播组需要 CAP_NET_ADMIN，groups=0 的普通 netlink socket 不要。
func openTransport(groups uint32) (*Transport, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, netlinkProto)
	if err != nil {
		return nil, fmt.Errorf("创建 netlink socket 失败：%w", err)
	}

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("绑定 netlink socket 失败：%w", err)
	}

	t := &Transport{fd: fd, linkDown: make(chan struct{}), epFd: -1, wakeFd: -1}
	if err := t.setupReadiness(); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return t, nil
}

// setupReadiness 建立「socket 可读」与「链路断开」共用的观察机制。
//
// 为什么是 epoll + eventfd，而不是「select 等 linkDown 通道 + 带短超时的 epoll_wait」：
// 后者把内核报文的到达延迟摊到那个短超时上（要么 100ms 级空转唤醒，要么关停要等到
// 下一次超时才被发现）。eventfd 把「通道已关闭」翻译成一个内核可读事件，与 socket fd
// 进同一次 epoll_wait，于是关停响应与报文到达都是事件驱动、都只花一次系统调用。
func (t *Transport) setupReadiness() error {
	epFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("创建 epoll 实例失败：%w", err)
	}
	wakeFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		unix.Close(epFd)
		return fmt.Errorf("创建链路唤醒 fd 失败：%w", err)
	}
	for _, fd := range [2]int{wakeFd, t.fd} {
		ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
		if err := unix.EpollCtl(epFd, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
			unix.Close(epFd)
			unix.Close(wakeFd)
			return fmt.Errorf("登记 netlink 可读性观察失败：%w", err)
		}
	}
	t.epFd, t.wakeFd = epFd, wakeFd
	return nil
}

// Fd 返回 socket 文件描述符。
func (t *Transport) Fd() int { return t.fd }

// Subscribe 建立接收侧：设置接收超时并清除非阻塞标志。
//
// 同一时刻只有一个接收方。重复调用是「换一个接收方」，因此先通知
// 上一个接收方退出，再重设 socket 模式。
func (t *Transport) Subscribe() error {
	// 通知上一个接收方退出（若已有）。
	if t.hasLinkDown() {
		t.resetLinkDown()
	}
	if err := unix.SetsockoptTimeval(t.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
		&unix.Timeval{
			Sec:  int64(recvTimeout / time.Second),
			Usec: int64((recvTimeout % time.Second) / time.Microsecond),
		}); err != nil {
		return fmt.Errorf("设置 netlink 接收超时失败：%w", err)
	}
	flags, err := unix.FcntlInt(uintptr(t.fd), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("读取 socket 标志失败：%w", err)
	}
	if err := unix.SetNonblock(t.fd, false); err != nil {
		_ = flags
		return fmt.Errorf("清除 socket 非阻塞标志失败：%w", err)
	}
	return nil
}

// Send 发送一段自定义载荷（内部补 `nlmsghdr`）。
//
// `nlmsg_type` 与 `nlmsg_seq` 均写 0：内核按自定义头里的 `msg_type` 分派，
// `nlmsg_seq` 从未被内核读取。
//
// 成功仅表示已投递到内核，不代表命令已被执行——需要执行确认的路径必须单独等待回复。
func (t *Transport) Send(payload []byte) error {
	total := nlmsgHdrLen + len(payload)
	if total > int(^uint32(0)) {
		return errors.New("netlink 报文超过 u32 长度域")
	}
	buf := make([]byte, total)
	putU32NE(buf[0:4], uint32(total)) // nlmsg_len
	putU16NE(buf[4:6], 0)             // nlmsg_type
	putU16NE(buf[6:8], 0)             // nlmsg_flags
	putU32NE(buf[8:12], 0)            // nlmsg_seq
	putU32NE(buf[12:16], 0)           // nlmsg_pid
	copy(buf[nlmsgHdrLen:], payload)

	t.sendMu.Lock()
	err := unix.Sendto(t.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
	t.txPend = err == nil
	t.sendMu.Unlock()
	if err != nil {
		bumpCounter(t.sendErrorCounter)
		return fmt.Errorf("发送 netlink 报文失败：%w", err)
	}
	bumpCounter(t.sentCounter)
	return nil
}

// TryRecv 尝试收取一条报文。
//
// 返回 `ok=false` 表示当前无数据（接收超时或被信号打断）。用 `MSG_TRUNC` 让内核返回
// 数据报的真实长度，从而能把「被截断」与「正常收完」区分开，而不是静默拿到半条。
//
// 长度取自 `nlmsghdr` 自身（宿主字节序），与内核 `fw_nl_recv_msg` 的取值方式一致：
// 数据报在 skb 里按 4 字节对齐，实得字节数可能比 `nlmsg_len` 多出最多 3 个填充字节。
func (t *Transport) TryRecv() (Datagram, bool, error) {
	buf := make([]byte, RecvBuf)
	n, from, err := unix.Recvfrom(t.fd, buf, unix.MSG_TRUNC)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) ||
			errors.Is(err, unix.EWOULDBLOCK) {
			return Datagram{}, false, nil
		}
		bumpCounter(t.recvErrorCounter)
		return Datagram{}, false, fmt.Errorf("收取 netlink 报文失败：%w", err)
	}
	if n > len(buf) {
		bumpCounter(t.recvErrorCounter)
		return Datagram{}, false, fmt.Errorf("%w：实得 %d 字节，缓冲 %d 字节",
			ErrTruncated, n, len(buf))
	}
	if n < nlmsgHdrLen {
		bumpCounter(t.recvErrorCounter)
		return Datagram{}, false, fmt.Errorf("%w：实得 %d 字节，不足一个 nlmsghdr",
			ErrMalformedDatagram, n)
	}
	nlmsgLen := int(getU32NE(buf[0:4]))
	if nlmsgLen < nlmsgHdrLen || nlmsgLen > n {
		bumpCounter(t.recvErrorCounter)
		return Datagram{}, false, fmt.Errorf("%w：nlmsg_len=%d，实得 %d 字节",
			ErrMalformedDatagram, nlmsgLen, n)
	}

	portID := uint32(0)
	if nl, ok := from.(*unix.SockaddrNetlink); ok {
		portID = nl.Pid
	}
	bumpCounter(t.receivedCounter)
	return Datagram{
		PortID:  portID,
		Payload: append([]byte(nil), buf[nlmsgHdrLen:nlmsgLen]...),
	}, true, nil
}

// Poll 等待任意一个被关注的事件。
//
// # 各掩码位的实际含义
//
// 只有四类是 Poll 能报告的：`EventRx`（socket 上有可读报文，需调用方在 interesting 里
// 显式索要）、`EventLinkDown`（接收侧已退出或 socket 出错）、`EventDeadline`（调用方的
// 截止时间已到）、`EventInterrupt`（本次等待内什么都没发生）。`EventTx`/`EventAbandon`
// 等位由别处产生（见 NotifyTxDone），Poll 不会凭空给出——旧实现连 socket 都不看，
// 把 interesting 当摆设，于是「等到可读」在这条链路上根本不存在。
//
// 等待时长取 `timeout` 与 `SetDeadline` 剩余两者的小值；两者都未给出时按 0 处理，即
// 做一次非阻塞探测。单次等待上限 `maxPollWait`（60 秒）：超过它的等待会被拆成多轮并以
// `EventInterrupt` 返回，调用方本就必须按「可能被唤醒」的语义循环调用 Poll。
//
// 链路断开通知（SignalLinkDown / Close）能立即打断这里的 epoll_wait，不必等超时。
func (t *Transport) Poll(timeout time.Duration, interesting EventType) (EventType, error) {
	if t.isClosed() {
		return EventLinkDown, nil
	}

	deadline := t.deadlineSnapshot()
	wait := timeout
	if !deadline.IsZero() {
		if remaining := time.Until(deadline); remaining <= 0 {
			return EventDeadline, nil
		} else if wait <= 0 || remaining < wait {
			wait = remaining
		}
	}

	// 不索要可读性：保持纯定时语义，只被链路断开或超时结束。
	// 走 linkDown 通道而不是 eventfd，是为了零值 Transport（测试里的占位）也不会崩。
	// wait 非正时 NewTimer 立即触发，正是「非阻塞探测」想要的行为。
	if interesting&EventRx == 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-t.linkDown:
			return EventLinkDown, nil
		case <-timer.C:
			return t.idleResult(deadline), nil
		}
	}

	if t.epFd < 0 {
		// 就绪观察未建立（OpenTransport 之外构造的占位对象）：退回定时轮询，
		// 由调用方的 TryRecv 自行判定有无数据。
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-t.linkDown:
			return EventLinkDown, nil
		case <-timer.C:
			return EventRx, nil
		}
	}

	var evs [4]unix.EpollEvent
	n, err := unix.EpollWait(t.epFd, evs[:], waitMillis(wait))
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return t.idleResult(deadline), nil
		}
		return 0, fmt.Errorf("等待 netlink 可读性失败：%w", err)
	}

	observed := EventType(0)
	for i := 0; i < n; i++ {
		switch evs[i].Fd {
		case int32(t.wakeFd):
			// 必须消费计数器：eventfd 是水平触发，留着它下次等待会立刻返回。
			drainWakeFd(t.wakeFd)
			return EventLinkDown, nil
		case int32(t.fd):
			// 错误/挂断：socket 已被内核侧终结，再 recvfrom 只会拿到同样的错误。
			if evs[i].Events&(unix.EPOLLERR|unix.EPOLLHUP|unix.EPOLLRDHUP) != 0 {
				return EventLinkDown, nil
			}
			if evs[i].Events&unix.EPOLLIN != 0 {
				observed |= EventRx
			}
		}
	}
	if observed != 0 {
		return observed, nil
	}
	return t.idleResult(deadline), nil
}

// isClosed 报告传输层是否已关闭。
func (t *Transport) isClosed() bool {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	return t.closed
}

// idleResult 给出「本次等待没等到可读」的结论：优先截止时间，其次无事发生。
func (t *Transport) idleResult(deadline time.Time) EventType {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return EventDeadline
	}
	return EventInterrupt
}

// maxPollWait 是单次 epoll_wait 的等待上限，防止超长 timeout 溢出内核的 int msec。
const maxPollWait = 60 * time.Second

// waitMillis 把时长换成 epoll 的毫秒数（向上取整，非阻塞探测为 0）。
func waitMillis(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	if d > maxPollWait {
		d = maxPollWait
	}
	return int((d + time.Millisecond - 1) / time.Millisecond)
}

// drainWakeFd 读空唤醒 fd 的计数器；无数据或失败都按「已清」处理。
func drainWakeFd(fd int) {
	var buf [8]byte
	_, _ = unix.Read(fd, buf[:])
}

// NotifyTxDone 由发送方在完成一次发送后调用，使 `EventTx` 可被观察到。
func (t *Transport) NotifyTxDone() {
	t.sendMu.Lock()
	t.txPend = true
	t.sendMu.Unlock()
}

// PopAbandon 取走一条待处理的放弃请求。
func (t *Transport) PopAbandon() (Abandon, bool) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	if len(t.pending) == 0 {
		return Abandon{}, false
	}
	a := t.pending[0]
	t.pending = t.pending[1:]
	return a, true
}

// Abandon 投递一条放弃请求。
func (t *Transport) Abandon(seq uint32) {
	t.sendMu.Lock()
	t.pending = append(t.pending, Abandon{Seq: seq})
	t.sendMu.Unlock()
}

// LinkDown 返回接收侧退出通知通道。
func (t *Transport) LinkDown() <-chan struct{} { return t.linkDown }

// SignalLinkDown 宣告接收侧已退出（幂等）。
//
// 两步都必要：关通道给本进程内的等待者（RecvTimeout 那一类 select），写 eventfd 给
// 阻塞在 epoll_wait 里的接收回路。只关通道的话，正在等待的 Poll 要等到自己的超时
// 才能发现链路已断。
func (t *Transport) SignalLinkDown() {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	select {
	case <-t.linkDown:
	default:
		close(t.linkDown)
	}
	t.pokeWakeFd()
}

// pokeWakeFd 给唤醒 fd 加 1；调用方须持 closeMu。fd 未建立或写入失败都按「无需唤醒」
// 处理——链路状态已经落在通道与 closed 标志上，Poll 的定时路径仍能收敛。
func (t *Transport) pokeWakeFd() {
	if t.wakeFd < 0 {
		return
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 1)
	_, _ = unix.Write(t.wakeFd, buf[:])
}

// Close 关闭 socket 并宣告接收侧退出。
func (t *Transport) Close() {
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		return
	}
	t.closed = true
	epFd, wakeFd := t.epFd, t.wakeFd
	t.epFd, t.wakeFd = -1, -1
	t.closeMu.Unlock()
	unix.Close(t.fd)
	if wakeFd >= 0 {
		unix.Close(wakeFd)
	}
	if epFd >= 0 {
		unix.Close(epFd)
	}
	t.SignalLinkDown()
}

// SetDeadline 设定截止时间；零值清除。
func (t *Transport) SetDeadline(d time.Duration) {
	t.deadlineMu.Lock()
	defer t.deadlineMu.Unlock()
	if d <= 0 {
		t.deadline = time.Time{}
		return
	}
	t.deadline = time.Now().Add(d)
}

// ClearDeadline 清除截止时间。
func (t *Transport) ClearDeadline() { t.SetDeadline(0) }

// DeadlineExpired 报告截止时间是否已到。
func (t *Transport) DeadlineExpired() bool {
	d := t.deadlineSnapshot()
	return !d.IsZero() && !time.Now().Before(d)
}

func (t *Transport) deadlineSnapshot() time.Time {
	t.deadlineMu.Lock()
	defer t.deadlineMu.Unlock()
	return t.deadline
}

func (t *Transport) hasLinkDown() bool {
	select {
	case <-t.linkDown:
		return true
	default:
		return false
	}
}

// resetLinkDown 重新武装接收侧：换一个新通道，并把上一次遗留的唤醒计数读空。
//
// 两步缺一：只换通道，旧的 eventfd 读数会让新接收方的第一次 Poll 立刻返回
// EventLinkDown，看起来「一上线就断链」。
func (t *Transport) resetLinkDown() {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	select {
	case <-t.linkDown:
		t.linkDown = make(chan struct{})
	default:
	}
	if t.wakeFd >= 0 {
		drainWakeFd(t.wakeFd)
	}
}

// 宿主字节序读写（nlmsghdr 是 netlink 惯例的宿主字节序，与自定义载荷的大端不同）。
func putU16NE(b []byte, v uint16) { b[0], b[1] = byte(v), byte(v>>8) }
func putU32NE(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
func getU32NE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
