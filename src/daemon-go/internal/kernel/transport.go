package kernel

import (
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
	// EventRx 表示有待发送的请求载荷。
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
}

// OpenTransport 创建并绑定 netlink socket。
//
// `nl_pid = 0` 交由内核分配 portid，`nl_groups = 1` 订阅内核广播组。
func OpenTransport() (*Transport, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, netlinkProto)
	if err != nil {
		return nil, fmt.Errorf("创建 netlink socket 失败：%w", err)
	}

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: netlinkGroup}
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("绑定 netlink socket 失败：%w", err)
	}

	return &Transport{fd: fd, linkDown: make(chan struct{})}, nil
}

// Fd 返回 socket 文件描述符。
func (t *Transport) Fd() int { return t.fd }

// Subscribe 建立接收侧：设置接收超时并清除非阻塞标志。
//
// 与 Rust 版一致：同一时刻只有一个接收方。重复调用是「换一个接收方」，因此先通知
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
		return fmt.Errorf("发送 netlink 报文失败：%w", err)
	}
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
		return Datagram{}, false, fmt.Errorf("收取 netlink 报文失败：%w", err)
	}
	if n > len(buf) {
		return Datagram{}, false, fmt.Errorf("%w：实得 %d 字节，缓冲 %d 字节",
			ErrTruncated, n, len(buf))
	}
	if n < nlmsgHdrLen {
		return Datagram{}, false, fmt.Errorf("%w：实得 %d 字节，不足一个 nlmsghdr",
			ErrMalformedDatagram, n)
	}
	nlmsgLen := int(getU32NE(buf[0:4]))
	if nlmsgLen < nlmsgHdrLen || nlmsgLen > n {
		return Datagram{}, false, fmt.Errorf("%w：nlmsg_len=%d，实得 %d 字节",
			ErrMalformedDatagram, nlmsgLen, n)
	}

	portID := uint32(0)
	if nl, ok := from.(*unix.SockaddrNetlink); ok {
		portID = nl.Pid
	}
	return Datagram{
		PortID:  portID,
		Payload: append([]byte(nil), buf[nlmsgHdrLen:nlmsgLen]...),
	}, true, nil
}

// Poll 等待任意一个被关注的事件。
//
// 与 Rust 版语义一致：收到放弃请求时返回 `EventAbandon`（由 reader goroutine 在
// 阻塞期间投递），截止时间到期返回 `EventDeadline`，超时无事件返回 `EventInterrupt`。
// `EventTx` 仅在上一次发送完成后由外部显式使能（见 NotifyTxDone），因为 netlink
// socket 没有真正的「可写」就绪可测。
func (t *Transport) Poll(timeout time.Duration, interesting EventType) (EventType, error) {
	t.closeMu.Lock()
	closed := t.closed
	t.closeMu.Unlock()
	if closed {
		return EventLinkDown, nil
	}

	deadlineMu := t.deadlineSnapshot()
	wait := timeout
	if !deadlineMu.IsZero() {
		if remaining := time.Until(deadlineMu); remaining <= 0 {
			return EventDeadline, nil
		} else if wait <= 0 || remaining < wait {
			wait = remaining
		}
	}

	select {
	case <-t.linkDown:
		return EventLinkDown, nil
	case <-time.After(wait):
		if !deadlineMu.IsZero() && !time.Now().Before(deadlineMu) {
			return EventDeadline, nil
		}
		return EventInterrupt, nil
	}
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
func (t *Transport) SignalLinkDown() {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	select {
	case <-t.linkDown:
	default:
		close(t.linkDown)
	}
}

// Close 关闭 socket 并宣告接收侧退出。
func (t *Transport) Close() {
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		return
	}
	t.closed = true
	t.closeMu.Unlock()
	unix.Close(t.fd)
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

func (t *Transport) resetLinkDown() {
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	select {
	case <-t.linkDown:
		t.linkDown = make(chan struct{})
	default:
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
