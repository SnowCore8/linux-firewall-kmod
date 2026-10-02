// Package kernel 承载与内核模块之间的 netlink 链：socket、报文配对、类型化请求 API。
//
// 分层与 Rust 版一致：transport 只负责字节收发，router 负责「回显 seq 的回复」与
// 「单向事件」的分派，client 在上层提供类型化请求。三者共用同一个 socket。
package kernel

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// MaxInFlight 是在途请求表容量上限。
const MaxInFlight = 64

// EventQueue 是内核推送队列容量。
//
// 满时按「拒绝并计数」处理而非阻塞：接收线程一旦被上层阻塞，socket 缓冲区会跟着
// 积压，最终内核丢弃事件——那是不可见的丢失，比「明确拒绝并计数」更糟。
const EventQueue = 4096

// RegisterError 是登记在途请求失败的原因。
//
// 三种原因对上层是三种处置：链路失联要告警、表满要退避重试、序号复用要查逻辑 bug。
type RegisterError int

// 登记失败原因取值。零值刻意留给成功，使 `err == registerOK` 与 Go 的零值判断一致。
const (
	// registerOK 表示登记成功。
	registerOK RegisterError = iota
	// RegisterLinkDown 表示接收侧已退出，回复永远不会到达。
	RegisterLinkDown
	// RegisterFull 表示在途请求表已满。
	RegisterFull
	// RegisterDuplicate 表示该 `(类型, seq)` 已被占用。
	RegisterDuplicate
)

// Error 实现 error。
func (e RegisterError) Error() string {
	switch e {
	case registerOK:
		return "登记成功"
	case RegisterLinkDown:
		return "与内核的接收链路已断开，无法登记在途请求"
	case RegisterFull:
		return "在途请求表已满"
	case RegisterDuplicate:
		return "请求序号与在途请求重复"
	default:
		return "未知的登记失败原因"
	}
}

// RouterStats 是接收与配对路径的计数快照。
type RouterStats struct {
	Received         uint64
	ForeignPortID    uint64
	Malformed        uint64
	UnknownType      uint64
	DecodeErrors     uint64
	UnmatchedReplies uint64
	ReplyUndelivered uint64
	PendingFull      uint64
	SeqCollisions    uint64
	LinkDown         uint64
	EventsDropped    uint64
}

type routerCounters struct {
	received         atomic.Uint64
	foreignPortID    atomic.Uint64
	malformed        atomic.Uint64
	unknownType      atomic.Uint64
	decodeErrors     atomic.Uint64
	unmatchedReplies atomic.Uint64
	replyUndelivered atomic.Uint64
	pendingFull      atomic.Uint64
	seqCollisions    atomic.Uint64
	linkDown         atomic.Uint64
	eventsDropped    atomic.Uint64
}

// replyKey 是在途请求的配对键：`(msg_type 原始取值, seq)`。
type replyKey struct {
	msgType uint16
	seq     uint32
}

// Incoming 是一条已解码的接收报文。
//
// MsgType 是公共头里的类型；Body 是载荷里的结构体指针（事件类型）或已解好的响应。
// 使用方应先读 MsgType 再做类型断言。
type Incoming struct {
	MsgType  contract.MsgType
	Seq      uint32
	Ddos     *contract.DdosEvent
	Ban      *contract.BanStateChange
	WL       *contract.WhitelistStateChange
	Cmd      *contract.CmdResult
	CfgAck   *contract.ConfigAck
	CfgChg   *contract.ConfigChange
	Stats    *contract.StatsResponse
	Bans     *contract.ListBansResponse
	Wls      *contract.ListWhitelistResponse
	Rates    *contract.ListRatesResponse
	Analysis *contract.AnalysisResponse
	RegAck   *contract.DaemonRegisterAck
}

// replyHandle 是一次在途请求的回复通道。
//
// 所有权规则与 Rust 版一致：Router 在配对成功后**先**从表中移除条目，再投递；
// 因此「请求超时放弃」与「回复迟到」之间不会发生二次投递。Drop 语义显式化为
// Abandon：超时或放弃时必须调用，否则该 `(类型, seq)` 会一直被占用。
type replyHandle struct {
	router *Router
	key    replyKey
	ch     chan Incoming
}

// RecvTimeout 等待配对回复。
//
// 链路断开优先于超时：断链后回复不可能到达，让调用方立刻拿到 LinkDown 而非白等到
// 自己的超时（否则每次关停都要多花一个超时周期）。
func (h *replyHandle) RecvTimeout(timeout time.Duration) (Incoming, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case msg := <-h.ch:
		return msg, nil
	case <-h.router.linkDown:
		return Incoming{}, ErrLinkDown
	case <-timer.C:
		return Incoming{}, ErrTimeout
	}
}

// Abandon 注销本在途请求；在超时或放弃路径上必须调用。
func (h *replyHandle) Abandon() { h.router.pending.remove(h.key) }

// Router 把接收到的报文分派到「在途请求的回复通道」或「事件流」。
type Router struct {
	pending  *pendingTable
	counters *routerCounters

	events   chan Incoming
	linkDown chan struct{}

	closeOnce sync.Once
}

// NewRouter 建立路由器。events 由调用方提供（缓冲大小建议取 EventQueue）。
func NewRouter(events chan Incoming) *Router {
	r := &Router{
		pending:  newPendingTable(),
		counters: &routerCounters{},
		events:   events,
		linkDown: make(chan struct{}),
	}
	return r
}

// Events 返回内核推送事件流。
func (r *Router) Events() <-chan Incoming { return r.events }

// Stats 返回计数快照。
func (r *Router) Stats() RouterStats {
	return RouterStats{
		Received:         r.counters.received.Load(),
		ForeignPortID:    r.counters.foreignPortID.Load(),
		Malformed:        r.counters.malformed.Load(),
		UnknownType:      r.counters.unknownType.Load(),
		DecodeErrors:     r.counters.decodeErrors.Load(),
		UnmatchedReplies: r.counters.unmatchedReplies.Load(),
		ReplyUndelivered: r.counters.replyUndelivered.Load(),
		PendingFull:      r.counters.pendingFull.Load(),
		SeqCollisions:    r.counters.seqCollisions.Load(),
		LinkDown:         r.counters.linkDown.Load(),
		EventsDropped:    r.counters.eventsDropped.Load(),
	}
}

// InFlight 返回当前在途请求数。
func (r *Router) InFlight() int { return r.pending.len() }

// Register 登记一条在途请求。
func (r *Router) Register(msgType contract.MsgType, seq uint32) (*replyHandle, error) {
	key := replyKey{uint16(msgType), seq}
	ch := make(chan Incoming, 1)
	err := r.pending.insert(key, ch)
	switch err {
	case registerOK:
		return &replyHandle{router: r, key: key, ch: ch}, nil
	case RegisterLinkDown:
		r.counters.linkDown.Add(1)
	case RegisterFull:
		r.counters.pendingFull.Add(1)
	case RegisterDuplicate:
		r.counters.seqCollisions.Add(1)
	}
	return nil, err
}

// Close 宣告接收侧已退出。幂等。
//
// 两件事缺一不可：置死标志（此后新登记被拒），并清空在途登记（丢弃各请求的通道，
// 使已在等待的调用方立即拿到 LinkDown，而不是空等到自己的超时）。
func (r *Router) Close() {
	r.closeOnce.Do(func() {
		r.pending.markDead()
		r.pending.clear()
		close(r.linkDown)
	})
}

// HandleDatagram 处理一条刚收到的报文。
//
// 处理顺序与 Rust 版一致，且顺序本身有语义：
//  1. 发送方必须是内核（portid 0），否则丢弃并计数；
//  2. 公共头必须合法（魔数、长度）；
//  3. 类型必须在契约内；
//  4. 回显 seq 的回复**先认领在途请求、再解码**——顺序颠倒会让「解码失败的回复」
//     被计成 unmatched，掩盖真正的解码错误；
//  5. 其余一律进事件队列（含 CmdResult：它用内核自增序号，不参与配对）。
func (r *Router) HandleDatagram(d Datagram) {
	if d.PortID != 0 {
		r.markForeignPortID()
		return
	}
	hdr, err := decodeHeader(d.Payload)
	if err != nil {
		r.markMalformed()
		return
	}
	r.counters.received.Add(1)
	if !hdr.MsgType.Known() {
		r.markUnknownType()
		return
	}

	if hdr.MsgType.SeqEchoedReply() {
		key := replyKey{uint16(hdr.MsgType), hdr.Seq}
		tx, claimed := r.pending.claim(key)
		if !claimed {
			// 无人在等：可能是客户端已超时放弃的迟到回复。计数而不推给事件流，
			// 否则一大页 LIST 结果会被当成健康事件灌进上层。
			r.counters.unmatchedReplies.Add(1)
			return
		}
		msg, err := decodeIncoming(hdr.MsgType, d.Payload)
		if err != nil {
			r.markDecodeError()
			return
		}
		select {
		case tx <- msg:
		default:
			r.counters.replyUndelivered.Add(1)
		}
		return
	}

	msg, err := decodeIncoming(hdr.MsgType, d.Payload)
	if err != nil {
		r.markDecodeError()
		return
	}
	r.pushEvent(msg)
}

// pushEvent 把一条事件交给上层；队列满即拒绝并计数，绝不阻塞接收线程。
func (r *Router) pushEvent(msg Incoming) {
	select {
	case r.events <- msg:
	default:
		r.counters.eventsDropped.Add(1)
	}
}

// markMalformed 记一次公共头解析失败。
func (r *Router) markMalformed() { r.counters.malformed.Add(1) }

// markForeignPortID 记一次发送方非内核的报文。
func (r *Router) markForeignPortID() { r.counters.foreignPortID.Add(1) }

// markUnknownType 记一次 `msg_type` 不在契约内的报文。
func (r *Router) markUnknownType() { r.counters.unknownType.Add(1) }

// markDecodeError 记一次字段解码失败的报文。
func (r *Router) markDecodeError() { r.counters.decodeErrors.Add(1) }

// pendingTable 是在途请求表。
type pendingTable struct {
	mu    sync.Mutex
	mapV  map[replyKey]chan Incoming
	alive atomic.Bool
}

func newPendingTable() *pendingTable {
	t := &pendingTable{mapV: make(map[replyKey]chan Incoming)}
	t.alive.Store(true)
	return t
}

// insert 登记一条在途请求。
//
// 两条拒绝规则：已存在的键拒绝而不是覆盖（覆盖会让先到的那条回复投给错误的等待方）；
// 接收侧已退出时拒绝（没有谁能再收到回复）。存活判断与插入在同一把锁内完成，故与
// 置死+清表之间不存在「插进空表然后干等」的竞态窗口。
func (t *pendingTable) insert(key replyKey, ch chan Incoming) RegisterError {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.alive.Load() {
		return RegisterLinkDown
	}
	if len(t.mapV) >= MaxInFlight {
		return RegisterFull
	}
	if _, dup := t.mapV[key]; dup {
		return RegisterDuplicate
	}
	t.mapV[key] = ch
	return registerOK
}

// claim 取走并移除在途请求的回复通道。
func (t *pendingTable) claim(key replyKey) (chan Incoming, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ch, ok := t.mapV[key]
	if ok {
		delete(t.mapV, key)
	}
	return ch, ok
}

// remove 移除在途请求（超时放弃路径）。
func (t *pendingTable) remove(key replyKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.mapV, key)
}

// markDead 置死：此后登记一律被拒。
func (t *pendingTable) markDead() { t.alive.Store(false) }

// clear 清空在途登记。先置死再清表由调用方保证。
func (t *pendingTable) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mapV = make(map[replyKey]chan Incoming)
}

func (t *pendingTable) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.mapV)
}
