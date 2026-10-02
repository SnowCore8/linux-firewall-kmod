package kernel

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// headerOnlyBytes 组装一条只含公共头的报文。
//
// 不复用 contract 的编码函数：这里要故意造出「契约内类型 + 非法长度」等被编码器
// 拒绝的报文，只有手写字节才做得到。
func headerOnlyBytes(t contract.MsgType, seq uint32) []byte {
	b := make([]byte, contract.HdrLen)
	binary.BigEndian.PutUint32(b[0:4], contract.Magic)
	binary.BigEndian.PutUint16(b[4:6], uint16(t))
	binary.BigEndian.PutUint16(b[6:8], uint16(len(b)))
	binary.BigEndian.PutUint32(b[8:12], seq)
	return b
}

// newTestRouter 建立一个带事件队列的路由器。
func newTestRouter(queue int) (*Router, chan Incoming) {
	events := make(chan Incoming, queue)
	return NewRouter(events), events
}

// kernel 包装一条来自内核（portid 0）的报文。
func kernel(payload []byte) Datagram { return Datagram{PortID: 0, Payload: payload} }

// ddosPayload 编码一条可解码的 DdosEvent 载荷。
func ddosPayload(t *testing.T, seq uint32) []byte {
	t.Helper()
	ev := &contract.DdosEvent{AF: contract.AFInet, Reason: "速率超限", RatePPS: 1000}
	payload, err := ev.Encode(seq)
	if err != nil {
		t.Fatalf("编码 DdosEvent 失败：%v", err)
	}
	return payload
}

// TestForeignPortIDIsRejectedAndCounted 覆盖「发送方不是内核」的分支。
func TestForeignPortIDIsRejectedAndCounted(t *testing.T) {
	router, events := newTestRouter(4)
	router.HandleDatagram(Datagram{PortID: 1234, Payload: headerOnlyBytes(contract.MsgStatsQuery, 0)})

	if got := router.Stats().ForeignPortID; got != 1 {
		t.Fatalf("外来报文计数 %d，期望 1", got)
	}
	if got := router.Stats().Received; got != 0 {
		t.Fatalf("外来报文不应计入 received，实得 %d", got)
	}
	if len(events) != 0 {
		t.Fatalf("外来报文不应进入事件队列，实得 %d 条", len(events))
	}
}

// TestUnknownTypeIsCountedNotSilentlyDropped 覆盖「类型不在契约内」的分支。
//
// 长度合法，故必须先计 received 再判类型：否则无法区分「内核发了我看不懂的东西」
// 与「链路上有垃圾」。
func TestUnknownTypeIsCountedNotSilentlyDropped(t *testing.T) {
	router, events := newTestRouter(4)
	payload := headerOnlyBytes(contract.MsgStatsQuery, 0)
	binary.BigEndian.PutUint16(payload[4:6], 999)
	router.HandleDatagram(kernel(payload))

	if got := router.Stats().UnknownType; got != 1 {
		t.Fatalf("未知类型计数 %d，期望 1", got)
	}
	if got := router.Stats().Received; got != 1 {
		t.Fatalf("长度合法应计入 received，实得 %d", got)
	}
	if len(events) != 0 {
		t.Fatalf("未知类型不应进入事件队列")
	}
}

// TestMalformedHeaderIsCounted 覆盖「公共头自相矛盾」的分支。
func TestMalformedHeaderIsCounted(t *testing.T) {
	router, _ := newTestRouter(4)
	payload := headerOnlyBytes(contract.MsgStatsQuery, 0)
	binary.BigEndian.PutUint16(payload[6:8], 64)
	router.HandleDatagram(kernel(payload))

	if got := router.Stats().Malformed; got != 1 {
		t.Fatalf("畸形头计数 %d，期望 1", got)
	}
	if got := router.Stats().Received; got != 0 {
		t.Fatalf("头非法不应计入 received，实得 %d", got)
	}
}

// TestBroadcastEventIsNeverClaimedAsReply 覆盖「广播事件与在途请求 seq 撞号」。
//
// DdosEvent 用内核自增序号，不参与配对。若把它按 seq 认领，等待 StatsResponse 的
// 调用方会收到一个类型不符的载荷，而真正的事件则永远丢失。
func TestBroadcastEventIsNeverClaimedAsReply(t *testing.T) {
	router, events := newTestRouter(4)
	handle, err := router.Register(contract.MsgStatsResponse, 7)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}
	defer handle.Abandon()

	// DdosEvent 定长 65 字节，去掉公共头后是 53 字节的载荷。
	router.HandleDatagram(kernel(ddosPayload(t, 7)))

	select {
	case msg := <-events:
		if msg.MsgType != contract.MsgDdosEvent {
			t.Fatalf("事件类型 %s，期望 DdosEvent", msg.MsgType)
		}
	default:
		t.Fatal("广播事件应进入事件队列")
	}
	if got := router.Stats().UnmatchedReplies; got != 0 {
		t.Fatalf("广播事件不得被当成回复认领，unmatched=%d", got)
	}
}

// TestMatchedReplyGoesToWaiter 覆盖「回显 seq 的回复投递给等待方」。
func TestMatchedReplyGoesToWaiter(t *testing.T) {
	router, events := newTestRouter(4)
	handle, err := router.Register(contract.MsgStatsResponse, 42)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}

	resp := &contract.StatsResponse{CurrentBans: 5}
	payload, err := resp.Encode(42)
	if err != nil {
		t.Fatalf("编码 StatsResponse 失败：%v", err)
	}
	router.HandleDatagram(kernel(payload))

	got, err := handle.RecvTimeout(200 * time.Millisecond)
	if err != nil {
		t.Fatalf("等待方未收到回复：%v", err)
	}
	if got.Stats == nil || got.Stats.CurrentBans != 5 {
		t.Fatalf("回复内容不符：%+v", got)
	}
	if len(events) != 0 {
		t.Fatalf("已配对的回复不得进入事件队列")
	}
	if router.InFlight() != 0 {
		t.Fatalf("配对成功后应移出在途表，实得 %d", router.InFlight())
	}
}

// TestAbandonedRequestMakesLateReplyUnmatched 覆盖「等待方已放弃，回复迟到」。
//
// 回复不能进事件队列：一大页 LIST 结果会被上层当成健康事件，掩盖真正的丢包。
func TestAbandonedRequestMakesLateReplyUnmatched(t *testing.T) {
	router, events := newTestRouter(4)
	handle, err := router.Register(contract.MsgStatsResponse, 9)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}
	handle.Abandon()

	resp := &contract.StatsResponse{CurrentBans: 1}
	payload, err := resp.Encode(9)
	if err != nil {
		t.Fatalf("编码 StatsResponse 失败：%v", err)
	}
	router.HandleDatagram(kernel(payload))

	if got := router.Stats().UnmatchedReplies; got != 1 {
		t.Fatalf("迟到回复计数 %d，期望 1", got)
	}
	if len(events) != 0 {
		t.Fatalf("迟到回复不得进入事件队列")
	}
}

// TestWrongSeqReplyIsUnmatched 覆盖「seq 对不上」：配对键必须同时含类型与序号。
func TestWrongSeqReplyIsUnmatched(t *testing.T) {
	router, _ := newTestRouter(4)
	handle, err := router.Register(contract.MsgStatsResponse, 100)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}
	defer handle.Abandon()

	resp := &contract.StatsResponse{CurrentBans: 1}
	payload, err := resp.Encode(101)
	if err != nil {
		t.Fatalf("编码 StatsResponse 失败：%v", err)
	}
	router.HandleDatagram(kernel(payload))

	if got := router.Stats().UnmatchedReplies; got != 1 {
		t.Fatalf("序号不符的回复应计为 unmatched，实得 %d", got)
	}
	if router.InFlight() != 1 {
		t.Fatalf("原在途请求应保持不变，实得 %d", router.InFlight())
	}
}

// TestBroadcastNonEventTypeStillGoesToTheEventQueue 覆盖「非配对类型一律进事件队列」。
//
// 查询类 msg_type 是守护进程发给内核的，内核不会回发；这里用同样是广播语义的
// ConfigChange 来验证「不参与配对」的报文走事件路径而非被丢弃。
func TestBroadcastNonEventTypeStillGoesToTheEventQueue(t *testing.T) {
	router, events := newTestRouter(4)
	chg := &contract.ConfigChange{ConfigPayload: contract.ConfigPayload{BanTime: 600}}
	payload, err := chg.Encode(3)
	if err != nil {
		t.Fatalf("编码 ConfigChange 失败：%v", err)
	}
	router.HandleDatagram(kernel(payload))

	if got := router.Stats().Received; got != 1 {
		t.Fatalf("合法报文应计入 received，实得 %d", got)
	}
	if len(events) != 1 {
		t.Fatalf("非配对类型应进入事件队列，实得 %d 条", len(events))
	}
	if got := router.Stats().UnmatchedReplies; got != 0 {
		t.Fatalf("不应计为 unmatched，实得 %d", got)
	}
}

// TestCmdResultIsEventNeverClaimed 覆盖「内核自增序号的单播不进配对」。
//
// CmdResult 用内核自增序号，与请求 seq 无关，故即使序号恰好相同也必须进事件流。
func TestCmdResultIsEventNeverClaimed(t *testing.T) {
	router, events := newTestRouter(4)
	handle, err := router.Register(contract.MsgConfigAck, 5)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}
	defer handle.Abandon()

	cmd := &contract.CmdResult{OriginalCmd: contract.MsgBanIP, ErrorCode: 22}
	payload, err := cmd.Encode(5)
	if err != nil {
		t.Fatalf("编码 CmdResult 失败：%v", err)
	}
	router.HandleDatagram(kernel(payload))

	if len(events) != 1 {
		t.Fatalf("CmdResult 应进入事件队列，实得 %d 条", len(events))
	}
	if got := router.Stats().UnmatchedReplies; got != 0 {
		t.Fatalf("CmdResult 不该走配对路径，unmatched=%d", got)
	}
	if router.InFlight() != 1 {
		t.Fatalf("在途请求不应被 CmdResult 认领，实得 %d", router.InFlight())
	}
}

// TestEventQueueFullDropsWithoutBlocking 覆盖「事件队列满」：必须拒绝并计数。
func TestEventQueueFullDropsWithoutBlocking(t *testing.T) {
	router, events := newTestRouter(1)
	payload := ddosPayload(t, 1)
	router.HandleDatagram(kernel(payload))
	router.HandleDatagram(kernel(payload))

	if got := len(events); got != 1 {
		t.Fatalf("队列容量 1，实得 %d 条", got)
	}
	if got := router.Stats().EventsDropped; got != 1 {
		t.Fatalf("丢弃计数 %d，期望 1", got)
	}
}

// TestDecodeErrorIsCounted 覆盖「类型已知但字段非法」：说明契约与内核实现分叉。
func TestDecodeErrorIsCounted(t *testing.T) {
	router, events := newTestRouter(4)
	// 类型声明为 DdosEvent（定长 65），实际给 12 字节的空载荷。
	router.HandleDatagram(kernel(headerOnlyBytes(contract.MsgDdosEvent, 1)))

	if got := router.Stats().DecodeErrors; got != 1 {
		t.Fatalf("解码失败计数 %d，期望 1", got)
	}
	if len(events) != 0 {
		t.Fatalf("解码失败不应进入事件队列")
	}
}

// TestDecodeErrorOnClaimedReplyKeepsTheClaim 覆盖「认领后解码失败」的计数归属。
//
// 必须先认领再解码：若顺序颠倒，这条报文会被计成 unmatched，真正的解码错误被掩盖。
func TestDecodeErrorOnClaimedReplyKeepsTheClaim(t *testing.T) {
	router, _ := newTestRouter(4)
	if _, err := router.Register(contract.MsgStatsResponse, 8); err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}
	router.HandleDatagram(kernel(headerOnlyBytes(contract.MsgStatsResponse, 8)))

	if got := router.Stats().DecodeErrors; got != 1 {
		t.Fatalf("解码失败计数 %d，期望 1", got)
	}
	if got := router.Stats().UnmatchedReplies; got != 0 {
		t.Fatalf("已认领的请求不得计为 unmatched，实得 %d", got)
	}
	if router.InFlight() != 0 {
		t.Fatalf("认领后条目应已移除，实得 %d", router.InFlight())
	}
}

// TestRegisterRejectsDuplicateSeq 覆盖「同一 (类型, seq) 不得登记两次」。
func TestRegisterRejectsDuplicateSeq(t *testing.T) {
	router, _ := newTestRouter(4)
	first, err := router.Register(contract.MsgStatsResponse, 1)
	if err != nil {
		t.Fatalf("首次登记失败：%v", err)
	}
	defer first.Abandon()

	if _, err := router.Register(contract.MsgStatsResponse, 1); err != RegisterDuplicate {
		t.Fatalf("重复序号应被拒，实得 %v", err)
	}
	if got := router.Stats().SeqCollisions; got != 1 {
		t.Fatalf("序号冲突计数 %d，期望 1", got)
	}
}

// TestRegisterRejectsWhenPendingTableIsFull 覆盖「在途表满」：请求应被拒而非排队。
func TestRegisterRejectsWhenPendingTableIsFull(t *testing.T) {
	router, _ := newTestRouter(4)
	handles := make([]*replyHandle, 0, MaxInFlight)
	for i := 0; i < MaxInFlight; i++ {
		h, err := router.Register(contract.MsgStatsResponse, uint32(i+1))
		if err != nil {
			t.Fatalf("第 %d 次登记失败：%v", i, err)
		}
		handles = append(handles, h)
	}
	defer func() {
		for _, h := range handles {
			h.Abandon()
		}
	}()

	if _, err := router.Register(contract.MsgStatsResponse, 9999); err != RegisterFull {
		t.Fatalf("表满时登记应被拒，实得 %v", err)
	}
	if got := router.Stats().PendingFull; got != 1 {
		t.Fatalf("表满计数 %d，期望 1", got)
	}
	if got := router.InFlight(); got != MaxInFlight {
		t.Fatalf("在途数 %d，期望 %d", got, MaxInFlight)
	}
}

// TestRegisterRejectsAfterClose 覆盖关停路径：置死后不得再登记。
//
// 置死与清表必须在同一临界区内生效，否则会出现「插入空表然后干等到超时」。
func TestRegisterRejectsAfterClose(t *testing.T) {
	router, _ := newTestRouter(4)
	waiter, err := router.Register(contract.MsgStatsResponse, 1)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}

	router.Close()

	if _, err := router.Register(contract.MsgStatsResponse, 2); err != RegisterLinkDown {
		t.Fatalf("关停后登记应返回 LinkDown，实得 %v", err)
	}
	if got := router.Stats().LinkDown; got != 1 {
		t.Fatalf("关停后登记应计为链路断开，实得 %d", got)
	}
	// 已在等待的调用方必须立刻拿到 LinkDown，而不是空等到自己的超时。
	start := time.Now()
	if _, err := waiter.RecvTimeout(5 * time.Second); err != ErrLinkDown {
		t.Fatalf("关停后等待方应立刻收到 LinkDown，实得 %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("关停应立刻唤醒等待方，实际耗时 %v", elapsed)
	}
}

// TestCloseIsIdempotent 覆盖重复关停：close 一个已关闭的通道会 panic。
func TestCloseIsIdempotent(t *testing.T) {
	router, _ := newTestRouter(4)
	router.Close()
	router.Close()

	if got := router.InFlight(); got != 0 {
		t.Fatalf("关停后应为空表，实得 %d", got)
	}
}
