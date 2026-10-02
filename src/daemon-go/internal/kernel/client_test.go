package kernel

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// newTestClient 建立一个不持有 socket 的客户端，用于验证纯逻辑（序号分配、登记映射、续页）。
//
// 收发路径必须靠真实 socket，不在单元测试范围内：这里只覆盖不依赖内核的部分。
func newTestClient() (*Client, *Router) {
	router, _ := newTestRouter(4)
	return NewClient(nil, router), router
}

// TestAllocSeqNeverReturnsZeroAcrossWraparound 覆盖序号回绕。
//
// 契约里 seq == 0 表示「不参与配对」，故 u32 回绕产出的 0 必须被跳过。
func TestAllocSeqNeverReturnsZeroAcrossWraparound(t *testing.T) {
	client, _ := newTestClient()
	client.nextSeq.Store(^uint32(0) - 1)

	if got := client.allocSeq(); got != ^uint32(0)-1 {
		t.Fatalf("首个序号 %d，期望 %d", got, ^uint32(0)-1)
	}
	if got := client.allocSeq(); got != ^uint32(0) {
		t.Fatalf("第二个序号 %d，期望 %d", got, ^uint32(0))
	}
	if got := client.allocSeq(); got != 1 {
		t.Fatalf("回绕后应跳过 0 并返回 1，实得 %d", got)
	}
}

// TestRegisteredMapsEveryRegisterErrorToItsSentinel 覆盖登记失败的三种映射。
//
// 三种原因对上层是三种处置；映射错了会把「表满重试」当成「链路失联告警」。
func TestRegisteredMapsEveryRegisterErrorToItsSentinel(t *testing.T) {
	client, router := newTestClient()

	// 链路断开。
	router.Close()
	if _, err := client.registered(contract.MsgStatsResponse, 1); !errors.Is(err, ErrLinkDown) {
		t.Fatalf("应映射为 ErrLinkDown，实得 %v", err)
	}

	// 表满：换一个未关停的路由器。
	client, router = newTestClient()
	held := make([]*replyHandle, 0, MaxInFlight)
	for i := 0; i < MaxInFlight; i++ {
		h, err := router.Register(contract.MsgStatsResponse, uint32(i+1))
		if err != nil {
			t.Fatalf("第 %d 次登记失败：%v", i, err)
		}
		held = append(held, h)
	}
	if _, err := client.registered(contract.MsgStatsResponse, 9999); !errors.Is(err, ErrBusy) {
		t.Fatalf("应映射为 ErrBusy，实得 %v", err)
	}
	for _, h := range held {
		h.Abandon()
	}

	// 序号复用。
	first, err := router.Register(contract.MsgStatsResponse, 4)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}
	defer first.Abandon()
	if _, err := client.registered(contract.MsgStatsResponse, 4); !errors.Is(err, ErrSeqReused) {
		t.Fatalf("应映射为 ErrSeqReused，实得 %v", err)
	}
}

// TestUnexpectedReplyErrorNamesBothTypes 覆盖协议违例的错误文案。
func TestUnexpectedReplyErrorNamesBothTypes(t *testing.T) {
	err := &UnexpectedReplyError{Expected: contract.MsgStatsResponse, Got: contract.MsgConfigAck}
	want := "期望 StatsResponse 回复，实得 ConfigAck"
	if err.Error() != want {
		t.Fatalf("错误文案 %q，期望 %q", err.Error(), want)
	}
}

// TestDrainWalksEveryPage 覆盖「按 total 收尾」：5 条、每页 2 条 ⇒ 3 次请求。
func TestDrainWalksEveryPage(t *testing.T) {
	calls := 0
	got, err := drain(2, func(offset, limit uint32) (uint32, uint32, []uint32, error) {
		calls++
		if limit != 2 {
			t.Fatalf("必须按调用方给的页上限请求，实得 %d", limit)
		}
		const total = 5
		end := offset + 2
		if end > total {
			end = total
		}
		page := make([]uint32, 0, 2)
		for i := offset; i < end; i++ {
			page = append(page, i)
		}
		return total, offset, page, nil
	})
	if err != nil {
		t.Fatalf("续页失败：%v", err)
	}
	if calls != 3 {
		t.Fatalf("请求次数 %d，期望 3", calls)
	}
	want := []uint32{0, 1, 2, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("收集到 %d 条，期望 %d 条", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 条为 %d，期望 %d", i, got[i], want[i])
		}
	}
}

// TestDrainStopsOnEmptyPage 覆盖「total 撒谎」：只有靠空页才能收尾，不能无限请求。
func TestDrainStopsOnEmptyPage(t *testing.T) {
	calls := 0
	got, err := drain(10, func(offset, _ uint32) (uint32, uint32, []uint32, error) {
		calls++
		if offset == 0 {
			return 100, offset, []uint32{1, 2, 3}, nil
		}
		return 100, offset, nil, nil
	})
	if err != nil {
		t.Fatalf("续页失败：%v", err)
	}
	if calls != 2 {
		t.Fatalf("请求次数 %d，期望 2（首页有数据 + 次页空）", calls)
	}
	if len(got) != 3 {
		t.Fatalf("收集到 %d 条，期望 3 条", len(got))
	}
}

// TestDrainStopsWhenOffsetDoesNotAdvance 覆盖防御性终止：起点不推进时不得死循环。
//
// 已收到的条目保留（它们确实到过本进程），但必须在本轮就停下——不能把「内核重复
// 回同一段」当成「还有下一页」而无限请求。
func TestDrainStopsWhenOffsetDoesNotAdvance(t *testing.T) {
	calls := 0
	got, err := drain(4, func(_, _ uint32) (uint32, uint32, []uint32, error) {
		calls++
		return 100, 0, []uint32{9, 9}, nil
	})
	if err != nil {
		t.Fatalf("续页失败：%v", err)
	}
	if calls != 2 {
		t.Fatalf("请求次数 %d，期望 2", calls)
	}
	if len(got) != 4 {
		t.Fatalf("收集到 %d 条，期望 4 条（两页各 2 条）", len(got))
	}
}

// TestDrainOfEmptyTableAsksOnce 覆盖空表：只应请求一次。
func TestDrainOfEmptyTableAsksOnce(t *testing.T) {
	calls := 0
	got, err := drain(8, func(_, _ uint32) (uint32, uint32, []uint32, error) {
		calls++
		return 0, 0, nil, nil
	})
	if err != nil {
		t.Fatalf("续页失败：%v", err)
	}
	if calls != 1 {
		t.Fatalf("请求次数 %d，期望 1", calls)
	}
	if len(got) != 0 {
		t.Fatalf("空表应得到 0 条，实得 %d 条", len(got))
	}
}

// TestPageCapsMatchTheContract 覆盖页上限来源。
//
// 页上限必须取自契约声明的尾部容量：写死旧值（64/256）会与契约分叉，
// 且会让每页少装条目、多跑几个来回。
func TestPageCapsMatchTheContract(t *testing.T) {
	var bans contract.ListBansResponse
	var wls contract.ListWhitelistResponse
	var rates contract.ListRatesResponse
	if got := pageCap(bans.MaxTailEntries()); got != 689 {
		t.Fatalf("封禁页上限 %d，期望 689", got)
	}
	if got := pageCap(wls.MaxTailEntries()); got != 1926 {
		t.Fatalf("白名单页上限 %d，期望 1926", got)
	}
	if got := pageCap(rates.MaxTailEntries()); got != 744 {
		t.Fatalf("速率页上限 %d，期望 744", got)
	}
}

// TestPageCapOfNegativeCapacityIsZero 覆盖防御性边界：负数容量不得转成巨大 u32。
func TestPageCapOfNegativeCapacityIsZero(t *testing.T) {
	if got := pageCap(-1); got != 0 {
		t.Fatalf("负容量应得 0，实得 %d", got)
	}
}

// TestAddrToWireMapsFamiliesAndUnmapsV4Mapped 覆盖地址到线格式的转换。
//
// v4-mapped 地址必须按 IPv4 下发：内核按 af+addr+prefix_len 三元组定位条目，
// 若按 IPv6 装填，同一地址的封禁与解封会落到两个键上。
func TestAddrToWireMapsFamiliesAndUnmapsV4Mapped(t *testing.T) {
	v4 := netip.MustParseAddr("203.0.113.7")
	af, wire, err := addrToWire(v4)
	if err != nil {
		t.Fatalf("转换 IPv4 失败：%v", err)
	}
	if af != contract.AFInet {
		t.Fatalf("地址族 %d，期望 AFInet", af)
	}
	if wire[0] != 203 || wire[1] != 0 || wire[2] != 113 || wire[3] != 7 {
		t.Fatalf("IPv4 线格式不符：%v", wire[:4])
	}
	if wire[4] != 0 || wire[15] != 0 {
		t.Fatalf("IPv4 的剩余字节应为 0：%v", wire[4:])
	}

	mapped := netip.MustParseAddr("::ffff:203.0.113.7")
	af, wire, err = addrToWire(mapped)
	if err != nil {
		t.Fatalf("转换 v4-mapped 失败：%v", err)
	}
	if af != contract.AFInet {
		t.Fatalf("v4-mapped 应按 IPv4 下发，实得地址族 %d", af)
	}
	if wire != [contract.Addr16Len]byte{203, 0, 113, 7} {
		t.Fatalf("v4-mapped 线格式不符：%v", wire[:4])
	}

	v6 := netip.MustParseAddr("2001:db8::1")
	af, wire, err = addrToWire(v6)
	if err != nil {
		t.Fatalf("转换 IPv6 失败：%v", err)
	}
	if af != contract.AFInet6 {
		t.Fatalf("地址族 %d，期望 AFInet6", af)
	}
	want6 := v6.As16()
	for i := range want6 {
		if wire[i] != want6[i] {
			t.Fatalf("IPv6 线格式第 %d 字节为 %d，期望 %d", i, wire[i], want6[i])
		}
	}
}

// TestAddrToWireRejectsNonUnicast 覆盖拒绝非法地址：不得静默下发全零地址。
func TestAddrToWireRejectsNonUnicast(t *testing.T) {
	if _, _, err := addrToWire(netip.Addr{}); err == nil {
		t.Fatal("零值地址应被拒绝")
	}
}

// TestPopcount8CountsSetBits 覆盖位图条目数统计。
func TestPopcount8CountsSetBits(t *testing.T) {
	cases := []struct {
		in   byte
		want int
	}{
		{0x00, 0},
		{0x01, 1},
		{0x80, 1},
		{0xFF, 8},
		{0x0F, 4},
		{0xAA, 4},
	}
	for _, tc := range cases {
		if got := popcount8(tc.in); got != tc.want {
			t.Fatalf("popcount8(0x%02X)=%d，期望 %d", tc.in, got, tc.want)
		}
	}
}

// TestClampTimeoutNeverGoesNegative 覆盖超时收敛。
func TestClampTimeoutNeverGoesNegative(t *testing.T) {
	if got := ClampTimeout(-time.Second); got != 0 {
		t.Fatalf("负超时应收敛为 0，实得 %v", got)
	}
	if got := ClampTimeout(0); got != 0 {
		t.Fatalf("零超时保持 0，实得 %v", got)
	}
	if got := ClampTimeout(time.Second); got != time.Second {
		t.Fatalf("正超时保持原值，实得 %v", got)
	}
}

// TestRecvTimeoutReportsTimeoutWhenNothingArrives 覆盖无回复路径。
func TestRecvTimeoutReportsTimeoutWhenNothingArrives(t *testing.T) {
	router, _ := newTestRouter(4)
	handle, err := router.Register(contract.MsgStatsResponse, 11)
	if err != nil {
		t.Fatalf("登记在途请求失败：%v", err)
	}
	if _, err := handle.RecvTimeout(30 * time.Millisecond); err != ErrTimeout {
		t.Fatalf("无回复应超时，实得 %v", err)
	}
	if router.InFlight() != 1 {
		t.Fatalf("超时后条目仍在表内，等待调用方 Abandon，实得 %d", router.InFlight())
	}
	handle.Abandon()
	if router.InFlight() != 0 {
		t.Fatalf("Abandon 后应移出在途表，实得 %d", router.InFlight())
	}
}
