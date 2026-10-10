package telemetry

import (
	"sync"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// TestSnapshotNeverNil 验证空存储也发布了可用快照：读侧不需要判空。
func TestSnapshotNeverNil(t *testing.T) {
	s := NewStore()
	snap := s.Snapshot()
	if !snap.SampledAt.IsZero() {
		t.Fatalf("未采样时 SampledAt 应为零值，实际 %v", snap.SampledAt)
	}
	if snap.Link.Registered {
		t.Fatal("未注册时 Link.Registered 应为 false")
	}
	if snap.Windows.Samples != 0 {
		t.Fatalf("未采样时窗口样本数应为 0，实际 %d", snap.Windows.Samples)
	}
}

// TestSnapshotIsDetachedCopy 验证读侧拿到的是副本：改返回值不会影响后续读数。
//
// 这条性质是「无锁读」的全部依据。若 Snapshot() 返回内部指针，HTTP handler 在遍历时
// 就能把写侧状态改脏。
func TestSnapshotIsDetachedCopy(t *testing.T) {
	s := NewStore()
	at := time.Unix(1700000000, 0)
	s.SetStats(contract.StatsResponse{CurrentBans: 7, TotalBans: 9}, at)

	snap := s.Snapshot()
	snap.Stats.CurrentBans = 999
	snap.Link.EventsDropped = 42

	if got := s.Snapshot().Stats.CurrentBans; got != 7 {
		t.Fatalf("改副本影响了快照：CurrentBans = %d，期望 7", got)
	}
	if got := s.Snapshot().Link.EventsDropped; got != 0 {
		t.Fatalf("改副本影响了链路计数：EventsDropped = %d，期望 0", got)
	}
}

// TestSetRatesCopiesEntries 验证速率条目在发布前被复制：调用方复用底层数组不会污染快照。
func TestSetRatesCopiesEntries(t *testing.T) {
	s := NewStore()
	entries := []contract.RateEntry{{Packets: 10, Bytes: 1000}}
	s.SetRates(Rates{GlobalPPS: 5, GlobalBPS: 500, Entries: entries}, time.Unix(1700000000, 0))

	entries[0].Packets = 999
	if got := s.Snapshot().Rates.Entries[0].Packets; got != 10 {
		t.Fatalf("快照条目被外部改写：Packets = %d，期望 10", got)
	}
}

// TestSetRatesFeedsOneWindowSamplePerQuery 验证一次采样恰好喂一个窗口样本。
//
// 内核的 global_pps 已经是「自上次查询以来的平均速率」，再按累计计数差分就是把速率算成
// 平方级；因此窗口样本数必须与 SetRates 调用数相等。
func TestSetRatesFeedsOneWindowSamplePerQuery(t *testing.T) {
	s := NewStore()
	for i := 0; i < 3; i++ {
		s.SetRates(Rates{GlobalPPS: uint64(100 + i*50), GlobalBPS: 1000}, time.Unix(int64(1700000000+i*5), 0))
	}
	snap := s.Snapshot()
	if snap.Windows.Samples != 3 {
		t.Fatalf("窗口样本数 = %d，期望 3", snap.Windows.Samples)
	}
	if !snap.Windows.PPS.Initialized || snap.Windows.PPS.Short <= 0 {
		t.Fatalf("PPS 平滑值未随样本推进： %+v", snap.Windows.PPS)
	}
	if !snap.Windows.SampledAt.Equal(time.Unix(1700000010, 0)) {
		t.Fatalf("SampledAt = %v，期望最后一个样本时刻", snap.Windows.SampledAt)
	}
}

// TestLinkStateTransitions 验证注册、采样、失败与路由器计数各自落在应起的字段上。
func TestLinkStateTransitions(t *testing.T) {
	s := NewStore()
	at := time.Unix(1700000000, 0)

	s.SetLinkRegistered(at)
	s.SetLinkSampled(at.Add(time.Second))
	s.BumpSampleFailure()
	s.SetRouterCounters(RouterCounters{EventsDropped: 4, DecodeErrors: 2, Malformed: 1, UnmatchedReplies: 3}, true)
	s.SetLinkError("内核拒绝指令 BanIp（errno=-22）", at.Add(2*time.Second))

	link := s.Snapshot().Link
	if !link.Registered {
		t.Fatal("SetLinkRegistered 后仍显示未注册")
	}
	if !link.LastSampleAt.Equal(at.Add(time.Second)) {
		t.Fatalf("LastSampleAt = %v", link.LastSampleAt)
	}
	if link.SampleFailures != 1 {
		t.Fatalf("SampleFailures = %d，期望 1", link.SampleFailures)
	}
	if !link.LinkDown || link.EventsDropped != 4 || link.UnmatchedReplies != 3 {
		t.Fatalf("路由器计数未并入： %+v", link)
	}
	if link.LastError == "" || link.LastErrorAt.IsZero() {
		t.Fatalf("链路失败原文未记录： %+v", link)
	}
}

// TestConcurrentReadersSeeConsistentSnapshot 是 -race 下的单写多读演练：
// 写侧任意时刻发布的都是一整份自洽状态，读侧不会看到跨字段撕裂。
func TestConcurrentReadersSeeConsistentSnapshot(t *testing.T) {
	s := NewStore()
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				snap := s.Snapshot()
				_ = snap.Stats.TotalBans + snap.Rates.GlobalPPS
			}
		}()
	}
	for i := 0; i < 200; i++ {
		at := time.Unix(1700000000+int64(i), 0)
		s.SetStats(contract.StatsResponse{TotalBans: uint64(i)}, at)
		s.SetRates(Rates{GlobalPPS: uint64(i), Entries: []contract.RateEntry{{Packets: uint64(i)}}}, at)
		s.SetLinkSampled(at)
	}
	close(done)
	wg.Wait()
}

// TestRingKeepsMostRecentAndNumbersMonotonically 验证环的回绕与编号语义。
func TestRingKeepsMostRecentAndNumbersMonotonically(t *testing.T) {
	r := NewRing(3)
	for i := 1; i <= 5; i++ {
		r.Push(Event{Kind: EventBan, IP: "203.0.113." + string(rune('0'+i))})
	}
	if r.Len() != 3 {
		t.Fatalf("Len = %d，期望容量 3", r.Len())
	}
	latest := r.Latest(3)
	if len(latest) != 3 {
		t.Fatalf("Latest(3) 返回 %d 条", len(latest))
	}
	if latest[0].Seq != 5 || latest[2].Seq != 3 {
		t.Fatalf("倒序编号 = [%d %d %d]，期望 5 4 3", latest[0].Seq, latest[1].Seq, latest[2].Seq)
	}
	for i := 1; i < len(latest); i++ {
		if latest[i-1].Seq <= latest[i].Seq {
			t.Fatalf("第 %d 条序号未递减", i)
		}
	}
	if got := len(r.Latest(0)); got != 0 {
		t.Fatalf("Latest(0) 返回 %d 条", got)
	}
	if got := len(r.Latest(100)); got != 3 {
		t.Fatalf("Latest(100) 返回 %d 条，期望 3", got)
	}
}

// TestRingPushStampsTimeWhenAbsent 验证零时刻被补成当前时间，读侧不需要处理零值。
func TestRingPushStampsTimeWhenAbsent(t *testing.T) {
	r := NewRing(0)
	if r.Capacity() != DefaultRingSize {
		t.Fatalf("默认容量 = %d，期望 %d", r.Capacity(), DefaultRingSize)
	}
	before := time.Now()
	e := r.Push(Event{Kind: EventDdos})
	if e.At.Before(before) {
		t.Fatalf("At = %v 早于调用时刻", e.At)
	}
	stamped := time.Unix(1600000000, 0)
	e2 := r.Push(Event{Kind: EventUnban, At: stamped})
	if !e2.At.Equal(stamped) {
		t.Fatalf("显式 At 被覆盖：%v", e2.At)
	}
}
