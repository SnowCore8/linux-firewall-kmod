package detect

import (
	"net/netip"
	"testing"
)

func ip(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("测试用 IP 非法 %q: %v", s, err)
	}
	return a
}

func TestCountsOnlyWithinWindow(t *testing.T) {
	w := NewFailureWindow()
	t0 := int64(10_000)
	if v := w.Observe(ip(t, "1.1.1.1"), t0, 300, 100); v.Recent != 1 {
		t.Fatalf("首次观测 Recent=%d, want 1", v.Recent)
	}
	if v := w.Observe(ip(t, "1.1.1.1"), t0+100, 300, 100); v.Recent != 2 {
		t.Fatalf("第二次观测 Recent=%d, want 2", v.Recent)
	}
	// t0 那次相隔 400 秒已滑出 300 秒窗口；t0+100 那次恰好相隔 300 秒仍在窗口边界内。
	v := w.Observe(ip(t, "1.1.1.1"), t0+400, 300, 100)
	if v.Recent != 2 {
		t.Fatalf("窗口内计数 Recent=%d, want 2", v.Recent)
	}
	if v.ReachedCap {
		t.Fatalf("不应达到 cap")
	}
}

func TestReachedCapFlagsWhenThresholdHit(t *testing.T) {
	w := NewFailureWindow()
	var last Verdict
	for i := 0; i < 5; i++ {
		last = w.Observe(ip(t, "2.2.2.2"), 42, 600, 5)
	}
	if last.Recent != 5 || !last.ReachedCap {
		t.Fatalf("达到 cap 必须被标出: %+v", last)
	}
}

func TestZeroWindowNeverCounts(t *testing.T) {
	w := NewFailureWindow()
	v := w.Observe(ip(t, "3.3.3.3"), 100, 0, 5)
	if v.Recent != 0 || v.ReachedCap {
		t.Fatalf("零窗口不应计数: %+v", v)
	}
	if got := w.Peek(ip(t, "3.3.3.3"), 100, 0, 5); got != 0 {
		t.Fatalf("零窗口 Peek=%d, want 0", got)
	}
}

func TestRingDropsOldestBeyondCapacity(t *testing.T) {
	w := NewFailureWindow()
	a := ip(t, "4.4.4.4")
	for i := 0; i < MaxTimestampsPerIP+10; i++ {
		w.Observe(a, 1_000, 10_000, ^uint32(0))
	}
	if got := w.Peek(a, 1_000, 10_000, ^uint32(0)); got != MaxTimestampsPerIP {
		t.Fatalf("每 IP 时间戳不应超过上限: Peek=%d want %d", got, MaxTimestampsPerIP)
	}
}

func TestPeekDoesNotMutateAndForgetClears(t *testing.T) {
	w := NewFailureWindow()
	a := ip(t, "5.5.5.5")
	w.Observe(a, 100, 600, 10)
	if got := w.Peek(a, 100, 600, 10); got != 1 {
		t.Fatalf("Peek=%d, want 1", got)
	}
	if got := w.Peek(a, 100, 600, 10); got != 1 {
		t.Fatalf("读路径无副作用，Peek 应稳定: %d", got)
	}
	w.Forget(a)
	if got := w.Peek(a, 100, 600, 10); got != 0 {
		t.Fatalf("Forget 后 Peek=%d, want 0", got)
	}
	if !w.IsEmpty() {
		t.Fatalf("Forget 后应为空")
	}
}

func TestCleanupRemovesOnlyFullyExpiredEntries(t *testing.T) {
	w := NewFailureWindow()
	w.Observe(ip(t, "6.6.6.6"), 100, 600, 10) // 过期
	w.Observe(ip(t, "7.7.7.7"), 900, 600, 10) // 未过期
	if n := w.CleanupExpired(1_000, 600); n != 1 {
		t.Fatalf("清理条数=%d, want 1", n)
	}
	if w.Len() != 1 {
		t.Fatalf("Len=%d, want 1", w.Len())
	}
	if got := w.Peek(ip(t, "7.7.7.7"), 1_000, 600, 10); got != 1 {
		t.Fatalf("保留项计数=%d, want 1", got)
	}
}

func TestFutureTimestampsAreIgnoredInCount(t *testing.T) {
	w := NewFailureWindow()
	a := ip(t, "8.8.8.8")
	w.Observe(a, 2_000, 600, 10) // now=1000 时这是未来
	if got := w.Peek(a, 1_000, 600, 10); got != 0 {
		t.Fatalf("未来时间戳不应计入: %d", got)
	}
	if got := w.Peek(a, 2_000, 600, 10); got != 1 {
		t.Fatalf("自身时刻应计入: %d", got)
	}
}

func TestIterReportsLatestTimestamp(t *testing.T) {
	w := NewFailureWindow()
	a := ip(t, "9.9.9.9")
	w.Observe(a, 100, 600, 10)
	w.Observe(a, 200, 600, 10)
	seen := map[netip.Addr]int64{}
	w.Iter(func(a netip.Addr, latest int64, tracked bool) {
		if !tracked {
			t.Fatalf("条目应带时间戳")
		}
		seen[a] = latest
	})
	if seen[a] != 200 {
		t.Fatalf("最新时间戳=%d, want 200", seen[a])
	}
}
