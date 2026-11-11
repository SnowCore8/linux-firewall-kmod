package persist

import (
	"bytes"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(Config{Path: filepath.Join(t.TempDir(), "facts_test.db")})
	if err != nil {
		t.Fatalf("建测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("解析地址 %s 失败: %v", s, err)
	}
	return a
}

func dbScore(t *testing.T, db *DB, ip string) int {
	t.Helper()
	rep, err := db.GetIPReputation(ip)
	if err != nil {
		t.Fatalf("读信誉分失败: %v", err)
	}
	if rep == nil {
		return -1
	}
	return rep.Score
}

// 每行日志都直查 SQLite 会把入站主链路钉死在磁盘上：未刷盘前库里必须一条都没有，
// 而内存里的分数已经按本次失败更新（判定层紧接着就要用它算阈值）。
func TestRecordFailureCoalescesUntilFlush(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{})
	ip := "203.0.113.10"

	for i := 0; i < 3; i++ {
		f.RecordFailure(addr(t, ip))
	}
	if got := f.ReputationScore(addr(t, ip)); got != 70 {
		t.Fatalf("三次失败后内存分数 = %d，期望 70", got)
	}
	if got := dbScore(t, db, ip); got != -1 {
		t.Fatalf("未刷盘前库里已有行（score=%d），折叠失效", got)
	}

	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	if got := dbScore(t, db, ip); got != 70 {
		t.Fatalf("刷盘后库里分数 = %d，期望 70", got)
	}
	// 再刷一次不该重复扣分。
	if err := f.Flush(); err != nil {
		t.Fatalf("二次刷盘失败: %v", err)
	}
	if got := dbScore(t, db, ip); got != 70 {
		t.Fatalf("重复刷盘把分数改成了 %d，期望仍是 70", got)
	}
}

// 分数下界是 0，且落库的 SQL 与内存的钳位必须同式（否则刷完盘分数会跳变）。
func TestReputationFloorIsZeroOnBothSides(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{})
	ip := "203.0.113.11"

	for i := 0; i < 20; i++ {
		f.RecordFailure(addr(t, ip))
	}
	if got := f.ReputationScore(addr(t, ip)); got != 0 {
		t.Fatalf("连扣 20 次后内存分数 = %d，期望 0", got)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	if got := dbScore(t, db, ip); got != 0 {
		t.Fatalf("刷盘后库里分数 = %d，期望 0", got)
	}
	if again := f.ReputationScore(addr(t, ip)); again != 0 {
		t.Fatalf("刷盘后内存分数变成 %d，期望仍是 0", again)
	}
}

// ::ffff:a.b.c.d 与 a.b.c.d 必须是同一条目：判定层与下发侧给出的写法不同，各存一份就
// 会有两个互不相见的信誉分。
func TestIPv4MappedSharesOneEntry(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{})

	f.RecordFailure(addr(t, "203.0.113.12"))
	mapped := netip.AddrFrom4([4]byte{203, 0, 113, 12}).AsSlice()
	mappedAddr := netip.AddrFrom16(v4In6(mapped))
	if got := f.ReputationScore(mappedAddr); got != 90 {
		t.Fatalf("映射写法读到 %d，期望 90（与点分写法同一条目）", got)
	}
	if entries, _ := f.Stats(); entries != 1 {
		t.Fatalf("缓存条目数 = %d，期望 1", entries)
	}
}

// 关停时必须等最终刷盘真正完成后才能关库：组合根按 done 通道等待，而不是只看 stopCh。
func TestFlusherDrainsBeforeDone(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{FlushEvery: time.Hour})
	ip := "203.0.113.13"
	f.RecordFailure(addr(t, ip))

	stop := make(chan struct{})
	done := f.StartFlusher(stop)
	close(stop)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopCh 关闭后 flusher 未在超时内完成最终刷盘")
	}
	if got := dbScore(t, db, ip); got != 90 {
		t.Fatalf("最终刷盘后库里分数 = %d，期望 90", got)
	}
}

func v4In6(b []byte) [16]byte {
	var a [16]byte
	a[10], a[11] = 0xff, 0xff
	copy(a[12:], b)
	return a
}

// 库里已有的分数必须作为起点，不能每次都从满分重算。
func TestExistingRowIsTheBaseline(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetIPReputation("203.0.113.13", 40); err != nil {
		t.Fatalf("预置信誉分失败: %v", err)
	}
	f := NewFacts(db, FactsOptions{})
	if got := f.ReputationScore(addr(t, "203.0.113.13")); got != 40 {
		t.Fatalf("起点分 = %d，期望沿用库里的 40", got)
	}
	f.RecordFailure(addr(t, "203.0.113.13"))
	if got := f.ReputationScore(addr(t, "203.0.113.13")); got != 30 {
		t.Fatalf("失败后 = %d，期望 30", got)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	if got := dbScore(t, db, "203.0.113.13"); got != 30 {
		t.Fatalf("刷盘后库里 = %d，期望 30（只扣折叠的那 10 分）", got)
	}
}

// 渐进式时长读的是历史封禁次数：库里已有的次数要读得到，NoteBan 要在缓存里 +1，
// 且不能把封禁扣分重复落一次库（那笔已由 banSink 的 RecordBan 写过了）。
func TestPriorBanCountAndNoteBan(t *testing.T) {
	db := newTestDB(t)
	ip := "203.0.113.14"
	if _, err := db.RecordBanHistory(ip, false); err != nil {
		t.Fatalf("预置封禁历史失败: %v", err)
	}
	f := NewFacts(db, FactsOptions{})
	if got := f.PriorBanCount(addr(t, ip)); got != 1 {
		t.Fatalf("历史封禁次数 = %d，期望 1", got)
	}

	f.NoteBan(addr(t, ip))
	if got := f.PriorBanCount(addr(t, ip)); got != 2 {
		t.Fatalf("NoteBan 后次数 = %d，期望 2", got)
	}
	if _, pending := f.Stats(); pending != 0 {
		t.Fatalf("NoteBan 不该产生待落盘扣分，pending=%d", pending)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	if got := dbScore(t, db, ip); got != -1 {
		t.Fatalf("NoteBan 把扣分落库了（score=%d），期望无写入", got)
	}
}

// 容量满时逐出最久未用的一条，并先把它折叠的扣分落盘——否则那部分账只剩内存里有一份。
//
// 序列里 21 被触碰两次（第二次把它提到最近使用），所以被逐出的是只失败过一次的 22。
func TestEvictionWritesPendingOnEvict(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{Capacity: 2})

	f.RecordFailure(addr(t, "203.0.113.21")) // 最久未用
	f.RecordFailure(addr(t, "203.0.113.22"))
	f.RecordFailure(addr(t, "203.0.113.21")) // 把 21 提到最近使用
	f.RecordFailure(addr(t, "203.0.113.23")) // 挤出 22

	if got := dbScore(t, db, "203.0.113.22"); got != 90 {
		t.Fatalf("被逐出条目落盘分数 = %d，期望 90（一次失败折叠落盘）", got)
	}
	entries, pending := f.Stats()
	if entries != 2 {
		t.Fatalf("缓存条目数 = %d，期望 2", entries)
	}
	if pending != 2 {
		t.Fatalf("待落盘条目数 = %d，期望 2", pending)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	if got := dbScore(t, db, "203.0.113.21"); got != 80 {
		t.Fatalf("两次失败的条目刷盘后 = %d，期望 80", got)
	}
}

// db 为 nil 时退化成纯内存：不 panic、不写库、分数仍按满分起算逐次扣减。
func TestNilDBIsMemoryOnly(t *testing.T) {
	f := NewFacts(nil, FactsOptions{})
	if got := f.ReputationScore(addr(t, "203.0.113.30")); got != 100 {
		t.Fatalf("未知 IP 起点分 = %d，期望 100", got)
	}
	f.RecordFailure(addr(t, "203.0.113.30"))
	f.NoteBan(addr(t, "203.0.113.30"))
	if got := f.ReputationScore(addr(t, "203.0.113.30")); got != 80 {
		t.Fatalf("一次失败 + 一次封禁后 = %d，期望 80", got)
	}
	if got := f.PriorBanCount(addr(t, "203.0.113.30")); got != 1 {
		t.Fatalf("封禁次数 = %d，期望 1", got)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("无库时刷盘应静默成功: %v", err)
	}
}

// waitUntil 轮询等待条件成立；测试里唯一的等待手段，避免依赖固定睡眠时长。
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("等待条件成立超时")
}

// 库侧的恢复/封禁写库改分必须能被判定层看到：只在首次访问时加载一次，阈值就会永远
// 按进程启动时的旧分算。重载后的有效分 = clamp(库中分) - 尚未落盘的 pending，
// 重载不能把未刷盘的失败扣分抹掉。
func TestScoreReloadPicksUpDBAndKeepsPending(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{ScoreReloadEvery: 20 * time.Millisecond})
	ip := "203.0.113.90"

	f.RecordFailure(addr(t, ip)) // pending=10，默认刷盘周期 5 秒，测试期间不会落盘
	if got := f.ReputationScore(addr(t, ip)); got != 90 {
		t.Fatalf("一次失败后内存分数 = %d，期望 90", got)
	}
	// 模拟恢复调度器/封禁写库把库里的分数改到 50（库侧不经过本缓存）。
	if err := db.SetIPReputation(ip, 50); err != nil {
		t.Fatalf("预置库中分数失败: %v", err)
	}

	stop := make(chan struct{})
	done := f.StartFlusher(stop)
	defer func() {
		close(stop)
		<-done
	}()

	waitUntil(t, 2*time.Second, func() bool {
		return f.ReputationScore(addr(t, ip)) == 40
	})
	if got := f.ReputationScore(addr(t, ip)); got != 40 {
		t.Fatalf("重载后分数 = %d，期望 40（库中 50 减未落盘的 10）", got)
	}
}

// total_failures 是失败条数而不是落盘批次数：一次折叠写入三条失败必须累加 3。
func TestFailureCountAddsPerRow(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{})
	ip := "203.0.113.91"

	for i := 0; i < 3; i++ {
		f.RecordFailure(addr(t, ip))
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	rep, err := db.GetIPReputation(ip)
	if err != nil || rep == nil {
		t.Fatalf("读信誉失败: %v（rep=%v）", err, rep)
	}
	if rep.TotalFailures != 3 {
		t.Fatalf("total_failures = %d，期望 3（按失败条数而不是批次）", rep.TotalFailures)
	}
	if rep.Score != 70 {
		t.Fatalf("分数 = %d，期望 70", rep.Score)
	}
}

// 扣分值可配置：与旧实现一致的 10 分是默认，装配方可以改。
func TestPenaltyIsConfigurable(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{FailurePenalty: 25})
	f.RecordFailure(addr(t, "203.0.113.40"))
	if got := f.ReputationScore(addr(t, "203.0.113.40")); got != 75 {
		t.Fatalf("扣分 25 后 = %d，期望 75", got)
	}
}

// 关停时 eventCh 里已入队但尚未落库的事件必须写完再退：它们正是风险查询接口的读数。
func TestStopDrainsQueuedRiskEvents(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{RiskEngineEnabled: true})
	ip := "203.0.113.50"
	f.RecordRiskEvent(addr(t, ip), risk.EventFailure, 1.0)
	f.Stop()

	n, err := db.CountEventsByIP(ip)
	if err != nil {
		t.Fatalf("统计事件失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("关停后库里事件数 = %d，期望 1（队列已排空）", n)
	}
	// 幂等：重复调用不能重复关 channel。
	f.Stop()
}

// Stop 之后仍可能有一条在途判定调用 RecordRiskEvent：不得向已关闭的 channel 发送。
func TestRecordRiskEventAfterStopIsSafe(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{RiskEngineEnabled: true})
	f.Stop()
	f.RecordRiskEvent(addr(t, "203.0.113.51"), risk.EventFailure, 1.0)
	f.RecordFailure(addr(t, "203.0.113.51"))
}

// 队列满时丢弃必须可计数，且告警按窗口限流：每条丢弃都打日志会把日志变成放大源。
func TestRiskEventQueueDropIsCountedAndRateLimited(t *testing.T) {
	var buf bytes.Buffer
	f := NewFacts(nil, FactsOptions{
		RiskEngineEnabled: true,
		Logger:            slog.New(slog.NewTextHandler(&buf, nil)),
	})
	ip := addr(t, "203.0.113.52")

	// 没有 DB 时不会启动 worker，队列填满后一直保持满状态。
	for i := 0; i < cap(f.eventCh); i++ {
		f.RecordRiskEvent(ip, risk.EventFailure, 1.0)
	}
	if got := len(f.eventCh); got != cap(f.eventCh) {
		t.Fatalf("队列长度 = %d，期望填满 %d", got, cap(f.eventCh))
	}

	f.RecordRiskEvent(ip, risk.EventFailure, 1.0) // 首次丢弃：告警
	f.RecordRiskEvent(ip, risk.EventFailure, 1.0) // 窗口内再丢：只计数

	f.mu.Lock()
	drops := f.eventDrops
	f.mu.Unlock()
	if drops != 2 {
		t.Fatalf("累计丢弃 = %d，期望 2", drops)
	}
	if n := strings.Count(buf.String(), "risk event queue full"); n != 1 {
		t.Fatalf("30 秒窗口内告警 %d 次，期望 1 次", n)
	}
}

// 逐出时落盘失败必须把欠账留在缓存里（重新入队），而不是随被逐出的对象一起丢掉。
func TestEvictionWriteFailureKeepsPending(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{Capacity: 1})
	f.RecordFailure(addr(t, "203.0.113.60"))

	_ = db.Close() // 让逐出落盘必定失败
	f.RecordFailure(addr(t, "203.0.113.61"))

	entries, pending := f.Stats()
	if entries != 2 {
		t.Fatalf("逐出落盘失败后条目数 = %d，期望 2（被逐出条目重新入队）", entries)
	}
	if pending != 2 {
		t.Fatalf("待落盘条目数 = %d，期望 2（欠账未丢）", pending)
	}
	if got := f.ReputationScore(addr(t, "203.0.113.60")); got != 90 {
		t.Fatalf("被逐出条目的分数 = %d，期望 90", got)
	}
}

// claimPending 模拟 writeAll 把某条目的待写量摘走清零（写库前的锁内动作）。
func claimPending(t *testing.T, f *Facts, ip string) (*factsEntry, uint32) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.index[ip]
	if !ok {
		t.Fatalf("条目 %s 不在索引里", ip)
	}
	e := el.Value.(*factsEntry)
	n := e.pending
	e.pending = 0
	return e, n
}

// 写库期间条目被逐出、同 IP 又建出替代条目时，写失败必须把欠账并入替代条目。
//
// 真实交错由调度决定；这里把顺序固定下来：先清零 pending（writeAll 已摘走），再让
// 逐出路径看到 0（不写库、直接摘链），随后同 IP 的新日志建替代条目，最后才还账。
// 若像旧实现那样直接还给原对象，欠账会挂到一条不再被索引的孤儿上，后续 Flush 永远
// 摘不到它，这部分扣分再也不会落盘。
func TestRequeueLostMergesIntoReplacement(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{Capacity: 2})
	ip := "203.0.113.70"

	f.RecordFailure(addr(t, ip))
	orphan, n := claimPending(t, f, ip)
	// 两个新 IP 依次把孤儿挤出缓存（容量 2，期间不打乱 LRU）。
	f.RecordFailure(addr(t, "203.0.113.71"))
	f.RecordFailure(addr(t, "203.0.113.72"))
	if _, ok := f.index[ip]; ok {
		t.Fatal("孤儿条目仍在索引里，交错前提不成立")
	}
	// 同 IP 再出现：库中没有它的记录（欠账从未落盘），替代条目从 100 扣到 90。
	f.RecordFailure(addr(t, ip))

	f.mu.Lock()
	f.requeueLostLocked(orphan, n)
	f.mu.Unlock()

	if got := f.ReputationScore(addr(t, ip)); got != 80 {
		t.Fatalf("合并欠账后内存分 = %d，期望 80", got)
	}
	if entries, pending := f.Stats(); entries != 2 || pending != 2 {
		t.Fatalf("entries=%d pending=%d，期望 2/2", entries, pending)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	if got := dbScore(t, db, ip); got != 80 {
		t.Fatalf("落库分数 = %d，期望 80（两笔欠账都到达）", got)
	}
}

// 写库期间条目被逐出且没有替代条目时，写失败必须把条目重新挂回索引。
func TestRequeueLostReinsertsEvictedEntry(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{Capacity: 1})
	ip := "203.0.113.80"

	f.RecordFailure(addr(t, ip))
	orphan, n := claimPending(t, f, ip)
	f.RecordFailure(addr(t, "203.0.113.81")) // 挤出孤儿，pending 为 0 故不写库
	if _, ok := f.index[ip]; ok {
		t.Fatal("孤儿条目仍在索引里，交错前提不成立")
	}

	f.mu.Lock()
	f.requeueLostLocked(orphan, n)
	f.mu.Unlock()

	if entries, pending := f.Stats(); entries != 2 || pending != 2 {
		t.Fatalf("entries=%d pending=%d，期望 2/2", entries, pending)
	}
	if got := f.ReputationScore(addr(t, ip)); got != 90 {
		t.Fatalf("重新入队后的分数 = %d，期望 90", got)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("刷盘失败: %v", err)
	}
	if got := dbScore(t, db, ip); got != 90 {
		t.Fatalf("落库分数 = %d，期望 90（重新入队的欠账已落盘）", got)
	}
}

// 封禁先落库、条目随后被逐出（或从未加载过）时，NoteBan 不得把同一次封禁记两遍。
//
// banSink 的顺序是 RecordBanHistory/RecordBan 先写库、再 NoteBan；两条路径的库值都
// 已经包含本次封禁。条目若在两者之间被 LRU 逐出，重新建条目从库里读到的就是封禁后的
// 值，再按「封禁前的内存读数」+1 会把这次封禁算成两次（次数多 1、扣分多 10）。
func TestNoteBanAfterEvictionDoesNotDoubleCount(t *testing.T) {
	const ip = "203.0.113.41"

	cases := []struct {
		name string
		// preload 表示 NoteBan 之前该条目已在内存里加载过（封禁前的读数）。
		preload bool
		// evict 表示落库与 NoteBan 之间条目被容量挤掉。
		evict bool
	}{
		{name: "从未加载", preload: false, evict: false},
		{name: "落库后被逐出", preload: true, evict: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			f := NewFacts(db, FactsOptions{Capacity: 1})

			if tc.preload {
				if got := f.PriorBanCount(addr(t, ip)); got != 0 {
					t.Fatalf("预加载时历史次数 = %d，期望 0", got)
				}
			}
			if _, err := db.RecordBanHistory(ip, false); err != nil {
				t.Fatalf("落封禁历史失败: %v", err)
			}
			if err := db.RecordBan(ip, DefaultBanPenalty); err != nil {
				t.Fatalf("落信誉扣分失败: %v", err)
			}
			if tc.evict {
				// 容量 1：触碰另一个地址就挤掉 ip 的条目。
				f.RecordFailure(addr(t, "203.0.113.42"))
			}

			f.NoteBan(addr(t, ip))

			if got := f.PriorBanCount(addr(t, ip)); got != 1 {
				t.Errorf("NoteBan 后历史次数 = %d，期望 1（库里的那次已计入）", got)
			}
			if got := f.ReputationScore(addr(t, ip)); got != 90 {
				t.Errorf("NoteBan 后信誉分 = %d，期望 90（只扣一次 %d）", got, DefaultBanPenalty)
			}
			if err := f.Flush(); err != nil {
				t.Fatalf("刷盘失败: %v", err)
			}
			if got := dbScore(t, db, ip); got != 90 {
				t.Errorf("刷盘后库里的分数 = %d，期望 90（NoteBan 不该再写一笔扣分）", got)
			}
		})
	}
}
