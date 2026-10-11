package persist

import (
	"net/netip"
	"path/filepath"
	"testing"
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

// 扣分值可配置：与旧实现一致的 10 分是默认，装配方可以改。
func TestPenaltyIsConfigurable(t *testing.T) {
	db := newTestDB(t)
	f := NewFacts(db, FactsOptions{FailurePenalty: 25})
	f.RecordFailure(addr(t, "203.0.113.40"))
	if got := f.ReputationScore(addr(t, "203.0.113.40")); got != 75 {
		t.Fatalf("扣分 25 后 = %d，期望 75", got)
	}
}
