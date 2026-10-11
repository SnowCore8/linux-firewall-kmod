package persist

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// 迁移前的三张表形状（逐列抄自加列之前的 schema）。
//
// 这里**手写**而不是调用 migrate()：要测的正是「库里已经有表、但没有新列」这个现场。
// 用新 schema 建库再跑 migrate() 等于什么都没核对——CREATE TABLE IF NOT EXISTS 会把
// 整张表跳过，ensureColumn 也就永远不会被执行。
const preMigrationSchema = `
	CREATE TABLE ban_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		jail_name TEXT NOT NULL,
		banned_at INTEGER NOT NULL,
		ban_count INTEGER NOT NULL DEFAULT 1,
		is_permanent INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE ip_reputation (
		ip TEXT PRIMARY KEY,
		score INTEGER NOT NULL DEFAULT 100,
		last_updated INTEGER NOT NULL,
		last_failure INTEGER,
		last_ban INTEGER
	);
	CREATE TABLE ban_history (
		ip TEXT PRIMARY KEY,
		ban_count INTEGER NOT NULL DEFAULT 0,
		last_banned_at INTEGER NOT NULL,
		is_permanent INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL
	);
`

// mustOpen 在指定路径上建/开库，并挂好关闭。
//
// 与 facts_test.go 里的 newTestDB 分开：迁移测试要**先在同一个路径上造出旧库**再打开，
// 路径必须由调用方挑，不能每次换一个新的临时目录。
func mustOpen(t *testing.T, path string) *DB {
	t.Helper()
	db, err := NewDB(Config{Path: path})
	if err != nil {
		t.Fatalf("打开测试库 %s 失败: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestMigrateBackfillsColumns 核对已在现场的旧库能被补上新列，且补列后可读可写。
//
// 三条都是「迁移只补列不补史」的现场：旧行的 duration_secs 必须是 NULL（不是 0，
// 0 会被时长直方图画成「0 秒封禁」），信誉计数必须从 0 起算（旧事件没有留下可回填的
// 每次扣分明细）。
func TestMigrateBackfillsColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	if _, err := raw.Exec(preMigrationSchema); err != nil {
		t.Fatalf("建旧表失败: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO ban_events (ip, jail_name, banned_at, ban_count, is_permanent, created_at)
		 VALUES ('203.0.113.50', 'sshd', 1700000000, 2, 0, 1700000000)`,
	); err != nil {
		t.Fatalf("写旧行失败: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO ip_reputation (ip, score, last_updated) VALUES ('203.0.113.50', 70, 1700000000)`,
	); err != nil {
		t.Fatalf("写旧信誉行失败: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭旧库失败: %v", err)
	}

	db := mustOpen(t, path)

	// 旧行读得出，且时长是「无从追究」而不是 0。
	events, err := db.GetBanEvents(10)
	if err != nil {
		t.Fatalf("读旧封禁事件失败: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("旧事件读数 = %d 条，期望 1 条", len(events))
	}
	if events[0].DurationSecs != nil {
		t.Errorf("旧行的 duration_secs = %v，迁移不补史应为 NULL", *events[0].DurationSecs)
	}

	// 新行带着时长写入，与旧行同表共存。
	dur := int64(1800)
	if err := db.RecordBanEvent("203.0.113.51", "sshd", 1, false, &dur); err != nil {
		t.Fatalf("写入带时长的封禁事件失败: %v", err)
	}
	if err := db.RecordBanEvent("203.0.113.52", "sshd", 1, true, nil); err != nil {
		t.Fatalf("写入永久封禁事件失败: %v", err)
	}
	samples, err := db.BanDurationSamples(100)
	if err != nil {
		t.Fatalf("读时长样本失败: %v", err)
	}
	if len(samples) != 3 {
		t.Fatalf("时长样本 = %d 条，期望 3 条（旧行也算在内，由读侧按 NULL 剔除）", len(samples))
	}

	// 信誉计数字段可用，且从 0 起累加（旧行没有这两列，补列后是默认 0）。
	if err := db.RecordFailure("203.0.113.50", 10); err != nil {
		t.Fatalf("记失败失败: %v", err)
	}
	if err := db.RecordBan("203.0.113.50", 10); err != nil {
		t.Fatalf("记封禁失败: %v", err)
	}
	rep, err := db.GetIPReputation("203.0.113.50")
	if err != nil {
		t.Fatalf("读信誉失败: %v", err)
	}
	if rep == nil {
		t.Fatalf("旧信誉行在补列后读不到")
	}
	if rep.TotalFailures != 1 || rep.TotalBans != 1 {
		t.Errorf("累计计数 = 失败 %d / 封禁 %d，补列后应各从 0 累加到 1", rep.TotalFailures, rep.TotalBans)
	}

	// ban_history 的 last_unbanned_at（第一批补的列）仍在新库上可用。
	if _, err := db.RecordBanHistory("203.0.113.50", false); err != nil {
		t.Fatalf("写封禁历史失败: %v", err)
	}
	if err := db.RecordUnbanHistory("203.0.113.50"); err != nil {
		t.Fatalf("写解封失败: %v", err)
	}
	h, err := db.GetBanHistory("203.0.113.50")
	if err != nil || h == nil {
		t.Fatalf("读封禁历史失败: %v (%+v)", err, h)
	}
	if h.LastUnbannedAt == 0 {
		t.Errorf("last_unbanned_at 没有落库")
	}
}

// TestMigrateIsIdempotent 核对第二次启动不会失败。
//
// ensureColumn 若不先查 pragma_table_info 而直接 ALTER，第二次打开就报 duplicate column
// name，daemon 再也起不来——这一条把「重复执行」钉住，而不是靠人记得。
func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")
	db := mustOpen(t, path)

	dur := int64(60)
	if err := db.RecordBanEvent("203.0.113.60", "sshd", 1, false, &dur); err != nil {
		t.Fatalf("写入封禁事件失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	again := mustOpen(t, path)
	events, err := again.GetBanEvents(10)
	if err != nil {
		t.Fatalf("重开后读事件失败: %v", err)
	}
	if len(events) != 1 || events[0].DurationSecs == nil || *events[0].DurationSecs != 60 {
		t.Errorf("重开后事件读数 = %+v，期望 1 条且时长 60 秒", events)
	}
}

// TestRecordBanHistoryReturnsSequence 核对返回的序号就是「这是第几封」。
//
// 手工封禁路径（POST /bans 与 /bans/batch）用它写 ban_events.ban_count；写死 1 会让
// 重复手工封禁的地址在分级成效里永远停在第 1 级。
func TestRecordBanHistoryReturnsSequence(t *testing.T) {
	db := newTestDB(t)
	const ip = "203.0.113.70"

	for want := 1; want <= 3; want++ {
		got, err := db.RecordBanHistory(ip, want == 3)
		if err != nil {
			t.Fatalf("第 %d 次封禁失败: %v", want, err)
		}
		if got != want {
			t.Fatalf("第 %d 次封禁返回序号 %d", want, got)
		}
	}
}

// TestGetBanLevelRows 核对分级成效的底账形状：按 ip × ban_count 折叠，
// 同一组合里只要有一次永久就记永久。
func TestGetBanLevelRows(t *testing.T) {
	db := newTestDB(t)

	rows := []struct {
		ip       string
		banCount int
		perm     bool
	}{
		{"203.0.113.71", 1, false},
		{"203.0.113.71", 2, false},
		{"203.0.113.71", 3, true},
		{"203.0.113.72", 1, false},
		{"203.0.113.73", 4, true},
		{"203.0.113.73", 5, true},
	}
	for _, r := range rows {
		if err := db.RecordBanEvent(r.ip, "sshd", r.banCount, r.perm, nil); err != nil {
			t.Fatalf("写封禁事件失败: %v", err)
		}
	}

	got, err := db.GetBanLevelRows()
	if err != nil {
		t.Fatalf("读分级底账失败: %v", err)
	}
	// ban_count>0 的六条写入各属不同的 ip×level 组合，折叠后仍是 6 行。
	if len(got) != len(rows) {
		t.Fatalf("底账行数 = %d，期望 %d（按 ip×ban_count 折叠）", len(got), len(rows))
	}
	byKey := make(map[[2]any]BanLevelRow, len(got))
	for _, r := range got {
		byKey[[2]any{r.IP, r.BanCount}] = r
	}
	for _, want := range rows {
		row, ok := byKey[[2]any{want.ip, want.banCount}]
		if !ok {
			t.Errorf("底账缺少 %s 的第 %d 级", want.ip, want.banCount)
			continue
		}
		if row.IsPermanent != want.perm {
			t.Errorf("%s 第 %d 级的永久标记 = %v，期望 %v", want.ip, want.banCount, row.IsPermanent, want.perm)
		}
	}
}
