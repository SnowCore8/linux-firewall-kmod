package persist

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// last_unbanned_at 是后加的列：现网的库里没有它，GET /api/v1/bans/:ip/detail 的
// last_unbanned_at 必须有真实来源，否则那一栏在面板上永远是 0，而 0 的意思
// （「没有过显式解封」）与「读不到」完全无法区分。
func TestMigrationAddsLastUnbannedAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// 手工造一份**旧 schema**（没有 last_unbanned_at），模拟升级现场。
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	if _, err := conn.Exec(`CREATE TABLE ban_history (
		ip TEXT PRIMARY KEY,
		ban_count INTEGER NOT NULL DEFAULT 0,
		last_banned_at INTEGER NOT NULL,
		is_permanent INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL
	)`); err != nil {
		t.Fatalf("建旧表失败: %v", err)
	}
	if _, err := conn.Exec(`INSERT INTO ban_history (ip, ban_count, last_banned_at, is_permanent, created_at)
		VALUES ('203.0.113.7', 2, 1000, 0, 1000)`); err != nil {
		t.Fatalf("写入旧行失败: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("关闭建表连接失败: %v", err)
	}

	db := newDBAt(t, path)
	if got, err := db.GetBanHistory("203.0.113.7"); err != nil {
		t.Fatalf("迁移后读历史失败: %v", err)
	} else if got == nil {
		t.Fatalf("迁移后旧行读不到")
	} else if got.BanCount != 2 || got.LastUnbannedAt != 0 {
		t.Fatalf("旧行读数走样: ban_count=%d last_unbanned_at=%d", got.BanCount, got.LastUnbannedAt)
	}

	if err := db.RecordUnbanHistory("203.0.113.7"); err != nil {
		t.Fatalf("记录解封失败: %v", err)
	}
	got, err := db.GetBanHistory("203.0.113.7")
	if err != nil {
		t.Fatalf("读回解封时间失败: %v", err)
	}
	if got.LastUnbannedAt <= 0 {
		t.Fatalf("last_unbanned_at 没有被写入: %+v", got)
	}

	// 第二次 NewDB 必须幂等：列已存在时 ALTER 会报 duplicate column，那会让守护进程
	// 从第二次启动起就再也起不来。
	if again := newDBAt(t, path); again == nil {
		t.Fatalf("重复迁移失败")
	}
}

// 从来没有被封禁过的 IP 不该因为一次解封就冒出一行 ban_count=0 的记录：那会进
// GetFrequentBans 与「独立 IP 数」统计。
func TestRecordUnbanHistoryDoesNotCreateRow(t *testing.T) {
	db := newTestDB(t)

	if err := db.RecordUnbanHistory("198.51.100.9"); err != nil {
		t.Fatalf("解封未封禁的 IP 应当静默成功: %v", err)
	}
	got, err := db.GetBanHistory("198.51.100.9")
	if err != nil {
		t.Fatalf("读历史失败: %v", err)
	}
	if got != nil {
		t.Fatalf("凭空多出一行封禁历史: %+v", got)
	}
}

// 重新封禁不清除上一次解封的时间：「刚被封之前它是什么时候被放出来的」是详情面板上
// 唯一能看出「反复回封」的读数。
func TestRecordBanHistoryKeepsLastUnbannedAt(t *testing.T) {
	db := newTestDB(t)

	if n, err := db.RecordBanHistory("203.0.113.8", false); err != nil {
		t.Fatalf("记录封禁失败: %v", err)
	} else if n != 1 {
		t.Fatalf("首次封禁返回的序号应为 1，实际 %d", n)
	}
	if err := db.RecordUnbanHistory("203.0.113.8"); err != nil {
		t.Fatalf("记录解封失败: %v", err)
	}
	before, err := db.GetBanHistory("203.0.113.8")
	if err != nil {
		t.Fatalf("读历史失败: %v", err)
	}
	if before.LastUnbannedAt == 0 {
		t.Fatalf("解封时间没有落库: %+v", before)
	}

	if n, err := db.RecordBanHistory("203.0.113.8", true); err != nil {
		t.Fatalf("再次记录封禁失败: %v", err)
	} else if n != 2 {
		t.Fatalf("第二次封禁返回的序号应为 2，实际 %d", n)
	}
	after, err := db.GetBanHistory("203.0.113.8")
	if err != nil {
		t.Fatalf("再次读历史失败: %v", err)
	}
	if after.BanCount != 2 || !after.IsPermanent {
		t.Fatalf("再次封禁的计数/永久标记没更新: %+v", after)
	}
	if after.LastUnbannedAt != before.LastUnbannedAt {
		t.Fatalf("再次封禁把上次解封时间改掉了: %d -> %d", before.LastUnbannedAt, after.LastUnbannedAt)
	}
}

func newDBAt(t *testing.T, path string) *DB {
	t.Helper()
	db, err := NewDB(Config{Path: path})
	if err != nil {
		t.Fatalf("打开库 %s 失败: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
