// 封禁活动读取面的行为核对：today_bans 依赖的正是这三条语义——半开区间、升序、以及
// 「banned_at 是 Unix 秒」这个与写入方一致的假设。
package persist

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// seedBanEvents 按给定的 Unix 秒写入封禁活动行。
func seedBanEvents(t *testing.T, db *DB, at []int64, jail string) {
	t.Helper()
	for i, sec := range at {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		if _, err := db.conn.Exec(
			`INSERT INTO ban_events (ip, jail_name, banned_at, ban_count, is_permanent, created_at)
			 VALUES (?, ?, ?, 1, 0, ?)`, ip, jail, sec, sec); err != nil {
			t.Fatalf("写入封禁活动行失败: %v", err)
		}
	}
}

// TestCountBanEventsBetweenIsHalfOpen 守住窗口的边界归属。
//
// 闭区间会让午夜那条同时落进「昨日」与「今日」，两天的和大于总数；半开区间
// [start, end) 保证一个时刻只属于一个窗口，这是 today_bans 与 recent_bans 共用它的前提。
func TestCountBanEventsBetweenIsHalfOpen(t *testing.T) {
	db := newDBAt(t, filepath.Join(t.TempDir(), "activity.db"))

	start := time.Unix(1_000, 0)
	end := time.Unix(2_000, 0)
	seedBanEvents(t, db, []int64{999, 1_000, 1_500, 1_999, 2_000}, "sshd")

	got, err := db.CountBanEventsBetween(start, end)
	if err != nil {
		t.Fatalf("窗口计数失败: %v", err)
	}
	// 上界那条（2000）不属于本窗口，下界那条（1000）属于。
	if got != 3 {
		t.Errorf("窗口 [1000,2000) 内计到 %d 条，期望 3 条（边界时刻只归一个窗口）", got)
	}

	// 空窗口报 0 而不是错误：历史库里没有今天的数据是正常状态，不是故障。
	if n, err := db.CountBanEventsBetween(time.Unix(5_000, 0), time.Unix(6_000, 0)); err != nil || n != 0 {
		t.Errorf("空窗口 = (%d,%v)，期望 (0,nil)", n, err)
	}
}

// TestGetBanActivitySinceOrdersAscending 核对趋势与热力图共用的那次读取的形状。
func TestGetBanActivitySinceOrdersAscending(t *testing.T) {
	db := newDBAt(t, filepath.Join(t.TempDir(), "activity.db"))

	// 故意乱序写入：读取方按「升序」归桶，靠写入顺序保证不了。
	seedBanEvents(t, db, []int64{300, 100, 200, 50}, "sshd")

	rows, err := db.GetBanActivitySince(time.Unix(100, 0))
	if err != nil {
		t.Fatalf("读取封禁活动失败: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("取回 %d 行，期望 3 行（banned_at >= 100，含边界）", len(rows))
	}
	for i, want := range []int64{100, 200, 300} {
		if rows[i].BannedAt != want {
			t.Errorf("第 %d 行 banned_at = %d，期望 %d（升序）", i, rows[i].BannedAt, want)
		}
		if rows[i].JailName != "sshd" {
			t.Errorf("第 %d 行 jail = %q，期望 sshd（按 jail 归集的图依赖它）", i, rows[i].JailName)
		}
	}
}
