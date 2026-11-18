package main

import (
	"log/slog"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

// TestBanSinkDefersLedgerUntilConfirm 验证自动封禁的底账不再在下发前写入：
// InsertPending 只登记，ConfirmBan 才摘除登记（真正写库在 db 非空时才发生）。
func TestBanSinkDefersLedgerUntilConfirm(t *testing.T) {
	ip := "198.51.100.250"
	cache := bans.GlobalCache()
	cache.Remove(ip)
	defer cache.Remove(ip)

	s := &banSink{cache: cache, logger: slog.Default(), pending: make(map[string]bans.BanInfo)}
	now := time.Now().Unix()
	info := bans.BanInfo{
		IP: ip, PrefixLen: 32, JailName: "test", Reason: "test",
		BannedAt: now, ExpiresAt: now + 60,
	}

	if !s.InsertPending(info) {
		t.Fatalf("InsertPending 失败")
	}
	if len(s.pending) != 1 {
		t.Fatalf("登记表 = %d，期望 1", len(s.pending))
	}
	// 确认前不能有底账写入入口被调用：这里 db 为 nil，能验证的只有登记表状态。
	s.ConfirmBan(ip)
	if len(s.pending) != 0 {
		t.Fatalf("确认后登记表仍为 %d，期望 0", len(s.pending))
	}
	s.ConfirmBan(ip) // 重复确认必须是空操作

	cache.Remove(ip)
	if !s.InsertPending(info) {
		t.Fatalf("第二次 InsertPending 失败")
	}
	s.RollbackInsert(ip)
	if len(s.pending) != 0 {
		t.Fatalf("回滚后登记表仍为 %d，期望 0", len(s.pending))
	}
}
