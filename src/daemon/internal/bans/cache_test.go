package bans

import (
	"net/netip"
	"testing"
	"time"
)

func info(ip, jail string) BanInfo {
	return BanInfo{IP: ip, JailName: jail, Reason: jail, BannedAt: 1700000000}
}

// TestTryInsertRejectsDuplicate 验证 TryInsert 的「单赢家」语义不变。
func TestTryInsertRejectsDuplicate(t *testing.T) {
	c := NewActiveBanCache()
	if !c.TryInsert(info("203.0.113.1", "sshd")) {
		t.Fatal("首次插入应为赢家")
	}
	if c.TryInsert(info("203.0.113.1", "other")) {
		t.Fatal("同一 IP 的第二次插入不应为赢家")
	}
	got, ok := c.Get("203.0.113.1")
	if !ok || got.JailName != "sshd" {
		t.Fatalf("被拒的插入覆盖了原条目： %+v ok=%v", got, ok)
	}
}

// TestUpsertOverwritesAndReportsChange 验证对账用的覆盖写：内容相同返回 false，字段变了返回 true。
//
// 「是否变化」直接决定是否推送封禁域，判错会让安静时段每轮都推一次全屏刷新。
func TestUpsertOverwritesAndReportsChange(t *testing.T) {
	c := NewActiveBanCache()
	base := info("203.0.113.2", "sshd")
	if !c.Upsert(base) {
		t.Fatal("新增条目应报告变化")
	}
	if c.Upsert(base) {
		t.Fatal("同样内容重复写入不应报告变化")
	}

	changed := base
	changed.JailName = "dovecot"
	changed.Reason = "procfs 手工封禁"
	changed.ExpiresAt = base.BannedAt + 3600
	if !c.Upsert(changed) {
		t.Fatal("字段变化应报告变化")
	}
	got, ok := c.Get("203.0.113.2")
	if !ok || got.JailName != "dovecot" || got.Reason != "procfs 手工封禁" || got.ExpiresAt != base.BannedAt+3600 {
		t.Fatalf("覆盖写未生效： %+v ok=%v", got, ok)
	}

	// 守护进程自己的判定记账不参与比较：内核事件里没有这两个字段，纳入比较会让每轮
	// 对账都判定「有变化」。
	bookkeeping := changed
	bookkeeping.FailCount = 9
	bookkeeping.BanCount = 3
	if c.Upsert(bookkeeping) {
		t.Fatal("仅 FailCount/BanCount 变化不应报告变化")
	}
}

// TestUpsertMovesReverseIndex 验证 jail 变更后反向索引不残留旧归属。
func TestUpsertMovesReverseIndex(t *testing.T) {
	c := NewActiveBanCache()
	c.Upsert(info("203.0.113.3", "sshd"))
	c.Upsert(info("203.0.113.3", "dovecot"))
	if _, ok := c.Get("203.0.113.3"); !ok {
		t.Fatal("条目丢失")
	}
	// 旧 jail 的集合里不应再有它：Stats 与按 jail 的解封都依赖这一点。
	c.mu.RLock()
	defer c.mu.RUnlock()
	if set := c.byJail["sshd"]; len(set) != 0 {
		t.Fatalf("旧 jail 反向索引残留 %d 条", len(set))
	}
	if len(c.byJail["dovecot"]) != 1 {
		t.Fatalf("新 jail 反向索引未建立：%d", len(c.byJail["dovecot"]))
	}
}

// TestUpsertClearsPendingAck 验证内核列表里出现的条目同时结束等待确认。
func TestUpsertClearsPendingAck(t *testing.T) {
	c := NewActiveBanCache()
	now := time.Unix(1700000000, 0)
	c.TryInsert(info("203.0.113.4", "sshd"))
	c.MarkPending("203.0.113.4", now)
	if !c.IsPending("203.0.113.4", now.Unix()) {
		t.Fatal("标记后应处于等待确认")
	}
	c.Upsert(info("203.0.113.4", "sshd"))
	if c.IsPending("203.0.113.4", now.Unix()) {
		t.Fatal("Upsert 之后仍挂着待确认标记")
	}
	if n := c.PendingCount(now.Unix()); n != 0 {
		t.Fatalf("PendingCount = %d，期望 0", n)
	}
}

// TestPendingAckExpires 验证待确认标记按时限自动失效，不需要额外清扫任务。
func TestPendingAckExpires(t *testing.T) {
	c := NewActiveBanCache()
	now := time.Unix(1700000000, 0)
	c.MarkPending("203.0.113.5", now)

	if !c.IsPending("203.0.113.5", now.Add(PendingAckTimeout-time.Second).Unix()) {
		t.Fatal("时限内应仍在等待确认")
	}
	if c.IsPending("203.0.113.5", now.Add(PendingAckTimeout).Unix()) {
		t.Fatal("到达时限后应撤销保护")
	}
	// 撤销必须是真的删除，否则 pending 表随运行时间无限增长。
	c.MarkPending("203.0.113.6", now)
	if n := c.PendingCount(now.Unix()); n != 1 {
		t.Fatalf("PendingCount = %d，期望只剩 1 条", n)
	}
	if n := c.PendingCount(now.Add(2 * PendingAckTimeout).Unix()); n != 0 {
		t.Fatalf("全部超时后 PendingCount = %d，期望 0", n)
	}
}

// TestRemoveClearsPendingAck 验证解封路径不留待确认残迹。
func TestRemoveClearsPendingAck(t *testing.T) {
	c := NewActiveBanCache()
	now := time.Unix(1700000000, 0)
	c.TryInsert(info("203.0.113.7", "sshd"))
	c.MarkPending("203.0.113.7", now)
	if !c.Remove("203.0.113.7") {
		t.Fatal("Remove 应报告确实存在")
	}
	if c.IsPending("203.0.113.7", now.Unix()) {
		t.Fatal("Remove 后仍挂着待确认标记")
	}
}

// TestSweepExpiredKeepsPermanentAndLive 验证过期兜底只摘过期条目。
//
// 永久封禁的 ExpiresAt 为 0，若按「早于当前时刻」判断会被当成已过期而整批抹掉。
func TestSweepExpiredKeepsPermanentAndLive(t *testing.T) {
	c := NewActiveBanCache()
	now := int64(1700000000)
	permanent := info("203.0.113.8", "sshd")
	permanent.IsPermanent = true
	live := info("203.0.113.9", "sshd")
	live.ExpiresAt = now + 3600
	expired := info("203.0.113.10", "sshd")
	expired.ExpiresAt = now - 1

	c.Upsert(permanent)
	c.Upsert(live)
	c.Upsert(expired)

	ips := c.SweepExpired(now)
	if len(ips) != 1 || ips[0] != expired.IP {
		t.Fatalf("清扫结果 = %v，期望只摘除 %s", ips, expired.IP)
	}
	if c.Len() != 2 {
		t.Fatalf("剩余条目 = %d，期望 2", c.Len())
	}
	if _, ok := c.Get(permanent.IP); !ok {
		t.Fatal("永久封禁被清扫掉了")
	}
	if _, ok := c.Get(live.IP); !ok {
		t.Fatal("未过期条目被清扫掉了")
	}
	if c.SweepExpired(now) != nil {
		t.Fatal("二次清扫应无产出")
	}
}

// TestSweepExpiredClearsReverseIndex 验证清扫同样维护反向索引。
func TestSweepExpiredClearsReverseIndex(t *testing.T) {
	c := NewActiveBanCache()
	now := int64(1700000000)
	expired := info("203.0.113.11", "recidive")
	expired.ExpiresAt = now - 1
	c.Upsert(expired)
	c.SweepExpired(now)

	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.byJail["recidive"]) != 0 {
		t.Fatalf("清扫后 jail 反向索引残留 %d 条", len(c.byJail["recidive"]))
	}
}

// TestUnbanTemporaryAlsoClearsPending 验证批量临时解封不留下待确认标记。
func TestUnbanTemporaryAlsoClearsPending(t *testing.T) {
	c := NewActiveBanCache()
	now := time.Unix(1700000000, 0)
	temp := info("203.0.113.12", "sshd")
	temp.ExpiresAt = now.Unix() + 60
	permanent := info("203.0.113.13", "sshd")
	permanent.IsPermanent = true

	c.Upsert(temp)
	c.Upsert(permanent)
	c.MarkPending(temp.IP, now)

	ips := c.UnbanTemporaryWithIPs()
	if len(ips) != 1 || ips[0] != temp.IP {
		t.Fatalf("解封结果 = %v，期望仅 %s", ips, temp.IP)
	}
	if c.IsPending(temp.IP, now.Unix()) {
		t.Fatal("批量解封后仍挂着待确认标记")
	}
	if _, ok := c.Get(permanent.IP); !ok {
		t.Fatal("永久封禁被批量解封误伤")
	}
}

// TestWhitelistKeysAreNormalized 验证白名单键唯一一套规则：主机位清零 + 恒带前缀。
//
// 这条是契约缺陷 HTTP_WHITELIST_KEY_DIVERGENCE 的回归测试：Go 的 Prefix.String() 不掩码
// 主机位，若键直接取文本，同一子网会因为「198.51.100.0/24」与「198.51.100.7/24」两个键
// 各存一条，表现为白名单里看到两条同一个网段、删了还在。
func TestWhitelistKeysAreNormalized(t *testing.T) {
	w := NewWhitelist()
	withHostBits := netip.MustParsePrefix("198.51.100.7/24")
	network := netip.MustParsePrefix("198.51.100.0/24")

	if !w.Add(withHostBits) {
		t.Fatal("首次加入应报告新增")
	}
	if w.Add(network) {
		t.Fatal("主机位不同的同一子网应归一到同一键")
	}
	list := w.List()
	if len(list) != 1 {
		t.Fatalf("表内有 %d 条：%v", len(list), list)
	}
	if list[0] != "198.51.100.0/24" {
		t.Fatalf("键未归一化：%s", list[0])
	}
	// 命中判断必须与键同源：存了带主机位的原值时，同一网段的其他地址仍可能命中，
	// 但读侧看到的网段与键不一致。
	w2 := NewWhitelist()
	w2.Add(netip.MustParsePrefix("192.0.2.77/24"))
	if !w2.Contains(netip.MustParseAddr("192.0.2.200")) {
		t.Fatal("掩码后的前缀未覆盖整个网段")
	}
	if w2.Contains(netip.MustParseAddr("192.0.3.1")) {
		t.Fatal("命中判断越出了前缀")
	}

	if !w.Remove(withHostBits) {
		t.Fatal("按带主机位的写法应能删除归一键")
	}
	if w.Remove(network) {
		t.Fatal("表已空，再次删除不应报告成功")
	}
}

// TestWhitelistIPv6AndBareAddressKeys 验证 IPv6 与裸地址同样落到带前缀的键上。
func TestWhitelistIPv6AndBareAddressKeys(t *testing.T) {
	w := NewWhitelist()
	if !w.Add(netip.MustParsePrefix("2001:db8:ff00::ffff/56")) {
		t.Fatal("IPv6 加入失败")
	}
	bare := netip.MustParsePrefix("203.0.113.50/32")
	if !w.Add(bare) {
		t.Fatal("裸 /32 加入失败")
	}
	keys := map[string]bool{}
	for _, k := range w.List() {
		keys[k] = true
	}
	if !keys["2001:db8:ff00::/56"] {
		t.Fatalf("IPv6 键未掩码：%v", keys)
	}
	if !keys["203.0.113.50/32"] {
		t.Fatalf("/32 键丢失前缀：%v", keys)
	}
	if !w.Contains(netip.MustParseAddr("2001:db8:ff00::1")) {
		t.Fatal("Contains 未命中掩码后的前缀")
	}
}
