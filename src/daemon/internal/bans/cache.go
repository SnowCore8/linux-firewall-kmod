package bans

import (
	"sync"
	"time"
)

// PendingAckTimeout 是一条封禁等待内核确认的时限。
//
// 内核在 netlink 处理路径里同步建条目并广播 BanStateChange，正常确认延迟是毫秒级；留下
// 这个时限只为了兜住「事件在 socket 缓冲溢出时被丢弃」这一种情况。时限一到就撤销保护，
// 宁可让对账把一个真实存在但没等到事件的条目重建（下一次对账就会从内核列表里补回来），
// 也不能让一条被内核拒绝的封禁永远赖在镜像里。
const PendingAckTimeout = 60 * time.Second

// ActiveBanCache 是活跃封禁的内存权威存储。
//
// 旧实现用两个独立锁分别保护「IP → 封禁信息」主表与「jail → IP 集合」反向索引，
// 写入时要同时更新两张表，两者之间的短暂不一致对外可见。这里用单锁把两张表绑成
// 一次原子更新：读方永不会看到「主表有、反向索引没有」的中间态。
type ActiveBanCache struct {
	mu     sync.RWMutex
	bans   map[string]BanInfo
	byJail map[string]map[string]struct{}
	// pending 是「已下发内核、等待 BanStateChange 确认」的 IP → 确认截止时刻（Unix 秒）。
	//
	// 它存在的唯一理由是让对账不冤枉刚下发的封禁：下发是「投递即返回」，内核的处理与
	// 本地镜像写入之间必然有一个短窗口，此时内核列表里还没有这条。没有这层保护，每 30
	// 秒一次的对账会把刚点下的封禁当幽灵抹掉。
	pending map[string]int64
}

// NewActiveBanCache 新建空缓存。
func NewActiveBanCache() *ActiveBanCache {
	return &ActiveBanCache{
		bans:    make(map[string]BanInfo),
		byJail:  make(map[string]map[string]struct{}),
		pending: make(map[string]int64),
	}
}

// TryInsert 原子地插入主表与反向索引，返回「本调用是否为赢家」。
//
// 与旧实现 `try_insert` 语义一致：同一 IP 已存在则返回 false（并发去重、防止重复
// 封禁与统计双计）。主表与反向索引在同一次加锁内更新，读方不会看到中间态。
func (c *ActiveBanCache) TryInsert(info BanInfo) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.bans[info.IP]; exists {
		return false
	}
	c.bans[info.IP] = info
	set := c.byJail[info.JailName]
	if set == nil {
		set = make(map[string]struct{})
		c.byJail[info.JailName] = set
	}
	set[info.IP] = struct{}{}
	return true
}

// Remove 从两张表里同时摘除一个 IP，返回是否确实存在。
func (c *ActiveBanCache) Remove(ip string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, ok := c.bans[ip]
	if !ok {
		return false
	}
	delete(c.bans, ip)
	delete(c.pending, ip)
	if set := c.byJail[info.JailName]; set != nil {
		delete(set, ip)
		if len(set) == 0 {
			delete(c.byJail, info.JailName)
		}
	}
	return true
}

// Upsert 写入或覆盖一个 IP 的封禁信息（与 TryInsert 的「已存在即失败」相反）。
//
// 供对账使用：内核才是封禁的权威源，镜像必须能按内核的当前事实被纠正——条目可能已在
// procfs 侧续期（时长、原因、jail 都变了），按 TryInsert 的语义就会被静默跳过，镜像
// 从此停在旧值上。返回 true 表示本次写入改变了指向的内容（新增，或字段有变），
// 调用方据此决定要不要通知订阅了封禁域的读侧。
func (c *ActiveBanCache) Upsert(info BanInfo) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, exists := c.bans[info.IP]
	// 内核列表里已经有它，确认也就完成了——即使内容没变化也要撤销待确认标记，
	// 否则「重复下发同一事实」会让标记一直挂满时限。
	delete(c.pending, info.IP)
	if exists && sameBan(prev, info) {
		return false
	}
	c.bans[info.IP] = info
	set := c.byJail[info.JailName]
	if set == nil {
		set = make(map[string]struct{})
		c.byJail[info.JailName] = set
	}
	set[info.IP] = struct{}{}
	// jail 变更时要把旧归属摘掉，否则反向索引里留着一个主表已不认领的 IP：按 jail 的
	// 统计与批量解封都会误伤（旧实现整表替换时靠「连索引一起重建」绕过这一点）。
	if exists && prev.JailName != info.JailName {
		if old := c.byJail[prev.JailName]; old != nil {
			delete(old, info.IP)
			if len(old) == 0 {
				delete(c.byJail, prev.JailName)
			}
		}
	}
	return true
}

// sameBan 比较两条封禁信息是否呈现为同一事实。
//
// 只比对会被内核侧改写且读侧看得见的字段；FailCount/BanCount 是守护进程自己的判定记账，
// 内核事件里没有它们，纳入比较会让对账每轮都判定「有变化」而空转推送。
func sameBan(a, b BanInfo) bool {
	return a.JailName == b.JailName &&
		a.Reason == b.Reason &&
		a.BannedAt == b.BannedAt &&
		a.ExpiresAt == b.ExpiresAt &&
		a.IsPermanent == b.IsPermanent &&
		a.Num == b.Num
}

// SweepExpired 摘除所有已按本地时钟过期的封禁，返回被摘除的 IP。
//
// 内核的 per-entry 定时器到期时会摘链并广播解封，因此这层清扫是兜底而非主路径：事件
// 丢失（socket 缓冲溢出时内核丢弃事件）会让镜像里的过期条目一直挂着，读侧看到一条
// 「还剩负数秒」的封禁。永久封禁永不被清扫。
func (c *ActiveBanCache) SweepExpired(now int64) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ips []string
	for ip, info := range c.bans {
		if !info.IsExpired(now) {
			continue
		}
		delete(c.bans, ip)
		delete(c.pending, ip)
		if set := c.byJail[info.JailName]; set != nil {
			delete(set, ip)
			if len(set) == 0 {
				delete(c.byJail, info.JailName)
			}
		}
		ips = append(ips, ip)
	}
	return ips
}

// MarkPending 标记一个 IP 正等待内核确认封禁。
func (c *ActiveBanCache) MarkPending(ip string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[ip] = now.Add(PendingAckTimeout).Unix()
}

// ClearPending 撤销等待确认标记（收到 BanStateChange 或内核回执失败时调用）。
func (c *ActiveBanCache) ClearPending(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, ip)
}

// IsPending 报告该 IP 是否仍在等待内核确认。过期的标记在读的时候一并回收，
// 因此不需要额外的清扫任务，pending 表也不会随时间堆积。
func (c *ActiveBanCache) IsPending(ip string, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline, ok := c.pending[ip]
	if !ok {
		return false
	}
	if now >= deadline {
		delete(c.pending, ip)
		return false
	}
	return true
}

// PendingCount 返回当前仍在等待确认的封禁数（诊断用）。
func (c *ActiveBanCache) PendingCount(now int64) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for ip, deadline := range c.pending {
		if now >= deadline {
			delete(c.pending, ip)
			continue
		}
		n++
	}
	return n
}

// Get 按 IP 取封禁信息。
func (c *ActiveBanCache) Get(ip string) (BanInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	info, ok := c.bans[ip]
	return info, ok
}

// Len 返回当前活跃封禁数。
func (c *ActiveBanCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.bans)
}

// All 返回全部封禁信息的副本。
func (c *ActiveBanCache) All() []BanInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]BanInfo, 0, len(c.bans))
	for _, info := range c.bans {
		out = append(out, info)
	}
	return out
}

// List 返回全部封禁信息的副本（All 的别名）。
func (c *ActiveBanCache) List() []BanInfo {
	return c.All()
}

// CountByJail 返回每个 jail 当前的活跃封禁数（读 byJail 反向索引，不复制封禁内容）。
//
// 这一份是**活跃**封禁的口径，与 /api/v1/stats 的 current_bans 同源；历史累计次数在
// ban_events 里，两者不是同一个数（契约的 JailResponse.ban_count 注释写明取前者）。
// 没有活跃封禁的 jail 不出现在返回值里，调用方按缺失记 0。
func (c *ActiveBanCache) CountByJail() map[string]uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]uint64, len(c.byJail))
	for jail, set := range c.byJail {
		out[jail] = uint64(len(set))
	}
	return out
}

// UnbanTemporary 解封所有非永久封禁，返回解封数量。
func (c *ActiveBanCache) UnbanTemporary() int {
	ips := c.UnbanTemporaryWithIPs()
	return len(ips)
}

// UnbanTemporaryWithIPs 解封所有非永久封禁，返回被解封的 IP 列表。
func (c *ActiveBanCache) UnbanTemporaryWithIPs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ips []string
	for ip, info := range c.bans {
		if !info.IsPermanent {
			delete(c.bans, ip)
			delete(c.pending, ip)
			if set := c.byJail[info.JailName]; set != nil {
				delete(set, ip)
				if len(set) == 0 {
					delete(c.byJail, info.JailName)
				}
			}
			ips = append(ips, ip)
		}
	}
	return ips
}

// Stats 返回缓存统计信息。
func (c *ActiveBanCache) Stats() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	permanent := 0
	temporary := 0
	for _, info := range c.bans {
		if info.IsPermanent {
			permanent++
		} else {
			temporary++
		}
	}
	return map[string]any{
		"total":     len(c.bans),
		"permanent": permanent,
		"temporary": temporary,
	}
}
