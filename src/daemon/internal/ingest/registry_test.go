package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestRegisterAssignsStableIDsAndResolvesWD 覆盖身份分配与 wd 路由。
func TestRegisterAssignsStableIDsAndResolvesWD(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()

	id1 := reg.Register(LogOwner("sshd"), filepath.Join(dir, "a.log"), 11, 111)
	id2 := reg.Register(LogOwner("nginx"), filepath.Join(dir, "b.log"), 22, 222)

	if id1 == id2 {
		t.Fatal("不同路径必须得到不同身份")
	}
	if id1.Get() != 0 || id2.Get() != 1 {
		t.Fatalf("身份应自 0 递增，实得 %d 与 %d", id1.Get(), id2.Get())
	}
	if got, ok := reg.Resolve(11); !ok || got != id1 {
		t.Fatalf("wd 11 应路由回 %v，实得 %v ok=%v", id1, got, ok)
	}
	if got, ok := reg.Resolve(22); !ok || got != id2 {
		t.Fatalf("wd 22 应路由回 %v", id2)
	}
	if reg.Len() != 2 {
		t.Fatalf("登记项应为 2，实得 %d", reg.Len())
	}

	entry, ok := reg.Get(id1)
	if !ok {
		t.Fatal("身份应存在")
	}
	if entry.Owner.Jail != "sshd" || entry.Inode != 111 {
		t.Fatalf("登记项不符：%+v", entry)
	}
	if entry.Owner.IsConfig {
		t.Fatal("日志源不应被标为配置文件")
	}
}

// TestReRegisteringSamePathKeepsIdentity 覆盖身份稳定性（结构问题的修复点）。
//
// 轮转重挂会换 wd、换 inode，但同一路径的身份必须不变——否则以身份为键的读取
// 偏移与半行缓冲会在重挂动作里被清空。
func TestReRegisteringSamePathKeepsIdentity(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()
	path := filepath.Join(dir, "a.log")

	id := reg.Register(LogOwner("sshd"), path, 11, 111)
	again := reg.Register(LogOwner("sshd"), path, 33, 333)

	if again != id {
		t.Fatalf("同一路径必须保持同一身份，实得 %v vs %v", again, id)
	}
	if reg.Len() != 1 {
		t.Fatalf("不应产生第二个登记项，实得 %d", reg.Len())
	}
	if got, ok := reg.Resolve(33); !ok || got != id {
		t.Fatal("新 wd 应指向同一身份")
	}
	if _, ok := reg.Resolve(11); ok {
		t.Fatal("旧 wd 不应再路由")
	}
	entry, _ := reg.Get(id)
	if entry.Inode != 333 {
		t.Fatalf("inode 应更新为 333，实得 %d", entry.Inode)
	}
}

// TestRebindingToTheSameWDKeepsRouting 覆盖内核复用同一 wd 的重挂。
func TestRebindingToTheSameWDKeepsRouting(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()
	path := filepath.Join(dir, "a.log")

	id := reg.Register(LogOwner("sshd"), path, 11, 111)
	again := reg.Register(LogOwner("sshd"), path, 11, 111)

	if again != id {
		t.Fatal("同一路径应保持身份")
	}
	if got, ok := reg.Resolve(11); !ok || got != id {
		t.Fatal("同 wd 重挂后仍须路由")
	}
	if reg.Len() != 1 {
		t.Fatalf("登记项应为 1，实得 %d", reg.Len())
	}
}

// TestReRegisteringCanChangeOwner 覆盖重载后同一路径改挂到别的 jail。
func TestReRegisteringCanChangeOwner(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()
	path := filepath.Join(dir, "shared.log")

	id := reg.Register(LogOwner("sshd"), path, 11, 111)
	same := reg.Register(LogOwner("nginx"), path, 11, 111)

	if same != id {
		t.Fatal("归属变化不应改变身份")
	}
	entry, _ := reg.Get(id)
	if entry.Owner.Jail != "nginx" {
		t.Fatalf("归属应更新为 nginx，实得 %q", entry.Owner.Jail)
	}
}

// TestPathNormalizationKeepsIdentityStable 覆盖路径归一化。
//
// 配置里可能写 `/var/log/./a.log` 或带冗余分隔符；归一化后必须仍是同一个源，
// 否则同一个文件会被读两遍、失败计数翻倍。
func TestPathNormalizationKeepsIdentityStable(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()

	id := reg.Register(LogOwner("sshd"), filepath.Join(dir, "a.log"), 11, 111)
	again := reg.Register(LogOwner("sshd"), filepath.Join(dir, ".", "a.log"), 12, 112)

	if again != id {
		t.Fatal("归一化后同一路径应保持身份")
	}
	if reg.Len() != 1 {
		t.Fatalf("登记项应为 1，实得 %d", reg.Len())
	}
}

// TestConfigOwnerIsDistinguished 覆盖配置文件监视项。
func TestConfigOwnerIsDistinguished(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()

	id := reg.Register(ConfigOwner(), filepath.Join(dir, "config.yaml"), 5, 55)
	entry, ok := reg.Get(id)
	if !ok {
		t.Fatal("身份应存在")
	}
	if !entry.Owner.IsConfig {
		t.Fatal("应标为配置文件")
	}
	if entry.Owner.Jail != "" {
		t.Fatalf("配置文件不应有 jail 归属，实得 %q", entry.Owner.Jail)
	}
}

// TestRemoveDropsAllThreeMappings 覆盖摘除。
func TestRemoveDropsAllThreeMappings(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()
	path := filepath.Join(dir, "a.log")

	id := reg.Register(LogOwner("sshd"), path, 11, 111)
	if !reg.ContainsPath(path) {
		t.Fatal("应已登记该路径")
	}

	removed, ok := reg.Remove(id)
	if !ok {
		t.Fatal("应有登记项")
	}
	if removed.Path != CleanPath(path) {
		t.Fatalf("摘除项路径不符：%q", removed.Path)
	}
	if _, ok := reg.Get(id); ok {
		t.Fatal("身份应已移除")
	}
	if _, ok := reg.Resolve(11); ok {
		t.Fatal("wd 映射应已移除")
	}
	if reg.ContainsPath(path) {
		t.Fatal("路径映射应已移除")
	}
	if !reg.IsEmpty() {
		t.Fatal("应已清空")
	}
}

// TestRemoveAfterRebindKeepsCurrentWDMapping 覆盖「重挂后按旧 wd 摘除」。
//
// 摘除时必须核对 byWD 里的映射是否确实指向本身份：轮转后 wd 已换，按旧 wd 删会
// 误删指向新 wd 的当前映射，导致后续事件路由此断掉。
func TestRemoveAfterRebindKeepsCurrentWDMapping(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()
	path := filepath.Join(dir, "a.log")

	id := reg.Register(LogOwner("sshd"), path, 11, 111)
	reg.Rebind(id, 22, 222)

	// 另一个源占用旧 wd 号（内核的 wd 可复用）。
	other := reg.Register(LogOwner("nginx"), filepath.Join(dir, "b.log"), 11, 999)
	if other == id {
		t.Fatal("应是另一个身份")
	}

	if _, ok := reg.Remove(id); !ok {
		t.Fatal("应能摘除")
	}
	if got, ok := reg.Resolve(11); !ok || got != other {
		t.Fatal("误删了别人的 wd 映射")
	}
	if _, ok := reg.Resolve(22); ok {
		t.Fatal("本身份的新 wd 映射应已移除")
	}
}

// TestRegistryEntriesSnapshotDoesNotAliasInternalState 覆盖快照不会串改内部状态。
func TestRegistryEntriesSnapshotDoesNotAliasInternalState(t *testing.T) {
	dir := newTempDir(t)
	reg := NewSourceRegistry()
	id := reg.Register(LogOwner("sshd"), filepath.Join(dir, "a.log"), 11, 111)

	snapshot := reg.Entries()
	if len(snapshot) != 1 {
		t.Fatalf("快照应有 1 项，实得 %d", len(snapshot))
	}
	snapshot[0].Owner.Jail = "mutated"

	entry, _ := reg.Get(id)
	if entry.Owner.Jail != "sshd" {
		t.Fatal("改动快照不应影响内部状态")
	}
}

// TestEventRoutingClosesTheLoopWithReader 覆盖采集层闭环：事件 → wd → 身份 → 新字节。
func TestEventRoutingClosesTheLoopWithReader(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "sshd.log")
	if err := os.WriteFile(path, []byte("old-history\n"), 0o644); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}

	watcher, err := NewWatcher()
	if err != nil {
		t.Fatalf("inotify 初始化失败：%v", err)
	}
	defer func() { _ = watcher.Close() }()

	wd, err := watcher.Add(path, LogFileWatchMask())
	if err != nil {
		t.Fatalf("添加 watch 失败：%v", err)
	}
	reg := NewSourceRegistry()
	id := reg.Register(LogOwner("sshd"), path, wd, 0)

	reader := NewSourceReader(nil)
	reader.OpenAtEnd(path)
	if reader.Offset() != 12 {
		t.Fatalf("启动偏移应为文件末尾（12），实得 %d", reader.Offset())
	}
	defer func() { _ = reader.Close() }()

	appendFile(t, path, []byte("Failed password for root from 1.2.3.4 port 22 ssh2\n"))

	// 事件驱动：轮询真实可读状态，等事件到达后按 wd 路由。
	deadline := time.Now().Add(5 * time.Second)
	var routed SourceID
	var found bool
	for time.Now().Before(deadline) && !found {
		ready, err := watcher.WaitReadable(50 * time.Millisecond)
		if err != nil {
			t.Fatalf("等待可读失败：%v", err)
		}
		if !ready {
			continue
		}
		events, err := watcher.ReadEvents()
		if err != nil {
			t.Fatalf("读事件失败：%v", err)
		}
		for _, ev := range events {
			if sid, ok := reg.Resolve(ev.WD); ok && ev.IsContentChange() {
				routed, found = sid, true
				break
			}
		}
	}
	if !found {
		t.Fatal("5 秒内未收到内容变更事件")
	}
	if routed != id {
		t.Fatalf("事件应按 wd 路由回稳定身份 %v，实得 %v", id, routed)
	}

	chunk, err := reader.ReadNew(path)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	want := "Failed password for root from 1.2.3.4 port 22 ssh2\n"
	if string(chunk.Bytes) != want {
		t.Fatalf("应正好读出追加的那一行，实得 %q", chunk.Bytes)
	}
	if chunk.Rotated {
		t.Fatal("追加不构成轮转")
	}
}

// TestWaitReadableTimesOutWithoutEvents 覆盖等待超时（避免退化成忙轮询）。
func TestWaitReadableTimesOutWithoutEvents(t *testing.T) {
	watcher, err := NewWatcher()
	if err != nil {
		t.Fatalf("inotify 初始化失败：%v", err)
	}
	defer func() { _ = watcher.Close() }()

	start := time.Now()
	ready, err := watcher.WaitReadable(30 * time.Millisecond)
	if err != nil {
		t.Fatalf("等待失败：%v", err)
	}
	if ready {
		t.Fatal("无事件时不应报告可读")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Fatalf("应在超时前阻塞，实际仅 %v", elapsed)
	}
}

// TestReadEventsIsEmptyWithoutEvents 覆盖非阻塞空读不是错误。
func TestReadEventsIsEmptyWithoutEvents(t *testing.T) {
	watcher, err := NewWatcher()
	if err != nil {
		t.Fatalf("inotify 初始化失败：%v", err)
	}
	defer func() { _ = watcher.Close() }()

	events, err := watcher.ReadEvents()
	if err != nil {
		t.Fatalf("空读不应报错：%v", err)
	}
	if len(events) != 0 {
		t.Fatalf("应无事件，实得 %d 条", len(events))
	}
}

// TestSelfGoneMaskIsRecognized 覆盖轮转信号掩码判定。
func TestSelfGoneMaskIsRecognized(t *testing.T) {
	if !(WatchEvent{Mask: unix.IN_MOVE_SELF}).IsSelfGone() {
		t.Fatal("IN_MOVE_SELF 应判为自身已移走")
	}
	if !(WatchEvent{Mask: unix.IN_DELETE_SELF}).IsSelfGone() {
		t.Fatal("IN_DELETE_SELF 应判为自身已删除")
	}
	if (WatchEvent{Mask: unix.IN_MODIFY}).IsSelfGone() {
		t.Fatal("内容变更不应判为自身已移走")
	}
	if !(WatchEvent{Mask: unix.IN_MODIFY}).IsContentChange() {
		t.Fatal("IN_MODIFY 应判为内容可能变多")
	}
	if !(WatchEvent{Mask: unix.IN_ATTRIB}).IsContentChange() {
		t.Fatal("IN_ATTRIB 应判为内容可能变多")
	}
	if (WatchEvent{Mask: unix.IN_ATTRIB}).IsSelfGone() {
		t.Fatal("属性变更不应判为自身已移走")
	}
}

// TestCloseIsIdempotent 覆盖重复关闭 inotify 实例。
func TestWatcherCloseIsIdempotent(t *testing.T) {
	watcher, err := NewWatcher()
	if err != nil {
		t.Fatalf("inotify 初始化失败：%v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("首次关闭失败：%v", err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatalf("重复关闭应无害：%v", err)
	}
}
