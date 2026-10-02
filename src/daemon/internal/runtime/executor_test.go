package runtime

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/ingest"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// fakeStats 记录统计计数，替代 Rust 侧的进程级 DAEMON_STATS。
type fakeStats struct {
	mu         sync.Mutex
	inotify    uint64
	rotations  uint64
	globalAdds int
	jailAdds   int
}

func (s *fakeStats) AddGlobal(_, _, _, _ uint64) {
	s.mu.Lock()
	s.globalAdds++
	s.mu.Unlock()
}

func (s *fakeStats) AddJail(string, uint64, uint64, uint64) {
	s.mu.Lock()
	s.jailAdds++
	s.mu.Unlock()
}

func (s *fakeStats) IncInotifyEvents() {
	s.mu.Lock()
	s.inotify++
	s.mu.Unlock()
}

func (s *fakeStats) IncLogRotations() {
	s.mu.Lock()
	s.rotations++
	s.mu.Unlock()
}

func (s *fakeStats) IncBansTriggered(string) {}

func (s *fakeStats) rotationCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotations
}

// fakeEnabled 是 Web UI 权威启用状态的可变替身。
type fakeEnabled struct {
	mu     sync.Mutex
	states map[string]bool
}

func newFakeEnabled() *fakeEnabled { return &fakeEnabled{states: map[string]bool{}} }

func (f *fakeEnabled) set(name string, enabled bool) {
	f.mu.Lock()
	f.states[name] = enabled
	f.mu.Unlock()
}

// SetEnabled 实现 JailEnabledSource 接口（导出给接口满足用）。
func (f *fakeEnabled) SetEnabled(name string, enabled bool) {
	f.set(name, enabled)
}

func (f *fakeEnabled) EnabledStates() map[string]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]bool, len(f.states))
	for k, v := range f.states {
		out[k] = v
	}
	return out
}

// tempLogDir 建一个测试专用临时目录。
func tempLogDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fw-inbound-test-*")
	if err != nil {
		t.Fatalf("建临时目录失败: %v", err)
	}
	return dir
}

// configWithLog 构造「单 jail、单日志文件」的最小配置。
func configWithLog(t *testing.T, path, jailName string) *config.Config {
	t.Helper()
	cfg := config.Default()
	jail := config.NewJail(jailName)
	jail.MaxRetries = 1
	jail.FindTime = 600
	jail.BanTime = 60
	jail.LogFiles = append(jail.LogFiles, path)
	jail.Regexes = append(jail.Regexes, config.RegexInfo{
		Name:     "default",
		Pattern:  logparse.DefaultSSHDPattern,
		Compiled: regexp.MustCompile(logparse.DefaultSSHDPattern),
	})
	cfg.Jails = append(cfg.Jails, jail)
	return &cfg
}

// fixture 装配一个测试用执行体。
func fixture(t *testing.T, path, jailName string, stats StatsSink, enabled JailEnabledSource) *InboundExecutor {
	t.Helper()
	signals, err := NewSignalSource()
	if err != nil {
		t.Fatalf("创建信号源失败: %v", err)
	}
	ex, err := NewInboundExecutor(configWithLog(t, path, jailName), signals, Deps{
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Stats:   stats,
		Enabled: enabled,
	})
	if err != nil {
		t.Fatalf("入站执行体应能装配: %v", err)
	}
	return ex
}

// appendFile 追加写入并 fsync。
func appendFile(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("追加打开失败: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("追加失败: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("sync 失败: %v", err)
	}
}

// driveUntil 事件驱动推进：反复 step 直到条件成立，不用固定 sleep 猜时间。
func driveUntil(t *testing.T, ex *InboundExecutor, done func() bool) {
	t.Helper()
	stop := NewShutdown()
	terminate := NewShutdown()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := ex.Step(20*time.Millisecond, stop, terminate); err != nil {
			t.Fatalf("step 不应失败: %v", err)
		}
		if done() {
			return
		}
	}
	t.Fatal("等待条件超时")
}

// 启动期必须定位到文件末尾，不回放历史；随后追加的行应被判定。
func TestStartupDoesNotReplayHistoryAndAppendedLinesAreJudged(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, []byte(failedLine("203.0.113.1")+"\n"), 0o644); err != nil {
		t.Fatalf("写日志失败: %v", err)
	}

	ex := fixture(t, log, "inbound-replay-test", &fakeStats{}, nil)
	defer ex.Close()

	if got := ex.pipeline.Counters().LinesParsed; got != 0 {
		t.Errorf("启动期必须定位到文件末尾，不回放历史内容: lines_parsed=%d", got)
	}
	if got := ex.registry.Len(); got != 1 {
		t.Errorf("应挂上唯一那个日志文件: len=%d", got)
	}

	// 阈值 1 在高峰时段会被抬高，喂三行保证必达阈值（不依赖跑测试时的真实时段）。
	batch := (failedLine("203.0.113.77") + "\n") + (failedLine("203.0.113.77") + "\n") + (failedLine("203.0.113.77") + "\n")
	appendFile(t, log, []byte(batch))

	driveUntil(t, ex, func() bool { return ex.pipeline.Counters().IPsExtracted >= 3 })
	counters := ex.pipeline.Counters()
	if counters.IPsExtracted != 3 {
		t.Errorf("三行都应提取出 IP: %d", counters.IPsExtracted)
	}
	if counters.RegexMatches != 3 {
		t.Errorf("三条都应走正则命中: %d", counters.RegexMatches)
	}
	if counters.BansIntent < 1 {
		t.Error("达到阈值必须产出封禁意图")
	}
}

// 轮转必须被检出，且新文件从头读起。
func TestRotationIsDetectedAndNewFileIsReadFromStart(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("写日志失败: %v", err)
	}

	stats := &fakeStats{}
	ex := fixture(t, log, "inbound-rotation-test", stats, nil)
	defer ex.Close()
	rotationsBefore := stats.rotationCount()

	// logrotate 风格：先改名（MOVE_SELF），再新建同名文件（新 inode）。
	if err := os.Rename(log, filepath.Join(dir, "auth.log.1")); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if err := os.WriteFile(log, []byte(failedLine("203.0.113.88")+"\n"), 0o644); err != nil {
		t.Fatalf("建新文件失败: %v", err)
	}

	driveUntil(t, ex, func() bool { return ex.pipeline.Counters().IPsExtracted >= 1 })
	if stats.rotationCount() <= rotationsBefore {
		t.Error("MOVE_SELF 必须记一次轮转")
	}
	if !ex.registry.ContainsPath(log) {
		t.Error("轮转后必须按路径重新挂上新的 inode")
	}
	if len(ex.pendingReadd) != 0 {
		t.Errorf("路径已存在的轮转不该留下待重挂项: %d", len(ex.pendingReadd))
	}
}

// 禁用某个 jail 时其监视被摘除，重新启用后恢复。
func TestDisabledJailLosesItsWatchesAndRegainsThem(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("写日志失败: %v", err)
	}

	name := "inbound-enabled-sync-test"
	enabled := newFakeEnabled()
	ex := fixture(t, log, name, &fakeStats{}, enabled)
	defer ex.Close()

	if !ex.registry.ContainsPath(log) {
		t.Fatal("初始应监视该日志")
	}

	// 模拟 Web UI 关闭该 jail：下一轮桥接后重建监视集合。
	enabled.set(name, false)
	ex.syncJailEnabled()
	if ex.registry.ContainsPath(log) {
		t.Error("禁用的 jail 不应继续监视其日志")
	}

	// 再打开：监视恢复。
	enabled.set(name, true)
	ex.syncJailEnabled()
	if !ex.registry.ContainsPath(log) {
		t.Error("重新启用后应恢复监视")
	}
}

// 「意图 → 缓存条目」的字段映射是执行体唯一的转发契约，逐字段对照。
func TestBanIntentIsMappedToBanInfoFieldByField(t *testing.T) {
	plan := decision.PlanBan(-1, 0, 1_700_000_000, 7)
	intent := BanIntent{
		Jail:   "sshd",
		IP:     netip.MustParseAddr("203.0.113.99"),
		Source: ingest.NewSourceID(0),
		Plan:   plan,
		Reason: "sshd: 7 次失败达到阈值 7",
	}

	ex := &InboundExecutor{}
	info, ok := ex.banInfoFor(&intent)
	if !ok {
		t.Fatal("合法 IP 必须能构造缓存条目")
	}
	if info.IP != "203.0.113.99" {
		t.Errorf("IP=%q", info.IP)
	}
	if info.JailName != "sshd" {
		t.Errorf("JailName=%q", info.JailName)
	}
	if info.Reason != "sshd" {
		t.Errorf("`reason` 必须是 jail 名（逐字对齐旧实现，前端「原因」列显示它）: %q", info.Reason)
	}
	if !info.IsPermanent {
		t.Error("ban_time < 0 必须判为永久")
	}
	if info.ExpiresAt != 0 {
		t.Errorf("永久封禁的过期时刻为 0: %d", info.ExpiresAt)
	}
	if info.FailCount != 7 {
		t.Errorf("FailCount=%d, want 7", info.FailCount)
	}
	if info.BanCount != 1 {
		t.Errorf("BanCount=%d, want 1", info.BanCount)
	}
	if info.Num == 0 {
		t.Error("IPv4 必须带上网络字节序整数索引")
	}
}
