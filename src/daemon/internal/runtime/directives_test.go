package runtime

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// fakeSink 是 BanSink 的替身：只记调用序列与下发次数。
type fakeSink struct {
	mu     sync.Mutex
	sends  []string
	acked  []string
	rolled []string
	// insertWinner 控制 TryInsert 是否让位（false 时模拟「已在镜像里」）。
	insertWinner bool
}

func newAcceptingSink() *fakeSink { return &fakeSink{insertWinner: true} }

func (s *fakeSink) TryInsert(info bans.BanInfo) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.insertWinner {
		return false
	}
	return true
}

func (s *fakeSink) MarkPendingAck(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acked = append(s.acked, ip)
}

func (s *fakeSink) Send(addr netip.Addr, _ uint8, _ uint32, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sends = append(s.sends, addr.String())
	return nil
}

func (s *fakeSink) RollbackInsert(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rolled = append(s.rolled, ip)
}

func (s *fakeSink) sendCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sends)
}

// directiveFixture 是带反向指令通道与假下发端的执行体。
func directiveFixture(t *testing.T, path, jailName string, sink BanSink) (*InboundExecutor, chan Directive) {
	t.Helper()
	signals, err := NewSignalSource()
	if err != nil {
		t.Fatalf("创建信号源失败: %v", err)
	}
	cmd := make(chan Directive, 8)
	ex, err := NewInboundExecutor(configWithLog(t, path, jailName), signals, Deps{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sink:      sink,
		KernelCmd: cmd,
	})
	if err != nil {
		t.Fatalf("入站执行体应能装配: %v", err)
	}
	t.Cleanup(ex.Close)
	return ex, cmd
}

// 内核侧 ban_time 被 procfs 改写后必须落进执行体持有的那份配置：默认值变了，未显式配置
// ban_time 的 jail 也要跟着变，否则面板显示新值而实际下发仍用旧值；显式配置过的 jail
// 不受默认值牵连。
func TestAdoptKernelBanTimeUpdatesInheritedJails(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}

	ex, _ := directiveFixture(t, log, "adopt-test", newAcceptingSink())
	explicit := config.NewJail("explicit-jail")
	explicit.BanTime = 999
	explicit.BanTimeSet = true
	ex.cfg.Jails = append(ex.cfg.Jails, explicit)
	ex.refreshJails()

	ex.applyDirective(Directive{
		Kind:        DirectiveKernelConfigChanged,
		ConfigFlags: uint32(contract.ConfigFlagBanTime),
		BanTimeSecs: 123,
	})

	if got := ex.cfg.DefaultBanTime; got != 123 {
		t.Fatalf("DefaultBanTime = %d，期望 123", got)
	}
	if got := ex.cfg.Jails[0].BanTime; got != 123 {
		t.Fatalf("继承默认值的 jail ban_time = %d，期望 123", got)
	}
	if got := ex.cfg.Jails[1].BanTime; got != 999 {
		t.Fatalf("显式配置 ban_time 的 jail 被改成 %d，期望保持 999", got)
	}
	// 规则集里带着每个 jail 的 ban_time，改了 cfg 不重建就等于没生效。
	if got := ex.pipeline.jails["adopt-test"].policy.BanTime; got != 123 {
		t.Fatalf("重建后的判定参数 ban_time = %d，期望 123", got)
	}
}

// 0 在内核侧不是合法 bantime：采纳它会把每个继承默认值的 jail 变成永久封禁。
func TestAdoptKernelBanTimeIgnoresZero(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}

	ex, _ := directiveFixture(t, log, "zero-test", newAcceptingSink())
	before := ex.cfg.DefaultBanTime
	ex.applyDirective(Directive{
		Kind:        DirectiveKernelConfigChanged,
		ConfigFlags: uint32(contract.ConfigFlagBanTime),
		BanTimeSecs: 0,
	})
	if ex.cfg.DefaultBanTime != before {
		t.Fatalf("ban_time=0 被采纳：%d → %d", before, ex.cfg.DefaultBanTime)
	}
}

func TestAdoptKernelDdosBanDuration(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}

	ex, _ := directiveFixture(t, log, "ddos-test", newAcceptingSink())
	ex.applyDirective(Directive{
		Kind:                DirectiveKernelConfigChanged,
		ConfigFlags:         uint32(contract.ConfigFlagDdosBanDuration),
		DdosBanDurationSecs: 7200,
	})
	if got := ex.cfg.Ddos.AutoBanDuration; got != 7200 {
		t.Fatalf("Ddos.AutoBanDuration = %d，期望 7200", got)
	}
}

// 内核拒绝一条封禁下发后必须抑制该 IP 的重复下发：条目已从镜像消失，下一条失败日志
// 就能重新占位，表满时会变成「每行日志一个 netlink 往返」，两侧都被同一个攻击者淹掉。
func TestRejectedDispatchIsSuppressedThenResumes(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}

	sink := newAcceptingSink()
	ex, cmd := directiveFixture(t, log, "reject-test", sink)
	// 抑制窗口缩到可测的长度（默认 60 秒，测试里等不起），但仍要明显长于下面「5 轮循环」
	// 的挂钟耗时——否则负载高时循环跨过窗口边界，抑制断言会随机失败。
	ex.rejectionTTL = 200 * time.Millisecond

	probe := failedLine("203.0.113.55") + "\n"
	appendFile(t, log, []byte(probe+probe+probe))
	driveUntil(t, ex, func() bool { return sink.sendCount() >= 1 })
	first := sink.sendCount()

	cmd <- Directive{Kind: DirectiveCommandRejected, IP: "203.0.113.55", Cmd: "BanIp", Errno: -22}
	// 排空通道要走到一轮迭代开头，先驱动一次把指令吃进来。
	driveUntil(t, ex, func() bool { return len(ex.rejected) == 1 })

	// 抑制期内继续喂同样的失败日志：判定与计数照走，但不得再下发。
	for i := 0; i < 5; i++ {
		appendFile(t, log, []byte(probe))
		if err := ex.Step(10*time.Millisecond, NewShutdown(), NewShutdown()); err != nil {
			t.Fatalf("step 不应失败: %v", err)
		}
	}
	if got := sink.sendCount(); got != first {
		t.Fatalf("抑制窗口内仍在重复下发：sends %d → %d", first, got)
	}

	// 窗口过后恢复下发能力。
	//
	// 追加一小批而不是一条：有效阈值 = ceil(max_retries × 高峰系数 × 内网系数 × 信誉系数)，
	// 高峰期（UTC 9–18 点）的 1.5 系数会把 max_retries=1 抬到 2。只补一条的话，恰在高峰
	// 时段跑测试就会因「单次失败未达阈值」而不下发——断言会随挂钟时刻变红变绿。补一小批
	// 则任何系数下都能越过阈值，断言与时钟无关。
	time.Sleep(300 * time.Millisecond)
	appendFile(t, log, []byte(probe+probe+probe))
	driveUntil(t, ex, func() bool { return sink.sendCount() > first })
	if got := sink.sendCount(); got <= first {
		t.Fatalf("抑制到期后应可再次下发，sends=%d", got)
	}
}

// 反面对照：没有被拒回执时，同样的喂法会重复下发。缺了这条对照，上面那个「抑制期内不再
// 下发」可能只是因为判定本来就不再产生意图，抑制逻辑等于没被检验。
func TestWithoutRejectionDispatchRepeats(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}
	sink := newAcceptingSink()
	ex, _ := directiveFixture(t, log, "repeat-test", sink)

	probe := failedLine("203.0.113.57") + "\n"
	appendFile(t, log, []byte(probe+probe+probe))
	driveUntil(t, ex, func() bool { return sink.sendCount() >= 1 })
	for i := 0; i < 5; i++ {
		appendFile(t, log, []byte(probe))
		if err := ex.Step(10*time.Millisecond, NewShutdown(), NewShutdown()); err != nil {
			t.Fatalf("step 不应失败: %v", err)
		}
	}
	if got := sink.sendCount(); got < 2 {
		t.Fatalf("未被抑制时也应只有 %d 次下发：判定不再产生意图，对照失效", got)
	}
}

// 同一 IP 连续被拒要把窗口往后推，而不是用新窗口把更晚的到期点改短。
func TestRepeatedRejectionExtendsWindow(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}
	ex, _ := directiveFixture(t, log, "extend-test", newAcceptingSink())
	ex.rejectionTTL = time.Hour

	ex.applyDirective(Directive{Kind: DirectiveCommandRejected, IP: "203.0.113.56"})
	late := ex.rejected["203.0.113.56"]
	ex.applyDirective(Directive{Kind: DirectiveCommandRejected, IP: "203.0.113.56"})
	if got := ex.rejected["203.0.113.56"]; got.Before(late) {
		t.Fatalf("重复被拒把抑制到期点改短了：%v → %v", late, got)
	}
}

// 没有目标地址的失败回执无法抑制任何东西：只记日志，不写抑制表。
func TestRejectionWithoutAddressIsInert(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}
	ex, _ := directiveFixture(t, log, "inert-test", newAcceptingSink())

	ex.applyDirective(Directive{Kind: DirectiveCommandRejected, IP: "", Cmd: "BanIp", Errno: -22})
	ex.applyDirective(Directive{Kind: DirectiveKind(200)})

	if len(ex.rejected) != 0 {
		t.Fatalf("无效回执写进了抑制表: %v", ex.rejected)
	}
}

// 生产方关闭通道后执行体必须停止接收：关闭的通道恒可读，留着通道引用会让每轮迭代
// 在排空处空转一遍。
func TestClosedDirectiveChannelStopsReceiving(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}
	ex, cmd := directiveFixture(t, log, "close-test", newAcceptingSink())

	close(cmd)
	stop, terminate := NewShutdown(), NewShutdown()
	if err := ex.Step(time.Millisecond, stop, terminate); err != nil {
		t.Fatalf("step 不应失败: %v", err)
	}
	if ex.cmd != nil {
		t.Fatal("通道已关闭，执行体仍持有引用（每轮都会空转）")
	}
	// 摘掉之后再来一轮也不能 panic。
	if err := ex.Step(time.Millisecond, stop, terminate); err != nil {
		t.Fatalf("二次 step 不应失败: %v", err)
	}
}

// 抑制条目跟着失败窗口清理同一节拍过期摘除，不留无限增长的表。
func TestPurgeRejectedDispatchesDropsExpired(t *testing.T) {
	dir := tempLogDir(t)
	defer os.RemoveAll(dir)
	log := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(log, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}
	ex, _ := directiveFixture(t, log, "purge-test", newAcceptingSink())
	now := time.Now()
	ex.rejected["live"] = now.Add(time.Minute)
	ex.rejected["gone"] = now.Add(-time.Minute)

	ex.purgeRejectedDispatches(now)
	if _, ok := ex.rejected["gone"]; ok {
		t.Fatal("过期条目未被摘除")
	}
	if _, ok := ex.rejected["live"]; !ok {
		t.Fatal("未过期条目被误摘")
	}
}
