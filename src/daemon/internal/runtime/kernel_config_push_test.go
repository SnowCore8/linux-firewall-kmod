package runtime

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// recordingPusher 是 KernelConfigPusher 的假实现：按值存下每次下发的投影。
type recordingPusher struct {
	mu      sync.Mutex
	changes []contract.SetConfig
	// rejected 与 err 分别扮演内核的两种回答：逐位拒绝、通道发不出去。
	rejected contract.ConfigFlags
	err      error
}

func (p *recordingPusher) ApplyConfig(change *contract.SetConfig) (contract.ConfigFlags, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if change != nil {
		p.changes = append(p.changes, *change)
	}
	return p.rejected, p.err
}

func (p *recordingPusher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.changes)
}

func (p *recordingPusher) last(t *testing.T) contract.SetConfig {
	t.Helper()

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.changes) == 0 {
		t.Fatalf("一次都没有下发")
	}
	return p.changes[len(p.changes)-1]
}

// fakeReloader 是 ConfigReloader 的替身：err 非空时模拟「重载失败、cfg 保持原样」。
type fakeReloader struct {
	err   error
	apply func(*config.Config)
}

func (f *fakeReloader) Reload(cfg *config.Config) error {
	if f.err != nil {
		return f.err
	}
	if f.apply != nil {
		f.apply(cfg)
	}
	return nil
}

func (f *fakeReloader) Rollback(cfg *config.Config) error { return f.Reload(cfg) }

// pushFixture 装配一个带假下发端的执行体。构造本身就是一次下发（初始装配）。
func pushFixture(t *testing.T, cfg *config.Config, reloader ConfigReloader, pusher KernelConfigPusher) *InboundExecutor {
	t.Helper()

	signals, err := NewSignalSource()
	if err != nil {
		t.Fatalf("创建信号源失败: %v", err)
	}
	ex, err := NewInboundExecutor(cfg, signals, Deps{
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Sink:         newAcceptingSink(),
		Reloader:     reloader,
		KernelConfig: pusher,
	})
	if err != nil {
		t.Fatalf("入站执行体应能装配: %v", err)
	}
	t.Cleanup(ex.Close)
	return ex
}

// TestInitialAssemblyPushesKernelConfig 盯住启动那一次下发。
//
// 内核模块的取值来自编译期默认与 insmod 参数，守护进程的配置若不在此刻发一次，
// 「服务刚起来的这段时间内核按谁的阈值判」就没有答案——要等到第一次 SIGHUP 或 API 写入才对齐。
func TestInitialAssemblyPushesKernelConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, path, "")

	pusher := &recordingPusher{}
	pushFixture(t, configWithLog(t, path, "sshd"), nil, pusher)

	if pusher.count() != 1 {
		t.Fatalf("初始装配下发 = %d 次，期望恰好一次", pusher.count())
	}
	change := pusher.last(t)
	if change.BanTime != uint32(config.Default().DefaultBanTime) {
		t.Errorf("BanTime = %d，期望配置里的默认封禁时长 %d", change.BanTime, config.Default().DefaultBanTime)
	}
	if change.RateWindowSeconds != config.Default().Ddos.CheckInterval {
		t.Errorf("RateWindowSeconds = %d，期望 ddos.check_interval %d",
			change.RateWindowSeconds, config.Default().Ddos.CheckInterval)
	}
}

// TestReloadPushesKernelConfigAfterSuccess 是「手工编辑文件 / SIGHUP 也要上内核」这一半。
func TestReloadPushesKernelConfigAfterSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, path, "")

	pusher := &recordingPusher{}
	cfg := configWithLog(t, path, "sshd")
	reloader := &fakeReloader{apply: func(c *config.Config) { c.DefaultBanTime = 1234 }}
	ex := pushFixture(t, cfg, reloader, pusher)

	before := pusher.count()
	ex.reloadConfig()
	if pusher.count() != before+1 {
		t.Fatalf("重载后下发 = %d 次，期望在 %d 次之上再加一次", pusher.count(), before)
	}
	if got := pusher.last(t).BanTime; got != 1234 {
		t.Errorf("重载下发的 BanTime = %d，期望重载后的 1234", got)
	}
}

// TestFailedReloadDoesNotPush：文件读坏了就不下发。
//
// 失败时 cfg 保持原样（重载器自己回滚），此时发一次只是把同一份值再推一遍；更要紧的是
// 「重载失败」这条日志后面紧跟一条「配置已下发内核」会让运维以为新内容生效了。
func TestFailedReloadDoesNotPush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, path, "")

	pusher := &recordingPusher{}
	ex := pushFixture(t, configWithLog(t, path, "sshd"), &fakeReloader{err: os.ErrInvalid}, pusher)

	before := pusher.count()
	ex.reloadConfig()
	if pusher.count() != before {
		t.Errorf("重载失败仍然下发了内核：%+v", pusher.changes)
	}
}

// TestRollbackPushesKernelConfig：SIGUSR1 回滚掉的那份配置同样要回到内核上。
func TestRollbackPushesKernelConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, path, "")

	pusher := &recordingPusher{}
	cfg := configWithLog(t, path, "sshd")
	reloader := &fakeReloader{apply: func(c *config.Config) {
		c.DefaultBanTime = 60
		c.Ddos.CheckInterval = 9
	}}
	ex := pushFixture(t, cfg, reloader, pusher)

	before := pusher.count()
	ex.rollbackConfig()
	if pusher.count() != before+1 {
		t.Fatalf("回滚后下发 = %d 次，期望在 %d 次之上再加一次", pusher.count(), before)
	}
	change := pusher.last(t)
	if change.BanTime != 60 || change.RateWindowSeconds != 9 {
		t.Errorf("回滚下发的载荷 = ban_time %d / rate_window %d，期望 60 / 9",
			change.BanTime, change.RateWindowSeconds)
	}
}

// TestPushFailureKeepsReload 定住「下发失败不升级成执行体的错误」：
// 配置已经落到本进程并生效于判定链，内核那一侧只是滞后，主链路不该为此停摆。
func TestPushFailureKeepsReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, path, "")

	pusher := &recordingPusher{err: os.ErrClosed, rejected: contract.ConfigFlagMaxSYN}
	cfg := configWithLog(t, path, "sshd")
	ex := pushFixture(t, cfg, &fakeReloader{apply: func(c *config.Config) { c.DefaultBanTime = 77 }}, pusher)

	ex.reloadConfig()
	if cfg.DefaultBanTime != 77 {
		t.Errorf("下发失败把重载结论也改了：DefaultBanTime = %d", cfg.DefaultBanTime)
	}
	if pusher.count() != 2 {
		t.Errorf("下发次数 = %d，期望装配 1 次 + 重载 1 次", pusher.count())
	}
	// rejected 位不能把执行体带崩，也不改变重载结论；这里只验证它走的是记日志那条分支。
	ex.pushKernelConfig("显式重试")
	if pusher.count() != 3 {
		t.Errorf("重试后下发次数 = %d，期望 3", pusher.count())
	}
}

// TestPushWithoutKernelConfigIsSafe：没装下发出口时重载照常。
func TestPushWithoutKernelConfigIsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.log")
	writeFile(t, path, "")

	ex := pushFixture(t, configWithLog(t, path, "sshd"), &fakeReloader{}, nil)
	ex.reloadConfig()
	ex.rollbackConfig()
}

// TestFileReloaderSeedsDefaults 是重载器那条 bug 的回归测试。
//
// 重载器原本从**零值** Config 起步解析文件，而初始加载（main.go）是 Default() + 文件。
// 两条路口径不同带来两种后果，都发生在「文件没写全」的时候：
//
//   - 没写 defaults 段：default_max_retries 落在 0，jail.Validate 直接拒掉整次重载。现象是
//     一条「配置重载失败」warn、守护进程继续按旧配置跑，而面板显示的是文件里的新值。
//   - 写了 defaults 却没写 ddos 段：重载**成功**，但整个 Ddos 配置被清零——check_interval
//     与八个速率上限都变 0，配置下发那条路会把一排全零速率发给内核并被逐位拒绝。
func TestFileReloaderSeedsDefaults(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	writeFile(t, logPath, "")

	t.Run("省略 ddos 段不再把速率清零", func(t *testing.T) {
		path := filepath.Join(dir, "with-defaults.yaml")
		writeFile(t, path, strings.Join([]string{
			"defaults:",
			"  max_retries: 3",
			"  findtime: 600",
			"  ban_time: 600",
			"jails:",
			"  sshd:",
			"    enabled: true",
			"    log_files:",
			"      - " + logPath,
			"",
		}, "\n"))

		cfg := config.Default()
		if err := NewFileReloader(path, slog.New(slog.NewTextHandler(io.Discard, nil))).Reload(&cfg); err != nil {
			t.Fatalf("重载失败: %v", err)
		}
		def := config.Default().Ddos
		if cfg.Ddos.CheckInterval != def.CheckInterval {
			t.Errorf("check_interval = %d，期望默认值 %d（文件里没写这一段）", cfg.Ddos.CheckInterval, def.CheckInterval)
		}
		if cfg.Ddos.GlobalConnRate != def.GlobalConnRate {
			t.Errorf("global_conn_rate = %d，期望默认值 %d", cfg.Ddos.GlobalConnRate, def.GlobalConnRate)
		}
		if cfg.Ddos.MaxSynPerSecond != def.MaxSynPerSecond {
			t.Errorf("max_syn_per_second = %d，期望默认值 %d", cfg.Ddos.MaxSynPerSecond, def.MaxSynPerSecond)
		}
		if cfg.Interval != config.Default().Interval {
			t.Errorf("interval = %d，期望默认值 %d（0 会让主链路空转）", cfg.Interval, config.Default().Interval)
		}
		if len(cfg.Jails) != 1 {
			t.Errorf("jails = %+v，期望文件里那一个", cfg.Jails)
		}
	})

	t.Run("省略 defaults 段也能通过校验", func(t *testing.T) {
		path := filepath.Join(dir, "no-defaults.yaml")
		writeFile(t, path, strings.Join([]string{
			"jails:",
			"  sshd:",
			"    enabled: true",
			"    log_files:",
			"      - " + logPath,
			"",
		}, "\n"))

		cfg := config.Default()
		if err := NewFileReloader(path, slog.New(slog.NewTextHandler(io.Discard, nil))).Reload(&cfg); err != nil {
			t.Fatalf("重载失败（修复前这里是 default_max_retries is 0）: %v", err)
		}
		if cfg.DefaultMaxRetries == 0 || cfg.DefaultBanTime == 0 {
			t.Errorf("defaults 没有被打底: retries=%d ban_time=%d", cfg.DefaultMaxRetries, cfg.DefaultBanTime)
		}
		// 文件里没给阈值的 jail 由智能默认补上，而它取的是**打底之后**的全局默认。
		if len(cfg.Jails) == 1 && cfg.Jails[0].MaxRetries == 0 {
			t.Errorf("jail 的 max_retries 为 0，智能默认没有跑在打底之后")
		}
	})
}

// writeFile 是测试里的一行写文件（失败即 fatal）。
func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
}
