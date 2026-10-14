package runtime

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// TestReloadAdoptsConfiguredListenAddress 钉住「文件里的端口就是重载后合成的监听
// 地址」，并断言本进程不重绑这件事有告警。
//
// metrics_port 曾是一个没有消费者的键：监听地址取的是一个写死 127.0.0.1:9119 的
// 字段，集成测试自起 daemon 时把空闲端口写进配置、再去那个端口等就绪，于是永远等
// 不到（test_18 的两条 setup 报错）。端口现在真的生效了，但 HTTP 只在启动时绑定
// 一次，所以错位必须以告警说破，不能让人以为写文件就能立刻换端口。
func TestReloadAdoptsConfiguredListenAddress(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	writeFile(t, logPath, "")
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, strings.Join([]string{
		"defaults:",
		"  max_retries: 3",
		"  findtime: 600",
		"  ban_time: 600",
		"  metrics_port: 49729",
		"jails:",
		"  sshd:",
		"    enabled: true",
		"    log_files:",
		"      - " + logPath,
		"",
	}, "\n"))

	cfg := config.Default()
	var logs bytes.Buffer
	reloader := NewFileReloader(path, slog.New(slog.NewTextHandler(&logs, nil)))
	if err := reloader.Reload(&cfg); err != nil {
		t.Fatalf("重载失败: %v", err)
	}
	if got := cfg.ListenAddress(); got != "127.0.0.1:49729" {
		t.Errorf("重载后监听地址 = %q，期望 \"127.0.0.1:49729\"", got)
	}
	if !strings.Contains(logs.String(), "HTTP 监听地址已改变") {
		t.Errorf("换了端口却没留下告警，日志: %s", logs.String())
	}
}

// TestReloadInDirectoryModeUsesTheDirectory 钉住随包 systemd 那条路：进程以 `-C <目录>`
// 启动，重载器拿到的必须是**那个目录**。
//
// 目录加载会把 cfg.ConfigFile 显式清空（否则重载只吃单个文件），而组合根一度把这个空串
// 交给重载器，于是每次 SIGHUP 都停在 `stat : no such file or directory`，计数器永不自增——
// 运维看到的现象是「改了文件、重发了信号，配置一个字没变」。
func TestReloadInDirectoryModeUsesTheDirectory(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	writeFile(t, logPath, "")
	writeFile(t, filepath.Join(dir, "default.yaml"), strings.Join([]string{
		"defaults:",
		"  max_retries: 5",
		"  findtime: 600",
		"  ban_time: 600",
		"",
	}, "\n"))
	writeFile(t, filepath.Join(dir, "sshd.yaml"), strings.Join([]string{
		"jails:",
		"  sshd:",
		"    enabled: true",
		"    log_files:",
		"      - " + logPath,
		"",
	}, "\n"))

	cfg := config.Default()
	var logs bytes.Buffer
	reloader := NewFileReloader(dir, slog.New(slog.NewTextHandler(&logs, nil)))
	if err := reloader.Reload(&cfg); err != nil {
		t.Fatalf("目录模式重载失败: %v（日志: %s）", err, logs.String())
	}
	if len(cfg.Jails) != 1 || cfg.Jails[0].MaxRetries != 5 {
		t.Errorf("目录里的 jail 没被采纳: jails = %+v", cfg.Jails)
	}
}

// TestRollbackInDirectoryModeReadsTheBackupNextToTheSource：备份文件住在配置来源旁边。
//
// 目录模式下 `filepath.Dir(r.path)` 会爬到目录的父目录去，那里没有本次部署的备份，
// 于是 SIGUSR1 的回滚永远退化成「重新加载当前目录」，用户以为回滚到了上一版。
func TestRollbackInDirectoryModeReadsTheBackupNextToTheSource(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	writeFile(t, logPath, "")
	// 校验要求 1..32 个 jail，备份与当前配置都得带上一份完整的 jails 段。
	jails := []string{
		"jails:",
		"  sshd:",
		"    enabled: true",
		"    log_files:",
		"      - " + logPath,
		"",
	}
	writeFile(t, filepath.Join(dir, "default.yaml"), strings.Join(append([]string{
		"defaults:",
		"  max_retries: 5",
		"",
	}, jails...), "\n"))
	writeFile(t, filepath.Join(dir, "config.yaml.rollback"), strings.Join(append([]string{
		"defaults:",
		"  max_retries: 9",
		"",
	}, jails...), "\n"))

	cfg := config.Default()
	reloader := NewFileReloader(dir, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := reloader.Rollback(&cfg); err != nil {
		t.Fatalf("目录模式回滚失败: %v", err)
	}
	if cfg.DefaultMaxRetries != 9 {
		t.Errorf("回滚后的默认 max_retries = %d，期望备份里的 9", cfg.DefaultMaxRetries)
	}
}
