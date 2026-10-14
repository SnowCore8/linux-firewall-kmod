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
