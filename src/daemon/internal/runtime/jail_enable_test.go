package runtime

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// TestSyncJailEnabledCompilesRegexes 回归：运行期启用一个禁用中的 jail 时必须补编译
// 正则。启动/重载只编译 enabled jail，禁用项的 Compiled 全是 nil；不补编译的话
// 规则集为空，只配正则的 jail 启用后完全失防。
func TestSyncJailEnabledCompilesRegexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}

	cfg := config.Default()
	j := config.NewJail("web")
	j.Enabled = false
	j.MaxRetries = 1
	j.FindTime = 600
	j.BanTime = 60
	j.LogFiles = append(j.LogFiles, path)
	j.Regexes = append(j.Regexes, config.RegexInfo{
		Name:    "nginx",
		Pattern: `nginx: client (\d+\.\d+\.\d+\.\d+)`,
	})
	// 装配要求至少有一个可监视的源，另加一个常开的 jail 满足这一点。
	sshPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(sshPath, nil, 0o644); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}
	ssh := config.NewJail("ssh")
	ssh.Enabled = true
	ssh.MaxRetries = 1
	ssh.FindTime = 600
	ssh.BanTime = 60
	ssh.LogFiles = append(ssh.LogFiles, sshPath)
	ssh.Regexes = append(ssh.Regexes, config.RegexInfo{
		Name:     "default",
		Pattern:  logparse.DefaultSSHDPattern,
		Compiled: regexp.MustCompile(logparse.DefaultSSHDPattern),
	})
	cfg.Jails = append(cfg.Jails, j, ssh)

	signals, err := NewSignalSource()
	if err != nil {
		t.Fatalf("创建信号源失败: %v", err)
	}
	enabled := newFakeEnabled()
	ex, err := NewInboundExecutor(&cfg, signals, Deps{
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Enabled: enabled,
	})
	if err != nil {
		t.Fatalf("装配执行体失败: %v", err)
	}

	if got := ex.pipeline.jails["web"].rules.Len(); got != 0 {
		t.Fatalf("禁用状态不应编译出规则，got %d", got)
	}

	enabled.set("web", true)
	ex.syncJailEnabled()

	if cfg.Jails[0].Regexes[0].Compiled == nil {
		t.Fatal("启用后应补编译正则")
	}
	rs := ex.pipeline.jails["web"].rules
	_, via, ok := rs.Parse("nginx: client 203.0.113.9")
	if !ok || via != logparse.MatchViaRegex {
		t.Fatalf("启用后规则集应命中该行，ok=%v via=%v", ok, via)
	}
}
