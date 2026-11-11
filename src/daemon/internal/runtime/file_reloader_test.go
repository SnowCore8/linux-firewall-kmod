package runtime

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// reloadFixture 写一份可被严格模式接受的最小配置（含一个 jail）并返回其路径。
func reloadFixture(t *testing.T, extraTop string) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	writeFile(t, logPath, "")
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, strings.Join([]string{
		"defaults:",
		"  max_retries: 3",
		"  findtime: 600",
		"  ban_time: 600",
		extraTop,
		"jails:",
		"  sshd:",
		"    enabled: true",
		"    log_files:",
		"      - " + logPath,
		"",
	}, "\n"))
	return path
}

// 出口探测得到的本机坐标不是 YAML 键，只在启动时填一次：重载从文件重建配置时必须
// 原样保留，否则一次 SIGHUP 就把地图上的本机标记抹掉，直到进程重启才会重新探测。
func TestReloadPreservesDetectedServerCoords(t *testing.T) {
	path := reloadFixture(t, "")
	cfg := config.Default()
	cfg.ServerLatitude = 31.23
	cfg.ServerLongitude = 121.47
	cfg.ServerCoordsSource = "detected"

	reloader := NewFileReloader(path, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := reloader.Reload(&cfg); err != nil {
		t.Fatalf("重载失败: %v", err)
	}
	if cfg.ServerCoordsSource != "detected" || cfg.ServerLatitude != 31.23 || cfg.ServerLongitude != 121.47 {
		t.Fatalf("重载抹掉了探测坐标: source=%q lat=%v lon=%v",
			cfg.ServerCoordsSource, cfg.ServerLatitude, cfg.ServerLongitude)
	}
}

// 文件显式给了坐标时以文件为准：探测结果只能兜底，不能盖过运维写下的值。
func TestReloadPrefersFileCoordsOverDetected(t *testing.T) {
	path := reloadFixture(t, "server_latitude: 50.0\nserver_longitude: 8.0")
	cfg := config.Default()
	cfg.ServerLatitude = 31.23
	cfg.ServerLongitude = 121.47
	cfg.ServerCoordsSource = "detected"

	reloader := NewFileReloader(path, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := reloader.Reload(&cfg); err != nil {
		t.Fatalf("重载失败: %v", err)
	}
	if !cfg.ServerCoordsSet || cfg.ServerLatitude != 50 || cfg.ServerLongitude != 8 {
		t.Fatalf("文件坐标未生效: set=%v lat=%v lon=%v",
			cfg.ServerCoordsSet, cfg.ServerLatitude, cfg.ServerLongitude)
	}
	if cfg.ServerCoordsSource == "detected" {
		t.Fatal("文件坐标被探测来源覆盖，来源标注会与坐标实际出处不符")
	}
}

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
	reloader := NewFileReloader(path, true, slog.New(slog.NewTextHandler(&logs, nil)))
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

// TestReloadWarnsOnLogSettingsChange 钉住「日志键热重载不生效、但必须说破」。
//
// slog 的 sink、级别与格式只在启动时的 logger.Init 建立，重载整份换入配置不会重建它们；
// 不告警时现场表现为「文件里改了 log_file、面板却一直空白」。
func TestReloadWarnsOnLogSettingsChange(t *testing.T) {
	dir := t.TempDir()
	authLog := filepath.Join(dir, "auth.log")
	writeFile(t, authLog, "")
	newLogFile := filepath.Join(dir, "new.log")
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, strings.Join([]string{
		"defaults:",
		"  log_file: " + newLogFile,
		"  log_level: 4",
		"  log_format: plain",
		"jails:",
		"  sshd:",
		"    enabled: true",
		"    log_files:",
		"      - " + authLog,
		"",
	}, "\n"))

	cfg := config.Default()
	var logs bytes.Buffer
	reloader := NewFileReloader(path, true, slog.New(slog.NewTextHandler(&logs, nil)))
	if err := reloader.Reload(&cfg); err != nil {
		t.Fatalf("重载失败: %v", err)
	}
	for _, want := range []string{"log_file 已改变", "log_level 已改变", "log_format 已改变"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("缺少 %q 告警，日志: %s", want, logs.String())
		}
	}
	// 配置本身就换了：告警说的是「新值要重启才生效」，不是「重载没吃到新值」。
	if cfg.LogFile != newLogFile {
		t.Errorf("cfg.LogFile = %q，期望 %q", cfg.LogFile, newLogFile)
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
	reloader := NewFileReloader(dir, true, slog.New(slog.NewTextHandler(&logs, nil)))
	if err := reloader.Reload(&cfg); err != nil {
		t.Fatalf("目录模式重载失败: %v（日志: %s）", err, logs.String())
	}
	if len(cfg.Jails) != 1 || cfg.Jails[0].MaxRetries != 5 {
		t.Errorf("目录里的 jail 没被采纳: jails = %+v", cfg.Jails)
	}
}

// TestReloadHonorsNonStrict 钉住启动与重载的同一口径：--no-strict 启动的进程，
// SIGHUP 重载同一份带未知键的文件也必须成功；严格模式则拒绝且不改写当前配置。
func TestReloadHonorsNonStrict(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	writeFile(t, logPath, "")
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, strings.Join([]string{
		"defaults:",
		"  max_retries: 4",
		"  unknown_key: 1",
		"jails:",
		"  sshd:",
		"    enabled: true",
		"    log_files:",
		"      - " + logPath,
		"",
	}, "\n"))

	t.Run("宽松模式接受未知键", func(t *testing.T) {
		cfg := config.Default()
		cfg.DefaultMaxRetries = 3
		reloader := NewFileReloader(path, false, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
		if err := reloader.Reload(&cfg); err != nil {
			t.Fatalf("--no-strict 下重载失败: %v", err)
		}
		if cfg.DefaultMaxRetries != 4 {
			t.Fatalf("重载后的 max_retries = %d，期望 4", cfg.DefaultMaxRetries)
		}
	})

	t.Run("严格模式拒绝且不改写", func(t *testing.T) {
		cfg := config.Default()
		cfg.DefaultMaxRetries = 7
		reloader := NewFileReloader(path, true, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
		if err := reloader.Reload(&cfg); err == nil {
			t.Fatal("严格模式应拒绝未知键")
		}
		if cfg.DefaultMaxRetries != 7 {
			t.Fatalf("失败的重载改写了 cfg: max_retries = %d", cfg.DefaultMaxRetries)
		}
	})
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
	reloader := NewFileReloader(dir, true, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err := reloader.Rollback(&cfg); err != nil {
		t.Fatalf("目录模式回滚失败: %v", err)
	}
	if cfg.DefaultMaxRetries != 9 {
		t.Errorf("回滚后的默认 max_retries = %d，期望备份里的 9", cfg.DefaultMaxRetries)
	}
}

// TestFileReloaderNilLogger 钉住构造处的 nil 兜底：调用方没给日志器时，
// 重载与回滚只能返回错误，不能因为 nil 解引用把进程打崩。
func TestFileReloaderNilLogger(t *testing.T) {
	cfg := config.Default()
	reloader := NewFileReloader(filepath.Join(t.TempDir(), "missing.yaml"), true, nil)
	if err := reloader.Reload(&cfg); err == nil {
		t.Fatal("配置文件不存在时重载应返回错误")
	}
	if err := reloader.Rollback(&cfg); err == nil {
		t.Fatal("配置文件不存在时回滚应返回错误")
	}
}
