package logger

import (
	"log/slog"
	"log/syslog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// TestOptionsFromConfig 断言配置字段到初始化参数的一一映射。
func TestOptionsFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.LogLevel = config.LogLevelDebug
	cfg.LogDestination = config.LogDestinationBoth
	cfg.LogFormat = config.LogFormatJSON
	cfg.LogMaxSizeMB = 10
	cfg.LogMaxFiles = 10

	opts := optionsFromConfig(&cfg)
	if opts.level != slog.LevelDebug {
		t.Fatalf("级别映射错误: %v", opts.level)
	}
	if opts.destination != config.LogDestinationBoth || opts.format != config.LogFormatJSON {
		t.Fatalf("目的地/格式映射错误: %d/%d", opts.destination, opts.format)
	}
	if opts.maxBytes != 10*1024*1024 {
		t.Fatalf("单片上限应为 10 MiB，实际 %d", opts.maxBytes)
	}
	if opts.maxFiles != 10 {
		t.Fatalf("片数上限应为 10，实际 %d", opts.maxFiles)
	}
	if opts.filePath != defaultLogPath {
		t.Fatalf("未配置 log_file 时应落到默认路径，实际 %s", opts.filePath)
	}
	if opts.dial == nil {
		t.Fatal("必须带有默认的连接实现")
	}
}

// TestLevelFromConfig 断言 log_level 的五个取值（含未知兜底）映射正确。
func TestLevelFromConfig(t *testing.T) {
	cases := []struct {
		level uint8
		want  slog.Level
	}{
		{config.LogLevelNone, levelSilent},
		{config.LogLevelErr, slog.LevelError},
		{config.LogLevelWarn, slog.LevelWarn},
		{config.LogLevelInfo, slog.LevelInfo},
		{config.LogLevelDebug, slog.LevelDebug},
		{200, slog.LevelInfo},
	}
	for _, c := range cases {
		if got := levelFromConfig(c.level); got != c.want {
			t.Fatalf("log_level=%d 期望 %v，实际 %v", c.level, c.want, got)
		}
	}
}

// TestResolveLogPath 断言显式路径优先、空路径落到默认值。
func TestResolveLogPath(t *testing.T) {
	configured := filepath.Join(t.TempDir(), "custom.log")
	if got := resolveLogPath(configured); got != configured {
		t.Fatalf("应保留显式路径，实际 %s", got)
	}
	if got := resolveLogPath(""); got != defaultLogPath {
		t.Fatalf("空路径应落到 %s，实际 %s", defaultLogPath, got)
	}
}

// TestLevelThresholdFilters 断言门槛以上的记录才写出，NONE 一条都不写。
func TestLevelThresholdFilters(t *testing.T) {
	cases := []struct {
		name  string
		level uint8
		want  int
	}{
		{"NONE", config.LogLevelNone, 0},
		{"ERROR", config.LogLevelErr, 1},
		{"WARN", config.LogLevelWarn, 2},
		{"INFO", config.LogLevelInfo, 3},
		{"DEBUG", config.LogLevelDebug, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fw.log")
			opts := options{
				level:       levelFromConfig(c.level),
				destination: config.LogDestinationFile,
				format:      config.LogFormatJSON,
				filePath:    path,
				maxBytes:    1024,
				maxFiles:    3,
				dial:        failDialer,
			}
			lg, closeSinks := initLogger(opts)
			lg.Debug("调试")
			lg.Info("信息")
			lg.Warn("告警")
			lg.Error("错误")
			if err := closeSinks(); err != nil {
				t.Fatalf("关闭 sink 失败: %v", err)
			}

			body := readFile(t, path)
			if c.want == 0 {
				if body != "" {
					t.Fatalf("级别 NONE 不应写出日志: %q", body)
				}
				return
			}
			if lines := splitLines(body); len(lines) != c.want {
				t.Fatalf("期望 %d 条，实际 %d: %q", c.want, len(lines), body)
			}
		})
	}
}

// TestDestinationFileWritesFileOnly 断言 file 目的地只落文件、不碰系统日志。
func TestDestinationFileWritesFileOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	dialed := false
	opts := options{
		level:       slog.LevelInfo,
		destination: config.LogDestinationFile,
		format:      config.LogFormatJSON,
		filePath:    path,
		maxBytes:    1024,
		maxFiles:    3,
		// file 目的地不应发起任何连接。
		dial: func(string, string) (*syslog.Writer, error) {
			dialed = true
			return nil, errDialFailed
		},
	}
	lg, closeSinks := initLogger(opts)
	lg.Warn("落盘", "jail", "sshd")
	if err := closeSinks(); err != nil {
		t.Fatalf("关闭 sink 失败: %v", err)
	}
	if dialed {
		t.Fatal("file 目的地不应连接系统日志")
	}

	fields := decodeJSON(t, splitLines(readFile(t, path))[0])
	if fields["msg"] != "落盘" || fields["jail"] != "sshd" {
		t.Fatalf("文件内容不符: %v", fields)
	}
}

// TestInitRegistersConfiguredLogFile 断言配置了 log_file 时路径被登记，且日志真的落到该文件。
func TestInitRegistersConfiguredLogFile(t *testing.T) {
	resetLogFilePath()
	defer resetLogFilePath()

	path := filepath.Join(t.TempDir(), "fw.log")
	cfg := config.Default()
	cfg.LogFile = path
	cfg.LogDestination = config.LogDestinationFile
	cfg.LogFormat = config.LogFormatJSON

	lg := Init(&cfg)
	lg.Info("测试启动", "jail", "sshd")

	got, ok := LogFilePath()
	if !ok || got != path {
		t.Fatalf("日志文件路径未登记: %q %v", got, ok)
	}
	line := splitLines(readFile(t, path))[0]
	if !strings.Contains(line, `"version":"`+config.Version+`"`) {
		t.Fatalf("缺少 version 字段: %s", line)
	}
}

// TestSetLogFileRegistersOnce 断言路径只可登记一次，空路径被拒绝。
func TestSetLogFileRegistersOnce(t *testing.T) {
	resetLogFilePath()
	defer resetLogFilePath()

	path := filepath.Join(t.TempDir(), "a.log")
	if err := SetLogFile(path); err != nil {
		t.Fatalf("首次登记应成功: %v", err)
	}
	if got, ok := LogFilePath(); !ok || got != path {
		t.Fatalf("登记结果不符: %q %v", got, ok)
	}
	if err := SetLogFile(filepath.Join(t.TempDir(), "b.log")); err == nil {
		t.Fatal("重复登记应失败")
	}
	if err := SetLogFile(""); err == nil {
		t.Fatal("空路径应失败")
	}
}

// TestLogFilePathUnregistered 断言未登记时返回空与 false。
func TestLogFilePathUnregistered(t *testing.T) {
	resetLogFilePath()
	defer resetLogFilePath()

	if got, ok := LogFilePath(); ok || got != "" {
		t.Fatalf("未登记时应返回空值: %q %v", got, ok)
	}
}

// TestLogThrottler 断言节流器按秒级间隔放行，间隔为 0 时始终放行。
func TestLogThrottler(t *testing.T) {
	th := NewLogThrottler(3600)
	if !th.CanLog() {
		t.Fatal("首次调用应放行")
	}
	if th.CanLog() {
		t.Fatal("间隔内不应再次放行")
	}

	always := NewLogThrottler(0)
	for i := 0; i < 3; i++ {
		if !always.CanLog() {
			t.Fatal("间隔为 0 时应始终放行")
		}
	}
}
