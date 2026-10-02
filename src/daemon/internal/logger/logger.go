package logger

import (
	"errors"
	"fmt"
	"log/slog"
	"log/syslog"
	"os"
	"sync/atomic"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// 固定的系统路径：均为操作系统约定位置，不随部署变化。
const (
	// defaultLogPath 是未配置 log_file 时使用的独立日志文件路径（与 Rust 版常量一致）。
	defaultLogPath = "/var/log/firewall-daemon.log"
	// syslogSocket 是本地 syslog 的域套接字。
	syslogSocket = "/dev/log"
	// journaldSocket 是 systemd-journald 的兼容 syslog 入口。
	journaldSocket = "/run/systemd/journal/dev-log"
	// syslogTag 是所有 syslog 消息的标签。
	syslogTag = "firewall-daemon"
	// levelSilent 高于任何真实级别，令 Enabled 恒为 false，对应 log_level = NONE。
	levelSilent = slog.Level(127)
)

// syslogDialer 建立到 syslog / journald 的连接；测试可替换为指向临时套接字的实现。
type syslogDialer func(network, address string) (*syslog.Writer, error)

// options 是初始化日志系统所需的全部参数，与配置字段一一对应。
type options struct {
	level       slog.Level
	destination uint8
	format      uint8
	filePath    string
	maxBytes    uint64
	maxFiles    uint32
	dial        syslogDialer
}

// optionsFromConfig 把配置映射为初始化参数。
//
// maxBytes 先转 uint64 再相乘：log_max_size_mb 是 uint32，直接乘 1024*1024 会溢出 32 位。
func optionsFromConfig(cfg *config.Config) options {
	return options{
		level:       levelFromConfig(cfg.LogLevel),
		destination: cfg.LogDestination,
		format:      cfg.LogFormat,
		filePath:    resolveLogPath(cfg.LogFile),
		maxBytes:    uint64(cfg.LogMaxSizeMB) * 1024 * 1024,
		maxFiles:    cfg.LogMaxFiles,
		dial:        dialSyslog,
	}
}

// levelFromConfig 把 log_level 取值映射为 slog 级别。
func levelFromConfig(level uint8) slog.Level {
	switch level {
	case config.LogLevelNone:
		return levelSilent
	case config.LogLevelErr:
		return slog.LevelError
	case config.LogLevelWarn:
		return slog.LevelWarn
	case config.LogLevelDebug:
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// resolveLogPath 返回配置的日志文件路径；未配置或为空时用默认路径。
func resolveLogPath(configured string) string {
	if configured != "" {
		return configured
	}
	return defaultLogPath
}

// dialSyslog 是生产环境的连接实现。
func dialSyslog(network, address string) (*syslog.Writer, error) {
	return syslog.Dial(network, address, syslog.LOG_DAEMON|syslog.LOG_INFO, syslogTag)
}

// warnStderr 在日志系统自身不可用时直接向 stderr 告警（对应 Rust 的 eprintln!）。
func warnStderr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "警告: "+format+"\n", args...)
}

// Init 按配置初始化日志系统并返回结构化日志器。
//
// 调用方此后经返回的 *slog.Logger 使用日志（logger.Info/Warn/Error/Debug），不存在全局
// 实例。配置了 log_file 时，路径同时登记给日志查看器使用（对应 Rust 的
// web_ui::log_viewer::set_log_file）；未配置时保持未登记，与 Rust 行为一致。
func Init(cfg *config.Config) *slog.Logger {
	if cfg.LogFile != "" {
		if err := SetLogFile(cfg.LogFile); err != nil {
			warnStderr("登记日志文件路径失败: %v", err)
		}
	}
	structured, _ := initLogger(optionsFromConfig(cfg))
	return structured
}

// initLogger 是初始化主体：按目的地建立 sink、按格式建立处理器。
//
// buildSinks 保证至少返回一个 sink（最差是 stderr），所以这里无需空集合兜底。
// 返回的 close 用于释放 sink；生产路径不调用（进程退出即释放），测试用它避免句柄泄漏。
func initLogger(opts options) (*slog.Logger, func() error) {
	sinks := buildSinks(opts)
	handler := newHandler(opts.format, fanout(sinks), opts.level)
	// version 作为根日志器属性，排在 msg 之后、各调用点自身的属性之前。
	return slog.New(handler).With("version", config.Version), closeAll(sinks)
}

// buildSinks 按目的地建立 sink；单个目的地不可用只告警并降级，绝不返回错误。
//
// 目的地语义：
//   - SYSLOG / JOURNAL：只写系统日志，不创建文件；
//   - FILE：只写文件；
//   - BOTH：文件与系统日志并行，文件不可用时自动退化为仅系统日志；
//   - 全部不可用：退化为 stderr。os.Stderr 由运行时持有、始终可写，故返回集合非空，
//     调用方不必处理「无处可写」。
func buildSinks(opts options) []sink {
	wantSyslog, wantJournal, wantFile := false, false, false
	switch opts.destination {
	case config.LogDestinationSyslog:
		wantSyslog = true
	case config.LogDestinationJournal:
		wantJournal = true
	case config.LogDestinationFile:
		wantFile = true
	case config.LogDestinationBoth:
		wantSyslog, wantFile = true, true
	default:
		// 解析层不会产生未知取值；兜底为文件，避免静默丢弃全部日志。
		wantFile = true
	}

	var sinks []sink
	if wantSyslog {
		if s, err := dialSyslogSink(opts); err != nil {
			warnStderr("无法连接 syslog %s: %v", syslogSocket, err)
		} else {
			sinks = append(sinks, s)
		}
	}
	if wantJournal {
		if s, err := dialJournaldSink(opts); err != nil {
			warnStderr("无法连接 journald: %v", err)
		} else {
			sinks = append(sinks, s)
		}
	}
	if wantFile {
		s, err := newFileSink(opts.filePath, opts.maxBytes, opts.maxFiles)
		if err != nil {
			warnStderr("无法打开日志文件 %s: %v", opts.filePath, err)
		} else {
			sinks = append(sinks, s)
		}
	}
	if len(sinks) == 0 {
		warnStderr("日志目的地均不可用，回退到 stderr")
		sinks = append(sinks, newStderrSink())
	}
	return sinks
}

// dialSyslogSink 连接本地 syslog：Unix 上既有数据报套接字也有流套接字，两者都试。
func dialSyslogSink(opts options) (sink, error) {
	if w, err := opts.dial("unixgram", syslogSocket); err == nil {
		return w, nil
	}
	return opts.dial("unix", syslogSocket)
}

// dialJournaldSink 连接 journald 的兼容 syslog 入口；不可用时退回本地 syslog。
func dialJournaldSink(opts options) (sink, error) {
	if w, err := opts.dial("unixgram", journaldSocket); err == nil {
		return w, nil
	}
	return opts.dial("unixgram", syslogSocket)
}

// logFilePath 保存已登记的日志文件路径（对应 Rust 的 web_ui::log_viewer 全局状态）。
var logFilePath atomic.Pointer[string]

// SetLogFile 登记日志文件路径，供日志查看器读取。
//
// 重复登记返回错误：该路径只在启动时设置一次，与 Rust 版 OnceLock 的语义一致。
func SetLogFile(path string) error {
	if path == "" {
		return errors.New("日志文件路径为空")
	}
	if !logFilePath.CompareAndSwap(nil, &path) {
		return errors.New("日志文件路径已登记")
	}
	return nil
}

// LogFilePath 返回已登记的日志文件路径；未登记时第二个返回值为 false。
func LogFilePath() (string, bool) {
	registered := logFilePath.Load()
	if registered == nil {
		return "", false
	}
	return *registered, true
}

// LogThrottler 限制同一调用点的日志频率，避免高频路径刷满日志。
type LogThrottler struct {
	last     atomic.Int64
	interval int64
}

// NewLogThrottler 创建节流器，interval 为两次放行之间的最小间隔秒数。
func NewLogThrottler(interval int64) *LogThrottler {
	return &LogThrottler{interval: interval}
}

// CanLog 在距上次放行已达 interval 秒时返回 true，并记录当前时刻。
func (t *LogThrottler) CanLog() bool {
	now := time.Now().Unix()
	if now-t.last.Load() >= t.interval {
		t.last.Store(now)
		return true
	}
	return false
}
