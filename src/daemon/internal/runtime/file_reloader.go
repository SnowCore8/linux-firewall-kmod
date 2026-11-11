package runtime

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/jail"
)

type fileReloader struct {
	path   string
	strict bool
	logger *slog.Logger
}

// NewFileReloader 构造配置重载器。strict 必须与启动时 `--no-strict` 的取值一致：
// 启动能接受的文件，SIGHUP 与回滚也必须按同一口径接受，否则会出现「能启动、不能重载」。
func NewFileReloader(path string, strict bool, logger *slog.Logger) ConfigReloader {
	// logger 为 nil 时回退 slog.Default()：Reload/Rollback/applyConfig 都要用它记日志，
	// 在构造处兜底比在每个调用点判空更不容易漏。
	if logger == nil {
		logger = slog.Default()
	}
	return &fileReloader{path: path, strict: strict, logger: logger}
}

func (r *fileReloader) Reload(cfg *config.Config) error {
	r.logger.Info("reloading configuration", "path", r.path)

	info, err := os.Stat(r.path)
	if err != nil {
		return err
	}
	// 从 Default() 起步，而不是零值：初始加载（main.go）就是「Default() + 文件」，重载必须
	// 同一条口径。零值起步会让一份没写 defaults 段的文件把 defaults.max_retries/findtime/
	// ban_time、整个 ddos 段、interval 都清成 0——Validate 会因 default_max_retries == 0
	// 直接拒掉整次重载（现象是「面板显示文件里的新值、守护进程按旧配置继续跑」），而恰好写了
	// defaults 却没写 ddos 的文件会加载成功，于是内核收到一排全零速率并被逐位拒绝。
	var newCfg = config.Default()
	if info.IsDir() {
		if err := config.LoadConfigDirectory(r.path, &newCfg, r.strict); err != nil {
			return err
		}
	} else {
		if err := config.ParseConfigFile(r.path, &newCfg, r.strict); err != nil {
			return err
		}
	}

	// 正则编译失败不阻断重载（见 jail.Finalize）：该 jail 退化为关键字回退，逐条告警后照常应用。
	warnings, err := jail.Finalize(&newCfg)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		r.logger.Warn("配置正则未能编译，该 jail 退化为其关键字回退", "detail", warning)
	}

	r.applyConfig(cfg, newCfg)
	r.logger.Info("configuration reloaded successfully")
	return nil
}

func (r *fileReloader) Rollback(cfg *config.Config) error {
	r.logger.Warn("configuration rollback requested")
	// 备份住在配置来源**旁边**：目录模式下 r.path 本身就是那个目录，再取一次 Dir 会爬到
	// 目录的父级去，那里没有本次部署的备份，于是回滚永远退化成「重新加载当前配置」。
	dir := r.path
	if info, err := os.Stat(r.path); err != nil || !info.IsDir() {
		dir = filepath.Dir(r.path)
	}
	backupPath := filepath.Join(dir, "config.yaml.rollback")

	if _, err := os.Stat(backupPath); err != nil {
		return r.Reload(cfg)
	}

	var newCfg = config.Default()
	if err := config.ParseConfigFile(backupPath, &newCfg, r.strict); err != nil {
		return err
	}

	// 与 Reload 同一口径：正则编译失败只告警，回滚照常应用。
	warnings, err := jail.Finalize(&newCfg)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		r.logger.Warn("配置正则未能编译，该 jail 退化为其关键字回退", "detail", warning)
	}

	r.applyConfig(cfg, newCfg)
	r.logger.Info("configuration rolled back successfully")
	return nil
}

// applyConfig 换入新配置，并说破监听地址的错位。
//
// HTTP 服务器只在启动时绑定一次端口，重载与回滚都不重绑。metrics_port 现在真的会
// 改变合成地址（此前那个字段没有消费者，怎么改都是 127.0.0.1:9119），所以两份不一致
// 时留一条告警，而不是让人以为把端口写进文件就立刻生效。
//
// 换入是整结构体赋值（含 Jails/TrustedIPs 的 slice 头），HTTP handler 与其它 goroutine
// 会并发读同一实例，所以必须在写锁内完成；监听地址的比较与告警放到锁外——日志是文件
// I/O，不该让它在持锁期间挡住所有读方。
func (r *fileReloader) applyConfig(cfg *config.Config, newCfg config.Config) {
	config.LockConfig()
	running := cfg.ListenAddress()
	// 日志的 sink、级别与格式只在启动时的 logger.Init 建立，换入新配置不会重建它们；
	// 记下旧值，换入后若变了就告警，否则表现为「文件里改了 log_file、面板却一直空白」。
	oldLogFile, oldLogLevel, oldLogFormat := cfg.LogFile, cfg.LogLevel, cfg.LogFormat
	// 出口探测得到的本机坐标不是 YAML 键，只在启动时填一次；新配置从文件重建后这两组
	// 字段为空，若直接换入，一次热重载就会把地图上的本机标记抹掉，直到进程重启才恢复。
	// 文件显式给了坐标时以文件为准（ServerCoordsSet），探测结果只作兜底。
	if !newCfg.ServerCoordsSet && cfg.ServerCoordsSource == "detected" {
		newCfg.ServerLatitude = cfg.ServerLatitude
		newCfg.ServerLongitude = cfg.ServerLongitude
		newCfg.ServerCoordsSource = cfg.ServerCoordsSource
	}
	*cfg = newCfg
	configured := cfg.ListenAddress()
	config.UnlockConfig()
	if configured != running {
		r.logger.Warn("HTTP 监听地址已改变，本进程不会重新绑定，需重启守护进程才会生效",
			"running", running, "configured", configured)
	}
	// 日志键同样只在启动时生效。逐项带 old/new 说破是哪一个键动了：只说「日志配置变了」
	// 时，运维还得自己翻两份文件比对。
	if oldLogFile != newCfg.LogFile {
		r.logger.Warn("log_file 已改变，本进程不会重建日志输出，需重启守护进程才会生效",
			"old", oldLogFile, "new", newCfg.LogFile)
	}
	if oldLogLevel != newCfg.LogLevel {
		r.logger.Warn("log_level 已改变，本进程不会重建日志级别，需重启守护进程才会生效",
			"old", oldLogLevel, "new", newCfg.LogLevel)
	}
	if oldLogFormat != newCfg.LogFormat {
		r.logger.Warn("log_format 已改变，本进程不会重建日志格式，需重启守护进程才会生效",
			"old", oldLogFormat, "new", newCfg.LogFormat)
	}
}
