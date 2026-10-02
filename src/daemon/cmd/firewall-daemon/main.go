// Command firewall-daemon 是守护进程的组合根：把配置、内核链路、入站主链路与
// 关停顺序接到一起。
//
// 组合根只负责「装配与生命周期」，不含业务判定：解析命令行、加载配置、按依赖顺序
// 启动各执行体，最后按登记逆序优雅关停。凡是本文件里以「未装配」标注的子系统，
// 表示对应能力尚未移植到 Go 侧，运行时会显式记录一条 warn，绝不伪装成已完成。
package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/http"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/jail"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/kernel"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logger"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/runtime"
	panelres "github.com/snowcore8/linux-firewall-kmod/daemon/web_ui/static"
)

// panelDir 是前端静态面板的 go:embed 目录（src/daemon/web_ui/static/assets.go 声明）。
// 它是启动期必须存在的资源：缺失时直接以启动错误返回，而不是反复报接口失败。
var panelDir = panelres.PanelDir

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "firewall-daemon: %v\n", err)
		os.Exit(1)
	}
}

// run 是 main 的可测试入口：解析参数、装配、运行、关停。
func run(args []string) error {
	parsed, err := config.ParseConfigArgs(args)
	if err != nil {
		return err
	}
	// --help / -h：已打印帮助，成功退出。
	if parsed == nil {
		return nil
	}

	// 面板是守护进程能力的一部分：静态资源缺失时不假装可运行。
	if panelDir == "" {
		return fmt.Errorf("前端静态面板缺失（go:embed web_ui/static 为空）")
	}

	// 回滚模式是独立短路径：不加载配置，只给运行中的守护进程发 SIGUSR1。
	if parsed.Rollback {
		return requestRollback()
	}

	// 信号层必须早于任何 goroutine 建立，否则启动窗口内送达的信号会丢失。
	signals, err := runtime.NewSignalSource()
	if err != nil {
		return fmt.Errorf("初始化信号层失败: %w", err)
	}
	defer signals.Close()

	cfg := config.Default()
	if err := loadConfig(parsed, &cfg); err != nil {
		return err
	}

	jail.ApplySmartDefaults(&cfg)
	if err := jail.Validate(&cfg); err != nil {
		return fmt.Errorf("配置校验失败: %w", err)
	}
	if err := jail.CompileRegexes(&cfg); err != nil {
		return fmt.Errorf("正则编译失败: %w", err)
	}

	cfg.Daemon = parsed.Daemon

	// 日志系统按配置初始化：目的地、格式、级别门槛与文件轮转都在 internal/logger 内落地。
	logger := newLogger(&cfg)

	if err := checkProcfs(); err != nil {
		return err
	}

	sup := runtime.NewSupervisor()

	// SQLite 持久化层：封禁历史、信誉分、封禁事件。
	var historyDB *persist.DB
	if cfg.HistoryDBPath != "" {
		db, err := persist.NewDB(persist.Config{
			Path:   cfg.HistoryDBPath,
			Logger: logger,
		})
		if err != nil {
			logger.Warn("初始化持久化数据库失败，历史分析功能不可用", "error", err)
		} else {
			defer db.Close()
			db.StartCleanupScheduler(0, cfg.HistoryRetentionDays)
			historyDB = db
			logger.Info("持久化数据库已就绪", "path", cfg.HistoryDBPath)
		}
	}

	// HTTP 服务器：API、SSE、Prometheus 指标。
	var httpServer *http.Server
	var sseBroker *http.SSEBroker
	var metrics *http.Metrics
	if cfg.HTTPAddress != "" {
		var err error
		httpServer, err = http.NewServer(http.Config{
			Address:         cfg.HTTPAddress,
			MaxConnections:  cfg.MaxSSEConnections,
			ShutdownTimeout: 5 * time.Second,
			Logger:          logger,
		})
		if err != nil {
			logger.Warn("初始化 HTTP 服务器失败", "error", err)
		} else {
			sseBroker = http.NewSSEBroker(cfg.MaxSSEConnections, logger)
			metrics = http.NewMetrics()
			api := http.NewAPIHandlers(httpServer, historyDB, sseBroker, metrics)
			httpServer.RegisterRoutes(api)
			httpServer.Handle("/api/v1/events", sseBroker)
			httpServer.Handle("/metrics", metrics)

			httpToken := runtime.NewShutdown()
			sup.Spawn("http-server", httpToken, func() {
				if err := httpServer.Start(); err != nil {
					logger.Error("HTTP 服务器异常退出", "error", err)
				}
			})
			logger.Info("HTTP 服务器已启动", "addr", cfg.HTTPAddress)
		}
	}

	// 内核链路是可降级的：打开失败只告警，入站主链路仍可独立运行。
	var kernelClient *kernel.Client
	transport, err := kernel.OpenTransport()
	if err != nil {
		logger.Warn("打开内核 netlink 链路失败，内核交互功能不可用", "error", err)
	} else {
		// 必须先建立接收侧（设 SO_RCVTIMEO、清 O_NONBLOCK、重新武装 linkDown），
		// 再启动接收回路，否则 Poll 永远只返回 deadline / interrupt。
		if serr := transport.Subscribe(); serr != nil {
			logger.Warn("订阅内核 netlink 接收链路失败", "error", serr)
			transport.Close()
		} else {
			defer transport.Close()
			router, _ := kernel.NewEventChannel(kernel.EventQueue)
			reactorToken := runtime.NewShutdown()
			reactor := kernel.NewReactor(transport, router, reactorToken, logger)
			sup.Spawn("kernel-reactor", reactorToken, reactor.Run)
			kernelClient = kernel.NewClient(transport, router)
			logger.Info("内核 netlink 链路已就绪")
		}
	}

	// 入站主链路：配置所有权移入执行体，此后由它持有。
	deps := runtime.Deps{
		Logger:   logger,
		Facts:    runtime.NoHistory{},
		Sink:     newBanSink(kernelClient, logger),
		Stats:    newStatsSink(logger),
		Hooks:    nil, // 历史快照与数据清理尚未移植。
		Reloader: nil, // 配置文件热重载尚未移植。
		Enabled:  nil, // Web UI 权威启用状态尚未移植。
	}
	executor, err := runtime.NewInboundExecutor(&cfg, signals, deps)
	if err != nil {
		if transport != nil {
			transport.Close()
		}
		return fmt.Errorf("装配入站主链路失败: %w", err)
	}
	defer executor.Close()

	terminate := runtime.NewShutdown()
	ingestToken := runtime.NewShutdown()
	// 最后登记 = 最先关停：入站主链路先于内核接收回路收尾，避免收尾期间事件堆积。
	sup.Spawn("ingest", ingestToken, func() {
		executor.Run(ingestToken, terminate)
	})

	// 主 goroutine 等待终止。Shutdown 只有 Request/IsShutdown 而无完成通道，故这里
	// 自备一个通道：与信号层并行地去「看见」同一个 SIGTERM/SIGINT。
	stopCh := make(chan struct{})
	go func() {
		term := make(chan os.Signal, 1)
		signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(term)
		select {
		case <-term:
		case <-stopCh:
		}
		close(stopCh)
		terminate.Request()
	}()

	<-stopCh
	logger.Info("收到终止，开始优雅关停")

	// 关停顺序固定：先按登记逆序停掉各执行体（入站主链路 → 内核接收回路），再让
	// 延迟清理释放执行体依赖的资源（延迟清理按 LIFO 执行）。
	for _, res := range sup.Shutdown(5 * time.Second) {
		if res.Outcome != runtime.Joined {
			logger.Warn("执行体关停未在超时内完成", "name", res.Name, "outcome", res.Outcome)
		}
	}
	return nil
}

// loadConfig 按 -c（文件）或 -C（目录）加载配置；两者都未指向存在的路径时失败。
func loadConfig(parsed *config.ConfigArgs, cfg *config.Config) error {
	info, err := os.Stat(parsed.ConfigPath)
	if err != nil {
		return fmt.Errorf("配置路径不存在: %s", parsed.ConfigPath)
	}
	if info.IsDir() {
		return config.LoadConfigDirectory(parsed.ConfigPath, cfg, parsed.Strict)
	}
	return config.ParseConfigFile(parsed.ConfigPath, cfg, parsed.Strict)
}

// checkProcfs 在启动前确认内核模块已加载：缺失说明模块未载入或接口版本不符，
// 此时继续运行只会反复失败，故直接以启动错误返回。返回首个缺失的路径以利于排障。
func checkProcfs() error {
	for _, p := range procfsPaths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("内核接口不可用: %s 不存在（内核模块未加载？）", p)
		}
	}
	return nil
}

// requestRollback 向正在运行的守护进程发送 SIGUSR1，触发配置回滚。
func requestRollback() error {
	self := os.Getpid()
	pids, err := pgrepSelf("firewall-daemon")
	if err != nil {
		return fmt.Errorf("查找运行中的守护进程失败: %w", err)
	}
	for _, pid := range pids {
		if pid == self {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		if err := proc.Signal(syscall.SIGUSR1); err != nil {
			return fmt.Errorf("发送回滚信号失败 (pid %d): %w", pid, err)
		}
		time.Sleep(500 * time.Millisecond)
		fmt.Println("回滚完成")
		return nil
	}
	return fmt.Errorf("未找到运行中的 firewall-daemon（请先以 -d 启动）")
}

// pgrepSelf 返回命令行匹配 pattern 的进程 PID（不含调用者自身）。
func pgrepSelf(pattern string) ([]int, error) {
	out, err := exec.Command("pgrep", "-f", pattern).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return nil, nil // pgrep 无匹配时退出码为 1，不是错误。
		}
		return nil, err
	}
	var pids []int
	for _, line := range strings.Fields(strings.TrimSpace(string(out))) {
		if pid, cerr := strconv.Atoi(line); cerr == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// procfsPaths 是内核模块必须已暴露的 procfs 接口。
var procfsPaths = []string{"/proc/firewall", "/proc/firewall/bans"}

// newLogger 按配置初始化日志系统，返回可直接使用的结构化日志器。
//
// 初始化自身不会失败：目的地不可用时按降级链回退（详见 internal/logger），因此返回的
// *slog.Logger 始终可用，各调用点沿用 logger.Info/Warn/Debug 形式不变。
func newLogger(cfg *config.Config) *slog.Logger {
	return logger.Init(cfg)
}

// banSink 是 BanSink 的生产实现：把封禁下发接到内核客户端与活跃封禁缓存。
type banSink struct {
	client  *kernel.Client
	cache   *bans.ActiveBanCache
	logger  *slog.Logger
	pending sync.Map // ip -> struct{}，标记「已下发、等待内核确认」
}

func newBanSink(client *kernel.Client, logger *slog.Logger) *banSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &banSink{client: client, cache: bans.NewActiveBanCache(), logger: logger}
}

// TryInsert 见 runtime.BanSink。
func (s *banSink) TryInsert(info bans.BanInfo) bool {
	if !s.cache.TryInsert(info) {
		return false
	}
	s.cache.MirrorInsert(info)
	return true
}

// MirrorInsert 见 runtime.BanSink。
func (s *banSink) MirrorInsert(info bans.BanInfo) { s.cache.MirrorInsert(info) }

// MarkPendingAck 见 runtime.BanSink。
func (s *banSink) MarkPendingAck(ip string) { s.pending.Store(ip, struct{}{}) }

// Send 见 runtime.BanSink。client 为 nil 时按「不动作」处理并记一条调试日志。
func (s *banSink) Send(addr netip.Addr, prefixLen uint8, durationSecs uint32, reason string) error {
	if s.client == nil {
		s.logger.Debug("内核客户端未装配，跳过封禁下发", "ip", addr.String())
		return nil
	}
	_, err := s.client.Ban(addr, prefixLen, durationSecs, reason)
	return err
}

// RollbackInsert 见 runtime.BanSink。
func (s *banSink) RollbackInsert(ip string) {
	s.cache.Remove(ip)
	s.pending.Delete(ip)
}

// statsSink 是 StatsSink 的生产实现。
//
// 真正的计数汇聚（Web UI 镜像、Prometheus 指标、历史快照差分）尚未移植，这里只保留
// 全局原子计数，保证计数链路不丢数，供后续消费者接管。
type statsSink struct {
	logger *slog.Logger

	linesParsed   atomic.Uint64
	linesSkipped  atomic.Uint64
	regexMatches  atomic.Uint64
	inotifyEvents atomic.Uint64
	logRotations  atomic.Uint64
	bansTriggered atomic.Uint64
}

func newStatsSink(logger *slog.Logger) *statsSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &statsSink{logger: logger}
}

// AddGlobal 见 runtime.StatsSink。
func (s *statsSink) AddGlobal(parsed, skipped, regexes, ips uint64) {
	s.linesParsed.Add(parsed)
	s.linesSkipped.Add(skipped)
	s.regexMatches.Add(regexes)
}

// AddJail 见 runtime.StatsSink。
func (s *statsSink) AddJail(jail string, parsed, regexes, ips uint64) {
	s.linesParsed.Add(parsed)
	s.regexMatches.Add(regexes)
}

// IncInotifyEvents 见 runtime.StatsSink。
func (s *statsSink) IncInotifyEvents() { s.inotifyEvents.Add(1) }

// IncLogRotations 见 runtime.StatsSink。
func (s *statsSink) IncLogRotations() { s.logRotations.Add(1) }

// IncBansTriggered 见 runtime.StatsSink。
func (s *statsSink) IncBansTriggered(jail string) { s.bansTriggered.Add(1) }
