// Command firewall-daemon 是守护进程的组合根：把配置、内核链路、入站主链路与
// 关停顺序接到一起。
//
// 组合根只负责「装配与生命周期」，不含业务判定：解析命令行、加载配置、按依赖顺序
// 启动各执行体，最后按登记逆序优雅关停。
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/http"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/jail"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/kernel"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logger"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/runtime"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
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

	// startedAt 是进程开始装配的时刻：GET /api/v1/stats 的 uptime_seconds 从这里起算，
	// 而不是 HTTP 服务器构造时刻——读配置、开历史库这些时间也算「启动了多久」。
	startedAt := time.Now()

	cfg := config.Default()
	if err := loadConfig(parsed, &cfg); err != nil {
		return err
	}

	// 后处理三步（智能默认 → 校验 → 编译）与重载器、PUT /config 的落盘前校验共用同一个
	// 函数：启动能过的配置、热重载与 API 写入必须按同一口径判，否则「能启动但不能重载」
	// 这类现象就没有解释。正则编译失败在这里只是告警（见 jail.Finalize），不能让进程退出。
	finalWarnings, err := jail.Finalize(&cfg)
	if err != nil {
		return fmt.Errorf("配置后处理失败: %w", err)
	}

	cfg.Daemon = parsed.Daemon

	// 日志系统按配置初始化：目的地、格式、级别门槛与文件轮转都在 internal/logger 内落地。
	logger := newLogger(&cfg)

	// logger 建在 Finalize 之后，warnings 只能先暂存到这里再逐条告警。
	for _, warning := range finalWarnings {
		logger.Warn("配置正则未能编译，该 jail 退化为其关键字回退", "detail", warning)
	}

	if err := checkProcfs(); err != nil {
		return err
	}

	sup := runtime.NewSupervisor()

	// Prometheus 指标注册表在整条装配链的最前面建立：内核链路、入站执行体、HTTP 面都要
	// 往里写计数，而它们的装配顺序不固定（内核链路早于 HTTP）。此前它只在 HTTP 段里建，
	// 于是 netlink 与配置重载这两组计数没有可写之处。禁用 HTTP 面（metrics_port=0）
	// 时它依旧存在，只是无人抓取。
	metrics := http.NewMetrics()
	// 预注册这些计数器，使 /metrics 从启动起就有稳定的 0 值样本行，而不是等到第一次自增
	// 才出现（Prometheus 抓取与集成测试都以此为存在性判据）。netlink 那四个即使链路建不
	// 起来也各留一条 0 值样本。
	metrics.Counter(kernel.CounterMessagesSentTotal)
	metrics.Counter(kernel.CounterMessagesReceivedTotal)
	metrics.Counter(kernel.CounterSendErrorsTotal)
	metrics.Counter(kernel.CounterRecvErrorsTotal)
	metrics.Counter(configReloadsMetric)

	// SQLite 持久化层：封禁历史、信誉分、封禁事件。
	var historyDB *persist.DB
	// facts 是判定层的信誉分/封禁次数缓存（nil 时执行体退回 NoHistory）。
	var facts *persist.Facts
	if cfg.HistoryDBPath != "" {
		db, err := persist.NewDB(persist.Config{
			Path:   cfg.HistoryDBPath,
			Logger: logger,
		})
		if err != nil {
			logger.Warn("初始化持久化数据库失败，历史分析功能不可用", "error", err)
		} else {
			defer db.Close()
			dbStopCh := make(chan struct{})
			defer close(dbStopCh)
			db.StartCleanupScheduler(0, cfg.HistoryRetentionDays, dbStopCh)
			db.StartReputationRecoveryScheduler(0, 1, 100, dbStopCh)
			// 判定层每行日志都要扣一次信誉分并立刻取分，直接查库会把入站主链路钉在磁盘上；
			// 这里按 IP 折叠，与库自带的两个调度器共用同一条 stop 通道（关停时最后刷一次盘）。
			facts = persist.NewFacts(db, persist.FactsOptions{Logger: logger})
			facts.StartFlusher(dbStopCh)
			historyDB = db
			logger.Info("持久化数据库已就绪", "path", cfg.HistoryDBPath)
		}
	}

	// 内核链路是可降级的：打开失败只告警，入站主链路仍可独立运行。
	// 先于 HTTP 服务器初始化，以便 banSink 持有有效的内核客户端供 API 下发。
	var kernelClient *kernel.Client
	var kernelRouter *kernel.Router
	var kernelEvents <-chan kernel.Incoming
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
			// 健康计数必须在接收回路启动前接好：Send/TryRecv 在热路径上直接读这些句柄，
			// 且此后再不改写。
			transport.SetMetrics(kernelMetrics{m: metrics})
			router, events := kernel.NewEventChannel(kernel.EventQueue)
			kernelRouter, kernelEvents = router, events
			reactorToken := runtime.NewShutdown()
			reactor := kernel.NewReactor(transport, router, reactorToken, logger)
			sup.Spawn("kernel-reactor", reactorToken, reactor.Run)
			kernelClient = kernel.NewClient(transport, router)
			logger.Info("内核 netlink 链路已就绪")
		}
	}

	// 封禁下发汇聚点：入站主链路与 HTTP API 共用同一个实例。
	//
	// 此前两处各建一个 banSink，写的是同一份进程级缓存所以结果没分叉，但「谁通知信誉缓存」
	// 这类回调只能挂在其中一个上，共用实例就把这个坑填平：封禁落库后由它同步 Facts 里的
	// 封禁次数与扣分，否则渐进式时长读到的是封禁前的旧次数。
	banSinkForDaemon := newBanSink(kernelClient, logger, historyDB)
	if facts != nil {
		banSinkForDaemon.noteBan = facts.NoteBan
	}
	// 白名单下发：与封禁同一个内核客户端，但没有缓存/库要联动——白名单表在内核侧，
	// 镜像由事件泵按内核回显重建，HTTP 只负责把规则发下去（见 http.KernelWhitelist）。
	whitelistSinkForDaemon := newWhitelistSink(kernelClient, logger)
	// 配置下发出口：HTTP 的 PUT /config 与执行体的重载/回滚共用一个实例（同一个内核客户端），
	// 两边投影出来的载荷逐字段相同，见 configSink。
	configSinkForDaemon := newConfigSink(kernelClient, logger)

	// 内核观测快照：事件泵是唯一写入者。
	//
	// 无条件建立，让读侧将来只有一个持有者：链路缺失时它保持零值快照，读侧就不需要区分
	// 「没有内核」与「内核还没采到样」。读侧接两处：/health 的链路字段，以及统计面
	// （/api/v1/stats 与 rates/*、协议分布那组端点）——它们都只读这一份快照。
	kernelStore := telemetry.NewStore()

	// Jail 启用状态源：HTTP API 与入站主链路共享。
	jailEnabled := runtime.NewJailEnabledSource()

	// HTTP 服务器：API、SSE、Prometheus 指标。
	var httpServer *http.Server
	var sseBroker *http.SSEBroker
	// api 要活在 if 之外：事件泵的域载荷镜像与执行体的 jails 变更通知都挂在它身上，
	// 而这两处都在 HTTP 段之后装配。监听地址为空（metrics_port=0）时它是 nil，
	// 两处注入都按缺席处理。
	var api *http.APIHandlers
	httpAddr := cfg.ListenAddress()
	if httpAddr != "" {
		var err error
		httpServer, err = http.NewServer(http.Config{
			Address:         httpAddr,
			MaxConnections:  cfg.MaxSSEConnections,
			ShutdownTimeout: 5 * time.Second,
			Logger:          logger,
		})
		if err != nil {
			logger.Warn("初始化 HTTP 服务器失败", "error", err)
		} else {
			// 两条 SSE 流各自的上限与心跳都取自契约生成物：events 10/15s，logs 5/15s。
			// 合用 cfg.MaxSSEConnections 会让日志页开满 5 条连接时把实时事件流一起饿死。
			sseBroker = http.NewEventsBroker(logger)
			defer sseBroker.Stop()
			logStream := http.NewLogsStream(logger)

			// 配置路径：优先单文件，其次目录
			configPath := cfg.ConfigFile
			if configPath == "" {
				configPath = cfg.ConfigDir
			}

			api = http.NewAPIHandlers(http.APIConfig{
				Server:    httpServer,
				DB:        historyDB,
				SSE:       sseBroker,
				LogStream: logStream,
				Metrics:   metrics,
				KernelBan: banSinkForDaemon,
				// 白名单下发出口：与封禁共用内核客户端，缺席时同样按「跳过下发」处理。
				KernelWhitelist: whitelistSinkForDaemon,
				// 配置下发出口：PUT /config 同步发一次，好把内核的采纳结论带回响应。
				KernelConfig: configSinkForDaemon,
				Username:     cfg.MetricsUsername,
				Password:     cfg.MetricsPassword,
				// 进程级唯一的认证失败账本：契约的锁定窗口不区分来源 IP，所以整进程一份。
				Lockout:          http.NewAuthLockout(),
				GetCurrentConfig: func() *config.Config { return &cfg },
				GetConfigPath:    func() string { return configPath },
				JailController:   jailEnabled,
				LogFilePath:      func() string { return cfg.LogFile },
				// GET /health 的读数来源：链路状态只有事件泵这份快照知道，procfs 在场与否
				// 由本进程自己 stat。
				GetKernelSnapshot: kernelStore.Snapshot,
				KmodPresent:       kernelProcPresent,
				// 统计面的三个读数来源：运行时长起点、速率历史环、内核模块自报版本。
				// 速率历史与快照同源（事件泵的同一批采样），异常检测的分位基线用的也是它。
				StartedAt:      startedAt,
				GetRateSamples: kernelStore.RateSamples,
				KernelVersion:  kernelModuleVersion,
			})
			// 路由全部由 RegisterRoutes 按契约 pattern 注册，包括 /api/v1/events 与
			// /metrics：它们都在契约的认证组里，在这里另注册一遍会绕过 RequireAuth。
			httpServer.RegisterRoutes(api)
			httpServer.RegisterStaticFiles(panelres.StaticFS())

			httpToken := runtime.NewShutdown()
			sup.Spawn("http-server", httpToken, func() {
				if err := httpServer.Start(); err != nil {
					logger.Error("HTTP 服务器异常退出", "error", err)
				}
			})
			logger.Info("HTTP 服务器已启动", "addr", httpAddr)
		}
	}

	// 反向指令通道：内核事件 → 入站执行体。容量 256 是「一个 poll 周期内可能到达的
	// CONFIG_CHANGE + 封禁被拒」的宽裕上界；满了由泵记日志丢弃，不钉住事件流。
	kernelCmd := make(chan runtime.Directive, 256)

	// 内核事件泵：NewEventChannel 的事件流到这里才有消费者。
	//
	// 在此之前内核推送的封禁/解封/白名单/DDoS 事件在 4096 深度的队列里堆满后被静默
	// 丢弃，本进程也从没发过 DAEMON_REGISTER——内核在收到注册前丢弃一切指令，于是
	// 「下发全部石沉大海」与「面板只看到自己下发过的那一小撮」同时成立。
	if kernelClient != nil && kernelEvents != nil {
		var pub kernel.Publisher
		if sseBroker != nil {
			pub = sseBroker
		}
		// 域载荷的形状出自表现层：泵只报「哪个域变了、它那张表里现在有什么」。
		// api 缺席（未配 HTTP 监听）时没有可信的载荷生产者，Mirror 留 nil，泵按
		// 「不发一份与 REST 不同形的帧」处理。
		var mirror kernel.DomainMirror
		if api != nil {
			mirror = api.SSEReplicas()
		}
		var met kernel.Metrics
		if metrics != nil {
			met = kernelMetrics{m: metrics}
		}
		pump, err := kernel.NewEventPump(kernel.PumpDeps{
			Sampler:   kernelClient,
			Events:    kernelEvents,
			Store:     kernelStore,
			Router:    kernelRouter,
			Ring:      telemetry.NewRing(0),
			Publish:   pub,
			Mirror:    mirror,
			Metrics:   met,
			Logger:    logger,
			Timeout:   kernel.DefaultRequestTimeout,
			Cache:     bans.GlobalCache(),
			Whitelist: bans.GlobalWhitelist(),
			// 内核侧配置变更与封禁下发被拒要交给入站执行体落地（配置所有权在它手上）。
			Directives: kernelCmd,
		})
		if err != nil {
			logger.Error("内核事件泵装配失败，内核事件将无人消费", "error", err)
		} else {
			pumpToken := runtime.NewShutdown()
			sup.Spawn("kernel-event-pump", pumpToken, func() { pump.Run(pumpToken) })
			logger.Info("内核事件泵已启动",
				"sample", kernel.SampleInterval.String(),
				"reconcile", kernel.ReconcileInterval.String(),
				"register", kernel.RegisterInterval.String(),
			)
		}
	} else {
		logger.Warn("内核链路不可用，事件泵未启动：封禁表只反映本进程的下发记录")
	}

	// 入站主链路：配置所有权移入执行体，此后由它持有。
	//
	// 判定事实源用库支撑的信誉缓存；库缺失（未配置路径或打开失败）时退回 NoHistory——
	// 阈值乘数按满分算，判定照常，只是不再有渐进式收紧。
	var decisionFacts runtime.DecisionFacts = runtime.NoHistory{}
	if facts != nil {
		decisionFacts = facts
	}
	deps := runtime.Deps{
		Logger:   logger,
		Facts:    decisionFacts,
		Sink:     banSinkForDaemon,
		Stats:    newStatsSink(logger, metrics),
		Hooks:    runtime.NewMaintenanceHooks(historyDB, logger),
		Reloader: runtime.NewFileReloader(cfg.ConfigFile, logger),
		// 配置一变就同步到内核：手工编辑文件、SIGHUP、SIGUSR1 都只经过执行体，
		// 少这一条那些路径改的值永远上不了内核（与 PUT /config 共用同一个出口实例）。
		KernelConfig: configSinkForDaemon,
		Enabled:      jailEnabled,
		KernelCmd:    kernelCmd,
		// jail 配置快照换了形状 → SSE 的 jails 域跟着推一帧。变更时机只有属主知道，
		// 所以这一声由执行体喊、由本组合根接到表现层（api 未装配时桥自己吞掉）。
		JailSnapshot: jailSnapshotBridge{api: api},
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

// procfsRoot 是内核模块暴露的 procfs 目录，也是「模块已加载」在本进程里唯一的可见证据。
const procfsRoot = "/proc/firewall"

// procfsPaths 是内核模块必须已暴露的 procfs 接口。
var procfsPaths = []string{procfsRoot, procfsRoot + "/bans"}

// kernelProcPresent 报 procfs 接口是否在场。
//
// GET /health 的 kmod_proc_present 读它。它与「租约是否持有」是两件事：模块在但租约没
// 拿到，指令会被内核丢弃；租约在但 procfs 消失，说明模块刚被重载过。
func kernelProcPresent() bool {
	_, err := os.Stat(procfsRoot)
	return err == nil
}

// sysfsModuleVersion 是内核模块自报版本号的位置。
//
// fw_main.c 里的 MODULE_VERSION("2.2") 由 modinfo 段编进模块，sysfs 按
// 「/sys/module/<模块名>/version」暴露；模块名与 Makefile 的 obj-m := firewall.o 一致。
const sysfsModuleVersion = "/sys/module/firewall/version"

// kernelModuleVersion 读内核模块的版本号，读不到时报空串。
//
// 空串是**要的形状**：模块未加载（或 sysfs 未挂载）时面板显示「内核 」，运维一眼看出
// 版本没读到。拿守护进程版本或 "unknown" 顶上去会被读成「模块在跑，只是版本没显示」。
func kernelModuleVersion() string {
	data, err := os.ReadFile(sysfsModuleVersion)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// newLogger 按配置初始化日志系统，返回可直接使用的结构化日志器。
//
// 初始化自身不会失败：目的地不可用时按降级链回退（详见 internal/logger），因此返回的
// *slog.Logger 始终可用，各调用点沿用 logger.Info/Warn/Debug 形式不变。
func newLogger(cfg *config.Config) *slog.Logger {
	return logger.Init(cfg)
}

// banSink 是 BanSink 的生产实现：把封禁下发接到内核客户端与活跃封禁缓存。
type banSink struct {
	client *kernel.Client
	cache  *bans.ActiveBanCache
	logger *slog.Logger
	db     *persist.DB
	// noteBan 在封禁落库后将「刚刚封了一次」同步进信誉缓存（可空）。
	noteBan func(netip.Addr)
}

func newBanSink(client *kernel.Client, logger *slog.Logger, db *persist.DB) *banSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &banSink{client: client, cache: bans.GlobalCache(), logger: logger, db: db}
}

// TryInsert 见 runtime.BanSink。原子地插入主表与反向索引。
func (s *banSink) TryInsert(info bans.BanInfo) bool {
	if !s.cache.TryInsert(info) {
		return false
	}
	if s.db != nil {
		// 自动路径的等级取判定层的 info.BanCount（= 此前次数 + 1，渐进式时长就是按它算的），
		// 底账里记同一个数，「这一级封多久」才对得上「这是第几封」。它与
		// RecordBanHistory 返回的累计值是同一个数，这里不依赖后者是为了让写事件这一步
		// 不被历史表的写入顺序牵着走。
		if err := s.db.RecordBanEvent(info.IP, info.JailName, int(info.BanCount), info.IsPermanent, info.PlannedDuration()); err != nil {
			s.logger.Error("record ban event", "error", err)
		}
		if _, err := s.db.RecordBanHistory(info.IP, info.IsPermanent); err != nil {
			s.logger.Error("record ban history", "error", err)
		}
		if err := s.db.RecordBan(info.IP, persist.DefaultBanPenalty); err != nil {
			s.logger.Error("record ban reputation", "error", err)
		}
	}
	// 库里的封禁次数与信誉分都被本方法改过了，判定层的缓存必须跟着走，否则它继续报告
	// 封禁前的旧值（渐进式时长读的就是这个次数）。
	if s.noteBan != nil {
		if addr, err := netip.ParseAddr(info.IP); err == nil {
			s.noteBan(addr)
		}
	}
	return true
}

// MarkPendingAck 见 runtime.BanSink：给刚下发的封禁挂一个「等待内核确认」的短标记。
//
// 对账周期以内核为准重建镜像，而内核的确认（BanStateChange）可能晚于下一个对账周期；
// 没有这个标记，用户几十秒前点下的封禁会被对账当成幽灵抹掉。
func (s *banSink) MarkPendingAck(ip string) { s.cache.MarkPending(ip, time.Now()) }

// Send 见 runtime.BanSink。client 为 nil 时按「不动作」处理并记一条调试日志。
func (s *banSink) Send(addr netip.Addr, prefixLen uint8, durationSecs uint32, reason string) error {
	if s.client == nil {
		s.logger.Debug("内核客户端未装配，跳过封禁下发", "ip", addr.String())
		return nil
	}
	_, err := s.client.Ban(addr, prefixLen, durationSecs, reason)
	return err
}

// Remove 向内核下发解封。client 为 nil 时按「不动作」处理。
func (s *banSink) Remove(addr netip.Addr, prefixLen uint8) error {
	if s.client == nil {
		s.logger.Debug("内核客户端未装配，跳过解封下发", "ip", addr.String())
		return nil
	}
	_, err := s.client.Unban(addr, prefixLen)
	return err
}

// RollbackInsert 见 runtime.BanSink。
func (s *banSink) RollbackInsert(ip string) {
	s.cache.Remove(ip)
}

// whitelistSink 是 http.KernelWhitelist 的生产实现：白名单规则的内核下发出口。
//
// 与 banSink 的分别：封禁要联动活跃缓存、历史库与信誉缓存（那是自动路径与手工路径
// 共用一个汇聚点的原因），白名单只需要把规则交给内核——镜像由事件泵按内核回显维护，
// HTTP 写入侧那份只是面板读的那张表。
type whitelistSink struct {
	client *kernel.Client
	logger *slog.Logger
}

func newWhitelistSink(client *kernel.Client, logger *slog.Logger) *whitelistSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &whitelistSink{client: client, logger: logger}
}

// Add 见 http.KernelWhitelist。client 为 nil 时按「未装配、跳过下发」处理并回 nil——
// 契约给 POST /api/v1/whitelist 编的码里没有「依赖未就绪」，模块缺席不是一次失败。
func (s *whitelistSink) Add(addr netip.Addr, prefixLen uint8, device string) error {
	if s.client == nil {
		s.logger.Debug("内核客户端未装配，跳过白名单下发", "cidr", addr.String(), "prefix_len", prefixLen)
		return nil
	}
	_, err := s.client.AddWhitelist(addr, prefixLen, device)
	return err
}

// Remove 见 http.KernelWhitelist。
func (s *whitelistSink) Remove(addr netip.Addr, prefixLen uint8, device string) error {
	if s.client == nil {
		s.logger.Debug("内核客户端未装配，跳过白名单移除下发", "cidr", addr.String(), "prefix_len", prefixLen)
		return nil
	}
	_, err := s.client.RemoveWhitelist(addr, prefixLen, device)
	return err
}

// configSink 是配置的内核下发出口，同时满足 http.KernelConfig 与
// runtime.KernelConfigPusher（两边是同一个方法签名，一处实现即可）。
//
// 为什么要两边都用：HTTP 的 PUT /config 必须同步发一次，才能把内核的采纳结论写进响应；
// 执行体的重载/回滚/初始装配也要发，否则手工编辑文件、SIGHUP、SIGUSR1 改的那些值永远
// 上不了内核。两条路投的是同一张投影表（config.KernelConfigChange），载荷逐字段相同，
// 重复发送只是重写同样的全局阈值。
type configSink struct {
	client  *kernel.Client
	logger  *slog.Logger
	timeout time.Duration
}

func newConfigSink(client *kernel.Client, logger *slog.Logger) *configSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &configSink{client: client, logger: logger, timeout: kernel.DefaultRequestTimeout}
}

// ApplyConfig 见 http.KernelConfig 与 runtime.KernelConfigPusher。
//
// client 为 nil（模块未加载 / netlink 建不起来）时按「未装配、跳过下发」处理并回 nil：
// 与封禁、白名单同口径。装配了却发不出去才回错误，由调用方决定是 50003 还是记一条 warn。
func (s *configSink) ApplyConfig(change *contract.SetConfig) (contract.ConfigFlags, error) {
	if s.client == nil {
		s.logger.Debug("内核客户端未装配，跳过配置下发", "flags", uint32(change.Flags))
		return 0, nil
	}
	ack, err := s.client.SetConfig(change, s.timeout)
	if err != nil {
		return 0, err
	}
	return ack.RejectedFlags, nil
}

// configReloadsMetric 是配置热重载成功次数的指标名。
//
// 它是本进程 /metrics 的公开契约（集成测试 17 以它为热重载的权威读数），不随内部反射改名。
const configReloadsMetric = "firewall_daemon_config_reloads_total"

// statsSink 是 StatsSink 的生产实现。
//
// 计数汇聚到 Prometheus 指标（当 metrics 非 nil 时）和全局原子计数。
type statsSink struct {
	logger  *slog.Logger
	metrics *http.Metrics

	linesParsed   atomic.Uint64
	linesSkipped  atomic.Uint64
	regexMatches  atomic.Uint64
	inotifyEvents atomic.Uint64
	logRotations  atomic.Uint64
	bansTriggered atomic.Uint64
	configReloads atomic.Uint64
}

func newStatsSink(logger *slog.Logger, metrics *http.Metrics) *statsSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &statsSink{logger: logger, metrics: metrics}
}

// AddGlobal 见 runtime.StatsSink。
func (s *statsSink) AddGlobal(parsed, skipped, regexes, ips uint64) {
	s.linesParsed.Add(parsed)
	s.linesSkipped.Add(skipped)
	s.regexMatches.Add(regexes)
	if s.metrics != nil {
		s.metrics.Counter("firewall_lines_parsed_total").Add(int64(parsed))
		s.metrics.Counter("firewall_lines_skipped_total").Add(int64(skipped))
		s.metrics.Counter("firewall_regex_matches_total").Add(int64(regexes))
	}
}

// AddJail 见 runtime.StatsSink。
func (s *statsSink) AddJail(jail string, parsed, regexes, ips uint64) {
	s.linesParsed.Add(parsed)
	s.regexMatches.Add(regexes)
	if s.metrics != nil {
		s.metrics.Counter("firewall_lines_parsed_total").Add(int64(parsed))
		s.metrics.Counter("firewall_regex_matches_total").Add(int64(regexes))
	}
}

// IncInotifyEvents 见 runtime.StatsSink。
func (s *statsSink) IncInotifyEvents() {
	s.inotifyEvents.Add(1)
	if s.metrics != nil {
		s.metrics.Counter("firewall_inotify_events_total").Add(1)
	}
}

// IncLogRotations 见 runtime.StatsSink。
func (s *statsSink) IncLogRotations() {
	s.logRotations.Add(1)
	if s.metrics != nil {
		s.metrics.Counter("firewall_log_rotations_total").Add(1)
	}
}

// IncBansTriggered 见 runtime.StatsSink。
func (s *statsSink) IncBansTriggered(jail string) {
	s.bansTriggered.Add(1)
	if s.metrics != nil {
		s.metrics.Counter("firewall_bans_triggered_total").Add(1)
	}
}

// IncConfigReloads 见 runtime.StatsSink。
func (s *statsSink) IncConfigReloads() {
	s.configReloads.Add(1)
	if s.metrics != nil {
		s.metrics.Counter(configReloadsMetric).Add(1)
	}
}

// jailSnapshotBridge 把执行体的「jail 配置快照变了」接到 SSE 的 jails 域推送。
//
// 为什么要一层壳：runtime 不得依赖表现层（http 反过来要读内核快照，那是循环依赖），
// 它只提供一个 JailSnapshotListener 接口；而 api 可能没装配（未配 HTTP 监听地址），
// nil *http.APIHandlers 直接满足接口会让每次回调都在方法里解引用 nil 字段 panic，
// 所以缺席的判断放在这里。
type jailSnapshotBridge struct{ api *http.APIHandlers }

// OnJailSnapshotChanged 见 runtime.JailSnapshotListener。
func (b jailSnapshotBridge) OnJailSnapshotChanged() {
	if b.api != nil {
		b.api.PublishJails()
	}
}

// kernelMetrics 把 http.Metrics 适配成 kernel.Metrics。
//
// 为什么不直接把 *http.Metrics 交给内核层：内核层不得依赖表现层（internal/http 反过来
// 要读内核快照，那会是循环依赖）。另一处摩擦是 *atomic.Int64 的 Add 带返回值，不满足
// kernel.CounterHandle 的无返回值签名，故各套一层壳。
type kernelMetrics struct{ m *http.Metrics }

// Counter 见 kernel.Metrics。
func (k kernelMetrics) Counter(name string) kernel.CounterHandle {
	return kernelCounter{c: k.m.Counter(name)}
}

// kernelCounter 是单条计数器的无返回值视图。
type kernelCounter struct{ c *atomic.Int64 }

// Add 见 kernel.CounterHandle。
func (h kernelCounter) Add(delta int64) { h.c.Add(delta) }
