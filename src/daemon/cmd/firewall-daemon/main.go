// Command firewall-daemon 是守护进程的组合根：把配置、内核链路、入站主链路与
// 关停顺序接到一起。
//
// 组合根只负责「装配与生命周期」，不含业务判定：解析命令行、加载配置、按依赖顺序
// 启动各执行体，最后按登记逆序优雅关停。
package main

import (
	"context"
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
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/daemonize"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/geoip"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/http"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/jail"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/kernel"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logger"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/netports"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/runtime"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/threatfeeds"
	panelres "github.com/snowcore8/linux-firewall-kmod/daemon/web_ui/static"
)

// panelDir 是前端静态面板的 go:embed 目录（src/daemon/web_ui/static/assets.go 声明）。
// 它是启动期必须存在的资源：缺失时直接以启动错误返回，而不是反复报接口失败。
var panelDir = panelres.PanelDir

// factoryDefaultPassword 是 config/default.yaml 的出厂占位口令。它随仓库公开分发、
// 人尽可猜，本身不是机密；这里只用它做启动期比对，检测「面板仍在用出厂口令」。
const factoryDefaultPassword = "changeme"

// factoryDefaultUsername 是 config/default.yaml 的出厂用户名，与口令同源。
// 单独检出它不构成风险，但它是「这组凭据仍是出厂值」的另一半证据。
const factoryDefaultUsername = "admin"

// daemonPIDFile 是 `-d` 模式写下的 PID 文件路径（与 --rollback 的查找口径无关：
// 回滚按进程名找，不读这个文件）。
const daemonPIDFile = "/run/firewall-daemon.pid"

// ingestExecutorName 是入站主链路在 Supervisor 里的登记名。
//
// 关停回报按这个名字判断执行体是否真的退出：没退出时不能释放它的 fd。
const ingestExecutorName = "ingest"

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

	// 守护化必须在建立信号层之前完成：父进程重新执行出子进程后立刻退出，
	// 子进程带着 FIREWALL_DAEMONIZED 继续走完整条装配路径。子进程退出时删除
	// PID 文件；父进程不删——它手里没有子进程的生命周期。
	if parsed.Daemon && !daemonize.IsChild() {
		return daemonize.Spawn(daemonPIDFile)
	}
	if parsed.Daemon {
		defer func() { _ = daemonize.RemovePIDFile(daemonPIDFile) }()
	}

	// 信号层必须早于任何 goroutine 建立，否则启动窗口内送达的信号会丢失。
	signals, err := runtime.NewSignalSource()
	if err != nil {
		return fmt.Errorf("初始化信号层失败: %w", err)
	}
	defer signals.Close()

	// startedAt 是进程开始装配的时刻：GET /api/v2/stats 的 uptime_seconds 从这里起算，
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

	// 认证与暴露面一起说：契约把「两项凭据都空」定义为不认证并放行，而监听地址出自同一个
	// defaults 段。绑定到局域网却没有凭据时显眼告警——这一步只报来源与形状，永不报值。
	userSrc, passSrc := cfg.CredentialSources()
	logger.Info("面板认证凭据", "username", userSrc, "password", passSrc, "authenticated", cfg.AuthEnabled())
	if addr := cfg.ListenAddress(); addr != "" && !cfg.AuthEnabled() && bindsBeyondLoopback(cfg.MetricsBindAddress) {
		logger.Warn("监听地址对外开放但未配置认证凭据：任何可达者都能读写面板并下发封禁",
			"addr", addr,
			"怎么修", "设置 FIREWALL_METRICS_USERNAME / FIREWALL_METRICS_PASSWORD（随包 EnvironmentFile 已备好），或把 defaults 段两项一起填，或把 metrics_bind_address 收回 127.0.0.1")
	}
	// 出厂凭据是公开值：两项都非空（AuthEnabled 为真）也算「已认证」，但它们人尽可猜，
	// 等同于无防护。命中就显眼告警——只报事实、绝不回显凭据值本身。
	warnIfFactoryDefaultCredentials(logger, &cfg)

	// GeoIP 读库是可选的：未配置或打不开时地理分布接口照常应答，只是不定位攻击源。
	// 出口探测是显式开关（默认关）：它会把本机公网 IP 发给探测端点，只在该开关打开
	// 且配置没给坐标时执行；失败只告警，不阻塞启动。
	var geoReader *geoip.Reader
	if cfg.GeoipDBPath != "" {
		reader, gerr := geoip.Open(cfg.GeoipDBPath)
		if gerr != nil {
			logger.Warn("GeoIP 数据库加载失败，攻击源地理分布不可用", "path", cfg.GeoipDBPath, "error", gerr)
		} else {
			geoReader = reader
			defer reader.Close()
			logger.Info("GeoIP 数据库已加载", "path", cfg.GeoipDBPath)
		}
	}
	cfg.ServerCoordsSource = "none"
	if cfg.ServerCoordsSet {
		cfg.ServerCoordsSource = "config"
	} else if cfg.GeoipDetectEgress && cfg.GeoipEgressProbeURL != "" {
		logger.Info("已向探测端点请求本机出口 IP", "url", cfg.GeoipEgressProbeURL)
		probeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		egress, perr := geoip.DetectEgress(probeCtx, cfg.GeoipEgressProbeURL)
		cancel()
		switch {
		case perr != nil:
			logger.Warn("本机出口 IP 探测失败，地图不显示本机坐标", "error", perr)
		case geoReader == nil:
			logger.Warn("已探测到本机出口 IP，但未加载 GeoIP 数据库，无法换算坐标", "ip", egress.String())
		default:
			if loc, ok := geoReader.Lookup(egress); ok {
				cfg.ServerLatitude = loc.Latitude
				cfg.ServerLongitude = loc.Longitude
				cfg.ServerCoordsSource = "detected"
				logger.Info("本机坐标来自出口探测", "ip", egress.String())
			} else {
				logger.Warn("本机出口 IP 不在 GeoIP 数据库中，无法换算坐标", "ip", egress.String())
			}
		}
	}

	if err := checkProcfs(); err != nil {
		return err
	}

	sup := runtime.NewSupervisor()

	// 终止通道与致命错误：信号（SIGTERM/SIGINT）与内核链路断开走同一个停止路径。
	// 链路断开是终态——内核模块卸载/重载后旧 socket 已死，继续运行只会让每次下发石沉
	// 大海。这里记录致命错误并按正常关停顺序收尾，让 run 以非零码返回，由 systemd 的
	// Restart=on-failure 拉起并重新注册。
	terminate := runtime.NewShutdown()
	stopCh := make(chan struct{})
	var (
		stopOnce sync.Once
		fatalMu  sync.Mutex
		fatalErr error
	)
	requestStop := func(err error) {
		if err != nil {
			fatalMu.Lock()
			if fatalErr == nil {
				fatalErr = err
			}
			fatalMu.Unlock()
		}
		stopOnce.Do(func() {
			close(stopCh)
			terminate.Request()
		})
	}

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
	// vectorDecayDone 在风险引擎启用时非 nil：向量表只有该开关打开才有写入。
	var vectorDecayDone <-chan struct{}
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
			cleanupDone := db.StartCleanupScheduler(0, cfg.HistoryRetentionDays, dbStopCh)
			recoveryDone := db.StartReputationRecoveryScheduler(0, 1, 100, dbStopCh)
			// 判定层每行日志都要扣一次信誉分并立刻取分，直接查库会把入站主链路钉在磁盘上；
			// 这里按 IP 折叠，与库自带的两个调度器共用同一条 stop 通道（关停时最后刷一次盘）。
			facts = persist.NewFacts(db, persist.FactsOptions{
				Logger:            logger,
				RiskEngineEnabled: cfg.RiskEngine.Enabled,
				RiskWeights:       cfg.RiskEngine.Weights,
				RiskHalfLifeDays:  cfg.RiskEngine.HalfLifeDays,
			})
			factsDone := facts.StartFlusher(dbStopCh)
			// 风险向量衰减也是周期任务：7 天半衰期只在库里有调用者时才生效。未启用风险
			// 引擎时向量表没有写入，不跑这条无谓的库操作（feature flag 语义）。
			if cfg.RiskEngine.Enabled {
				vectorDecayDone = db.StartRiskVectorDecayScheduler(0, dbStopCh)
			}
			// 关停顺序：先停各调度器，再等所有后台任务结束，最后才关库。
			// 这段 defer 在 db.Close 之后登记，LIFO 执行时排在它前面。
			defer func() {
				close(dbStopCh)
				<-cleanupDone
				<-recoveryDone
				<-factsDone
				if vectorDecayDone != nil {
					<-vectorDecayDone
				}
				// 风险事件 worker 也写同一个库：必须先排空它再走到 db.Close。
				facts.Stop()
			}()
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
			reactor := kernel.NewReactor(transport, router, reactorToken, logger,
				kernel.WithLinkDownHandler(func(linkErr error) {
					logger.Error("内核 netlink 链路断开，请求终止进程", "error", linkErr)
					requestStop(fmt.Errorf("内核 netlink 链路断开: %w", linkErr))
				}))
			sup.Spawn("kernel-reactor", reactorToken, reactor.Run)
			kernelClient = kernel.NewClient(transport, router)
			logger.Info("内核 netlink 链路已就绪")
		}
	}

	// 受保护端口位图：protect_open_ports 打开时把本机非回环监听端口发给内核，
	// 关闭时下发全零位图（语义见 config.DdosConfig.ProtectOpenPorts）。
	//
	// 周期重扫覆盖「监听端口随服务增减」，但只有位图真的变了才发：内核每收一次都会
	// 打一行 pr_info，无条件重发会让 dmesg 每 30 秒长一行。内核模块重载会丢掉位图，
	// 那条路径由租约确认后的强制下发兜住（见 OnLeaseClaimed）。
	var pushProtectedPorts func(force bool)
	if kernelClient != nil {
		var (
			portsMu   sync.Mutex
			lastPorts [contract.ProtectedPortsLen]byte
			hasPorts  bool
		)
		pushProtectedPorts = func(force bool) {
			var bitmap [contract.ProtectedPortsLen]byte
			count := 0
			// 这个闭包由 protected-ports 执行体与内核事件泵（租约确认）并发调用，而热重载
			// 会整份替换 cfg：开关只在读锁内取一次。
			config.RLockConfig()
			protectOpenPorts := cfg.Ddos.ProtectOpenPorts
			config.RUnlockConfig()
			if protectOpenPorts {
				bmp, n, err := netports.ListeningPorts("/proc/net")
				if err != nil {
					logger.Warn("扫描本机监听端口失败，保留内核现有位图", "error", err)
					return
				}
				bitmap, count = bmp, n
			}

			// 扫描在锁外，比较与下发在锁内：租约确认与周期重扫可能并发调用，
			// 谁先到谁发，后到的看到相同位图直接返回。
			portsMu.Lock()
			defer portsMu.Unlock()
			if !force && hasPorts && bitmap == lastPorts {
				return
			}
			if _, err := kernelClient.SetProtectedPorts(bitmap); err != nil {
				logger.Warn("下发受保护端口位图失败", "ports", count, "error", err)
				return
			}
			lastPorts, hasPorts = bitmap, true
			logger.Info("受保护端口位图已下发内核", "ports", count)
		}
		portsToken := runtime.NewShutdown()
		sup.Spawn("protected-ports", portsToken, func() {
			pushProtectedPorts(true)
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-portsToken.Done():
					return
				case <-ticker.C:
					pushProtectedPorts(false)
				}
			}
		})
	}

	// 重试队列：DB 写入失败时暂存操作，后台协程按指数退避重试。
	// 持久化文件与 DB 同目录（<db_path>.retry.json），保证重启后能恢复未写入的事件。
	var retryQueue *persist.RetryQueue
	if historyDB != nil && cfg.HistoryDBPath != "" {
		retryQueue = persist.NewRetryQueue(historyDB, persist.RetryQueueConfig{
			MaxSize:          1000,
			PersistPath:      cfg.HistoryDBPath + ".retry.json",
			Logger:           logger,
			RetryInterval:    2 * time.Second,
			MaxRetryInterval: 2 * time.Minute,
		})
		retryQueue.LoadPersisted()
		defer retryQueue.Stop()
	}

	// 封禁下发汇聚点：入站主链路与 HTTP API 共用同一个实例。
	//
	// 此前两处各建一个 banSink，写的是同一份进程级缓存所以结果没分叉，但「谁通知信誉缓存」
	// 这类回调只能挂在其中一个上，共用实例就把这个坑填平：封禁落库后由它同步 Facts 里的
	// 封禁次数与扣分，否则渐进式时长读到的是封禁前的旧次数。
	banSinkForDaemon := newBanSink(kernelClient, logger, historyDB, retryQueue)
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
	// （/api/v2/stats 与 rates/*、协议分布那组端点）——它们都只读这一份快照。
	kernelStore := telemetry.NewStore()

	// Jail 启用状态源：HTTP API 与入站主链路共享。
	jailEnabled := runtime.NewJailEnabledSource()

	// 威胁情报源管理器：面板展示与判定层共用同一份内存缓存。
	// 未启用或装配失败时为 nil：threat-feeds 三个 handler 按可空依赖口径应答
	// 「服务不可用」，判定层退回纯本地窗口判定——都不阻断启动。
	var feedMgr *threatfeeds.FeedManager
	if cfg.ThreatFeeds.Enabled {
		feedCfg := threatfeeds.Config{
			Enabled:          true,
			RefreshInterval:  time.Duration(cfg.ThreatFeeds.RefreshInterval) * time.Second,
			HTTPTimeout:      time.Duration(cfg.ThreatFeeds.HTTPTimeout) * time.Second,
			MaxRetries:       cfg.ThreatFeeds.MaxRetries,
			FailureThreshold: cfg.ThreatFeeds.FailureThreshold,
			CooldownDuration: time.Duration(cfg.ThreatFeeds.CooldownDuration) * time.Second,
		}
		for _, s := range cfg.ThreatFeeds.Sources {
			feedCfg.Sources = append(feedCfg.Sources, threatfeeds.SourceConfig{
				Name:       s.Name,
				URL:        s.URL,
				Enabled:    s.Enabled,
				Category:   s.Category,
				Confidence: s.Confidence,
			})
		}
		mgr, ferr := threatfeeds.NewFeedManager(feedCfg)
		if ferr != nil {
			logger.Warn("装配威胁情报源管理器失败，threat-feeds 接口将应答服务不可用", "error", ferr)
		} else {
			feedMgr = mgr
			defer feedMgr.Stop()
			feedMgr.StartScheduler()
		}
	}

	// HTTP 服务器：API、SSE、Prometheus 指标。
	var httpServer *http.Server
	var sseBroker *http.SSEBroker
	// 配置来源：单文件优先，其次目录。重载器与 PUT /config 必须认同一个来源——目录模式
	// 会显式清空 cfg.ConfigFile（否则重载只吃其中一个文件），拿它当路径就 stat 到空串，
	// 每次 SIGHUP 都停在「没有那个文件或目录」，改文件的人以为重载生效了。
	configSource := cfg.ConfigFile
	if configSource == "" {
		configSource = cfg.ConfigDir
	}
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
				GetConfigPath:    func() string { return configSource },
				JailController:   jailEnabled,
				LogFilePath: func() string {
					// 重载不会重建 slog sink，实际写入目标只在启动时确定；只报日志系统
					// 登记的那个路径，让接口与文件一致。未登记说明目的地不含文件
					// （syslog/journal），此时回空串让接口如实报「未配置」，而不是让
					// 面板去读一个没人写入的 cfg.LogFile。
					if path, ok := registeredLogFilePath(); ok {
						return path
					}
					return ""
				},
				// GET /health 的读数来源：链路状态只有事件泵这份快照知道，procfs 在场与否
				// 由本进程自己 stat。
				GetKernelSnapshot: kernelStore.Snapshot,
				KmodPresent:       kernelProcPresent,
				// 统计面的三个读数来源：运行时长起点、速率历史环、内核模块自报版本。
				// 速率历史与快照同源（事件泵的同一批采样），异常检测的分位基线用的也是它。
				StartedAt:      startedAt,
				GetRateSamples: kernelStore.RateSamples,
				KernelVersion:  kernelModuleVersion,
				ThreatFeeds:    feedMgr,
				GeoIP:          geoReader,
			})
			// 路由全部由 RegisterRoutes 按契约 pattern 注册，包括 /api/v2/events 与
			// /metrics：它们都在契约的认证组里，在这里另注册一遍会绕过 RequireAuth。
			httpServer.RegisterRoutes(api)
			httpServer.RegisterStaticFiles(panelres.StaticFS())

			httpToken := runtime.NewShutdown()
			sup.Spawn("http-server", httpToken, func() {
				// Start 只负责伺服；关停由本执行体在自己的令牌上等待，然后调 Stop。
				// 此前这个令牌没人看，http.Server.Stop 没有调用点，监督器只能等满
				// 每段 5 秒的超时并记「执行体关停未在超时内完成」，端口在这 5 秒里
				// 一直被占着，紧接着重启就撞 bind: address already in use。
				serveDone := make(chan struct{})
				go func() {
					defer close(serveDone)
					if err := httpServer.Start(); err != nil {
						logger.Error("HTTP 服务器异常退出", "error", err)
					}
				}()
				select {
				case <-serveDone:
					// Start 自己返回了（监听侧故障），无需再关停一遍。
				case <-httpToken.Done():
					// 先断两条 SSE 流再关服务器：Shutdown 要等所有活跃连接变空闲，
					// 而 SSE 连接永远不会空闲——顺序反了就只能等超时。
					sseBroker.Stop()
					logStream.Stop()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := httpServer.Stop(ctx); err != nil {
						logger.Warn("HTTP 服务器关停未完全收敛", "error", err)
					}
					<-serveDone
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
		// trusted_ips 只在启动时下发一次：先复制一份，避免回调在配置热重载替换 *cfg 后
		// 与执行体并发读同一字段。语义与配置文件注释一致：改这一段要重启。
		trustedIPs := append([]string(nil), cfg.TrustedIPs...)
		pushConfiguredTrustedIPs := func() {
			if len(trustedIPs) == 0 {
				return
			}
			pushed, skipped := pushTrustedIPs(whitelistSinkForDaemon, trustedIPs, logger)
			logger.Info("trusted_ips 已下发内核白名单",
				"configured", len(trustedIPs), "pushed", pushed, "skipped", skipped)
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
			// 注册成功之前内核丢弃一切指令；trusted_ips 与端口位图必须在确认租约之后才发。
			OnLeaseClaimed: func() {
				pushConfiguredTrustedIPs()
				if pushProtectedPorts != nil {
					// 强制发一次：内核模块刚重载时位图是空的，即使本进程记得旧值。
					pushProtectedPorts(true)
				}
			},
		})
		if err != nil {
			logger.Error("内核事件泵装配失败，内核事件将无人消费", "error", err)
		} else if err := pump.ClaimLease(); err != nil {
			// 单实例约束在这里落地：内核明确说「已有活跃的守护进程」时，本进程每一条
			// 下发都会被丢弃——继续跑只会多一块显示自己那一小撮的面板。以非零码退出，
			// 让 systemd/运维看得见「第二个实例被拒」，而不是让它静默并跑。
			// 链路问题（超时、模块刚重载）不走这条路，交给泵按周期重试。
			return err
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
	// 情报缓存只在启用时接入；关闭或装配失败时判定层不查情报。
	var intel runtime.ThreatIntel
	if feedMgr != nil {
		intel = feedIntel{mgr: feedMgr}
	}
	deps := runtime.Deps{
		Logger:      logger,
		Facts:       decisionFacts,
		ThreatIntel: intel,
		Sink:        banSinkForDaemon,
		Stats:       newStatsSink(logger, metrics),
		Hooks:       runtime.NewMaintenanceHooks(historyDB, logger),
		Reloader:    runtime.NewFileReloader(configSource, parsed.Strict, logger),
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
		return fmt.Errorf("装配入站主链路失败: %w", err)
	}

	ingestToken := runtime.NewShutdown()
	// 最后登记 = 最先关停：入站主链路先于内核接收回路收尾，避免收尾期间事件堆积。
	sup.Spawn(ingestExecutorName, ingestToken, func() {
		executor.Run(ingestToken, terminate)
	})

	// 主 goroutine 等待终止。Shutdown 只有 Request/IsShutdown 而无完成通道，故这里
	// 自备一个通道：与信号层并行地去「看见」同一个 SIGTERM/SIGINT。
	go func() {
		term := make(chan os.Signal, 1)
		signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(term)
		select {
		case <-term:
		case <-stopCh:
			return
		}
		requestStop(nil)
	}()

	<-stopCh
	logger.Info("收到终止，开始优雅关停")

	// 关停顺序固定：先按登记逆序停掉各执行体（入站主链路 → 内核接收回路），再让
	// 延迟清理释放执行体依赖的资源（延迟清理按 LIFO 执行）。
	ingestJoined := false
	for _, res := range sup.Shutdown(5 * time.Second) {
		if res.Outcome != runtime.Joined {
			logger.Warn("执行体关停未在超时内完成", "name", res.Name, "outcome", res.Outcome)
			continue
		}
		if res.Name == ingestExecutorName {
			ingestJoined = true
		}
	}

	// 只有确认退出后才释放执行体的 fd：超时的那条 goroutine 可能仍阻塞在 poll/读取上，
	// 而 watcher 与信号 fd 的访问没有同步，提前 Close 会与它并发（数据竞争 + 关闭后
	// 复用的 fd）。进程随后退出，未释放的 fd 由内核回收。
	if ingestJoined {
		executor.Close()
	} else {
		logger.Warn("入站主链路未在超时内退出，跳过其 fd 释放")
	}

	// 链路断开是致命错误：清理完成后原样返回，main 以非零码退出，交给 systemd 重启。
	fatalMu.Lock()
	fatal := fatalErr
	fatalMu.Unlock()
	return fatal
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

// registeredLogFilePath 返回日志系统实际写入的文件路径（含未配置 log_file 时的默认
// 路径）。run 内的局部 logger 是 *slog.Logger、遮蔽了包名，故把包级调用收在这里。
func registeredLogFilePath() (string, bool) {
	return logger.LogFilePath()
}

// warnIfFactoryDefaultCredentials 在面板仍用出厂凭据时告警，绝不拒绝启动。
//
// 判据是「认证已启用（两项都非空）且任一维度等于出厂值」：口令是公开值，猜到就能登录；
// 用户名仍是默认值本身不构成风险，但它说明这组凭据原封未动——只换了用户名、口令没换的
// 半改配置反而更危险，因为改的人以为已经改过了。所以任一维度命中都告警。
// 调用点在凭据定型之后（环境变量覆盖已在配置解析末尾完成）、HTTP 服务器开始监听之前，
// 让告警先于任何登录尝试落到日志里；真实凭据覆盖后两个维度都不等于出厂值，不会误报。
//
// 只写布尔事实，不写口令、也不写用户名以外的凭据内容——日志会被收集、转发并长期留存，
// 把凭据值写进去等于把钥匙抄在日志里。
func warnIfFactoryDefaultCredentials(logger *slog.Logger, cfg *config.Config) {
	if !cfg.AuthEnabled() {
		// 两项没凑齐时认证本身是关的，入口另有一条「未配置认证」告警负责说明；
		// 这里再报默认值只会重复。
		return
	}
	usernameDefault := cfg.MetricsUsername == factoryDefaultUsername
	passwordDefault := cfg.MetricsPassword == factoryDefaultPassword
	if !usernameDefault && !passwordDefault {
		return
	}
	logger.Warn("面板仍在使用出厂默认凭据，等同于无防护：任何能访问监听端口的人都能登录并下发封禁",
		"username_is_default", usernameDefault,
		"password_is_default", passwordDefault,
		"怎么修", "设置 FIREWALL_METRICS_USERNAME / FIREWALL_METRICS_PASSWORD（随包 EnvironmentFile 已备好），或把 defaults 段两项改成强随机值，改后重启守护进程")
}

// feedIntel 把威胁情报管理器接到判定层，只暴露查询，不泄露管理器其余能力。
type feedIntel struct{ mgr *threatfeeds.FeedManager }

// ThreatLookup 见 runtime.ThreatIntel。
func (f feedIntel) ThreatLookup(ip netip.Addr) (string, float64, bool) {
	entry, ok := f.mgr.Lookup(ip)
	if !ok || entry == nil {
		return "", 0, false
	}
	return entry.Source, entry.Confidence, true
}

// banSink 是 BanSink 的生产实现：把封禁下发接到内核客户端与活跃封禁缓存。
type banSink struct {
	client *kernel.Client
	cache  *bans.ActiveBanCache
	logger *slog.Logger
	db     *persist.DB
	// retryQueue 在 DB 写入失败时暂存操作，由后台协程重试（可空）。
	retryQueue *persist.RetryQueue
	// noteBan 在封禁落库后将「刚刚封了一次」同步进信誉缓存（可空）。
	noteBan func(netip.Addr)
}

func newBanSink(client *kernel.Client, logger *slog.Logger, db *persist.DB, rq *persist.RetryQueue) *banSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &banSink{client: client, cache: bans.GlobalCache(), logger: logger, db: db, retryQueue: rq}
}

// InsertPending 见 runtime.BanSink：原子地占位并挂上「等待内核确认」标记。
//
// 标记必须与占位同一锁周期：分开调用会在两步之间留出对账窗口，把刚投递、内核列表里
// 尚未出现的封禁当幽灵摘掉。
func (s *banSink) InsertPending(info bans.BanInfo) bool {
	// 自动判定路径只封单机，构造点不带前缀；占位前回填，使镜像里的条目从一开始就有
	// 可解封的前缀，而不是依赖解封时再猜。
	if info.PrefixLen == 0 {
		if addr, err := netip.ParseAddr(info.IP); err == nil {
			info.PrefixLen = bans.FullPrefixLen(addr)
		}
	}
	if !s.cache.InsertPending(info, time.Now()) {
		return false
	}
	s.recordBanLedger(info)
	// 库里的封禁次数与信誉分都被本条底账改过了，判定层的缓存必须跟着走，否则它继续报告
	// 封禁前的旧值（渐进式时长读的就是这个次数）。
	if s.noteBan != nil {
		if addr, err := netip.ParseAddr(info.IP); err == nil {
			s.noteBan(addr)
		}
	}
	return true
}

// recordBanLedger 写一次封禁底账：事件 → 历史 → 信誉。DB 未装配时什么也不做。
//
// 自动单 IP 封禁与集群网段封禁共用这一处：两条路都算「封禁已发生」，底账口径必须一致，
// 否则复发统计与分级成效在网段封禁上会凭空缺一段。写入失败交给重试队列暂存。
func (s *banSink) recordBanLedger(info bans.BanInfo) {
	if s.db == nil {
		return
	}
	// 自动路径的等级取判定层的 info.BanCount（= 此前次数 + 1，渐进式时长就是按它算的），
	// 底账里记同一个数，「这一级封多久」才对得上「这是第几封」。它与
	// RecordBanHistory 返回的累计值是同一个数，这里不依赖后者是为了让写事件这一步
	// 不被历史表的写入顺序牵着走。
	if err := s.db.RecordBanEvent(info.IP, info.JailName, int(info.BanCount), info.IsPermanent, info.PlannedDuration()); err != nil {
		s.logger.Error("record ban event", "error", err)
		if s.retryQueue != nil {
			s.retryQueue.EnqueueBanEvent(info.IP, info.JailName, int(info.BanCount), info.IsPermanent, info.PlannedDuration())
		}
	}
	if _, err := s.db.RecordBanHistory(info.IP, info.IsPermanent); err != nil {
		s.logger.Error("record ban history", "error", err)
		if s.retryQueue != nil {
			s.retryQueue.EnqueueBanHistory(info.IP, info.IsPermanent)
		}
	}
	if err := s.db.RecordBan(info.IP, persist.DefaultBanPenalty); err != nil {
		s.logger.Error("record ban reputation", "error", err)
		if s.retryQueue != nil {
			s.retryQueue.EnqueueBanReputation(info.IP, persist.DefaultBanPenalty)
		}
	}
}

// RecordClusterBan 见 runtime.ClusterBanRecorder：一次已成功下发的网段封禁的底账。
//
// 只写底账、不占活跃缓存，也不动 facts：InsertPending 那条路按单 IP 键占位并挂待确认
// 标记，而 /24 不是一个 netip.Addr，内核回显的条目也不是「一个地址」，占位会与事件泵
// 的对账互相误伤；信誉缓存同样按地址键，网段没有可对应的单地址。
func (s *banSink) RecordClusterBan(info bans.BanInfo) {
	s.recordBanLedger(info)
}

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
// 契约给 POST /api/v2/whitelist 编的码里没有「依赖未就绪」，模块缺席不是一次失败。
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

// pushTrustedIPs 把 `trusted_ips` 里声明的地址下发进内核白名单，返回下发成功与被跳过
// 的条数。
//
// 为什么值得单独走一次下发：放行必须在丢包之前决定才算数，而判定链路口子在内核那边；
// 用户态镜像那份只是面板读的表。配置文件的注释承诺「启动时自动加入内核白名单」，这个函数
// 就是那句承诺的消费者。
//
// 形状照 http.AddWhitelist：先占镜像、再下发、下发失败撤回镜像。区别是**一条失败不影响
// 其余**，也不中止启动——一个写错的地址不该让防火墙整个起不来，但必须显眼告警，因为漏
// 放行的代价是运维自己被自己的规则封掉。
func pushTrustedIPs(sink http.KernelWhitelist, list []string, logger *slog.Logger) (pushed, skipped int) {
	if logger == nil {
		logger = slog.Default()
	}
	for _, text := range list {
		prefix, err := bans.WhitelistPrefixFromText(text)
		if err != nil {
			logger.Warn("trusted_ips 有一条无法解析，已跳过：该地址不会进内核白名单", "entry", text, "error", err)
			skipped++
			continue
		}
		prefix = prefix.Masked()
		added := bans.GlobalWhitelist().Add(prefix)
		if sink == nil {
			// 内核客户端缺席（模块没加载 / netlink 链路没建起来）：镜像里仍留着这条规则，
			// 与 HTTP 写入侧同一口径——契约没给白名单编「依赖未就绪」这个码。
			logger.Debug("内核白名单出口未装配，可信地址只留在镜像里", "cidr", prefix.String())
			pushed++
			continue
		}
		if err := sink.Add(prefix.Addr(), uint8(prefix.Bits()), ""); err != nil {
			logger.Warn("可信地址下发内核白名单失败", "cidr", prefix.String(), "error", err)
			if added {
				bans.GlobalWhitelist().Remove(prefix)
			}
			skipped++
			continue
		}
		pushed++
	}
	return pushed, skipped
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
