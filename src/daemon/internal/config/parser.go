package config

import (
	"bytes"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// yamlConfig 是顶层 YAML 结构：defaults + jails + 各功能段。
//
// 严格模式：未知顶层字段直接报错（deny_unknown_fields 语义）。
type yamlConfig struct {
	Defaults            *yamlDefaults       `yaml:"defaults"`
	Jails               map[string]yamlJail `yaml:"jails"`
	Ddos                *yamlDdos           `yaml:"ddos"`
	Webui               *yamlWebui          `yaml:"webui"`
	TrustedIPs          []string            `yaml:"trusted_ips"`
	Capacity            *yamlCapacity       `yaml:"capacity"`
	ThreatFeeds         *yamlThreatFeeds    `yaml:"threat_feeds"`
	RiskEngine          *yamlRiskEngine     `yaml:"risk_engine"`
	GeoipDBPath         *string             `yaml:"geoip_db_path"`
	ServerLatitude      yaml.Node           `yaml:"server_latitude"`
	ServerLongitude     yaml.Node           `yaml:"server_longitude"`
	GeoipDetectEgress   *bool               `yaml:"geoip_detect_egress"`
	GeoipEgressProbeURL *string             `yaml:"geoip_egress_probe_url"`
}

// yamlDefaults 是全局默认字段集合；缺省表示「使用 Config 默认值」。
type yamlDefaults struct {
	MaxRetries      *uint32 `yaml:"max_retries"`
	FindTime        *uint32 `yaml:"findtime"`
	BanTime         *int32  `yaml:"ban_time"`
	Interval        *uint32 `yaml:"interval"`
	MetricsPort     *uint16 `yaml:"metrics_port"`
	MetricsBindAddr *string `yaml:"metrics_bind_address"`
	MetricsUsername *string `yaml:"metrics_username"`
	MetricsPassword *string `yaml:"metrics_password"`
	LogFile         *string `yaml:"log_file"`
	LogLevel        *uint8  `yaml:"log_level"`
	LogDestination  *string `yaml:"log_destination"`
	LogFormat       *string `yaml:"log_format"`
	LogMaxSizeMB    *uint32 `yaml:"log_max_size_mb"`
	LogMaxFiles     *uint32 `yaml:"log_max_files"`
	// 历史库：路径为空 = 不启用（面板的分析页全部回 503「依赖未就绪」）。
	HistoryDBPath        *string `yaml:"history_db_path"`
	HistoryRetentionDays *uint32 `yaml:"history_retention_days"`
}

// yamlJail 是单个 jail 的 YAML 表示：支持 `regex` 单条 + `regexes` 嵌套映射两种写法。
type yamlJail struct {
	Enabled    *bool                     `yaml:"enabled"`
	LogFiles   *[]string                 `yaml:"log_files"`
	MaxRetries *uint32                   `yaml:"max_retries"`
	FindTime   *uint32                   `yaml:"findtime"`
	BanTime    *int32                    `yaml:"ban_time"`
	Regex      *string                   `yaml:"regex"`
	RegexName  *string                   `yaml:"regex_name"`
	Regexes    map[string]yamlRegexEntry `yaml:"regexes"`
	Cluster    *yamlCluster              `yaml:"cluster"`
}

// yamlCluster 是 jail 的集群扫描检测段；只覆盖显式给出的字段。
type yamlCluster struct {
	Enabled   *bool   `yaml:"enabled"`
	AuditOnly *bool   `yaml:"audit_only"`
	PrefixV4  *uint8  `yaml:"prefix_v4"`
	PrefixV6  *uint8  `yaml:"prefix_v6"`
	Window    *uint32 `yaml:"window"`
	MinIPs    *uint32 `yaml:"min_ips"`
	MaxPerIP  *uint32 `yaml:"max_per_ip"`
	BanTime   *uint32 `yaml:"ban_time"`
}

// yamlRegexEntry 是嵌套 regexes 映射的 value。
type yamlRegexEntry struct {
	Pattern string `yaml:"pattern"`
}

// yamlDdos 是 DDoS 防护配置的 YAML 表示。
type yamlDdos struct {
	Enabled               *bool   `yaml:"enabled"`
	GlobalConnRate        *uint32 `yaml:"global_conn_rate"`
	AutoBanDuration       *uint32 `yaml:"auto_ban_duration"`
	AutoBanThreshold      *uint32 `yaml:"auto_ban_threshold"`
	CheckInterval         *uint32 `yaml:"check_interval"`
	BaselineWarmupSample  *uint32 `yaml:"baseline_warmup_samples"`
	MaxSynPerSecond       *uint32 `yaml:"max_syn_per_second"`
	MaxUDPPerSecond       *uint32 `yaml:"max_udp_per_second"`
	MaxICMPPerSecond      *uint32 `yaml:"max_icmp_per_second"`
	MaxACKPerSecond       *uint32 `yaml:"max_ack_per_second"`
	MaxRSTPerSecond       *uint32 `yaml:"max_rst_per_second"`
	MaxFINPerSecond       *uint32 `yaml:"max_fin_per_second"`
	StaticThreshold       *bool   `yaml:"static_threshold"`
	DynamicThreshold      *bool   `yaml:"dynamic_threshold"`
	DdosDetection         *bool   `yaml:"ddos_detection"`
	DynamicThresholdRatio *uint32 `yaml:"dynamic_threshold_ratio_x100"`
	MaxBansPerSecond      *uint32 `yaml:"max_bans_per_second"`
	MaxRateEntries        *uint32 `yaml:"max_rate_entries"`
	ProtectOpenPorts      *bool   `yaml:"protect_open_ports"`
}

// yamlWebui 是 Web UI 配置的 YAML 表示。
type yamlWebui struct {
	SSEPushInterval     *uint32 `yaml:"sse_push_interval"`
	RateWarningPPS      *uint64 `yaml:"rate_warning_pps"`
	RateCriticalPPS     *uint64 `yaml:"rate_critical_pps"`
	RateWarningSYN      *uint64 `yaml:"rate_warning_syn"`
	RateCriticalSYN     *uint64 `yaml:"rate_critical_syn"`
	MaxSynPerSecond     *uint32 `yaml:"max_syn_per_second"`
	MaxUDPPerSecond     *uint32 `yaml:"max_udp_per_second"`
	MaxICMPPerSecond    *uint32 `yaml:"max_icmp_per_second"`
	MaxACKPerSecond     *uint32 `yaml:"max_ack_per_second"`
	MaxRSTPerSecond     *uint32 `yaml:"max_rst_per_second"`
	MaxFINPerSecond     *uint32 `yaml:"max_fin_per_second"`
	StaticThreshold     *bool   `yaml:"static_threshold"`
	DynamicThreshold    *bool   `yaml:"dynamic_threshold"`
	DdosDetection       *bool   `yaml:"ddos_detection"`
	MaxBanEntries       *uint32 `yaml:"max_ban_entries"`
	MaxWhitelistEntries *uint32 `yaml:"max_whitelist_entries"`
	MaxRateEntries      *uint32 `yaml:"max_rate_entries"`
	MaxLocalIPCache     *uint32 `yaml:"max_local_ip_cache"`
	// clear_logs_at 是日志页的过滤起点（ISO 时间戳字符串，空串 = 不过滤）。它随 webui 段
	// 落盘，因此热重载与重启都会保留——前端 Logs/Settings 页的「持久化」文案即以此为准。
	ClearLogsAt *string `yaml:"clear_logs_at"`
}

// yamlCapacity 是容量配置的 YAML 表示。
type yamlCapacity struct {
	MaxBanEntries       *uint32 `yaml:"max_ban_entries"`
	MaxWhitelistEntries *uint32 `yaml:"max_whitelist_entries"`
	MaxRateEntries      *uint32 `yaml:"max_rate_entries"`
	MaxLocalIPCache     *uint32 `yaml:"max_local_ip_cache"`
}

// yamlThreatFeeds 是威胁情报源配置的 YAML 表示。
type yamlThreatFeeds struct {
	Enabled          *bool                  `yaml:"enabled"`
	RefreshInterval  *uint32                `yaml:"refresh_interval"`
	HTTPTimeout      *uint32                `yaml:"http_timeout"`
	MaxRetries       *int                   `yaml:"max_retries"`
	FailureThreshold *int                   `yaml:"failure_threshold"`
	CooldownDuration *uint32                `yaml:"cooldown_duration"`
	Sources          []yamlThreatFeedSource `yaml:"sources"`
}

// yamlThreatFeedSource 是单个情报源的 YAML 表示。
type yamlThreatFeedSource struct {
	Name       string   `yaml:"name"`
	URL        string   `yaml:"url"`
	Enabled    *bool    `yaml:"enabled"`
	Category   string   `yaml:"category"`
	Confidence *float64 `yaml:"confidence"`
}

// yamlRiskEngine 是多维风险引擎配置的 YAML 表示。
type yamlRiskEngine struct {
	Enabled      *bool              `yaml:"enabled"`
	HalfLifeDays *float64           `yaml:"half_life_days"`
	Weights      map[string]float64 `yaml:"weights"`
}

// ParseConfig 把 YAML 内容解析进 cfg。
//
// 失败时不修改 cfg（原子性）：所有字段在局部结构上校验通过后，才一次性写入。
// 唯一的例外后置步骤是认证凭据的环境变量覆盖（见 credentials_env.go），它只在成功后执行。
func ParseConfig(content string, cfg *Config) error {
	return parseConfigFrom(content, cfg, false, true)
}

// parseConfigFrom 是文件与目录两条加载路径的共同实现。
//
// runtimeOverride 声明内容来自守护进程自动管理的运行期覆盖文件：这类文件只携带运行期
// 状态（当前是 jail 的 enabled），因此 jail 处理多一条规则——未定义的 jail 名忽略并
// 告警，自动写回的文件不能凭空造出一个缺 log_files 的 jail。
//
// strict 对应 `--no-strict`：为 false 时忽略未知 YAML 键。它必须从加载入口一路传进来，
// 不能在解码处写死——否则「启动宽松、重载严格」这类偏差会让同一个文件的行为取决于谁读它。

// checkYAMLAliasBomb 检测 YAML 别名展开炸弹（billion laughs 攻击）。
// 统计锚点 (&name) 与别名 (*name) 数量，别名引用总数超过 1000 或别名数远超锚点数时拒绝。
func checkYAMLAliasBomb(content string) error {
	const maxAliasRefs = 1000
	anchors := 0
	aliases := 0
	for i := 0; i < len(content); i++ {
		if content[i] == '&' && i+1 < len(content) && isIdentStart(content[i+1]) {
			anchors++
		} else if content[i] == '*' && i+1 < len(content) && isIdentStart(content[i+1]) {
			aliases++
		}
	}
	if aliases > maxAliasRefs {
		return fmt.Errorf("YAML 别名引用数 %d 超过上限 %d，疑似别名展开攻击", aliases, maxAliasRefs)
	}
	if anchors > 0 && aliases > anchors*10 {
		return fmt.Errorf("YAML 别名数 %d 远超锚点数 %d，疑似别名展开攻击", aliases, anchors)
	}
	return nil
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func parseConfigFrom(content string, cfg *Config, runtimeOverride, strict bool) error {
	// 防止 YAML 别名展开炸弹（billion laughs 攻击）：统计锚点与别名数量，
	// 别名数超过锚点数 10 倍或总引用超过 1000 时拒绝。
	if err := checkYAMLAliasBomb(content); err != nil {
		return err
	}

	var yc yamlConfig
	dec := yaml.NewDecoder(bytes.NewReader([]byte(content)))
	dec.KnownFields(strict)
	if err := dec.Decode(&yc); err != nil {
		return fmt.Errorf("解析 YAML 配置失败: %w", err)
	}

	// 1. defaults
	if err := applyDefaults(&yc, cfg); err != nil {
		return err
	}
	// 2. jails（同名后到优先，按键排序保证顺序确定）
	if err := applyJails(&yc, cfg, runtimeOverride); err != nil {
		return err
	}
	// 3. ddos
	if err := applyDdos(&yc, cfg); err != nil {
		return err
	}
	// 4. webui
	if err := applyWebui(&yc, cfg); err != nil {
		return err
	}
	// 5. trusted_ips
	if err := applyTrustedIPs(&yc, cfg); err != nil {
		return err
	}
	// 6. capacity
	if err := applyCapacity(&yc, cfg); err != nil {
		return err
	}
	// 7. threat_feeds
	if err := applyThreatFeeds(&yc, cfg); err != nil {
		return err
	}
	// 8. risk_engine
	if err := applyRiskEngine(&yc, cfg); err != nil {
		return err
	}
	// 9~11. geoip / 本机坐标 / 探测地址
	if err := applyGeoip(&yc, cfg); err != nil {
		return err
	}
	// 11. 认证凭据的环境变量覆盖（见 credentials_env.go）：放在 YAML 全部应用之后，
	// 于是优先级是「环境变量 > YAML > Default()」，且失败路径仍然不碰 cfg。
	applyEnvCredentials(cfg)
	return nil
}

// applyDefaults 把 defaults 段应用到 cfg。
func applyDefaults(yc *yamlConfig, cfg *Config) error {
	d := yc.Defaults
	if d == nil {
		return nil
	}
	if d.MaxRetries != nil {
		cfg.DefaultMaxRetries = *d.MaxRetries
	}
	if d.FindTime != nil {
		cfg.DefaultFindTime = *d.FindTime
	}
	if d.BanTime != nil {
		cfg.DefaultBanTime = *d.BanTime
	}
	if d.Interval != nil {
		cfg.Interval = *d.Interval
	}
	if d.MetricsPort != nil {
		cfg.MetricsPort = *d.MetricsPort
	}
	if d.MetricsBindAddr != nil {
		cfg.MetricsBindAddress = *d.MetricsBindAddr
	}
	if d.MetricsUsername != nil {
		cfg.MetricsUsername = *d.MetricsUsername
	}
	if d.MetricsPassword != nil {
		cfg.MetricsPassword = *d.MetricsPassword
	}
	if d.LogFile != nil {
		cfg.LogFile = *d.LogFile
	}
	if d.LogLevel != nil {
		cfg.LogLevel = *d.LogLevel
	}
	if d.LogDestination != nil {
		v, ok := map[string]uint8{"syslog": LogDestinationSyslog, "file": LogDestinationFile, "both": LogDestinationBoth, "journal": LogDestinationJournal}[*d.LogDestination]
		if !ok {
			return fmt.Errorf("log_destination 取值非法: %s", *d.LogDestination)
		}
		cfg.LogDestination = v
	}
	if d.LogFormat != nil {
		v, ok := map[string]uint8{"plain": LogFormatPlain, "json": LogFormatJSON}[*d.LogFormat]
		if !ok {
			return fmt.Errorf("log_format 取值非法: %s", *d.LogFormat)
		}
		cfg.LogFormat = v
	}
	if d.LogMaxSizeMB != nil {
		if *d.LogMaxSizeMB > 100000 {
			return fmt.Errorf("log_max_size_mb 不能超过 100000 (100GB)")
		}
		cfg.LogMaxSizeMB = *d.LogMaxSizeMB
	}
	if d.LogMaxFiles != nil {
		if *d.LogMaxFiles > 1000 {
			return fmt.Errorf("log_max_files 不能超过 1000")
		}
		cfg.LogMaxFiles = *d.LogMaxFiles
	}
	// 历史库：路径是总开关——空串时 persist 根本不建，面板的分析面（复发/分级成效/时长
	// 直方图/三类推荐）全部回 503。这两个键此前只存在于 Config 结构里、YAML 无法写，
	// 于是整片分析面在真实部署里点不亮（E2E 的控制台洁净度断言就是这么撞开的）。
	if d.HistoryDBPath != nil {
		cfg.HistoryDBPath = *d.HistoryDBPath
	}
	if d.HistoryRetentionDays != nil {
		if *d.HistoryRetentionDays == 0 || *d.HistoryRetentionDays > 3650 {
			return fmt.Errorf("history_retention_days=%d 超出合理范围 (1-3650)", *d.HistoryRetentionDays)
		}
		cfg.HistoryRetentionDays = int(*d.HistoryRetentionDays)
	}
	return nil
}

// applyJails 应用 jails 段：同名 jail 后到优先，只覆盖显式给出的字段。
//
// Go map 迭代顺序随机，故先按键排序，保证同一份配置总是产生同一顺序的 jail 列表。
func applyJails(yc *yamlConfig, cfg *Config, runtimeOverride bool) error {
	if len(yc.Jails) == 0 {
		return nil
	}
	names := make([]string, 0, len(yc.Jails))
	for name := range yc.Jails {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		yj := yc.Jails[name]
		if err := applyJailDefinition(cfg, name, &yj, runtimeOverride); err != nil {
			return err
		}
	}

	if len(cfg.Jails) > MaxJails {
		return fmt.Errorf("jail 数量 %d 超过上限 %d", len(cfg.Jails), MaxJails)
	}
	return nil
}

// applyJailDefinition 应用单个 jail 的定义。
func applyJailDefinition(cfg *Config, name string, yj *yamlJail, runtimeOverride bool) error {
	// jail 名校验：防止空串、路径分隔符、控制字符、过长名称
	if err := validateJailName(name); err != nil {
		return err
	}
	// 运行期覆盖文件里出现未定义的 jail 名时忽略并告警，不凭空创建。
	if runtimeOverride {
		if findJail(cfg, name) == nil {
			logWarnf("运行期覆盖配置引用了未定义的 jail %q，忽略", name)
			return nil
		}
	}

	needsDefault := false
	j := findJail(cfg, name)
	if j == nil {
		nj := NewJail(name)
		nj.LogFiles = nil
		nj.Regexes = nil
		cfg.Jails = append(cfg.Jails, nj)
		j = &cfg.Jails[len(cfg.Jails)-1]
		needsDefault = true
	}

	if yj.Enabled != nil {
		j.Enabled = *yj.Enabled
	}
	if yj.LogFiles != nil {
		if err := validateLogFiles(j, *yj.LogFiles); err != nil {
			return err
		}
	}
	if yj.MaxRetries != nil {
		j.MaxRetries = validateMaxRetries(cfg, *yj.MaxRetries)
		j.MaxRetriesSet = true
	}
	if yj.FindTime != nil {
		j.FindTime = validateFindtime(cfg, *yj.FindTime)
		j.FindTimeSet = true
	}
	if yj.BanTime != nil {
		j.BanTime = validateBantime(cfg, *yj.BanTime)
		j.BanTimeSet = true
	}
	if yj.Regex != nil {
		if len(j.Regexes) >= MaxRegexPatterns {
			return fmt.Errorf("jail %q 的正则数量超过上限 %d", name, MaxRegexPatterns)
		}
		rn := "custom"
		if yj.RegexName != nil {
			rn = *yj.RegexName
		}
		j.Regexes = append(j.Regexes, RegexInfo{Name: rn, Pattern: *yj.Regex})
	}
	if yj.Regexes != nil {
		rnames := make([]string, 0, len(yj.Regexes))
		for rn := range yj.Regexes {
			rnames = append(rnames, rn)
		}
		sort.Strings(rnames)
		for _, rn := range rnames {
			if len(j.Regexes) >= MaxRegexPatterns {
				return fmt.Errorf("jail %q 的正则数量超过上限 %d", name, MaxRegexPatterns)
			}
			j.Regexes = append(j.Regexes, RegexInfo{Name: rn, Pattern: yj.Regexes[rn].Pattern})
		}
	}
	applyCluster(j, yj.Cluster)

	// 只有真正新建的 jail 才应用智能默认，避免用户显式值被覆盖。
	if needsDefault {
		applySmartDefaults(j, yj.MaxRetries != nil, yj.FindTime != nil, yj.BanTime != nil)
	}
	return nil
}

// applyCluster 只覆盖 cluster 段里显式给出的字段。
func applyCluster(j *Jail, yc *yamlCluster) {
	if yc == nil {
		return
	}
	if yc.Enabled != nil {
		j.Cluster.Enabled = *yc.Enabled
	}
	if yc.AuditOnly != nil {
		j.Cluster.AuditOnly = *yc.AuditOnly
	}
	if yc.PrefixV4 != nil {
		j.Cluster.PrefixV4 = *yc.PrefixV4
	}
	if yc.PrefixV6 != nil {
		j.Cluster.PrefixV6 = *yc.PrefixV6
	}
	if yc.Window != nil {
		j.Cluster.Window = *yc.Window
	}
	if yc.MinIPs != nil {
		j.Cluster.MinIPs = *yc.MinIPs
	}
	if yc.MaxPerIP != nil {
		j.Cluster.MaxPerIP = *yc.MaxPerIP
	}
	if yc.BanTime != nil {
		j.Cluster.BanTime = *yc.BanTime
	}
}

// findJail 按名查找 jail，返回指向 cfg.Jails 元素的指针。
func findJail(cfg *Config, name string) *Jail {
	for i := range cfg.Jails {
		if cfg.Jails[i].Name == name {
			return &cfg.Jails[i]
		}
	}
	return nil
}

// FindJail 按名查找 jail，返回指向 cfg.Jails 元素的指针（供包外使用）。
func (c *Config) FindJail(name string) *Jail { return findJail(c, name) }

// validateJailName 校验 jail 名：非空、长度上限、禁止路径分隔符和控制字符。
// jail 名用于日志、指标标签、运行期覆盖文件名，非法字符可能导致路径穿越或指标注入。
func validateJailName(name string) error {
	const maxJailNameLen = 64
	if name == "" {
		return fmt.Errorf("jail 名不能为空")
	}
	if len(name) > maxJailNameLen {
		return fmt.Errorf("jail 名 %q 长度 %d 超过上限 %d", name, len(name), maxJailNameLen)
	}
	for _, r := range name {
		if r == '/' || r == '\\' || r == '\x00' || r < ' ' {
			return fmt.Errorf("jail 名 %q 包含非法字符 %q", name, r)
		}
	}
	return nil
}

func validateLogFiles(j *Jail, files []string) error {
	if len(files) > MaxLogFiles {
		return fmt.Errorf("jail %q 的 log_files 数量 %d 超过上限 %d", j.Name, len(files), MaxLogFiles)
	}
	for _, p := range files {
		if err := ValidateAndNormalizePath(p); err != nil {
			return fmt.Errorf("jail %q 的 log_file %q 不合法: %w", j.Name, p, err)
		}
	}
	j.LogFiles = append(j.LogFiles[:0], files...)
	return nil
}

func validateMaxRetries(cfg *Config, v uint32) uint32 {
	if v == 0 {
		return retriesOr(cfg.DefaultMaxRetries, 3)
	}
	return v
}

func validateFindtime(cfg *Config, v uint32) uint32 {
	if v == 0 {
		return findtimeOr(cfg.DefaultFindTime, 600)
	}
	if v < 10 {
		return 10
	}
	return v
}

func validateBantime(cfg *Config, v int32) int32 {
	if v == 0 {
		return bantimeOr(cfg.DefaultBanTime, 600)
	}
	return v
}

func findtimeOr(v, fallback uint32) uint32 {
	if v >= 60 {
		return v
	}
	return fallback
}

func retriesOr(v, fallback uint32) uint32 {
	if v >= 1 {
		return v
	}
	return fallback
}

func bantimeOr(v, fallback int32) int32 {
	if v != 0 {
		return v
	}
	return fallback
}

// applyTrustedIPs 校验并应用 trusted_ips：每条必须是合法 IP 或 CIDR。
// 无效条目会让启动期显式报错，而不是静默带着无意义的值运行。
func applyTrustedIPs(yc *yamlConfig, cfg *Config) error {
	if yc.TrustedIPs == nil {
		return nil
	}
	out := make([]string, 0, len(yc.TrustedIPs))
	for i, raw := range yc.TrustedIPs {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return fmt.Errorf("trusted_ips[%d] 为空", i)
		}
		if _, err := netip.ParsePrefix(entry); err != nil {
			if _, aerr := netip.ParseAddr(entry); aerr != nil {
				return fmt.Errorf("trusted_ips[%d] 不是合法 IP 或 CIDR: %q", i, raw)
			}
		}
		out = append(out, entry)
	}
	cfg.TrustedIPs = out
	return nil
}

// applySmartDefaults 为只写了 log_files / regex 的极简 jail 推断合理默认：
// 未显式给出的字段才填，已显式给出的保持不动。
//
//   - findtime：默认 10m，若 ban_time 明显更长则放宽到 1h
//   - ban_time：默认 1h
//   - max_retries：默认 3，若 findtime 较短则收紧到 2
func applySmartDefaults(j *Jail, hasRetries, hasFindtime, hasBantime bool) {
	if !hasFindtime {
		j.FindTime = 600
	}
	if !hasBantime {
		if j.FindTime > 0 && j.FindTime > 3600*2 {
			j.BanTime = 86400
		} else {
			j.BanTime = 3600
		}
	}
	if !hasRetries {
		if j.FindTime < 300 {
			j.MaxRetries = 2
		} else {
			j.MaxRetries = 3
		}
	}
}

func applyDdos(yc *yamlConfig, cfg *Config) error {
	d := yc.Ddos
	if d == nil {
		return nil
	}
	setBool(&cfg.Ddos.Enabled, d.Enabled)
	if err := setU32Bounded(&cfg.Ddos.GlobalConnRate, d.GlobalConnRate, 1, 10000000, "ddos.global_conn_rate"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.AutoBanDuration, d.AutoBanDuration, 1, 86400, "ddos.auto_ban_duration"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.AutoBanThreshold, d.AutoBanThreshold, 1, 1000000, "ddos.auto_ban_threshold"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.CheckInterval, d.CheckInterval, 1, 3600, "ddos.check_interval"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.BaselineWarmupSample, d.BaselineWarmupSample, 1, 100000, "ddos.baseline_warmup_sample"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxSynPerSecond, d.MaxSynPerSecond, 1, 10000000, "ddos.max_syn_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxUDPPerSecond, d.MaxUDPPerSecond, 1, 10000000, "ddos.max_udp_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxICMPPerSecond, d.MaxICMPPerSecond, 1, 10000000, "ddos.max_icmp_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxACKPerSecond, d.MaxACKPerSecond, 1, 10000000, "ddos.max_ack_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxRSTPerSecond, d.MaxRSTPerSecond, 1, 10000000, "ddos.max_rst_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxFINPerSecond, d.MaxFINPerSecond, 1, 10000000, "ddos.max_fin_per_second"); err != nil {
		return err
	}
	setBool(&cfg.Ddos.StaticThreshold, d.StaticThreshold)
	setBool(&cfg.Ddos.DynamicThreshold, d.DynamicThreshold)
	setBool(&cfg.Ddos.DdosDetection, d.DdosDetection)
	if err := setU32Bounded(&cfg.Ddos.DynamicThresholdRatioX100, d.DynamicThresholdRatio, 100, 1000, "ddos.dynamic_threshold_ratio_x100"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxBansPerSecond, d.MaxBansPerSecond, 1, 10000, "ddos.max_bans_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Ddos.MaxRateEntries, d.MaxRateEntries, 1, 10000000, "ddos.max_rate_entries"); err != nil {
		return err
	}
	setBool(&cfg.Ddos.ProtectOpenPorts, d.ProtectOpenPorts)
	return nil
}

func applyWebui(yc *yamlConfig, cfg *Config) error {
	w := yc.Webui
	if w == nil {
		return nil
	}
	if err := setU32Bounded(&cfg.Webui.SSEPushInterval, w.SSEPushInterval, 1, 60, "webui.sse_push_interval"); err != nil {
		return err
	}
	setU64(&cfg.Webui.RateWarningPPS, w.RateWarningPPS)
	setU64(&cfg.Webui.RateCriticalPPS, w.RateCriticalPPS)
	setU64(&cfg.Webui.RateWarningSYN, w.RateWarningSYN)
	setU64(&cfg.Webui.RateCriticalSYN, w.RateCriticalSYN)
	if cfg.Webui.RateWarningPPS >= cfg.Webui.RateCriticalPPS {
		return fmt.Errorf("webui.rate_warning_pps(%d) 必须小于 rate_critical_pps(%d)", cfg.Webui.RateWarningPPS, cfg.Webui.RateCriticalPPS)
	}
	if cfg.Webui.RateWarningSYN >= cfg.Webui.RateCriticalSYN {
		return fmt.Errorf("webui.rate_warning_syn(%d) 必须小于 rate_critical_syn(%d)", cfg.Webui.RateWarningSYN, cfg.Webui.RateCriticalSYN)
	}
	if err := setU32Bounded(&cfg.Webui.MaxSynPerSecond, w.MaxSynPerSecond, 1, 10_000_000, "webui.max_syn_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxUDPPerSecond, w.MaxUDPPerSecond, 1, 10_000_000, "webui.max_udp_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxICMPPerSecond, w.MaxICMPPerSecond, 1, 10_000_000, "webui.max_icmp_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxACKPerSecond, w.MaxACKPerSecond, 1, 10_000_000, "webui.max_ack_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxRSTPerSecond, w.MaxRSTPerSecond, 1, 10_000_000, "webui.max_rst_per_second"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxFINPerSecond, w.MaxFINPerSecond, 1, 10_000_000, "webui.max_fin_per_second"); err != nil {
		return err
	}
	setBool(&cfg.Webui.StaticThreshold, w.StaticThreshold)
	setBool(&cfg.Webui.DynamicThreshold, w.DynamicThreshold)
	setBool(&cfg.Webui.DdosDetection, w.DdosDetection)
	// webui.* 是面板表单的持久化位置，ddos.* 是内核下发读取的单一来源。
	// YAML 两段都写时以显式给出的 webui 键为准（PUT /config 只改这一处）。
	if w.StaticThreshold != nil {
		cfg.Ddos.StaticThreshold = *w.StaticThreshold
	}
	if w.DynamicThreshold != nil {
		cfg.Ddos.DynamicThreshold = *w.DynamicThreshold
	}
	if w.DdosDetection != nil {
		cfg.Ddos.DdosDetection = *w.DdosDetection
	}
	if err := setU32Bounded(&cfg.Webui.MaxBanEntries, w.MaxBanEntries, 1, 10_000_000, "webui.max_ban_entries"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxWhitelistEntries, w.MaxWhitelistEntries, 1, 1_000_000, "webui.max_whitelist_entries"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxRateEntries, w.MaxRateEntries, 1, 10_000_000, "webui.max_rate_entries"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Webui.MaxLocalIPCache, w.MaxLocalIPCache, 1, 1_000_000, "webui.max_local_ip_cache"); err != nil {
		return err
	}
	setString(&cfg.Webui.ClearLogsAt, w.ClearLogsAt)
	return nil
}

func applyCapacity(yc *yamlConfig, cfg *Config) error {
	c := yc.Capacity
	if c == nil {
		return nil
	}
	if err := setU32Bounded(&cfg.Capacity.MaxBanEntries, c.MaxBanEntries, 1, 10_000_000, "capacity.max_ban_entries"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Capacity.MaxWhitelistEntries, c.MaxWhitelistEntries, 1, 1_000_000, "capacity.max_whitelist_entries"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Capacity.MaxRateEntries, c.MaxRateEntries, 1, 10_000_000, "capacity.max_rate_entries"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.Capacity.MaxLocalIPCache, c.MaxLocalIPCache, 1, 1_000_000, "capacity.max_local_ip_cache"); err != nil {
		return err
	}
	return nil
}

// applyThreatFeeds 应用威胁情报源配置。
func applyThreatFeeds(yc *yamlConfig, cfg *Config) error {
	tf := yc.ThreatFeeds
	if tf == nil {
		return nil
	}
	setBool(&cfg.ThreatFeeds.Enabled, tf.Enabled)
	if err := setU32Bounded(&cfg.ThreatFeeds.RefreshInterval, tf.RefreshInterval, 60, 86400, "threat_feeds.refresh_interval"); err != nil {
		return err
	}
	if err := setU32Bounded(&cfg.ThreatFeeds.HTTPTimeout, tf.HTTPTimeout, 5, 300, "threat_feeds.http_timeout"); err != nil {
		return err
	}
	if tf.MaxRetries != nil {
		if *tf.MaxRetries < 0 || *tf.MaxRetries > 10 {
			return fmt.Errorf("threat_feeds.max_retries 必须在 0-10 范围内，实际是 %d", *tf.MaxRetries)
		}
		cfg.ThreatFeeds.MaxRetries = *tf.MaxRetries
	}
	if tf.FailureThreshold != nil {
		if *tf.FailureThreshold < 1 || *tf.FailureThreshold > 100 {
			return fmt.Errorf("threat_feeds.failure_threshold 必须在 1-100 范围内，实际是 %d", *tf.FailureThreshold)
		}
		cfg.ThreatFeeds.FailureThreshold = *tf.FailureThreshold
	}
	if tf.CooldownDuration != nil {
		cfg.ThreatFeeds.CooldownDuration = *tf.CooldownDuration
	}
	// 情报源列表：YAML 给出完整列表时替换默认值
	if len(tf.Sources) > 0 {
		cfg.ThreatFeeds.Sources = make([]ThreatFeedSourceConfig, 0, len(tf.Sources))
		for _, src := range tf.Sources {
			// 校验 URL 格式，防止 file:// 等危险协议或空串
			if err := validateThreatFeedURL(src.URL); err != nil {
				return fmt.Errorf("threat_feeds.sources[%s].url: %w", src.Name, err)
			}
			sc := ThreatFeedSourceConfig{
				Name:     src.Name,
				URL:      src.URL,
				Category: src.Category,
			}
			if src.Enabled != nil {
				sc.Enabled = *src.Enabled
			}
			if src.Confidence != nil {
				sc.Confidence = *src.Confidence
			}
			cfg.ThreatFeeds.Sources = append(cfg.ThreatFeeds.Sources, sc)
		}
	}
	return nil
}

// validateThreatFeedURL 校验情报源 URL 格式。
// 只允许 http/https 协议，拒绝 file://、ftp:// 等可能导致本地文件读取或 SSRF 的协议。
func validateThreatFeedURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL 不能为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("URL 解析失败: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
		// 允许
	default:
		return fmt.Errorf("不支持的协议 %q，只允许 http/https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("URL 缺少主机名")
	}
	return nil
}

// applyRiskEngine 应用 risk_engine 段。
//
// half_life_days 必须 > 0：半衰期为零或负数会让衰减函数失去意义（所有历史事件瞬间归零
// 或计算出发散值），风险引擎的判定结果将不可预测。
func applyRiskEngine(yc *yamlConfig, cfg *Config) error {
	re := yc.RiskEngine
	if re == nil {
		return nil
	}
	setBool(&cfg.RiskEngine.Enabled, re.Enabled)
	if re.HalfLifeDays != nil {
		if *re.HalfLifeDays <= 0 {
			return fmt.Errorf("risk_engine.half_life_days 必须大于 0，实际是 %v", *re.HalfLifeDays)
		}
		if *re.HalfLifeDays > 365 {
			return fmt.Errorf("risk_engine.half_life_days 不能超过 365（一年），实际是 %v", *re.HalfLifeDays)
		}
		cfg.RiskEngine.HalfLifeDays = *re.HalfLifeDays
	}
	if len(re.Weights) > 0 {
		if cfg.RiskEngine.Weights == nil {
			cfg.RiskEngine.Weights = make(map[string]float64, len(re.Weights))
		}
		for k, v := range re.Weights {
			if v < 0 || v > 100 {
				return fmt.Errorf("risk_engine.weights[%s] 必须在 [0, 100] 范围内，实际是 %v", k, v)
			}
			cfg.RiskEngine.Weights[k] = v
		}
	}
	return nil
}

// applyGeoip 应用 geoip 段与本机坐标 / 探测地址。
//
// 经纬度必须成对给出：只写一个是配置错误（半份坐标会把标记画到错误位置），拒绝加载。
func applyGeoip(yc *yamlConfig, cfg *Config) error {
	if yc.GeoipDBPath != nil {
		cfg.GeoipDBPath = *yc.GeoipDBPath
	}

	lat, latSet, err := parseCoordField(yc.ServerLatitude, "server_latitude")
	if err != nil {
		return err
	}
	lon, lonSet, err := parseCoordField(yc.ServerLongitude, "server_longitude")
	if err != nil {
		return err
	}
	if latSet != lonSet {
		return fmt.Errorf("server_latitude 与 server_longitude 必须成对给出")
	}
	if latSet {
		if lat < -90 || lat > 90 {
			return fmt.Errorf("server_latitude 必须在 [-90, 90]，实际 %v", lat)
		}
		if lon < -180 || lon > 180 {
			return fmt.Errorf("server_longitude 必须在 [-180, 180]，实际 %v", lon)
		}
		cfg.ServerLatitude = lat
		cfg.ServerLongitude = lon
		cfg.ServerCoordsSet = true
	}

	if yc.GeoipDetectEgress != nil {
		cfg.GeoipDetectEgress = *yc.GeoipDetectEgress
	}
	if yc.GeoipEgressProbeURL != nil {
		u, err := normalizeProbeURL(*yc.GeoipEgressProbeURL)
		if err != nil {
			return err
		}
		cfg.GeoipEgressProbeURL = u
	}
	return nil
}

// parseCoordField 解析一个坐标字段；节点缺省或空串表示未给出（set=false）。
func parseCoordField(n yaml.Node, field string) (float64, bool, error) {
	if n.Kind == 0 {
		return 0, false, nil
	}
	v, set, err := parseCoord(&n)
	if err != nil {
		return 0, false, fmt.Errorf("%s 解析失败: %w", field, err)
	}
	return v, set, nil
}

// parseCoord 解析 YAML 坐标：接受数值，或字符串（空串表示未设置）。
func parseCoord(n *yaml.Node) (float64, bool, error) {
	switch n.Tag {
	case "!!int", "!!float":
		v, err := strconv.ParseFloat(strings.TrimSpace(n.Value), 64)
		return v, err == nil, err
	case "!!str":
		s := strings.TrimSpace(n.Value)
		if s == "" {
			return 0, false, nil
		}
		v, err := strconv.ParseFloat(s, 64)
		return v, err == nil, err
	default:
		return 0, false, fmt.Errorf("坐标必须是数值或字符串（可为空），实际标签 %s", n.Tag)
	}
}

// MaxProbeURLLen 是出口 IP 探测地址的长度上限。
const MaxProbeURLLen = 2048

// normalizeProbeURL 校验出口 IP 探测地址。
//
// 严格校验而非「非法就退回默认」：这是守护进程唯一会主动发出去的请求目标，静默改
// 地址等于把用户意图换成了别的。空串表示未设置（走内置默认地址）。路径允许存在，
// 只要求协议为 http(s) 且主机名非空。
func normalizeProbeURL(raw string) (string, error) {
	url := strings.TrimSpace(raw)
	if url == "" {
		return "", nil
	}
	if len(url) > MaxProbeURLLen {
		return "", fmt.Errorf("geoip_egress_probe_url 过长（上限 %d）: %s", MaxProbeURLLen, url)
	}
	for _, r := range url {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' || r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("geoip_egress_probe_url 含空白或控制字符: %q", url)
		}
	}
	lower := strings.ToLower(url)
	var schemeLen int
	switch {
	case strings.HasPrefix(lower, "https://"):
		schemeLen = len("https://")
	case strings.HasPrefix(lower, "http://"):
		schemeLen = len("http://")
	default:
		return "", fmt.Errorf("geoip_egress_probe_url 必须以 http:// 或 https:// 开头: %q", url)
	}
	host := url[schemeLen:]
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return "", fmt.Errorf("geoip_egress_probe_url 缺少主机名: %q", url)
	}
	return url, nil
}

func setBool(dst *bool, v *bool) {
	if v != nil {
		*dst = *v
	}
}

func setU32(dst *uint32, v *uint32) {
	if v != nil {
		*dst = *v
	}
}

func setU32Bounded(dst *uint32, v *uint32, min, max uint32, name string) error {
	if v != nil {
		if *v < min || *v > max {
			return fmt.Errorf("%s 必须在 %d-%d 范围内，实际是 %d", name, min, max, *v)
		}
		*dst = *v
	}
	return nil
}

func setU64(dst *uint64, v *uint64) {
	if v != nil {
		*dst = *v
	}
}

func setString(dst *string, v *string) {
	if v != nil {
		*dst = *v
	}
}
