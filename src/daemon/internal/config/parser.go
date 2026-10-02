package config

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// yamlConfig 是顶层 YAML 结构：defaults + jails + 各功能段。
//
// 严格模式：未知顶层字段直接报错（对应 Rust 的 deny_unknown_fields）。
type yamlConfig struct {
	Defaults            *yamlDefaults       `yaml:"defaults"`
	Jails               map[string]yamlJail `yaml:"jails"`
	Ddos                *yamlDdos           `yaml:"ddos"`
	Webui               *yamlWebui          `yaml:"webui"`
	TrustedIPs          []string            `yaml:"trusted_ips"`
	Capacity            *yamlCapacity       `yaml:"capacity"`
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
	Enabled              *bool   `yaml:"enabled"`
	GlobalConnRate       *uint32 `yaml:"global_conn_rate"`
	AutoBanDuration      *uint32 `yaml:"auto_ban_duration"`
	AutoBanThreshold     *uint32 `yaml:"auto_ban_threshold"`
	CheckInterval        *uint32 `yaml:"check_interval"`
	BaselineWarmupSample *uint32 `yaml:"baseline_warmup_samples"`
	MaxSynPerSecond      *uint32 `yaml:"max_syn_per_second"`
	MaxUDPPerSecond      *uint32 `yaml:"max_udp_per_second"`
	MaxICMPPerSecond     *uint32 `yaml:"max_icmp_per_second"`
	MaxACKPerSecond      *uint32 `yaml:"max_ack_per_second"`
	MaxRSTPerSecond      *uint32 `yaml:"max_rst_per_second"`
	MaxFINPerSecond      *uint32 `yaml:"max_fin_per_second"`
	StaticThreshold      *bool   `yaml:"static_threshold"`
	DynamicThreshold     *bool   `yaml:"dynamic_threshold"`
	DdosDetection        *bool   `yaml:"ddos_detection"`
	MaxBansPerSecond     *uint32 `yaml:"max_bans_per_second"`
	MaxRateEntries       *uint32 `yaml:"max_rate_entries"`
	ProtectOpenPorts     *bool   `yaml:"protect_open_ports"`
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
}

// yamlCapacity 是容量配置的 YAML 表示。
type yamlCapacity struct {
	MaxBanEntries       *uint32 `yaml:"max_ban_entries"`
	MaxWhitelistEntries *uint32 `yaml:"max_whitelist_entries"`
	MaxRateEntries      *uint32 `yaml:"max_rate_entries"`
	MaxLocalIPCache     *uint32 `yaml:"max_local_ip_cache"`
}

// ParseConfig 把 YAML 内容解析进 cfg。
//
// 失败时不修改 cfg（原子性）：所有字段在局部结构上校验通过后，才一次性写入。
func ParseConfig(content string, cfg *Config) error {
	return parseConfigFrom(content, cfg, false)
}

// ParseConfigFrom 同 ParseConfig，但可声明内容来自守护进程自动管理的运行期覆盖文件。
//
// 这类文件只携带运行期状态（当前是 jail 的 enabled），因此 jail 处理多一条规则：
// 未定义的 jail 名忽略并告警——自动写回的文件不能凭空造出一个缺 log_files 的 jail，
// 否则它下一次启动会直接拒绝加载。
func parseConfigFrom(content string, cfg *Config, runtimeOverride bool) error {
	var yc yamlConfig
	dec := yaml.NewDecoder(bytes.NewReader([]byte(content)))
	dec.KnownFields(true)
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
	applyDdos(&yc, cfg)
	// 4. webui
	applyWebui(&yc, cfg)
	// 5. trusted_ips
	if yc.TrustedIPs != nil {
		cfg.TrustedIPs = append([]string(nil), yc.TrustedIPs...)
	}
	// 6. capacity
	applyCapacity(&yc, cfg)
	// 7~9. geoip / 本机坐标 / 探测地址
	return applyGeoip(&yc, cfg)
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
		cfg.LogMaxSizeMB = *d.LogMaxSizeMB
	}
	if d.LogMaxFiles != nil {
		cfg.LogMaxFiles = *d.LogMaxFiles
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

func validateLogFiles(j *Jail, files []string) error {
	if len(files) > MaxLogFiles {
		return fmt.Errorf("jail %q 的 log_files 数量 %d 超过上限 %d", j.Name, len(files), MaxLogFiles)
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

func applyDdos(yc *yamlConfig, cfg *Config) {
	d := yc.Ddos
	if d == nil {
		return
	}
	setBool(&cfg.Ddos.Enabled, d.Enabled)
	setU32(&cfg.Ddos.GlobalConnRate, d.GlobalConnRate)
	setU32(&cfg.Ddos.AutoBanDuration, d.AutoBanDuration)
	setU32(&cfg.Ddos.AutoBanThreshold, d.AutoBanThreshold)
	setU32(&cfg.Ddos.CheckInterval, d.CheckInterval)
	setU32(&cfg.Ddos.BaselineWarmupSample, d.BaselineWarmupSample)
	setU32(&cfg.Ddos.MaxSynPerSecond, d.MaxSynPerSecond)
	setU32(&cfg.Ddos.MaxUDPPerSecond, d.MaxUDPPerSecond)
	setU32(&cfg.Ddos.MaxICMPPerSecond, d.MaxICMPPerSecond)
	setU32(&cfg.Ddos.MaxACKPerSecond, d.MaxACKPerSecond)
	setU32(&cfg.Ddos.MaxRSTPerSecond, d.MaxRSTPerSecond)
	setU32(&cfg.Ddos.MaxFINPerSecond, d.MaxFINPerSecond)
	setBool(&cfg.Ddos.StaticThreshold, d.StaticThreshold)
	setBool(&cfg.Ddos.DynamicThreshold, d.DynamicThreshold)
	setBool(&cfg.Ddos.DdosDetection, d.DdosDetection)
	setU32(&cfg.Ddos.MaxBansPerSecond, d.MaxBansPerSecond)
	setU32(&cfg.Ddos.MaxRateEntries, d.MaxRateEntries)
	setBool(&cfg.Ddos.ProtectOpenPorts, d.ProtectOpenPorts)
}

func applyWebui(yc *yamlConfig, cfg *Config) {
	w := yc.Webui
	if w == nil {
		return
	}
	setU32(&cfg.Webui.SSEPushInterval, w.SSEPushInterval)
	setU64(&cfg.Webui.RateWarningPPS, w.RateWarningPPS)
	setU64(&cfg.Webui.RateCriticalPPS, w.RateCriticalPPS)
	setU64(&cfg.Webui.RateWarningSYN, w.RateWarningSYN)
	setU64(&cfg.Webui.RateCriticalSYN, w.RateCriticalSYN)
	setU32(&cfg.Webui.MaxSynPerSecond, w.MaxSynPerSecond)
	setU32(&cfg.Webui.MaxUDPPerSecond, w.MaxUDPPerSecond)
	setU32(&cfg.Webui.MaxICMPPerSecond, w.MaxICMPPerSecond)
	setU32(&cfg.Webui.MaxACKPerSecond, w.MaxACKPerSecond)
	setU32(&cfg.Webui.MaxRSTPerSecond, w.MaxRSTPerSecond)
	setU32(&cfg.Webui.MaxFINPerSecond, w.MaxFINPerSecond)
	setBool(&cfg.Webui.StaticThreshold, w.StaticThreshold)
	setBool(&cfg.Webui.DynamicThreshold, w.DynamicThreshold)
	setBool(&cfg.Webui.DdosDetection, w.DdosDetection)
	setU32(&cfg.Webui.MaxBanEntries, w.MaxBanEntries)
	setU32(&cfg.Webui.MaxWhitelistEntries, w.MaxWhitelistEntries)
	setU32(&cfg.Webui.MaxRateEntries, w.MaxRateEntries)
	setU32(&cfg.Webui.MaxLocalIPCache, w.MaxLocalIPCache)
}

func applyCapacity(yc *yamlConfig, cfg *Config) {
	c := yc.Capacity
	if c == nil {
		return
	}
	setU32(&cfg.Capacity.MaxBanEntries, c.MaxBanEntries)
	setU32(&cfg.Capacity.MaxWhitelistEntries, c.MaxWhitelistEntries)
	setU32(&cfg.Capacity.MaxRateEntries, c.MaxRateEntries)
	setU32(&cfg.Capacity.MaxLocalIPCache, c.MaxLocalIPCache)
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

// normalizeProbeURL 校验出口 IP 探测地址，语义与 Rust validate_probe_url 一致。
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

func setU64(dst *uint64, v *uint64) {
	if v != nil {
		*dst = *v
	}
}
