// Package config 承载守护进程的配置模型、YAML 解析与默认值。
//
// 覆盖默认值、字段合并规则（同名 jail 后到优先、只覆盖显式
// 给出的字段）、严格模式（未知 key 直接报错）等语义。
package config

import (
	"net"
	"net/netip"
	"regexp"
	"strconv"
)

// FamilyOf 返回地址族的判定码，与 netlink 契约的 `fw_addr_family` 取值一致。
//
// 判定发生在 netip.Addr 层面，避免上层为「用 /32 还是 /128」自己维护一份映射：
// 集群检测与 CIDR 归一化都依赖同一份地址族知识。
func FamilyOf(addr netip.Addr) uint8 {
	if addr.Is4() {
		return 2
	}
	return 10
}

// Jail 相关上限，与内核契约一致。
const (
	// MaxFailedTimestamps 是单个 IP 保留的失败时间戳上限（超出时 FIFO 移出最旧）。
	MaxFailedTimestamps = 100
	// MaxLogFiles 是单个 jail 可配置的日志文件数上限。
	MaxLogFiles = 10
	// MaxRegexPatterns 是单个 jail 可配置的正则表达式数上限。
	MaxRegexPatterns = 10
	// MaxRegexNameLen 是正则名称字符串的字节上限。
	MaxRegexNameLen = 64
	// MaxJails 是全局可同时活跃的 jail 数上限。
	MaxJails = 32
)

// ClusterConfig 是 jail 的集群扫描检测参数。
//
// 整段缺省时保持零值之外的默认值（关闭检测）；段内只覆盖显式给出的字段。
type ClusterConfig struct {
	Enabled   bool
	AuditOnly bool
	PrefixV4  uint8
	PrefixV6  uint8
	Window    uint32
	MinIPs    uint32
	MaxPerIP  uint32
	BanTime   uint32
}

// 集群聚合前缀长度默认值。
const (
	DefaultClusterPrefixV4 uint8 = 24
	DefaultClusterPrefixV6 uint8 = 48
)

// DefaultClusterConfig 返回集群检测的默认配置（默认关闭）。
func DefaultClusterConfig() ClusterConfig {
	return ClusterConfig{
		Enabled:   false,
		AuditOnly: true,
		PrefixV4:  DefaultClusterPrefixV4,
		PrefixV6:  DefaultClusterPrefixV6,
		Window:    60,
		MinIPs:    5,
		MaxPerIP:  3,
		BanTime:   3600,
	}
}

// PrefixFor 返回该地址族应使用的聚合前缀长度。
func (c ClusterConfig) PrefixFor(af uint8) uint8 {
	if af == 10 {
		return c.PrefixV6
	}
	return c.PrefixV4
}

// RegexInfo 是一条命名正则：原始模式串 + 编译结果。
//
// Compiled 在编译阶段填充；为 nil 时匹配热路径跳过该条。
type RegexInfo struct {
	Name     string
	Pattern  string
	Compiled *regexp.Regexp
}

// Jail 是单个服务的配置与运行期状态。
type Jail struct {
	Name     string
	Enabled  bool
	LogFiles []string
	Regexes  []RegexInfo

	MaxRetries uint32
	FindTime   uint32
	// BanTime 为 -1 表示永久封禁。
	BanTime int32
	Cluster ClusterConfig

	// *_Set 区分「用户显式配置」与「智能默认推断」，避免被默认值覆盖。
	MaxRetriesSet bool
	FindTimeSet   bool
	BanTimeSet    bool
}

// DdosConfig 是 DDoS 防护配置。
type DdosConfig struct {
	Enabled              bool
	GlobalConnRate       uint32
	AutoBanDuration      uint32
	AutoBanThreshold     uint32
	CheckInterval        uint32
	BaselineWarmupSample uint32

	MaxSynPerSecond  uint32
	MaxUDPPerSecond  uint32
	MaxICMPPerSecond uint32
	MaxACKPerSecond  uint32
	MaxRSTPerSecond  uint32
	MaxFINPerSecond  uint32

	StaticThreshold  bool
	DynamicThreshold bool
	DdosDetection    bool

	MaxBansPerSecond uint32
	MaxRateEntries   uint32

	// ProtectOpenPorts 把本机对外监听端口自动纳入速率判定。关闭后下发全零位图，
	// 与「从未下发」（内核按全端口受保护处理）语义不同。
	ProtectOpenPorts bool
}

// DefaultDdosConfig 返回 DDoS 配置默认值。
func DefaultDdosConfig() DdosConfig {
	return DdosConfig{
		Enabled:              true,
		GlobalConnRate:       100000,
		AutoBanDuration:      3600,
		AutoBanThreshold:     3,
		CheckInterval:        5,
		BaselineWarmupSample: 50,
		MaxSynPerSecond:      2000,
		MaxUDPPerSecond:      10000,
		MaxICMPPerSecond:     500,
		MaxACKPerSecond:      20000,
		MaxRSTPerSecond:      2000,
		MaxFINPerSecond:      2000,
		StaticThreshold:      true,
		DynamicThreshold:     false,
		DdosDetection:        true,
		MaxBansPerSecond:     200,
		MaxRateEntries:       65536,
		ProtectOpenPorts:     true,
	}
}

// WebuiConfig 是 Web UI 的推送与告警阈值配置。
type WebuiConfig struct {
	SSEPushInterval uint32
	RateWarningPPS  uint64
	RateCriticalPPS uint64
	RateWarningSYN  uint64
	RateCriticalSYN uint64

	MaxSynPerSecond  uint32
	MaxUDPPerSecond  uint32
	MaxICMPPerSecond uint32
	MaxACKPerSecond  uint32
	MaxRSTPerSecond  uint32
	MaxFINPerSecond  uint32

	StaticThreshold  bool
	DynamicThreshold bool
	DdosDetection    bool

	MaxBanEntries       uint32
	MaxWhitelistEntries uint32
	MaxRateEntries      uint32
	MaxLocalIPCache     uint32

	// ClearLogsAt 是前端「清空」后设置的时间戳（过滤早于此时间的日志行）。
	ClearLogsAt string
}

// DefaultWebuiConfig 返回 Web UI 配置默认值。
func DefaultWebuiConfig() WebuiConfig {
	return WebuiConfig{
		SSEPushInterval:     1,
		RateWarningPPS:      50000,
		RateCriticalPPS:     200000,
		RateWarningSYN:      1000,
		RateCriticalSYN:     5000,
		MaxSynPerSecond:     2000,
		MaxUDPPerSecond:     10000,
		MaxICMPPerSecond:    500,
		MaxACKPerSecond:     20000,
		MaxRSTPerSecond:     2000,
		MaxFINPerSecond:     2000,
		StaticThreshold:     true,
		DynamicThreshold:    false,
		DdosDetection:       true,
		MaxBanEntries:       65535,
		MaxWhitelistEntries: 65535,
		MaxRateEntries:      65535,
		MaxLocalIPCache:     65535,
	}
}

// CapacityConfig 是用户自定义的各项上限。
type CapacityConfig struct {
	MaxBanEntries       uint32
	MaxWhitelistEntries uint32
	MaxRateEntries      uint32
	MaxLocalIPCache     uint32
}

// DefaultCapacityConfig 返回容量配置默认值。
func DefaultCapacityConfig() CapacityConfig {
	return CapacityConfig{
		MaxBanEntries:       65535,
		MaxWhitelistEntries: 65535,
		MaxRateEntries:      65535,
		MaxLocalIPCache:     65535,
	}
}

// 日志目的地与格式取值。
const (
	LogDestinationSyslog  uint8 = 0
	LogDestinationFile    uint8 = 1
	LogDestinationBoth    uint8 = 2
	LogDestinationJournal uint8 = 3

	LogFormatPlain uint8 = 0
	LogFormatJSON  uint8 = 1

	// LogLevelNone 至 LogLevelDebug 对应 0..=4。
	LogLevelNone  uint8 = 0
	LogLevelErr   uint8 = 1
	LogLevelWarn  uint8 = 2
	LogLevelInfo  uint8 = 3
	LogLevelDebug uint8 = 4
)

// Config 是 CLI / YAML / 默认值三路合并后的最终配置。
type Config struct {
	DefaultMaxRetries uint32
	DefaultFindTime   uint32
	DefaultBanTime    int32

	Daemon   bool
	Interval uint32

	MetricsPort        uint16
	MetricsBindAddress string
	MetricsUsername    string
	MetricsPassword    string

	ConfigFile string
	ConfigDir  string

	LogFile        string
	LogLevel       uint8
	LogDestination uint8
	LogFormat      uint8
	LogMaxSizeMB   uint32
	LogMaxFiles    uint32

	StrictMode bool

	Jails      []Jail
	Ddos       DdosConfig
	Webui      WebuiConfig
	TrustedIPs []string
	Capacity   CapacityConfig

	GeoipDBPath         string
	ServerLatitude      float64
	ServerLongitude     float64
	ServerCoordsSet     bool
	GeoipDetectEgress   bool
	GeoipEgressProbeURL string

	// HTTP 面的监听地址不是独立配置项，而是由 metrics_bind_address + metrics_port
	// 现场合成，见 ListenAddress。
	MaxSSEConnections    int
	HistoryDBPath        string
	HistoryRetentionDays int
}

// Default 返回配置的默认值。
//
// 字段改动必须验证集成测试仍通过，以保证行为等价。
func Default() Config {
	return Config{
		DefaultMaxRetries:  3,
		DefaultFindTime:    600,
		DefaultBanTime:     600,
		Daemon:             false,
		Interval:           1,
		MetricsPort:        9119,
		MetricsBindAddress: "127.0.0.1",
		LogLevel:           LogLevelInfo,
		LogDestination:     LogDestinationBoth,
		LogFormat:            LogFormatPlain,
		LogMaxSizeMB:         10,
		LogMaxFiles:          10,
		StrictMode:           true,
		Ddos:                 DefaultDdosConfig(),
		Webui:                DefaultWebuiConfig(),
		Capacity:             DefaultCapacityConfig(),
		MaxSSEConnections:    32,
		HistoryDBPath:        "",
		HistoryRetentionDays: 7,
	}
}

// ListenAddress 是 HTTP 面（面板、/api/v1、/metrics 共用同一端口）的监听地址，
// 由 metrics_bind_address 与 metrics_port 现场合成。
//
// 这两个键此前没有消费者：监听地址取自一个写死 127.0.0.1:9119 的字段，改
// metrics_port 不生效，`config/default.yaml` 声明的 0.0.0.0（局域网访问面板）
// 也被静默降级成只听回环。改成方法后不存在「缓存值与配置不一致」这种状态，
// PUT /config 与热重载落盘之后再读就是新值。
//
// metrics_port = 0 表示关闭 HTTP 面（口径见 jail.Validate 的注释），返回空串，
// 由组合根按「缺席」处理。
func (c *Config) ListenAddress() string {
	if c.MetricsPort == 0 {
		return ""
	}
	// 绑定地址为空时按回环处理：宁可只听本地，也不让一个空值把面板开放到所有网卡。
	host := c.MetricsBindAddress
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(c.MetricsPort)))
}

// NewJail 创建新 jail：数值字段为 0，运行期容器按上限预分配。
func NewJail(name string) Jail {
	return Jail{
		Name:     name,
		Enabled:  true,
		LogFiles: make([]string, 0, MaxLogFiles),
		Regexes:  make([]RegexInfo, 0, MaxRegexPatterns),
		Cluster:  DefaultClusterConfig(),
	}
}
