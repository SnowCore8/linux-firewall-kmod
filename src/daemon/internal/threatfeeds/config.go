package threatfeeds

import "time"

// SourceConfig 是单个情报源的配置。
type SourceConfig struct {
	// Name 是源的唯一标识（如 "ipsum", "firehol"）。
	Name string `yaml:"name"`
	// URL 是拉取地址。
	URL string `yaml:"url"`
	// Enabled 控制该源是否启用。
	Enabled bool `yaml:"enabled"`
	// Category 是默认分类（可被解析器覆盖）。
	Category string `yaml:"category"`
	// Confidence 是默认置信度（可被解析器覆盖）。
	Confidence float64 `yaml:"confidence"`
}

// Config 是威胁情报系统的完整配置。
type Config struct {
	// Enabled 是总开关，false 时整个情报系统不启动。
	Enabled bool `yaml:"enabled"`
	// RefreshInterval 是自动刷新间隔，默认 24 小时。
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	// HTTPTimeout 是单次拉取的 HTTP 超时，默认 30 秒。
	HTTPTimeout time.Duration `yaml:"http_timeout"`
	// MaxRetries 是拉取失败后的重试次数，默认 3。
	MaxRetries int `yaml:"max_retries"`
	// FailureThreshold 是触发熔断的连续失败次数，默认 3。
	FailureThreshold int `yaml:"failure_threshold"`
	// CooldownDuration 是熔断冷却时长，默认 1 小时。
	CooldownDuration time.Duration `yaml:"cooldown_duration"`
	// Sources 是配置的情报源列表。
	Sources []SourceConfig `yaml:"sources"`
}

// DefaultConfig 返回默认配置，内置推荐情报源。
//
// 默认启用全部内置源：IPsum、FireHOL Level 1、DShield、Blocklist.de、Feodo Tracker。
func DefaultConfig() Config {
	return Config{
		Enabled:          true,
		RefreshInterval:  24 * time.Hour,
		HTTPTimeout:      30 * time.Second,
		MaxRetries:       3,
		FailureThreshold: 3,
		CooldownDuration: 1 * time.Hour,
		Sources: []SourceConfig{
			{
				Name:       "ipsum",
				URL:        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
				Enabled:    true,
				Category:   "abuse",
				Confidence: 0.8,
			},
			{
				Name:       "firehol_level1",
				URL:        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
				Enabled:    true,
				Category:   "abuse",
				Confidence: 0.85,
			},
			{
				Name:       "dshield",
				URL:        "https://www.dshield.org/block.txt",
				Enabled:    true,
				Category:   "scanner",
				Confidence: 0.7,
			},
			{
				Name:       "blocklist_de",
				URL:        "https://lists.blocklist.de/lists/all.txt",
				Enabled:    true,
				Category:   "abuse",
				Confidence: 0.75,
			},
			{
				Name:       "feodo",
				URL:        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
				Enabled:    true,
				Category:   "botnet",
				Confidence: 0.9,
			},
		},
	}
}

// EnabledSources 返回配置中启用的源列表。
func (c *Config) EnabledSources() []SourceConfig {
	var result []SourceConfig
	for _, src := range c.Sources {
		if src.Enabled {
			result = append(result, src)
		}
	}
	return result
}
