package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// findUp 从测试文件所在目录逐级向上查找相对路径，避免硬编码绝对路径。
func findUp(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 失败")
	}
	dir := filepath.Dir(thisFile)
	for {
		cand := filepath.Join(dir, rel)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("向上查找未找到 %s", rel)
		}
		dir = parent
	}
}

func readFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(findUp(t, rel))
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", rel, err)
	}
	return string(raw)
}

func TestDefaultMatchesRustDefaults(t *testing.T) {
	c := Default()
	checks := []struct {
		name string
		got  any
		want any
	}{
		{"DefaultMaxRetries", c.DefaultMaxRetries, uint32(3)},
		{"DefaultFindTime", c.DefaultFindTime, uint32(600)},
		{"DefaultBanTime", c.DefaultBanTime, int32(600)},
		{"Interval", c.Interval, uint32(1)},
		{"MetricsPort", c.MetricsPort, uint16(9119)},
		{"MetricsBindAddress", c.MetricsBindAddress, "127.0.0.1"},
		{"LogLevel", c.LogLevel, uint8(LogLevelInfo)},
		{"LogDestination", c.LogDestination, uint8(LogDestinationBoth)},
		{"LogFormat", c.LogFormat, uint8(LogFormatPlain)},
		{"LogMaxSizeMB", c.LogMaxSizeMB, uint32(10)},
		{"LogMaxFiles", c.LogMaxFiles, uint32(10)},
		{"StrictMode", c.StrictMode, true},
		{"Ddos.Enabled", c.Ddos.Enabled, true},
		{"Ddos.MaxSynPerSecond", c.Ddos.MaxSynPerSecond, uint32(2000)},
		{"Ddos.ProtectOpenPorts", c.Ddos.ProtectOpenPorts, true},
		{"Webui.SSEPushInterval", c.Webui.SSEPushInterval, uint32(1)},
		{"Webui.RateWarningPPS", c.Webui.RateWarningPPS, uint64(50000)},
		{"Capacity.MaxBanEntries", c.Capacity.MaxBanEntries, uint32(65535)},
		{"Storage.Retention.BanHistoryDays", c.Storage.Retention.BanHistoryDays, uint32(90)},
		{"Storage.Writer.ChannelSize", c.Storage.Writer.ChannelSize, 1000},
	}
	for _, ck := range checks {
		if ck.got != ck.want {
			t.Errorf("%s = %v，期望 %v", ck.name, ck.got, ck.want)
		}
	}
	if len(c.Jails) != 0 {
		t.Errorf("默认配置不应有 jail，实际 %d 个", len(c.Jails))
	}
	if c.ServerCoordsSet {
		t.Error("默认配置不应设置本机坐标")
	}
}

func TestParseDefaultYaml(t *testing.T) {
	cfg := Default()
	if err := ParseConfig(readFile(t, filepath.Join("config", "default.yaml")), &cfg); err != nil {
		t.Fatalf("解析 default.yaml 失败: %v", err)
	}

	if cfg.DefaultMaxRetries != 3 || cfg.DefaultFindTime != 600 || cfg.DefaultBanTime != 900 {
		t.Errorf("defaults 未生效: %+v", cfg)
	}
	if cfg.Interval != 1 || cfg.MetricsPort != 9119 || cfg.MetricsBindAddress != "0.0.0.0" {
		t.Errorf("defaults 网络项未生效: %+v", cfg)
	}
	if cfg.MetricsUsername != "snow" || cfg.MetricsPassword != "9420" {
		t.Errorf("metrics 认证未生效: %q/%q", cfg.MetricsUsername, cfg.MetricsPassword)
	}
	if cfg.LogFile != "/var/log/firewall.log" || cfg.LogLevel != LogLevelInfo {
		t.Errorf("日志项未生效: %q/%d", cfg.LogFile, cfg.LogLevel)
	}
	if cfg.Ddos.GlobalConnRate != 100000 || cfg.Ddos.MaxRateEntries != 65536 {
		t.Errorf("ddos 未生效: %+v", cfg.Ddos)
	}

	sshd := cfg.FindJail("sshd")
	if sshd == nil {
		t.Fatal("未解析出 sshd jail")
	}
	if !sshd.Enabled {
		t.Error("sshd 应启用")
	}
	if len(sshd.LogFiles) != 2 || sshd.LogFiles[0] != "/var/log/auth.log" {
		t.Errorf("sshd log_files 不符: %v", sshd.LogFiles)
	}
	if sshd.MaxRetries != 2 || sshd.FindTime != 600 || sshd.BanTime != -1 {
		t.Errorf("sshd 数值不符: retries=%d findtime=%d bantime=%d", sshd.MaxRetries, sshd.FindTime, sshd.BanTime)
	}
	if !sshd.MaxRetriesSet || !sshd.FindTimeSet || !sshd.BanTimeSet {
		t.Error("sshd 的显式赋值标记应为 true")
	}
	if len(sshd.Regexes) != 3 {
		t.Fatalf("sshd 正则数 %d，期望 3", len(sshd.Regexes))
	}
	// 排序后顺序确定：connection_closed / failed_password / invalid_user
	if sshd.Regexes[0].Name != "connection_closed" || sshd.Regexes[2].Name != "invalid_user" {
		t.Errorf("正则顺序不确定: %v", sshd.Regexes)
	}
	for _, r := range sshd.Regexes {
		if !strings.Contains(r.Pattern, "([0-9]{1,3}") {
			t.Errorf("正则 %s 的捕获组丢失: %s", r.Name, r.Pattern)
		}
	}
}

func TestStrictModeRejectsUnknownField(t *testing.T) {
	cfg := Default()
	if err := ParseConfig("defaults:\n  max_retries: 3\nunknown_section: 1\n", &cfg); err == nil {
		t.Fatal("顶层未知字段应被拒绝")
	}
	cfg2 := Default()
	if err := ParseConfig("defaults:\n  unknown_key: 3\n", &cfg2); err == nil {
		t.Fatal("defaults 内未知字段应被拒绝")
	}
	cfg3 := Default()
	if err := ParseConfig("jails:\n  sshd:\n    log_files: [/var/log/auth.log]\n    unknown: 1\n", &cfg3); err == nil {
		t.Fatal("jail 内未知字段应被拒绝")
	}
}

func TestJailMergeLastWins(t *testing.T) {
	// 同一份 YAML 里同名 key 由解析器决定后到优先；这里验证合并只覆盖显式字段。
	cfg := Default()
	yml := `
defaults:
  findtime: 1200
jails:
  sshd:
    log_files: [/var/log/auth.log]
    max_retries: 5
`
	if err := ParseConfig(yml, &cfg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	j := cfg.FindJail("sshd")
	if j == nil {
		t.Fatal("未解析出 sshd")
	}
	if j.MaxRetries != 5 {
		t.Errorf("max_retries 应为 5，实际 %d", j.MaxRetries)
	}
	// findtime 未显式给出：走 smart default 600（而非 defaults 段的 1200）。
	if j.FindTime != 600 {
		t.Errorf("未显式 findtime 应为 smart default 600，实际 %d", j.FindTime)
	}
	if j.BanTime != 3600 {
		t.Errorf("未显式 ban_time 应为 smart default 3600，实际 %d", j.BanTime)
	}
}

func TestJailLimits(t *testing.T) {
	cfg := Default()
	var b strings.Builder
	b.WriteString("jails:\n  sshd:\n    log_files: [/a]\n    regexes:\n")
	for i := 0; i < MaxRegexPatterns+1; i++ {
		b.WriteString("      r")
		b.WriteString(string(rune('a' + i)))
		b.WriteString(":\n        pattern: \"x\"\n")
	}
	if err := ParseConfig(b.String(), &cfg); err == nil {
		t.Fatalf("正则数超过 %d 应被拒绝", MaxRegexPatterns)
	}
}

func TestCoordPairingAndRange(t *testing.T) {
	cases := []struct {
		name    string
		yml     string
		wantErr bool
	}{
		{"成对数值", "server_latitude: 39.9\nserver_longitude: 116.4\n", false},
		{"成对字符串", "server_latitude: \"39.9\"\nserver_longitude: \"116.4\"\n", false},
		{"都空串", "server_latitude: \"\"\nserver_longitude: \"\"\n", false},
		{"只给纬度", "server_latitude: 39.9\n", true},
		{"只给经度", "server_longitude: 116.4\n", true},
		{"纬度越界", "server_latitude: 91\nserver_longitude: 0\n", true},
		{"经度越界", "server_latitude: 0\nserver_longitude: 181\n", true},
		{"非数值", "server_latitude: \"abc\"\nserver_longitude: 0\n", true},
	}
	for _, tc := range cases {
		cfg := Default()
		err := ParseConfig(tc.yml, &cfg)
		if tc.wantErr && err == nil {
			t.Errorf("%s：应报错但通过了", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s：不应报错，实际 %v", tc.name, err)
		}
	}
}

func TestProbeURLNormalization(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"   ", "", false},
		{"https://api.ip.sb/geoip", "https://api.ip.sb/geoip", false},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", false},
		{"http://host/a/b", "http://host/a/b", false},
		{"http://host?x=1", "http://host?x=1", false},
		{"http://host/../etc", "http://host/../etc", false},
		{"api.ip.sb/geoip", "", true},
		{"ftp://host", "", true},
		{"http://host with space", "", true},
		{"https://", "", true},
		{"https://" + strings.Repeat("a", MaxProbeURLLen), "", true},
	}
	for _, tc := range cases {
		got, err := normalizeProbeURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q 应报错", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q 不应报错: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q 归一化为 %q，期望 %q", tc.in, got, tc.want)
		}
	}
}

func TestValidateAndNormalizePath(t *testing.T) {
	bad := []string{
		"/var/log/../../etc/shadow",
		"/var/log/%2e%2e/etc/shadow",
		"/var/log/secure;rm -rf /",
		"/var/log/$(whoami)",
		"/var/log/`id`",
		"/var/log/a|b",
		"/var/log/a&b",
	}
	for _, p := range bad {
		if err := ValidateAndNormalizePath(p); err == nil {
			t.Errorf("%q 应被拒绝", p)
		}
	}
	tooLong := "/var/log/" + strings.Repeat("a", MaxPathLen)
	if err := ValidateAndNormalizePath(tooLong); err == nil {
		t.Error("超长路径应被拒绝")
	}
	good := []string{"/var/log/auth.log", "relative/auth.log", "/var/log/secure-2026"}
	for _, p := range good {
		if err := ValidateAndNormalizePath(p); err != nil {
			t.Errorf("%q 不应被拒绝: %v", p, err)
		}
	}
}

func TestNewJailDefaults(t *testing.T) {
	j := NewJail("sshd")
	if !j.Enabled || j.Name != "sshd" {
		t.Fatalf("NewJail 基础字段不符: %+v", j)
	}
	if j.Cluster.Enabled || j.Cluster.PrefixV4 != 24 || j.Cluster.PrefixV6 != 48 {
		t.Errorf("NewJail 集群默认不符: %+v", j.Cluster)
	}
	if j.Cluster.PrefixFor(10) != 48 || j.Cluster.PrefixFor(2) != 24 {
		t.Error("PrefixFor 未按地址族选择")
	}
}
