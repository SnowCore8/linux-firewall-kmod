package sources

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIpsumSource_Parse(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "ipsum.txt"))
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	src := NewIpsumSource("https://example.com/ipsum.txt", "abuse", 0.8)
	entries, err := src.Parse(data)
	if err != nil {
		t.Fatalf("Parse() 错误 = %v", err)
	}

	// 测试数据有 6 个有效 IP
	if len(entries) != 6 {
		t.Errorf("Parse() 返回 %d 条，想要 6 条", len(entries))
	}

	// 验证源名称
	for _, e := range entries {
		if e.Source != "ipsum" {
			t.Errorf("Source = %s，想要 ipsum", e.Source)
		}
		if e.Category != "abuse" {
			t.Errorf("Category = %s，想要 abuse", e.Category)
		}
		if e.Confidence != 0.8 {
			t.Errorf("Confidence = %f，想要 0.8", e.Confidence)
		}
	}
}

func TestFireHOLSource_Parse(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "firehol.txt"))
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	src := NewFireHOLSource("firehol", "https://example.com/firehol.txt", "abuse", 0.85)
	entries, err := src.Parse(data)
	if err != nil {
		t.Fatalf("Parse() 错误 = %v", err)
	}

	// 测试数据有 5 个 CIDR
	if len(entries) != 5 {
		t.Errorf("Parse() 返回 %d 条，想要 5 条", len(entries))
	}

	// 验证都是 CIDR 格式
	for _, e := range entries {
		if e.Source != "firehol" {
			t.Errorf("Source = %s，想要 firehol", e.Source)
		}
		// 验证是 CIDR（bits < 128 for IPv6 or < 32 for IPv4）
		if e.IP.Bits() >= 32 && !e.IP.Addr().Is6() {
			t.Errorf("期望 CIDR 格式，但得到 /%d", e.IP.Bits())
		}
	}
}

func TestDShieldSource_Parse(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "dshield.txt"))
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	src := NewDShieldSource("https://example.com/dshield.txt", "scanner", 0.7)
	entries, err := src.Parse(data)
	if err != nil {
		t.Fatalf("Parse() 错误 = %v", err)
	}

	// 测试数据有 3 个 IP
	if len(entries) != 3 {
		t.Errorf("Parse() 返回 %d 条，想要 3 条", len(entries))
	}

	for _, e := range entries {
		if e.Source != "dshield" {
			t.Errorf("Source = %s，想要 dshield", e.Source)
		}
		if e.Category != "scanner" {
			t.Errorf("Category = %s，想要 scanner", e.Category)
		}
	}
}

func TestBlocklistSource_Parse(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "blocklist.txt"))
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	src := NewBlocklistSource("https://example.com/blocklist.txt", "abuse", 0.75)
	entries, err := src.Parse(data)
	if err != nil {
		t.Fatalf("Parse() 错误 = %v", err)
	}

	// 测试数据有 5 个 IP
	if len(entries) != 5 {
		t.Errorf("Parse() 返回 %d 条，想要 5 条", len(entries))
	}

	for _, e := range entries {
		if e.Source != "blocklist_de" {
			t.Errorf("Source = %s，想要 blocklist_de", e.Source)
		}
	}

	// TTL 必须覆盖默认 24h 刷新间隔（与其余源同取 25h）：TTL 更短会让条目在下一轮
	// 拉取前就集体过期，判定层跳过而面板仍显示同步成功。
	const wantTTL = 25 * time.Hour
	const tolerance = time.Minute
	now := time.Now()
	for _, e := range entries {
		ttl := e.ExpiresAt.Sub(now)
		if ttl < wantTTL-tolerance || ttl > wantTTL+tolerance {
			t.Errorf("%s 的 ExpiresAt 距 now = %v，想要约 %v", e.IP, ttl, wantTTL)
		}
	}
}

func TestFeodoSource_Parse(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "feodo.csv"))
	if err != nil {
		t.Fatalf("读取测试数据失败: %v", err)
	}

	src := NewFeodoSource("https://example.com/feodo.csv", "botnet", 0.9)
	entries, err := src.Parse(data)
	if err != nil {
		t.Fatalf("Parse() 错误 = %v", err)
	}

	// 测试数据有 3 个 IP（跳过表头）
	if len(entries) != 3 {
		t.Errorf("Parse() 返回 %d 条，想要 3 条", len(entries))
	}

	for _, e := range entries {
		if e.Source != "feodo" {
			t.Errorf("Source = %s，想要 feodo", e.Source)
		}
		if e.Category != "botnet" {
			t.Errorf("Category = %s，想要 botnet", e.Category)
		}
		if e.Confidence != 0.9 {
			t.Errorf("Confidence = %f，想要 0.9", e.Confidence)
		}
	}
}

func TestSource_Name(t *testing.T) {
	tests := []struct {
		source interface{ Name() string }
		want   string
	}{
		{NewIpsumSource("", "", 0), "ipsum"},
		{NewFireHOLSource("firehol", "", "", 0), "firehol"},
		{NewDShieldSource("", "", 0), "dshield"},
		{NewBlocklistSource("", "", 0), "blocklist_de"},
		{NewFeodoSource("", "", 0), "feodo"},
	}

	for _, tt := range tests {
		got := tt.source.Name()
		if got != tt.want {
			t.Errorf("Name() = %s，想要 %s", got, tt.want)
		}
	}
}

func BenchmarkIpsumSource_Parse(b *testing.B) {
	data, _ := os.ReadFile(filepath.Join("testdata", "ipsum.txt"))
	src := NewIpsumSource("", "abuse", 0.8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = src.Parse(data)
	}
}

func TestParseSourcesSkipOversizedLine(t *testing.T) {
	huge := make([]byte, maxFeedLineBytes+1024)
	for i := range huge {
		huge[i] = 'a'
	}
	data := []byte("203.0.113.1\n")
	data = append(data, huge...)
	data = append(data, '\n')
	data = append(data, []byte("203.0.113.2\n")...)

	ipsum := NewIpsumSource("", "abuse", 0.8)
	entries, err := ipsum.Parse(data)
	if err != nil {
		t.Fatalf("IpsumSource.Parse() 错误 = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("IpsumSource.Parse() 条目数 = %d，想要 2", len(entries))
	}

	dshield := NewDShieldSource("", "abuse", 0.7)
	entries, err = dshield.Parse(data)
	if err != nil {
		t.Fatalf("DShieldSource.Parse() 错误 = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("DShieldSource.Parse() 条目数 = %d，想要 2", len(entries))
	}

	feodo := NewFeodoSource("", "botnet", 0.9)
	if _, err := feodo.Parse(data); err != nil {
		t.Fatalf("FeodoSource.Parse() 错误 = %v", err)
	}
}

// TestParseIPListPrefixLimits 钉住前缀下限：IPv4 至少 /8、IPv6 至少 /16，
// 且任何 0.0.0.0/x、::/x 的未指定网段一律拒绝。上限内的网段原样保留。
func TestParseIPListPrefixLimits(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour)
	tests := []struct {
		entry string
		want  bool
	}{
		{"0.0.0.0/0", false},
		{"10.0.0.0/7", false},
		{"10.0.0.0/8", true},
		{"0.0.0.0/8", false},
		{"::/0", false},
		{"2001:db8::/15", false},
		{"::/16", false},
		{"2001:db8::/16", true},
		{"1.2.3.4/32", true},
		{"1.2.3.0/24", true},
		{"2001:db8::/48", true},
		{"2001:db8::1/128", true},
		{"0.0.0.0", false},
		{"::", false},
	}
	for _, tt := range tests {
		t.Run(tt.entry, func(t *testing.T) {
			entries, err := parseIPList([]byte(tt.entry+"\n"), "test", "abuse", 0.8, expiresAt)
			if err != nil {
				t.Fatalf("parseIPList() 错误 = %v", err)
			}
			got := len(entries) == 1
			if got != tt.want {
				t.Fatalf("条目 %q 是否接受 = %v，想要 %v（返回 %d 条）", tt.entry, got, tt.want, len(entries))
			}
			if got && entries[0].IP.String() != tt.entry {
				t.Errorf("保留的条目 = %s，想要 %s", entries[0].IP, tt.entry)
			}
		})
	}
}

// TestSourcesRejectUnsuitablePrefixes 核对五个源适配器都走同一前缀校验：
// 0.0.0.0/0 与 ::/0 被丢弃，同批 /24 与 /48 照常保留。
func TestSourcesRejectUnsuitablePrefixes(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		parse func([]byte) ([]FeedEntry, error)
	}{
		{
			name:  "firehol",
			data:  "0.0.0.0/0\n::/0\n198.51.100.0/24\n2001:db8::/48\n",
			parse: NewFireHOLSource("firehol", "", "abuse", 0.85).Parse,
		},
		{
			name:  "blocklist_de",
			data:  "0.0.0.0/0\n::/0\n198.51.100.0/24\n2001:db8::/48\n",
			parse: NewBlocklistSource("", "abuse", 0.75).Parse,
		},
		{
			name:  "dshield",
			data:  "0.0.0.0/0\t1\tx\n::/0\t1\tx\n198.51.100.0/24\t1\tx\n2001:db8::/48\t1\tx\n",
			parse: NewDShieldSource("", "scanner", 0.7).Parse,
		},
		{
			name:  "ipsum",
			data:  "0.0.0.0/0\t5\n::/0\t5\n198.51.100.0/24\t5\n2001:db8::/48\t5\n",
			parse: NewIpsumSource("", "abuse", 0.8).Parse,
		},
		{
			name:  "feodo",
			data:  "2026-11-01,0.0.0.0/0,443,x,malware,online\n2026-11-01,::/0,443,x,malware,online\n2026-11-01,198.51.100.0/24,443,x,malware,online\n2026-11-01,2001:db8::/48,443,x,malware,online\n",
			parse: NewFeodoSource("", "botnet", 0.9).Parse,
		},
	}
	want := []string{"198.51.100.0/24", "2001:db8::/48"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, err := tc.parse([]byte(tc.data))
			if err != nil {
				t.Fatalf("Parse() 错误 = %v", err)
			}
			if len(entries) != len(want) {
				t.Fatalf("Parse() 返回 %d 条，想要 %d 条", len(entries), len(want))
			}
			for i, w := range want {
				if got := entries[i].IP.String(); got != w {
					t.Errorf("entries[%d].IP = %s，想要 %s", i, got, w)
				}
			}
		})
	}
}
