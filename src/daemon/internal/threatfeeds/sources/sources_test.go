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
