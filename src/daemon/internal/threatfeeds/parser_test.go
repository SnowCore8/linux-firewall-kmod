package threatfeeds

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseIPList(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantCount int
		wantIPs   []string
	}{
		{
			name:      "纯 IP 列表",
			data:      "192.168.1.1\n10.0.0.1\n",
			wantCount: 2,
			wantIPs:   []string{"192.168.1.1/32", "10.0.0.1/32"},
		},
		{
			name:      "带注释",
			data:      "# 注释行\n192.168.1.1\n# 另一行注释\n10.0.0.1\n",
			wantCount: 2,
			wantIPs:   []string{"192.168.1.1/32", "10.0.0.1/32"},
		},
		{
			name:      "CIDR 格式",
			data:      "192.168.1.0/24\n10.0.0.0/8\n",
			wantCount: 2,
			wantIPs:   []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		{
			name:      "混合 IP 和 CIDR",
			data:      "192.168.1.1\n10.0.0.0/8\n",
			wantCount: 2,
			wantIPs:   []string{"192.168.1.1/32", "10.0.0.0/8"},
		},
		{
			name:      "空行和空白",
			data:      "\n\n192.168.1.1\n\n\n10.0.0.1\n\n",
			wantCount: 2,
			wantIPs:   []string{"192.168.1.1/32", "10.0.0.1/32"},
		},
		{
			name:      "无效 IP 跳过",
			data:      "192.168.1.1\ninvalid-ip\n10.0.0.1\n",
			wantCount: 2,
			wantIPs:   []string{"192.168.1.1/32", "10.0.0.1/32"},
		},
		{
			name:      "IPv6 地址",
			data:      "2001:db8::1\nfe80::1/64\n",
			wantCount: 2,
			wantIPs:   []string{"2001:db8::1/128", "fe80::1/64"},
		},
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := ParseIPList([]byte(tt.data), "test", "abuse", 0.8, expiresAt)
			if err != nil {
				t.Fatalf("ParseIPList() 错误 = %v", err)
			}
			if len(entries) != tt.wantCount {
				t.Errorf("ParseIPList() 返回 %d 条，想要 %d 条", len(entries), tt.wantCount)
			}
			for i, wantIP := range tt.wantIPs {
				if i >= len(entries) {
					break
				}
				gotIP := entries[i].IP.String()
				if gotIP != wantIP {
					t.Errorf("entries[%d].IP = %s，想要 %s", i, gotIP, wantIP)
				}
				if entries[i].Source != "test" {
					t.Errorf("entries[%d].Source = %s，想要 test", i, entries[i].Source)
				}
				if entries[i].Category != "abuse" {
					t.Errorf("entries[%d].Category = %s，想要 abuse", i, entries[i].Category)
				}
				if entries[i].Confidence != 0.8 {
					t.Errorf("entries[%d].Confidence = %f，想要 0.8", i, entries[i].Confidence)
				}
			}
		})
	}
}

func TestStripComments(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1 # 注释", "192.168.1.1 "},
		{"# 全行注释", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := StripComments(tt.input)
		if got != tt.want {
			t.Errorf("StripComments(%q) = %q，想要 %q", tt.input, got, tt.want)
		}
	}
}

func TestFeedEntry_IsExpired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"未过期", now.Add(1 * time.Hour), false},
		{"已过期", now.Add(-1 * time.Hour), true},
		{"刚好过期", now.Add(-1 * time.Second), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// FeedEntry 已移到 sources 包，这里直接测试时间比较
			got := time.Now().After(tt.expiresAt)
			if got != tt.want {
				t.Errorf("IsExpired() = %v，想要 %v", got, tt.want)
			}
		})
	}
}

func BenchmarkParseIPList(b *testing.B) {
	// 生成 1000 行 IP 列表
	var data string
	for i := 0; i < 1000; i++ {
		data += "192.168.1.1\n"
	}
	expiresAt := time.Now().Add(24 * time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseIPList([]byte(data), "bench", "test", 0.5, expiresAt)
	}
}

func TestParseIPList_IPv6(t *testing.T) {
	data := "2001:db8::1\nfe80::1/64\n"
	expiresAt := time.Now().Add(24 * time.Hour)
	entries, err := ParseIPList([]byte(data), "test", "abuse", 0.8, expiresAt)
	if err != nil {
		t.Fatalf("ParseIPList() 错误 = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("返回 %d 条，想要 2 条", len(entries))
	}
	// 验证 IPv6 地址
	wantPrefixes := []string{"2001:db8::1/128", "fe80::1/64"}
	for i, want := range wantPrefixes {
		if i >= len(entries) {
			break
		}
		got := entries[i].IP.String()
		if got != want {
			t.Errorf("entries[%d].IP = %s，想要 %s", i, got, want)
		}
	}
}

func TestParseIPList_MixedFormats(t *testing.T) {
	data := `# Mixed formats
192.168.1.1
10.0.0.0/8
2001:db8::1
fe80::/10
invalid-line
172.16.0.1
`
	expiresAt := time.Now().Add(24 * time.Hour)
	entries, err := ParseIPList([]byte(data), "test", "mixed", 0.5, expiresAt)
	if err != nil {
		t.Fatalf("ParseIPList() 错误 = %v", err)
	}
	// 应该有 5 个有效条目（跳过 invalid-line）
	if len(entries) != 5 {
		t.Errorf("返回 %d 条，想要 5 条", len(entries))
	}
}

func TestParseIPList_EmptyInput(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)
	entries, err := ParseIPList([]byte(""), "test", "empty", 0.5, expiresAt)
	if err != nil {
		t.Fatalf("ParseIPList() 错误 = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("返回 %d 条，想要 0 条", len(entries))
	}
}

func TestParseIPList_OnlyComments(t *testing.T) {
	data := `# 注释 1
# 注释 2
# 注释 3
`
	expiresAt := time.Now().Add(24 * time.Hour)
	entries, err := ParseIPList([]byte(data), "test", "comments", 0.5, expiresAt)
	if err != nil {
		t.Fatalf("ParseIPList() 错误 = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("返回 %d 条，想要 0 条", len(entries))
	}
}

func TestFeedEntry_IPContains(t *testing.T) {
	tests := []struct {
		name   string
		prefix netip.Prefix
		ip     netip.Addr
		want   bool
	}{
		{
			name:   "IPv4 精确匹配",
			prefix: netip.MustParsePrefix("192.168.1.1/32"),
			ip:     netip.MustParseAddr("192.168.1.1"),
			want:   true,
		},
		{
			name:   "IPv4 CIDR 匹配",
			prefix: netip.MustParsePrefix("192.168.1.0/24"),
			ip:     netip.MustParseAddr("192.168.1.100"),
			want:   true,
		},
		{
			name:   "IPv4 CIDR 不匹配",
			prefix: netip.MustParsePrefix("192.168.1.0/24"),
			ip:     netip.MustParseAddr("192.168.2.1"),
			want:   false,
		},
		{
			name:   "IPv6 精确匹配",
			prefix: netip.MustParsePrefix("2001:db8::1/128"),
			ip:     netip.MustParseAddr("2001:db8::1"),
			want:   true,
		},
		{
			name:   "IPv6 CIDR 匹配",
			prefix: netip.MustParsePrefix("2001:db8::/32"),
			ip:     netip.MustParseAddr("2001:db8::1"),
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.prefix.Contains(tt.ip)
			if got != tt.want {
				t.Errorf("Contains() = %v，想要 %v", got, tt.want)
			}
		})
	}
}

// TestParseIPListSkipsOverlongLine 钉住「单个超长行不该让整份列表失败」。
//
// 默认 64 KiB 的 Scanner 上限会让 100 KiB 的一行返回 ErrTooLong，整个源解析直接失败；
// 修好后超长行按非法内容跳过，其余有效行照常产出。
func TestParseIPListSkipsOverlongLine(t *testing.T) {
	expiresAt := time.Now().Add(24 * time.Hour)

	t.Run("100KiB 行", func(t *testing.T) {
		data := "192.0.2.1\n" + strings.Repeat("x", 100*1024) + "\n198.51.100.2\n"
		entries, err := ParseIPList([]byte(data), "test", "abuse", 0.8, expiresAt)
		if err != nil {
			t.Fatalf("超长行不应让解析失败: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("返回 %d 条，想要 2 条", len(entries))
		}
		if got := entries[0].IP.String(); got != "192.0.2.1/32" {
			t.Errorf("entries[0].IP = %s，想要 192.0.2.1/32", got)
		}
		if got := entries[1].IP.String(); got != "198.51.100.2/32" {
			t.Errorf("entries[1].IP = %s，想要 198.51.100.2/32", got)
		}
	})

	t.Run("超过单行上限的行", func(t *testing.T) {
		data := "192.0.2.1\n" + strings.Repeat("y", maxFeedLineBytes+1024) + "\n198.51.100.2\n"
		entries, err := ParseIPList([]byte(data), "test", "abuse", 0.8, expiresAt)
		if err != nil {
			t.Fatalf("超限行应被跳过而不是失败: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("返回 %d 条，想要 2 条", len(entries))
		}
	})
}
