package threatfeeds

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func ipAddrs(ips ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

func TestDialTargetsRejectsPrivateAddress(t *testing.T) {
	_, err := dialTargets("raw.githubusercontent.com", ipAddrs("93.184.216.34", "10.0.0.1"), "443")
	if err == nil {
		t.Fatal("解析结果含私有地址时应拒绝连接")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("错误信息未标明 SSRF 防护: %v", err)
	}
}

func TestDialTargetsRejectsMappedPrivateAddress(t *testing.T) {
	if _, err := dialTargets("raw.githubusercontent.com", ipAddrs("::ffff:127.0.0.1"), "443"); err == nil {
		t.Error("mapped 回环地址应被拒绝")
	}
}

func TestDialTargetsSkipsUnusableEntries(t *testing.T) {
	// 长度非 4/16 的 IP 转不成 netip.Addr。跳过它之后若仍取 ips[0]，
	// 就等于连到了没校验过的地址。
	ips := []net.IPAddr{
		{IP: net.IP{10, 0, 0}},
		{IP: net.ParseIP("93.184.216.34")},
	}
	targets, err := dialTargets("raw.githubusercontent.com", ips, "443")
	if err != nil {
		t.Fatalf("应跳过不可用项后成功: %v", err)
	}
	if len(targets) != 1 || targets[0] != "93.184.216.34:443" {
		t.Errorf("targets = %v，期望只含 93.184.216.34:443", targets)
	}
}

func TestDialTargetsEmptyResult(t *testing.T) {
	// 旧实现在空解析结果上直接取 ips[0]，会 panic。
	if _, err := dialTargets("example.invalid", nil, "443"); err == nil {
		t.Error("空解析结果应返回错误")
	}
	if _, err := dialTargets("example.invalid", []net.IPAddr{{IP: net.IP{1, 2, 3}}}, "443"); err == nil {
		t.Error("全部项不可用时应返回错误")
	}
}

func TestDialTargetsMappedIPv4KeepsPort(t *testing.T) {
	targets, err := dialTargets("raw.githubusercontent.com", ipAddrs("::ffff:93.184.216.34"), "443")
	if err != nil {
		t.Fatalf("公网 mapped 地址不应被拒: %v", err)
	}
	if len(targets) != 1 || !strings.HasSuffix(targets[0], ":443") {
		t.Errorf("targets = %v，期望保留端口 443", targets)
	}
}

// TestIsPrivateAddrReservedPrefixes 覆盖标准库分类漏掉的保留/特殊用途网段边界。
//
// 100.64/10 运营商级 NAT、192.0.0.0/24 协议分配、198.18/15 基准测试、240/4 保留段
// 都不是可路由的公网单播地址，连过去只会打到内网或本机协议栈。
func TestIsPrivateAddrReservedPrefixes(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"100.63.255.255", false},
		{"100.64.0.0", true},
		{"100.127.255.255", true},
		{"100.128.0.0", false},
		{"192.0.0.255", true},
		{"192.0.1.0", false},
		{"198.17.255.255", false},
		{"198.18.0.0", true},
		{"198.19.255.255", true},
		{"198.20.0.0", false},
		{"223.255.255.255", false},
		{"224.0.0.1", true},
		{"240.0.0.0", true},
		{"255.255.255.255", true},
		{"8.8.8.8", false},
		{"::ffff:100.64.0.1", true},
		{"::ffff:192.0.0.1", true},
	}
	for _, tt := range tests {
		addr := netip.MustParseAddr(tt.addr)
		if got := isPrivateAddr(addr); got != tt.want {
			t.Errorf("isPrivateAddr(%s) = %v，想要 %v", tt.addr, got, tt.want)
		}
	}
}

// TestValidateURLRejectsNonWhitelistedTargets 钉住拉取期与配置期同一判据：
// http 与非白名单域名都必须被拒，且白名单域名必须放行。
func TestValidateURLRejectsNonWhitelistedTargets(t *testing.T) {
	for _, raw := range []string{
		"http://raw.githubusercontent.com/ipsum.txt",
		"https://example.com/feed.txt",
		"https://127.0.0.1/feed.txt",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", raw, err)
		}
		if err := validateURL(u); err == nil {
			t.Errorf("%s 应被拒绝", raw)
		}
	}
	u, err := url.Parse("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
	if err != nil {
		t.Fatalf("解析白名单 URL 失败: %v", err)
	}
	if err := validateURL(u); err != nil {
		t.Errorf("白名单 https URL 应放行: %v", err)
	}
}
