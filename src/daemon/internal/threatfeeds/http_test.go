package threatfeeds

import (
	"net"
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
