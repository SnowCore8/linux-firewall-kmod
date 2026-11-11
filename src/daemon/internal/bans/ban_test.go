package bans

import (
	"net/netip"
	"testing"
)

// 4-in-6 写法必须是「一个 IPv4 地址」：前缀长度、缓存键、Num 都与点分写法一致，
// 否则下发的前缀族与长度对不上，或同一主机在镜像里分裂成两条。
func TestMappedFormIsIPv4Everywhere(t *testing.T) {
	const dotted = "203.0.113.9"
	v4, err := ValidateIP(dotted)
	if err != nil {
		t.Fatalf("点分写法校验失败: %v", err)
	}
	mapped, err := ValidateIP("::ffff:" + dotted)
	if err != nil {
		t.Fatalf("映射写法校验失败: %v", err)
	}
	if !mapped.Addr.Is4() {
		t.Fatalf("映射写法的 Addr 未折回 IPv4: %v", mapped.Addr)
	}
	if got := CanonicalIP(mapped.Addr); got != dotted {
		t.Fatalf("映射写法的规范键 = %s，期望 %s", got, dotted)
	}
	if mapped.Num != v4.Num {
		t.Fatalf("映射写法 Num = %d，期望与点分写法一致（%d）", mapped.Num, v4.Num)
	}
	if got := FullPrefixLen(mapped.Addr); got != 32 {
		t.Fatalf("映射写法前缀长度 = %d，期望 32", got)
	}
	if got := FullPrefixLen(netip.MustParseAddr("2001:db8::1")); got != 128 {
		t.Fatalf("IPv6 前缀长度 = %d，期望 128", got)
	}
}

// 映射写法的保留地址要按 IPv4 判据拒绝：::ffff:127.0.0.1 就是 127.0.0.1。
func TestMappedReservedAddressesRejected(t *testing.T) {
	for _, s := range []string{"::ffff:127.0.0.1", "::ffff:169.254.1.1", "::ffff:224.0.0.1"} {
		if _, err := ValidateIP(s); err == nil {
			t.Fatalf("%s 应被拒绝", s)
		}
	}
}

// IPv6 的多种文本写法折到同一个规范键。
func TestCanonicalIPCollapsesIPv6Spellings(t *testing.T) {
	expanded := netip.MustParseAddr("2001:0db8:0000:0000:0000:0000:0000:0001")
	if got := CanonicalIP(expanded); got != "2001:db8::1" {
		t.Fatalf("规范键 = %s，期望 2001:db8::1", got)
	}
}
