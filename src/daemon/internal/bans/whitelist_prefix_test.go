package bans

import (
	"net/netip"
	"testing"
)

func TestWhitelistPrefixFromTextFoldsBothSpellings(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"203.0.113.7", "203.0.113.7/32"},
		{"10.0.0.1/8", "10.0.0.1/8"},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8"},
		{"2001:db8::1", "2001:db8::1/128"},
		// 映射写法但前缀长度不足 96：这不是「一个 IPv4 前缀」，保持原样交给内核判断。
		{"::ffff:0:0/8", "::ffff:0:0/8"},
	}
	for _, tc := range cases {
		got, err := WhitelistPrefixFromText(tc.text)
		if err != nil {
			t.Errorf("%q 解析失败: %v", tc.text, err)
			continue
		}
		// 这一层只负责「同一个子网只有一个形状」，主机位由调用方掩掉（Masked 是写入侧
		// 的下一步，两层分开才能各自被测出来）。按前缀本身比，不按文本比：同一个地址
		// 的 ::ffff:0:0 与 ::ffff:0.0.0.0 两种书写在 Go 的 String() 里就是一种。
		if want := netip.MustParsePrefix(tc.want); got != want {
			t.Errorf("%q 归一为 %s，期望 %s", tc.text, got, want)
		}
	}
}

func TestWhitelistPrefixFromTextRejectsNonAddress(t *testing.T) {
	for _, text := range []string{"", "10.0.0.0/33", "not-an-ip"} {
		if _, err := WhitelistPrefixFromText(text); err == nil {
			t.Errorf("%q 被接受了，期望解析失败", text)
		}
	}
}

func TestNormalizeWhitelistPrefixLeavesIPv6Alone(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/32")
	if got := NormalizeWhitelistPrefix(prefix); got != prefix {
		t.Errorf("IPv6 前缀被改写: %s → %s", prefix, got)
	}
}
