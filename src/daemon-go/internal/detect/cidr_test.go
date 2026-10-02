package detect

import (
	"errors"
	"testing"
)

func TestNewCidrKeyMasksNetworkBits(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5/24":    "10.0.0.0/24",
		"10.0.0.0/24":    "10.0.0.0/24",
		"203.0.113.7/1":  "128.0.0.0/1",
		"2001:db8::5/48": "2001:db8::/48",
		"0.0.0.0/0":      "0.0.0.0/0",
		"::/0":           "::/0",
	}
	for in, want := range cases {
		if got := MustCidrKey(in).Key(); got != want {
			t.Errorf("解析 %q 得到 %q, want %q", in, got, want)
		}
	}
}

func TestParseCidrKeyNormalizesBareAddress(t *testing.T) {
	if got := MustCidrKey("10.1.2.3").Key(); got != "10.1.2.3/32" {
		t.Errorf("裸 IPv4 应归一为 /32: %q", got)
	}
	if got := MustCidrKey("2001:db8::1").Key(); got != "2001:db8::1/128" {
		t.Errorf("裸 IPv6 应归一为 /128: %q", got)
	}
	if got := MustCidrKey("  10.0.0.5/24  ").Key(); got != "10.0.0.0/24" {
		t.Errorf("两端空白应被忽略: %q", got)
	}
}

// 前缀超出位宽时向上收敛到 /32 或 /128（构造路径），文本解析路径则报错。
func TestCidrPrefixBounds(t *testing.T) {
	if got := NewCidrKey(ip(t, "10.0.0.5"), 40).Key(); got != "10.0.0.5/32" {
		t.Errorf("IPv4 前缀越界应收敛到 /32: %q", got)
	}
	if got := NewCidrKey(ip(t, "2001:db8::1"), 200).Key(); got != "2001:db8::1/128" {
		t.Errorf("IPv6 前缀越界应收敛到 /128: %q", got)
	}
	if _, err := ParseCidrKey("10.0.0.0/33"); !errors.Is(err, ErrCidrPrefixTooLarge) {
		t.Errorf("/33 应报前缀越界: %v", err)
	}
	if _, err := ParseCidrKey("2001:db8::/129"); !errors.Is(err, ErrCidrPrefixTooLarge) {
		t.Errorf("/129 应报前缀越界: %v", err)
	}
}

func TestParseCidrKeyRejections(t *testing.T) {
	cases := []struct {
		text string
		want error
	}{
		{"", ErrCidrEmpty},
		{"   ", ErrCidrEmpty},
		{"10.0.0.0/24/8", ErrCidrMultipleSlashes},
		{"not-an-ip/24", ErrCidrInvalidAddr},
		{"10.0.0.0/", ErrCidrInvalidPrefix},
		{"10.0.0.0/1x", ErrCidrInvalidPrefix},
		{"10.0.0.0/-1", ErrCidrInvalidPrefix},
	}
	for _, c := range cases {
		if _, err := ParseCidrKey(c.text); !errors.Is(err, c.want) {
			t.Errorf("解析 %q 错误=%v, want %v", c.text, err, c.want)
		}
	}
}

func TestCidrKeyAccessors(t *testing.T) {
	k := MustCidrKey("10.0.0.5/24")
	if k.PrefixLen() != 24 {
		t.Errorf("PrefixLen=%d, want 24", k.PrefixLen())
	}
	if got := k.Addr().String(); got != "10.0.0.0" {
		t.Errorf("Addr=%s, want 10.0.0.0", got)
	}
	if k.String() != k.Key() {
		t.Errorf("String 与 Key 应一致: %q vs %q", k.String(), k.Key())
	}
	if k.Prefix().String() != "10.0.0.0/24" {
		t.Errorf("Prefix=%s", k.Prefix())
	}
}

// 4-in-6 映射地址按 IPv6 处理（与 Rust 版一致，不做还原）：同一主机若以 v4 与 v4 映射
// 两种写法出现，会得到两个不同的键——这是与 Rust 版对齐的行为，不是缺陷。
func TestCidrKeyKeepsV4MappedAsIPv6(t *testing.T) {
	if got := MustCidrKey("::ffff:10.0.0.5/104").Key(); got != "::ffff:10.0.0.0/104" {
		t.Errorf("v4 映射地址应按 IPv6 归一: %q", got)
	}
}
