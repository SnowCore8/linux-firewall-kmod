package logparse

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("测试用 IP 非法 %q: %v", s, err)
	}
	return a
}

func TestExtractIPv4FromSSHLog(t *testing.T) {
	line := "Jun 11 15:30:00 host sshd[1]: Failed password for root from 192.168.1.100 port 22"
	got, ok := ExtractIP(line)
	if !ok {
		t.Fatalf("应提取出 IP")
	}
	if got != mustAddr(t, "192.168.1.100") {
		t.Fatalf("提取结果错误: %v", got)
	}
}

func TestExtractIPv6(t *testing.T) {
	got, ok := ExtractIP("from 2001:db8::1 port 22")
	if !ok || got != mustAddr(t, "2001:db8::1") {
		t.Fatalf("IPv6 提取失败: ok=%v got=%v", ok, got)
	}
}

func TestExtractSkipsReservedAndKeepsScanning(t *testing.T) {
	got, ok := ExtractIP("from 127.0.0.1 then from 10.0.0.1")
	if !ok || got != mustAddr(t, "10.0.0.1") {
		t.Fatalf("应跳过环回并继续扫描: ok=%v got=%v", ok, got)
	}
	if _, ok := ExtractIP("from ::1 port 22"); ok {
		t.Fatalf("::1 是保留段，不应被提取")
	}
	if _, ok := ExtractIP("no ip here"); ok {
		t.Fatalf("无 IP 的行不应有提取结果")
	}
}

func TestExtractRejectsMalformedShapes(t *testing.T) {
	for _, line := range []string{"1.2.3.4.5", "deadbeef1.2.3.4", "from 1.2.3"} {
		if got, ok := ExtractIP(line); ok {
			t.Fatalf("畸形输入 %q 不应提取出 IP，却得到 %v", line, got)
		}
	}
}

func TestReservedPredicateMatchesLegacySet(t *testing.T) {
	reserved := []string{
		"0.0.0.0", "0.1.2.3", "127.0.0.1", "224.0.0.1", "239.255.255.255",
		"255.255.255.255", "::1", "::", "ff02::1", "fe80::1",
	}
	for _, s := range reserved {
		if !IsReserved(mustAddr(t, s)) {
			t.Errorf("%s 应判为保留段", s)
		}
	}
	global := []string{"10.0.0.1", "192.168.1.100", "1.1.1.1", "2001:db8::1"}
	for _, s := range global {
		if IsReserved(mustAddr(t, s)) {
			t.Errorf("%s 不应判为保留段", s)
		}
	}
}

// `[203.0.113.50:12345]` 的 `host:port` 是**一个** token：提取层把它整体交给地址
// 解析并因无法解析而放弃。带端口的形态只由 jail 正则的捕获组命中（捕获组不含端口），
// 提取层不做「去掉端口再试」的猜测。
func TestExtractDoesNotSplitHostPort(t *testing.T) {
	if got, ok := ExtractIP("get a user connection [203.0.113.50:12345]"); ok {
		t.Fatalf("host:port 不应被提取层切出地址，却得到 %v", got)
	}
	// 端口与地址之间被非 IP 字符隔开时，提取层照常切出地址。
	if got, ok := ExtractIP("get a user connection from 203.0.113.50 port 12345"); !ok ||
		got != mustAddr(t, "203.0.113.50") {
		t.Fatalf("空格分隔的 host/port 应切出地址: ok=%v got=%v", ok, got)
	}
}
