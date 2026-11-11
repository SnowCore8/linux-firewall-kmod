package netports

import (
	"math/bits"
	"os"
	"path/filepath"
	"testing"
)

const (
	tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tcpRowFmt = "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001\n"
)

func writeTable(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("写入测试表 %s 失败: %v", name, err)
	}
}

func portSet(bmp [8192]byte, port uint16) bool {
	return bmp[port/8]&(1<<(port%8)) != 0
}

func countSet(bmp [8192]byte) int {
	n := 0
	for _, b := range bmp {
		n += bits.OnesCount8(b)
	}
	return n
}

// 端口位是否与期望一致：期望端口置位，其余全部清零，总数匹配。
func assertPorts(t *testing.T, bmp [8192]byte, count int, want ...uint16) {
	t.Helper()
	wantSet := make(map[uint16]bool, len(want))
	for _, p := range want {
		wantSet[p] = true
		if !portSet(bmp, p) {
			t.Errorf("端口 %d 应置位但未置位", p)
		}
	}
	for p := 0; p < 65536; p++ {
		if !wantSet[uint16(p)] && portSet(bmp, uint16(p)) {
			t.Errorf("端口 %d 不应置位但已置位", p)
		}
	}
	if got := countSet(bmp); got != len(want) {
		t.Errorf("实际置位数 %d，期望 %d", got, len(want))
	}
	if count != len(want) {
		t.Errorf("返回计数 %d，期望 %d", count, len(want))
	}
}

func TestTCPListenIncludedEstablishedExcluded(t *testing.T) {
	dir := t.TempDir()
	writeTable(t, dir, "tcp", tcpHeader+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001\n"+
		"   1: 0100007F:0016 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 1002\n"+
		"   2: 0200000A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1003\n")

	bmp, count, err := ListeningPorts(dir)
	if err != nil {
		t.Fatalf("ListeningPorts 返回错误: %v", err)
	}
	// 22（通配）、8080（10.0.0.2）入选；已建立连接与回环地址排除。
	assertPorts(t, bmp, count, 22, 8080)
}

func TestUDPBoundIncluded(t *testing.T) {
	dir := t.TempDir()
	writeTable(t, dir, "udp", tcpHeader+
		"   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2001\n"+
		"   1: 00000000:0036 0100007F:0035 07 00000000:00000000 00:00000000 00000000     0        0 2002\n"+
		"   2: 0100007F:0037 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2003\n"+
		"   3: 0200000A:0038 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2004\n")

	bmp, count, err := ListeningPorts(dir)
	if err != nil {
		t.Fatalf("ListeningPorts 返回错误: %v", err)
	}
	// 53（通配）、56（10.0.0.2）入选；已连接 socket 与回环地址排除。
	assertPorts(t, bmp, count, 53, 56)
}

func TestIPv6LoopbackExcludedWildcardIncluded(t *testing.T) {
	dir := t.TempDir()
	writeTable(t, dir, "tcp6", tcpHeader+
		"   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3001\n"+
		"   1: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3002\n")
	writeTable(t, dir, "udp6", tcpHeader+
		"   0: 00000000000000000000000000000000:0222 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3003\n"+
		"   1: 00000000000000000000000001000000:0223 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 3004\n")

	bmp, count, err := ListeningPorts(dir)
	if err != nil {
		t.Fatalf("ListeningPorts 返回错误: %v", err)
	}
	// IPv6 通配地址入选；::1 上仅绑定的端口排除。
	assertPorts(t, bmp, count, 22, 546)
}

func TestMalformedLinesIgnored(t *testing.T) {
	dir := t.TempDir()
	writeTable(t, dir, "tcp", tcpHeader+
		"  垃圾行\n"+
		"   0: 不是地址 00000000:0000 0A\n"+
		"   1: 00000000:ZZZZ 00000000:0000 0A\n"+
		"   2: 00000000:0000 00000000:0000 0A\n"+
		"   3: 00000000:0016\n"+
		"   4: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4001\n")

	bmp, count, err := ListeningPorts(dir)
	if err != nil {
		t.Fatalf("ListeningPorts 返回错误: %v", err)
	}
	assertPorts(t, bmp, count, 22)
}

func TestMissingIPv6TablesTolerated(t *testing.T) {
	dir := t.TempDir()
	writeTable(t, dir, "tcp", tcpHeader+tcpRowFmt)

	bmp, count, err := ListeningPorts(dir)
	if err != nil {
		t.Fatalf("缺少 IPv6 表不应报错: %v", err)
	}
	assertPorts(t, bmp, count, 22)
}

func TestAllTablesMissingReturnsError(t *testing.T) {
	if _, _, err := ListeningPorts(t.TempDir()); err == nil {
		t.Fatal("四张表全部缺失时应返回错误")
	}
}
