// Package netports 从 /proc/net 的套接字表提取本地监听端口位图。
//
// 位图格式与 netlink 报文 SetProtectedPorts 一致：位 i 置位表示端口 i
// 可接收外部流量，共 65536 位、8192 字节。
package netports

import (
	"bufio"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// 套接字状态字段（hex）。
	stateTCPListen      = "0A"
	stateUDPUnconnected = "07"

	// 回环地址：IPv4 为小端序，IPv6 为全零前缀 + 末尾 1。
	loopbackV4 = "0100007F"
	loopbackV6 = "00000000000000000000000001000000"
)

// procTables 是需要扫描的套接字表，顺序即扫描顺序。
var procTables = []string{"tcp", "tcp6", "udp", "udp6"}

// ListeningPorts 扫描 procNetDir（通常为 "/proc/net"）下的 tcp、tcp6、udp、udp6，
// 返回可接收外部流量的本地监听/绑定端口位图，以及置位数量。
//
// 文件缺失不算错误（IPv6 表可能不存在）；四个文件全部不可读时返回错误。
func ListeningPorts(procNetDir string) ([8192]byte, int, error) {
	var bmp [8192]byte
	readable := 0

	for _, name := range procTables {
		f, err := os.Open(filepath.Join(procNetDir, name))
		if err != nil {
			// 缺表视为空表；其余打开错误同样跳过，由 readable 判定是否全不可读。
			continue
		}
		readable++

		// tcp/udp 是 IPv4，tcp6/udp6 是 IPv6；两者解析规则相同。
		isUDP := strings.HasPrefix(name, "udp")
		err = scanTable(f, isUDP, &bmp)

		ferr := f.Close()
		if err == nil {
			err = ferr
		}
		if err != nil {
			return [8192]byte{}, 0, fmt.Errorf("netports: 读取 %s 失败: %w", name, err)
		}
	}

	if readable == 0 {
		return [8192]byte{}, 0, fmt.Errorf("netports: %s 下没有任何可读的套接字表", procNetDir)
	}

	count := 0
	for _, b := range bmp {
		count += bits.OnesCount8(b)
	}
	return bmp, count, nil
}

// scanTable 逐行解析单张套接字表，把命中的端口写入 bmp。
func scanTable(f *os.File, isUDP bool, bmp *[8192]byte) error {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// 表头与残缺行字段不足，直接忽略。
		if len(fields) < 4 {
			continue
		}

		state := fields[3]
		if isUDP {
			// 只收已绑定未连接的服务端 socket：状态 07 且对端地址全零。
			remoteAddr, _, ok := splitAddrPort(fields[2])
			if !ok || !strings.EqualFold(state, stateUDPUnconnected) || !isZeroAddr(remoteAddr) {
				continue
			}
		} else if !strings.EqualFold(state, stateTCPListen) {
			continue
		}

		localAddr, localPort, ok := splitAddrPort(fields[1])
		if !ok {
			continue
		}
		if isLoopback(localAddr) {
			continue
		}
		if localPort == 0 {
			continue
		}
		bmp[localPort/8] |= 1 << (localPort % 8)
	}
	return scanner.Err()
}

// splitAddrPort 拆分 "HEXADDR:HEXPORT"，端口按 16 位十六进制解析。
func splitAddrPort(s string) (addr string, port uint16, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	v, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return "", 0, false
	}
	return s[:i], uint16(v), true
}

// isZeroAddr 判断地址字段是否全零（udp 的未连接对端、IPv4/IPv6 通配地址）。
func isZeroAddr(addr string) bool {
	for _, r := range addr {
		if r != '0' {
			return false
		}
	}
	return addr != ""
}

// isLoopback 判断本地地址是否仅绑定回环。
func isLoopback(addr string) bool {
	return strings.EqualFold(addr, loopbackV4) || strings.EqualFold(addr, loopbackV6)
}
