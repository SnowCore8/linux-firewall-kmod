// Package logparse 提供「日志字节流 → 来源 IP」的解析原语：行分割、IP 提取、
// 正则规则集。
//
// 语义与 Rust 守护进程的 parse 模块逐条对齐：词边界判定、长度窗口、保留段拒绝、
// 正则捕获组从右往左扫描、关键字回退，均保持一致。本包不读全局状态，纯函数可重入。
package logparse

import "net/netip"

// IP 候选的长度窗口（字节，闭开区间）：短 IPv4 最短 7 字节（`0.0.0.0`），
// 完整 IPv6 最长 45 字节（`INET6_ADDRSTRLEN` - 1）。
const (
	minCandidateLen = 7
	maxCandidateLen = 46
)

// ExtractIP 从一行文本中提取第一个合法的、可作为封禁对象的 IP。
//
// 命中保留段时继续向后扫描（而非整体放弃）：一行里可能有 `from 127.0.0.1`
// 这类噪声在前、真实来源 IP 在后。
func ExtractIP(line string) (netip.Addr, bool) {
	for pos := 0; pos < len(line); {
		start, end, ok := findIPCandidate(line, pos)
		if !ok {
			return netip.Addr{}, false
		}
		if addr, ok := validateCandidate(line[start:end]); ok {
			return addr, true
		}
		pos = start + 1
	}
	return netip.Addr{}, false
}

// findIPCandidate 从 startFrom 起查找 IP 候选的字节范围。
//
// 词边界检查：候选前后字符不能是 hex / `.` / `:`，避免把长十六进制串或
// `1.2.3.4.5` 这类非 IP 片段误判成 IP。起点前一字节落在长 token 中间时，
// 从起点后移一位继续找。
func findIPCandidate(line string, startFrom int) (start, end int, ok bool) {
	i := startFrom
	for i < len(line) && !isHexDigit(line[i]) {
		i++
	}
	if i >= len(line) {
		return 0, 0, false
	}

	candidateStart := i
	if candidateStart > 0 {
		prev := line[candidateStart-1]
		if isHexDigit(prev) || prev == '.' || prev == ':' {
			return findIPCandidate(line, candidateStart+1)
		}
	}

	for i < len(line) && (isHexDigit(line[i]) || line[i] == '.' || line[i] == ':') {
		i++
	}
	if i < len(line) {
		next := line[i]
		if isHexDigit(next) || next == '.' || next == ':' {
			return findIPCandidate(line, candidateStart+1)
		}
	}
	return candidateStart, i, true
}

// validateCandidate 校验一个已通过词边界检查的候选串。
func validateCandidate(candidate string) (netip.Addr, bool) {
	if len(candidate) < minCandidateLen || len(candidate) >= maxCandidateLen {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return netip.Addr{}, false
	}
	if IsReserved(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}

// IsReserved 报告该地址是否属于「永不作为封禁对象」的保留段。
//
// 判据按地址族的字面形式走（不从 IPv4 映射地址还原）：v4 的 `0.0.0.0/8`、
// `127.0.0.0/8`、`224.0.0.0/4`、`255.255.255.255`；v6 的 `::`、`::1`、
// `ff00::/8`、`fe80::/10`。
func IsReserved(addr netip.Addr) bool {
	if addr.Is4() {
		return isReservedV4(addr.As4())
	}
	if !addr.Is6() {
		return false
	}
	a := addr.As16()
	switch a {
	case [16]byte{}: // ::      未指定
		return true
	case [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}: // ::1  环回
		return true
	}
	if a[0] == 0xff { // ff00::/8  组播
		return true
	}
	seg0 := uint16(a[0])<<8 | uint16(a[1])
	return seg0&0xffc0 == 0xfe80 // fe80::/10  链路本地
}

// isReservedV4 是 IPv4 保留段判据。
func isReservedV4(o [4]byte) bool {
	switch {
	case o[0] == 0: // 0.0.0.0/8「本网络」
		return true
	case o[0] == 255 && o[1] == 255 && o[2] == 255 && o[3] == 255: // 广播
		return true
	case o[0] == 127: // 环回
		return true
	case o[0] >= 224 && o[0] <= 239: // 组播
		return true
	}
	return false
}

// isHexDigit 判定 ASCII 十六进制字符，与 Rust 的 `is_ascii_hexdigit` 一致
// （不接受 Unicode 数字）。
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
