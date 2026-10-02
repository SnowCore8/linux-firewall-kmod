// Package bans 承载封禁的内存模型：单条封禁信息、IP 校验、活跃封禁缓存。
//
// 旧实现把这三样与进程级全局态（单个 static 缓存、pending ack 集合、通知通道）绑在
// 一起，导致同一份逻辑无法在测试里独立存在。这里把它们做成可构造的结构体与纯函数，
// 全局单例留给组合根持有。
package bans

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// ValidatedIP 是校验通过的地址描述。
type ValidatedIP struct {
	// Addr 是标准库地址表示。
	Addr netip.Addr
	// Num 仅 IPv4 有效（主机序整数，与旧实现一致），IPv6 为 0。
	Num uint32
}

// FullPrefixLen 返回单机封禁应使用的完整前缀长度：IPv4 为 /32、IPv6 为 /128。
func FullPrefixLen(addr netip.Addr) uint8 {
	if addr.Is4() {
		return 32
	}
	return 128
}

// ValidateIPv4 校验 IPv4 文本；拒绝长度越界与保留段。
//
// 拒绝段与旧实现逐条一致：0.0.0.0、255.255.255.255、127/8、224–239/4、169.254/16。
func ValidateIPv4(text string) (ValidatedIP, error) {
	// INET_ADDRSTRLEN = 16。
	if text == "" || len(text) >= 16 {
		return ValidatedIP{}, fmt.Errorf("invalid IPv4 length")
	}
	addr, err := netip.ParseAddr(text)
	if err != nil || !addr.Is4() {
		return ValidatedIP{}, fmt.Errorf("invalid IPv4: %q", text)
	}
	o := addr.As4()
	first, second := o[0], o[1]
	// Num 用主机序整数，等价于旧实现的 from_ne_bytes：同一段内存按本机字节序读成 u32。
	num := nativeUint32(o)
	if num == 0 || num == 0xFFFF_FFFF || first == 127 || (first >= 224 && first <= 239) || (first == 169 && second == 254) {
		return ValidatedIP{}, fmt.Errorf("rejected IPv4 address: %s (loopback/broadcast/multicast/link-local)", text)
	}
	return ValidatedIP{Addr: addr, Num: num}, nil
}

// ValidateIP 校验通用 IP：先试 IPv4，再试 IPv6。
//
// IPv6 额外拒绝 loopback / multicast / unspecified / link-local（fe80::/10）。
func ValidateIP(text string) (ValidatedIP, error) {
	// INET6_ADDRSTRLEN = 46。
	if text == "" || len(text) >= 46 {
		return ValidatedIP{}, fmt.Errorf("invalid IP length")
	}
	if v, err := ValidateIPv4(text); err == nil {
		return v, nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil || !addr.Is6() {
		return ValidatedIP{}, fmt.Errorf("invalid IP: %q", text)
	}
	b := addr.As16()
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() || (b[0]&0xFF == 0xFE && b[1]&0xC0 == 0x80) {
		return ValidatedIP{}, fmt.Errorf("rejected IPv6 address: %s (loopback/multicast/unspecified/link-local)", text)
	}
	return ValidatedIP{Addr: addr, Num: 0}, nil
}

// nativeUint32 按本机字节序把 4 字节读成 u32，复刻旧实现的 from_ne_bytes。
func nativeUint32(b [4]byte) uint32 {
	if isBigEndian {
		return binary.BigEndian.Uint32(b[:])
	}
	return binary.LittleEndian.Uint32(b[:])
}

// BanInfo 是单条封禁的完整信息。
type BanInfo struct {
	// IP 是地址文本表示（IPv4 或 IPv6）。
	IP string
	// Num 仅 IPv4 有效（主机序），IPv6 为 0。
	Num uint32
	// JailName 是触发封禁的 jail 名。
	JailName string
	// Reason 是封禁原因（旧前端「原因」列显示的就是它）。
	Reason string
	// BannedAt 是封禁时刻（Unix 秒）。
	BannedAt int64
	// ExpiresAt 是过期时刻（Unix 秒），0 表示永久。
	ExpiresAt int64
	// IsPermanent 报告是否永久封禁。
	IsPermanent bool
	// FailCount 是触发封禁前的失败次数。
	FailCount uint32
	// BanCount 是该 IP 累计被封禁次数。
	BanCount uint32
}

// IsExpired 判断封禁是否已过期（永久封禁永不过期）。
func (b BanInfo) IsExpired(now int64) bool {
	return !b.IsPermanent && b.ExpiresAt > 0 && now >= b.ExpiresAt
}

// DurationSecs 计算封禁持续时长（秒）。
func (b BanInfo) DurationSecs(now int64) int64 {
	if b.IsPermanent || b.ExpiresAt == 0 {
		return now - b.BannedAt
	}
	return b.ExpiresAt - b.BannedAt
}
