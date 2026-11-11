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
//
// 先 Unmap：`::ffff:1.2.3.4` 在 netip 里 BitLen 仍按 128 算，不折回 v4 就会得出 /128，
// 而下发侧 addrToWire 会把它按 AF_INET 发出去——前缀长度与前缀族对不上，内核直接拒绝。
func FullPrefixLen(addr netip.Addr) uint8 {
	if addr.Unmap().Is4() {
		return 32
	}
	return 128
}

// CanonicalIP 返回地址在镜像缓存与历史库里使用的规范键。
//
// IPv4 映射写法折回点分形式，IPv6 取压缩小写形式：同一主机只能有一个键。内核事件里的
// 地址由 addrFromWire 还原（同样归一），下发侧 addrToWire 也会 Unmap——只有这里也归一，
// 「手工封禁的键」与「内核回显的键」才是同一个，否则同一 IP 在表里出现两条、对账把一条
// 当幽灵抹掉。
func CanonicalIP(addr netip.Addr) string {
	return addr.Unmap().String()
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
// IPv4 映射写法（`::ffff:1.2.3.4`）先 Unmap 再按 IPv4 判据校验：它就是一个 IPv4 地址，
// 必须与点分写法得到同一条键、同一个 Num，且同样拒绝映射形式的回环/组播/链路本地。
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
	addr = addr.Unmap()
	if addr.Is4() {
		return ValidateIPv4(addr.String())
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
	// PrefixLen 是该封禁对应的前缀长度（IPv4 /32、IPv6 /128 为单机）。
	// 0 表示未知：解封时调用方须回退到 FullPrefixLen，否则网段封禁会被按单机解封。
	PrefixLen uint8
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

// PlannedDuration 返回这次封禁**计划**的时长（秒），永久封禁或读数不自洽时返回 nil。
//
// 它是 ban_events.duration_secs 的唯一来源（时长直方图读这一列）。用 nil 而不是 0：
// 0 在直方图里是「封了 0 秒」的一个真实桶，而永久封禁没有「时长」这个读数——把未知
// 和一个合法的极小值写成同一个数，面板就会把「不知道」画成一根柱子。
//
// ExpiresAt <= BannedAt 也归入 nil：那是「过期时刻不晚于封禁时刻」的不自洽数据
// （调用方构造 BanInfo 时的时序错误），按「没有时长」处理比按 0 秒处理更不容易被读成事实。
func (b BanInfo) PlannedDuration() *int64 {
	if b.IsPermanent || b.ExpiresAt <= b.BannedAt {
		return nil
	}
	d := b.ExpiresAt - b.BannedAt
	return &d
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
