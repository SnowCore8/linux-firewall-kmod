// 白名单前缀的文本形态：把「CIDR 或裸 IP」两种写法折成与内核同一个形状的键。
//
// 归一化收在这一处，写入侧的三条路径（HTTP 添加、启动时下发配置里的可信地址、镜像重建）
// 才不会出现两个键——缺陷 HTTP_WHITELIST_KEY_DIVERGENCE 记的正是「同一个子网有两个键」。
package bans

import (
	"net/netip"
)

// NormalizeWhitelistPrefix 把 IPv4 映射前缀（::ffff:10.0.0.0/104 这类）折成 IPv4 本体。
//
// 不归一会有两份键：镜像里存 "::ffff:10.0.0.0/104"，而内核按 AF_INET 回显同一条规则时
// 事件泵算出的是 "10.0.0.0/32"（kernel/consumer.go 的 prefixFromAddr 从线格式的
// af+addr+prefix_len 重建）——同一条白名单在表里出现两次，删除只能打中其中一条。
// 前缀长度不足 96 的映射写法（::ffff:0:0/8）不是「一个 IPv4 前缀」，保持原样。
func NormalizeWhitelistPrefix(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr()
	if addr.Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	return prefix
}

// WhitelistPrefixFromText 把「CIDR 或裸 IP」折成一个已归一的前缀。
//
// 裸 IP 的主机位长度必须由地址自己决定：写死 32 会让 IPv6 的 /128 变成非法前缀，
// 而调用方不该关心这次输入是 v4 还是 v6。
func WhitelistPrefixFromText(text string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return NormalizeWhitelistPrefix(prefix), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() || addr.Is4In6() {
		return netip.PrefixFrom(addr.Unmap(), 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}
