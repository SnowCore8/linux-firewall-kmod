package detect

import (
	"errors"
	"net/netip"
	"strings"
)

// CIDR 文本解析的错误取值。
var (
	// ErrCidrEmpty 表示输入为空白。
	ErrCidrEmpty = errors.New("CIDR 文本为空")
	// ErrCidrMultipleSlashes 表示出现多个 `/`。
	ErrCidrMultipleSlashes = errors.New("CIDR 文本含多个 /")
	// ErrCidrInvalidAddr 表示地址部分无法解析。
	ErrCidrInvalidAddr = errors.New("CIDR 地址部分非法")
	// ErrCidrInvalidPrefix 表示前缀部分不是十进制数。
	ErrCidrInvalidPrefix = errors.New("CIDR 前缀部分非法")
	// ErrCidrPrefixTooLarge 表示前缀超出该地址族的位宽。
	ErrCidrPrefixTooLarge = errors.New("CIDR 前缀超出地址族位宽")
)

// CidrKey 是归一化后的 CIDR 键：网络地址 + 前缀，且网络位已置零。
//
// 零值不可用；只能经 NewCidrKey 或 ParseCidrKey 构造，因此「未归一化的键」在类型
// 层面不可表示。键的稳定文本形式为 `{network}/{prefix}`：`10.0.0.5/24` 与 `10.0.0.0/24`
// 归一为同一键；裸地址按 `/32` 或 `/128` 归一；`0.0.0.0/0` 与 `::/0` 原样保留。
type CidrKey struct {
	key string
}

// NewCidrKey 由地址与前缀长度构造归一化键。前缀超出该地址族位宽时收敛到 /32 或 /128
// （不报错），因为调用方（集群聚合、netlink 回包）传的前缀越界时按「全主机」处理这一
// 退化行为需要可预测，而不是生成一个永远匹配不上的键。
//
// 地址族按字面形式判定（与 Rust 版一致）：IPv4 映射地址（`::ffff:a.b.c.d`）仍按 IPv6
// 处理，不做还原。
func NewCidrKey(addr netip.Addr, prefix uint8) CidrKey {
	maxBits := uint8(128)
	if addr.Is4() {
		maxBits = 32
	}
	if prefix > maxBits {
		prefix = maxBits
	}
	p := netip.PrefixFrom(addr, int(prefix)).Masked()
	return CidrKey{key: p.String()}
}

// ParseCidrKey 解析 CIDR 文本并归一化。裸地址按 `/32` 或 `/128` 归一。
func ParseCidrKey(text string) (CidrKey, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return CidrKey{}, ErrCidrEmpty
	}
	slashCount := strings.Count(s, "/")
	if slashCount > 1 {
		return CidrKey{}, ErrCidrMultipleSlashes
	}

	addrPart := s
	prefixPart := ""
	if slashCount == 1 {
		idx := strings.IndexByte(s, '/')
		addrPart = s[:idx]
		prefixPart = s[idx+1:]
	}

	addr, err := netip.ParseAddr(addrPart)
	if err != nil {
		return CidrKey{}, ErrCidrInvalidAddr
	}

	maxBits := uint8(128)
	if addr.Is4() {
		maxBits = 32
	}

	if slashCount == 0 {
		return NewCidrKey(addr, maxBits), nil
	}

	prefix, err := parsePrefixNumber(prefixPart)
	if err != nil {
		return CidrKey{}, err
	}
	if prefix > maxBits {
		return CidrKey{}, ErrCidrPrefixTooLarge
	}
	return NewCidrKey(addr, prefix), nil
}

// MustCidrKey 是 ParseCidrKey 的测试与常量场景简写：解析失败直接 panic。
func MustCidrKey(text string) CidrKey {
	k, err := ParseCidrKey(text)
	if err != nil {
		panic("非法 CIDR 文本: " + text + ": " + err.Error())
	}
	return k
}

// parsePrefixNumber 解析前缀部分，拒绝空串、前导 `+`/`-` 与非数字字符。
func parsePrefixNumber(s string) (uint8, error) {
	if s == "" {
		return 0, ErrCidrInvalidPrefix
	}
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, ErrCidrInvalidPrefix
		}
		n = n*10 + uint32(c-'0')
		if n > 128 {
			// 立即判定越界，避免超长数字串溢出。
			return 0, ErrCidrPrefixTooLarge
		}
	}
	return uint8(n), nil
}

// Key 返回归一化后的稳定文本形式 `{network}/{prefix}`。
func (k CidrKey) Key() string { return k.key }

// String 实现 fmt.Stringer，输出与 Key 相同。
func (k CidrKey) String() string { return k.key }

// Prefix 把键还原为 netip.Prefix。键始终非零值且已归一化。
func (k CidrKey) Prefix() netip.Prefix {
	p, err := netip.ParsePrefix(k.key)
	if err != nil {
		// 键只可能由本包构造，故此处不可达；panic 而非返回零值，避免静默产出错误数据。
		panic("CidrKey 内部文本非法: " + k.key)
	}
	return p
}

// Addr 返回键中的网络地址。
func (k CidrKey) Addr() netip.Addr { return k.Prefix().Addr() }

// PrefixLen 返回前缀长度。
func (k CidrKey) PrefixLen() int { return k.Prefix().Bits() }

// SubnetKey 返回 addr 在给定前缀长度下的聚合网段键（集群扫描检测用）。
func SubnetKey(addr netip.Addr, prefix uint8) CidrKey {
	return NewCidrKey(addr, prefix)
}
