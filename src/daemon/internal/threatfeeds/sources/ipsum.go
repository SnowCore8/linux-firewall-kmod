// Package sources 实现各威胁情报源的适配器。
package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

// FeedEntry 是一条情报记录。
type FeedEntry struct {
	IP         netip.Prefix
	Source     string
	Category   string
	Confidence float64
	ExpiresAt  time.Time
}

// FeedSource 定义情报源接口。
type FeedSource interface {
	Name() string
	URL() string
	Parse(data []byte) ([]FeedEntry, error)
}

// maxFeedLineBytes 是单行长度上限。超长行（连同剩余部分）丢弃后继续，单行坏数据
// 不该让整个源失效；真正的读错误仍然返回。
const maxFeedLineBytes = 1 << 20

// forEachLine 逐行回调，回调收到的行已去掉行尾换行符。
func forEachLine(data []byte, fn func(string)) error {
	reader := bufio.NewReaderSize(bytes.NewReader(data), maxFeedLineBytes)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// 丢弃超长行的剩余部分，直到换行或读完。
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = reader.ReadSlice('\n')
			}
			if err == nil || errors.Is(err, io.EOF) {
				continue
			}
			return err
		}
		if len(line) > 0 {
			fn(strings.TrimRight(string(line), "\r\n"))
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

// 情报条目的前缀长度下限：IPv4 /8、IPv6 /16。
//
// 缓存按网段匹配（cache.go 的 Lookup 用前缀长度分桶），一条 /0 能命中任意源 IP；
// 而置信度 ≥ 0.8 的源命中即直封（runtime/pipeline.go 的 feedBanConfidence），
// 一条超宽网段会把受监视日志里首次出现的任意源 IP 全部封掉。
const (
	minIPv4PrefixBits = 8
	minIPv6PrefixBits = 16
)

// normalizePrefix 把 IPv4-mapped IPv6 前缀归一成 IPv4 前缀。
//
// 归一必须发生在长度与未指定判断之前：`::ffff:0.0.0.0/96` 的地址本身不是
// 未指定地址，但去掉映射前缀后就是 0.0.0.0/0；若不先 Unmap，它能以 /96 通过
// IPv6 长度下限，缓存再把它归一成 0.0.0.0/0 命中任意 IPv4。
//
// ok=false 表示前缀无效，或映射长度不足 /96（无法对应任何 IPv4 网段）。
func normalizePrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	if !prefix.Addr().Is4In6() {
		return prefix, true
	}
	bits := prefix.Bits() - 96
	if bits < 0 {
		return netip.Prefix{}, false
	}
	out := netip.PrefixFrom(prefix.Addr().Unmap(), bits)
	if !out.IsValid() {
		return netip.Prefix{}, false
	}
	return out, true
}

// IsUsablePrefix 报告前缀是否符合情报条目规则：归一成 IPv4 后至少 /8、IPv6 至少
// /16，且掩码后不是未指定网段。
//
// 缓存入口（threatfeeds/cache.go 的 Merge）也调用它做第二道防线，避免绕过适配器
// 直接写入的坏网段进入索引。
func IsUsablePrefix(prefix netip.Prefix) bool {
	return isUsablePrefix(prefix)
}

// isUsablePrefix 判断前缀是否足够窄、且不是未指定地址网段。
//
// 未指定地址按归一 + 掩码后判断，0.0.0.0/x 与 ::/x 的任何长度都算未指定，避免一条
// 0.0.0.0/8 借「长度合规」命中 0.0.0.0/8 内的所有地址。
func isUsablePrefix(prefix netip.Prefix) bool {
	prefix, ok := normalizePrefix(prefix)
	if !ok {
		return false
	}
	if prefix.Addr().IsUnspecified() || prefix.Masked().Addr().IsUnspecified() {
		return false
	}
	if prefix.Addr().Is4() {
		return prefix.Bits() >= minIPv4PrefixBits
	}
	return prefix.Bits() >= minIPv6PrefixBits
}

// parseFeedEntry 把一行文本解析为情报条目，是所有源适配器共用的唯一入口。
//
// ok=false 表示文本不是合法 IP/CIDR；rejected=true 表示语法合法但被前缀长度下限
// 或未指定网段规则拒绝，调用方据此计数上报，不静默丢弃。
func parseFeedEntry(text, source, category string, confidence float64, expiresAt time.Time) (FeedEntry, bool, bool) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil {
		addr, addrErr := netip.ParseAddr(text)
		if addrErr != nil {
			return FeedEntry{}, false, false
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		prefix = netip.PrefixFrom(addr, bits)
	}
	if !isUsablePrefix(prefix) {
		return FeedEntry{}, false, true
	}
	// 映射写法在入口就归一成 v4 形态，条目与缓存键、Lookup 的地址族保持一致。
	// isUsablePrefix 已确认可归一，这里的 ok 必为 true。
	normalized, _ := normalizePrefix(prefix)
	return FeedEntry{
		IP:         normalized,
		Source:     source,
		Category:   category,
		Confidence: confidence,
		ExpiresAt:  expiresAt,
	}, true, false
}

// logRejectedPrefixes 在本次解析有被前缀规则拒绝的条目时上报一次，避免逐行刷屏。
func logRejectedPrefixes(source string, rejected int) {
	if rejected == 0 {
		return
	}
	slog.Warn("情报源条目被前缀下限或未指定网段规则拒绝",
		"source", source,
		"count", rejected,
		"min_ipv4_bits", minIPv4PrefixBits,
		"min_ipv6_bits", minIPv6PrefixBits)
}

// parseIPList 解析纯 IP 列表（每行一个 IP 或 CIDR）。
func parseIPList(data []byte, source, category string, confidence float64, expiresAt time.Time) ([]FeedEntry, error) {
	var entries []FeedEntry
	rejected := 0
	err := forEachLine(data, func(raw string) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}

		// 移除行内注释
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			return
		}

		entry, ok, bad := parseFeedEntry(line, source, category, confidence, expiresAt)
		if bad {
			rejected++
		}
		if ok {
			entries = append(entries, entry)
		}
	})
	if err != nil {
		return nil, err
	}
	logRejectedPrefixes(source, rejected)
	return entries, nil
}

// IpsumSource 是 IPsum 情报源适配器。
type IpsumSource struct {
	url        string
	category   string
	confidence float64
}

// NewIpsumSource 创建 IPsum 源适配器。
func NewIpsumSource(url, category string, confidence float64) *IpsumSource {
	return &IpsumSource{url: url, category: category, confidence: confidence}
}

// Name 返回源名称。
func (s *IpsumSource) Name() string { return "ipsum" }

// URL 返回拉取地址。
func (s *IpsumSource) URL() string { return s.url }

// Parse 解析 IPsum 数据。
// ipsum 格式为 `IP\tCOUNT`（如 `45.148.10.151\t10`），需先按 Tab 分割取 IP 部分。
func (s *IpsumSource) Parse(data []byte) ([]FeedEntry, error) {
	expiresAt := time.Now().Add(25 * time.Hour)
	var entries []FeedEntry
	rejected := 0
	err := forEachLine(data, func(raw string) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}
		// ipsum 格式：IP\tCOUNT，取第一列
		if idx := strings.IndexByte(line, '\t'); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			return
		}
		entry, ok, bad := parseFeedEntry(line, s.Name(), s.category, s.confidence, expiresAt)
		if bad {
			rejected++
		}
		if ok {
			entries = append(entries, entry)
		}
	})
	if err != nil {
		return nil, err
	}
	logRejectedPrefixes(s.Name(), rejected)
	return entries, nil
}
