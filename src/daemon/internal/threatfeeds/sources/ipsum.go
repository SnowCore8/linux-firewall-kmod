// Package sources 实现各威胁情报源的适配器。
package sources

import (
	"bufio"
	"bytes"
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

// parseIPList 解析纯 IP 列表（每行一个 IP 或 CIDR）。
func parseIPList(data []byte, source, category string, confidence float64, expiresAt time.Time) ([]FeedEntry, error) {
	var entries []FeedEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 移除行内注释
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		// 尝试解析为 CIDR
		if prefix, err := netip.ParsePrefix(line); err == nil {
			entries = append(entries, FeedEntry{
				IP:         prefix,
				Source:     source,
				Category:   category,
				Confidence: confidence,
				ExpiresAt:  expiresAt,
			})
			continue
		}

		// 尝试解析为单个 IP
		if addr, err := netip.ParseAddr(line); err == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			entries = append(entries, FeedEntry{
				IP:         netip.PrefixFrom(addr, bits),
				Source:     source,
				Category:   category,
				Confidence: confidence,
				ExpiresAt:  expiresAt,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
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
func (s *IpsumSource) Parse(data []byte) ([]FeedEntry, error) {
	expiresAt := time.Now().Add(25 * time.Hour)
	return parseIPList(data, s.Name(), s.category, s.confidence, expiresAt)
}
