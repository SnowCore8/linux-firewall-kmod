// Package sources 实现各威胁情报源的适配器。
package sources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
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

// parseIPList 解析纯 IP 列表（每行一个 IP 或 CIDR）。
func parseIPList(data []byte, source, category string, confidence float64, expiresAt time.Time) ([]FeedEntry, error) {
	var entries []FeedEntry
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

		// 尝试解析为 CIDR
		if prefix, err := netip.ParsePrefix(line); err == nil {
			entries = append(entries, FeedEntry{
				IP:         prefix,
				Source:     source,
				Category:   category,
				Confidence: confidence,
				ExpiresAt:  expiresAt,
			})
			return
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
	})
	if err != nil {
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
// ipsum 格式为 `IP\tCOUNT`（如 `45.148.10.151\t10`），需先按 Tab 分割取 IP 部分。
func (s *IpsumSource) Parse(data []byte) ([]FeedEntry, error) {
	expiresAt := time.Now().Add(25 * time.Hour)
	var entries []FeedEntry
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
		if addr, err := netip.ParseAddr(line); err == nil {
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			entries = append(entries, FeedEntry{
				IP:         netip.PrefixFrom(addr, bits),
				Source:     s.Name(),
				Category:   s.category,
				Confidence: s.confidence,
				ExpiresAt:  expiresAt,
			})
		}
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}
