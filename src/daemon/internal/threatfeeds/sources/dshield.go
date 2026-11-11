package sources

import (
	"strings"
	"time"
)

// parseTSV 解析 TSV 格式（Tab 分隔），用于 DShield 等。
func parseTSV(data []byte, source, category string, confidence float64, expiresAt time.Time) ([]FeedEntry, error) {
	var entries []FeedEntry
	rejected := 0
	err := forEachLine(data, func(raw string) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 1 {
			return
		}

		ipStr := strings.TrimSpace(fields[0])
		if ipStr == "" {
			return
		}

		entry, ok, bad := parseFeedEntry(ipStr, source, category, confidence, expiresAt)
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

// DShieldSource 是 DShield 情报源适配器。
type DShieldSource struct {
	url        string
	category   string
	confidence float64
}

// NewDShieldSource 创建 DShield 源适配器。
func NewDShieldSource(url, category string, confidence float64) *DShieldSource {
	return &DShieldSource{url: url, category: category, confidence: confidence}
}

// Name 返回源名称。
func (s *DShieldSource) Name() string { return "dshield" }

// URL 返回拉取地址。
func (s *DShieldSource) URL() string { return s.url }

// Parse 解析 DShield 数据。
func (s *DShieldSource) Parse(data []byte) ([]FeedEntry, error) {
	expiresAt := time.Now().Add(25 * time.Hour)
	return parseTSV(data, s.Name(), s.category, s.confidence, expiresAt)
}
