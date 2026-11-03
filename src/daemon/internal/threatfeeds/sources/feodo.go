package sources

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
	"time"
)

// parseCSV 解析 CSV 格式，用于 Feodo Tracker 等。
// Feodo 格式：First seen,IP address,Port,Domain,Malware,Status
func parseCSV(data []byte, source, category string, confidence float64, expiresAt time.Time) ([]FeedEntry, error) {
	var entries []FeedEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 跳过表头
		if strings.HasPrefix(strings.ToLower(line), "first_seen") || strings.HasPrefix(strings.ToLower(line), "# first") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}

		// Feodo 格式：IP 在第二列（索引 1）
		ipStr := strings.TrimSpace(fields[1])
		if ipStr == "" {
			continue
		}

		if addr, err := netip.ParseAddr(ipStr); err == nil {
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

// FeodoSource 是 Feodo Tracker 情报源适配器。
type FeodoSource struct {
	url        string
	category   string
	confidence float64
}

// NewFeodoSource 创建 Feodo Tracker 源适配器。
func NewFeodoSource(url, category string, confidence float64) *FeodoSource {
	return &FeodoSource{url: url, category: category, confidence: confidence}
}

// Name 返回源名称。
func (s *FeodoSource) Name() string { return "feodo" }

// URL 返回拉取地址。
func (s *FeodoSource) URL() string { return s.url }

// Parse 解析 Feodo Tracker 数据。
func (s *FeodoSource) Parse(data []byte) ([]FeedEntry, error) {
	expiresAt := time.Now().Add(25 * time.Hour)
	return parseCSV(data, s.Name(), s.category, s.confidence, expiresAt)
}
