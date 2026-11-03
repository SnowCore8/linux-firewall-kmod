package sources

import "time"

// FireHOLSource 是 FireHOL 情报源适配器。
type FireHOLSource struct {
	url        string
	category   string
	confidence float64
}

// NewFireHOLSource 创建 FireHOL 源适配器。
func NewFireHOLSource(url, category string, confidence float64) *FireHOLSource {
	return &FireHOLSource{url: url, category: category, confidence: confidence}
}

// Name 返回源名称。
func (s *FireHOLSource) Name() string { return "firehol" }

// URL 返回拉取地址。
func (s *FireHOLSource) URL() string { return s.url }

// Parse 解析 FireHOL 数据。
func (s *FireHOLSource) Parse(data []byte) ([]FeedEntry, error) {
	expiresAt := time.Now().Add(25 * time.Hour)
	return parseIPList(data, s.Name(), s.category, s.confidence, expiresAt)
}
