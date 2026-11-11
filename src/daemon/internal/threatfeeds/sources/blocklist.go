package sources

import "time"

// BlocklistSource 是 Blocklist.de 情报源适配器。
type BlocklistSource struct {
	url        string
	category   string
	confidence float64
}

// NewBlocklistSource 创建 Blocklist.de 源适配器。
func NewBlocklistSource(url, category string, confidence float64) *BlocklistSource {
	return &BlocklistSource{url: url, category: category, confidence: confidence}
}

// Name 返回源名称。
func (s *BlocklistSource) Name() string { return "blocklist_de" }

// URL 返回拉取地址。
func (s *BlocklistSource) URL() string { return s.url }

// Parse 解析 Blocklist.de 数据。
//
// TTL 取 25 小时，与其余源同量级：默认 refresh_interval 是 24 小时，TTL 若短于
// 刷新间隔，条目会在下一轮拉取前集体过期、判定层跳过，而面板仍显示同步成功。
func (s *BlocklistSource) Parse(data []byte) ([]FeedEntry, error) {
	expiresAt := time.Now().Add(25 * time.Hour)
	return parseIPList(data, s.Name(), s.category, s.confidence, expiresAt)
}
