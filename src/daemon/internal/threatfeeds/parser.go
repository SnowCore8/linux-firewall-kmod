package threatfeeds

import (
	"bufio"
	"bytes"
	"net/netip"
	"strings"
	"time"
)

// StripComments 移除行首的 # 注释，返回清理后的行。
func StripComments(line string) string {
	idx := strings.Index(line, "#")
	if idx < 0 {
		return line
	}
	return line[:idx]
}

// ParseIPList 解析纯 IP 列表（每行一个 IP 或 CIDR）。
//
// 忽略空行和注释行（# 开头）。
func ParseIPList(data []byte, sourceName, category string, confidence float64, expiresAt time.Time) ([]FeedEntry, error) {
	var entries []FeedEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 移除行内注释
		line = StripComments(line)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 尝试解析为 CIDR
		if prefix, err := netip.ParsePrefix(line); err == nil {
			entries = append(entries, FeedEntry{
				IP:         prefix,
				Source:     sourceName,
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
				Source:     sourceName,
				Category:   category,
				Confidence: confidence,
				ExpiresAt:  expiresAt,
			})
			continue
		}

		// 解析失败，跳过该行
		continue
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}
