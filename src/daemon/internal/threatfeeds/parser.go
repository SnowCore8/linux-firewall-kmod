package threatfeeds

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"
)

// maxFeedLineBytes 是情报源的单行上限：1 MiB。
//
// 情报源里偶发的一行超长内容（被污染的 CSV 行、混进来的二进制）不该让整份列表作废：
// 超限行按非法内容跳过，其余行照常解析。
const maxFeedLineBytes = 1 << 20

// StripComments 移除行首的 # 注释，返回清理后的行。
func StripComments(line string) string {
	idx := strings.Index(line, "#")
	if idx < 0 {
		return line
	}
	return line[:idx]
}

// forEachFeedLine 逐行遍历 data，超过 maxFeedLineBytes 的行整行丢弃。
//
// 不用 bufio.Scanner：它在单行超过上限时返回 ErrTooLong 并永久停止，无法「跳过这一行
// 继续读下一行」，一个坏行就够让整个源解析失败。bufio.Reader.ReadSlice 超长时返回
// ErrBufferFull，把该行剩余片段读完丢弃即可续读；只有读体内的真正错误才向上返回。
func forEachFeedLine(data []byte, visit func(line []byte)) error {
	reader := bufio.NewReaderSize(bytes.NewReader(data), maxFeedLineBytes)
	for {
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// 超长行：丢弃已读片段，继续读到换行为止。
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = reader.ReadSlice('\n')
			}
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > 0 {
			visit(line)
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

// ParseIPList 解析纯 IP 列表（每行一个 IP 或 CIDR）。
//
// 忽略空行和注释行（# 开头）。
func ParseIPList(data []byte, sourceName, category string, confidence float64, expiresAt time.Time) ([]FeedEntry, error) {
	var entries []FeedEntry

	err := forEachFeedLine(data, func(raw []byte) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			return
		}

		// 移除行内注释
		line = StripComments(line)
		line = strings.TrimSpace(line)
		if line == "" {
			return
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
				Source:     sourceName,
				Category:   category,
				Confidence: confidence,
				ExpiresAt:  expiresAt,
			})
			return
		}

		// 解析失败，跳过该行
	})

	if err != nil {
		return nil, err
	}
	return entries, nil
}
