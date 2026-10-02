package http

import (
	"bufio"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// RateEntry 是一条速率历史记录。
type RateEntry struct {
	Timestamp int64  `json:"timestamp"`
	RatePPS   uint64 `json:"rate_pps"`
	Type      string `json:"type"` // syn/udp/icmp/ack/rst/fin/total
}

// GetRatesHistory 返回 DDoS 速率历史数据。
//
// 数据来源：
//  1. 优先从 /proc/firewall/rates 读取（内核模块提供的速率历史环形缓冲区）
//  2. 若 procfs 不可用，返回当前 DDoS 统计快照
//
// 查询参数：
//   - limit: 返回条数上限（默认 100，最大 1000）
func (h *APIHandlers) GetRatesHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	limit := parseLimit(r, 100, 1000)

	// 尝试从 procfs 读取速率历史
	entries, err := readProcfsRates(limit)
	if err != nil {
		// procfs 不可用，返回当前快照
		h.server.logger.Debug("读取 procfs 速率失败，返回当前快照", "error", err)
		WriteSuccess(w, map[string]any{
			"entries":    []RateEntry{},
			"source":     "snapshot",
			"message":    "内核速率历史不可用，仅返回当前统计",
			"ddos_stats": h.getDdosSnapshot(),
		})
		return
	}

	WriteSuccess(w, map[string]any{
		"entries": entries,
		"source":  "procfs",
		"count":   len(entries),
	})
}

// readProcfsRates 从 /proc/firewall/rates 读取速率历史。
//
// 内核模块输出格式（每行一条）：
//
//	timestamp rate_pps type
//
// 例如：
//
//	1698765432 15000 syn
//	1698765432 8000 udp
func readProcfsRates(limit int) ([]RateEntry, error) {
	f, err := os.Open("/proc/firewall/rates")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []RateEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ts, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		rate, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		entries = append(entries, RateEntry{
			Timestamp: ts,
			RatePPS:   rate,
			Type:      fields[2],
		})
		if len(entries) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return entries, err
	}
	return entries, nil
}

// getDdosSnapshot 返回当前 DDoS 统计快照。
//
// 当 procfs 速率历史不可用时，提供当前累计统计作为降级方案。
func (h *APIHandlers) getDdosSnapshot() map[string]any {
	if h.metrics == nil {
		return map[string]any{
			"message": "metrics not available",
		}
	}
	return map[string]any{
		"events_detected":     h.metrics.Counter("firewall_ddos_events_total").Load(),
		"auto_bans_triggered": h.metrics.Counter("firewall_ddos_auto_bans_total").Load(),
	}
}
