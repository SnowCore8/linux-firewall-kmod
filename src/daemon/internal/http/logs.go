package http

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// GetLogs 查询日志文件内容，支持分页与级别过滤。
//
// 查询参数：
//   - level: 日志级别过滤（error/warn/info/debug），为空返回全部
//   - offset: 从末尾向前偏移的行数（默认 0，即从最新开始）
//   - limit: 返回行数（默认 100，最大 1000）
//
// 返回顺序：最新在前（倒序）。
func (h *APIHandlers) GetLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	logFile := ""
	if h.logFilePath != nil {
		logFile = h.logFilePath()
	}
	if logFile == "" {
		WriteServiceUnavailable(w, "日志文件未配置")
		return
	}

	levelFilter := strings.ToLower(r.URL.Query().Get("level"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit := parseLimit(r, 100, 1000)

	lines, totalSize, err := readLogTail(logFile, offset, limit, levelFilter)
	if err != nil {
		if os.IsNotExist(err) {
			WriteNotFound(w, "日志文件不存在")
			return
		}
		h.server.logger.Error("读取日志文件失败", "error", err)
		WriteInternalError(w, "读取日志失败")
		return
	}

	WriteSuccess(w, map[string]any{
		"lines":     lines,
		"count":     len(lines),
		"offset":    offset,
		"limit":     limit,
		"file_size": totalSize,
		"log_file":  logFile,
		"level":     levelFilter,
	})
}

// StreamLogs SSE 推送实时日志。
//
// 打开日志文件 → 定位到末尾 → 轮询读取新增行 → 通过 SSE 推送。
// 每个连接一个 goroutine 做 tail-f 轮询，客户端断开时自动退出。
func (h *APIHandlers) StreamLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	logFile := ""
	if h.logFilePath != nil {
		logFile = h.logFilePath()
	}
	if logFile == "" {
		WriteServiceUnavailable(w, "日志文件未配置")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	f, err := os.Open(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			WriteNotFound(w, "日志文件不存在")
			return
		}
		WriteInternalError(w, "无法打开日志文件")
		return
	}
	defer f.Close()

	// 定位到文件末尾，只推送新内容
	if _, err := f.Seek(0, 2); err != nil {
		WriteInternalError(w, "日志文件定位失败")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	levelFilter := strings.ToLower(r.URL.Query().Get("level"))
	ctx := r.Context()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	scanner := bufio.NewScanner(f)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 读取新增行
			for scanner.Scan() {
				line := scanner.Text()
				if levelFilter != "" && !matchesLogLevel(line, levelFilter) {
					continue
				}
				event := fmt.Sprintf("event: log\ndata: %s\n\n", line)
				if _, err := fmt.Fprint(w, event); err != nil {
					return
				}
				flusher.Flush()
			}
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// readLogTail 从日志文件末尾读取指定行数。
//
// 先读取全部行，过滤后取最后 offset+limit 行，再倒序返回。
// 对于大文件（>10MB），只读取最后 10000 行以控制内存。
func readLogTail(path string, offset, limit int, levelFilter string) ([]string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	totalSize := fi.Size()

	// 大文件优化：只读取最后部分
	const maxReadSize = 10 * 1024 * 1024 // 10MB
	if totalSize > maxReadSize {
		if _, err := f.Seek(-maxReadSize, 2); err != nil {
			return nil, 0, err
		}
		// 跳过不完整的行
		scanner := bufio.NewScanner(f)
		if scanner.Scan() {
			// 第一行可能不完整，跳过
		}
	}

	var allLines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if levelFilter != "" && !matchesLogLevel(line, levelFilter) {
			continue
		}
		allLines = append(allLines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, totalSize, err
	}

	// 倒序取 offset 开始的 limit 行
	total := len(allLines)
	end := total - offset
	if end < 0 {
		end = 0
	}
	start := end - limit
	if start < 0 {
		start = 0
	}

	result := make([]string, 0, end-start)
	for i := end - 1; i >= start; i-- {
		result = append(result, allLines[i])
	}
	return result, totalSize, nil
}

// matchesLogLevel 检查日志行是否匹配指定级别。
//
// 支持两种格式：
//   - JSON 格式: {"level":"info",...}
//   - 纯文本格式: time=... level=INFO ...
func matchesLogLevel(line, level string) bool {
	lower := strings.ToLower(line)
	switch level {
	case "error", "err":
		return strings.Contains(lower, `"level":"error"`) ||
			strings.Contains(lower, "level=error") ||
			strings.Contains(lower, "level=err") ||
			strings.Contains(lower, "[error]") ||
			strings.Contains(lower, "ERROR")
	case "warn", "warning":
		return strings.Contains(lower, `"level":"warn"`) ||
			strings.Contains(lower, "level=warn") ||
			strings.Contains(lower, "level=warning") ||
			strings.Contains(lower, "[warn]") ||
			strings.Contains(lower, "WARN")
	case "info":
		return strings.Contains(lower, `"level":"info"`) ||
			strings.Contains(lower, "level=info") ||
			strings.Contains(lower, "[info]") ||
			strings.Contains(lower, "INFO")
	case "debug":
		return strings.Contains(lower, `"level":"debug"`) ||
			strings.Contains(lower, "level=debug") ||
			strings.Contains(lower, "[debug]") ||
			strings.Contains(lower, "DEBUG")
	default:
		return true
	}
}
