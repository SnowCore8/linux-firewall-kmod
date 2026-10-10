package http

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// 日志流的两处参数：轮询间隔与单行上限。
//
// 1 秒轮询沿用旧实现的节奏——日志文件由 slog 追加，更密的轮询只是多几遍空 stat。
// 512 KiB 的单行上限给 JSON 记录留余量（配置快照那类行会带上一整段结构）。
const (
	logTailPollInterval = 1 * time.Second
	maxLogLineBytes     = 512 * 1024
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

// StreamLogs 经 `/api/v1/logs/stream` 推送实时日志行。
//
// 接入名额、握手帧、心跳与 503 全部由 streamSSE 统一处理（与 `/api/v1/events` 同一套
// 语义、各自独立的上限），这里只负责「把文件末尾之后的新行写成 log 帧」。
//
// 文件在占名额**之前**就打开并定位：流一旦写出响应头就无法再改状态码，而契约给这条流
// 只声明了 200 与 503，所以预检失败一律 503，不开 404 这种契约上没有的口子。
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

	f, err := os.Open(logFile)
	if err != nil {
		h.server.logger.Warn("日志流打开文件失败", "path", logFile, "error", err)
		WriteServiceUnavailable(w, "日志文件不可读")
		return
	}
	// 定位到末尾：这条流推的是「从这里开始的未来」，历史行由 GET /api/v1/logs 负责。
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		WriteServiceUnavailable(w, "日志文件定位失败")
		return
	}

	level := strings.ToLower(r.URL.Query().Get("level"))
	done := make(chan struct{})
	logger := h.server.logger

	streamSSE(w, r, h.logStream,
		func(out chan []byte) bool {
			go tailLogs(r.Context(), f, level, &sseConn{out: out}, done, logger)
			return true
		},
		func(chan []byte) { close(done) },
		func(conn sseConnWriter) error {
			return conn.writeFrame("connected", map[string]any{
				"stream":          h.logStream.Name(),
				"max_connections": h.logStream.Max(),
			})
		})
}

// tailLogs 轮询日志文件，把新增行按 `log` 事件写给这一条连接。
//
// 每连接一个 goroutine 而不是共用一个读取器扇出：这条流的每一帧只属于发起请求的那个
// 客户端，且各连接的 level 过滤不同，共享读取要么重复扫描要么互相串数据。
//
// 不处理日志轮转（文件被 rename/truncate）：偏移在末尾之后时读不到新行，流会静默停住。
// 与旧实现同范围，接回 inode 跟踪属于后续包。
func tailLogs(ctx context.Context, f *os.File, level string, conn *sseConn, done chan struct{}, logger *slog.Logger) {
	defer func() {
		if err := f.Close(); err != nil {
			logger.Warn("日志流关闭文件失败", "error", err)
		}
	}()

	ticker := time.NewTicker(logTailPollInterval)
	defer ticker.Stop()

	// 单行上限与 readLogTail 一致：一条超长的 JSON 记录不该整条丢掉。
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLineBytes)

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			for scanner.Scan() {
				line := scanner.Text()
				if level != "" && !matchesLogLevel(line, level) {
					continue
				}
				// 原始行逐字进 data：前端 parseLine 收到的就是文件里的那条 JSON 记录。
				if err := conn.writeFrame("log", sseRaw(line)); err != nil {
					logger.Debug("日志流写出失败，停止推送", "error", err)
					return
				}
			}
			if err := scanner.Err(); err != nil {
				// 前端把 error 帧的 data 当人类可读文本直接显示，所以这里给纯文本而不是对象。
				_ = conn.writeFrame("error", sseRaw("读取日志文件失败: "+err.Error()))
				return
			}
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
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLineBytes)
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
