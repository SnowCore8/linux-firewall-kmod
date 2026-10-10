package http

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// 日志流的两处参数：轮询间隔与单行上限。
//
// 1 秒轮询沿用旧实现的节奏——日志文件由 slog 追加，更密的轮询只是多几遍空 stat。
// 512 KiB 的单行上限给 JSON 记录留余量（配置快照那类行会带上一整段结构）。
const (
	logTailPollInterval = 1 * time.Second
	maxLogLineBytes     = 512 * 1024
)

// 日志查询的分页参数（缺省沿用改造前的 limit=100/max=1000，契约 LogPageResponse
// 没有为它们编别的数字）。
const (
	logDefaultPage     = 1
	logDefaultPageSize = 100
	logMaxPageSize     = 1000
)

// GetLogs 按契约的分页与过滤查询日志文件（GET /api/v1/logs）。
//
// 载荷是 LogPageResponse：items 里每行带**文件中的物理行号**，顺序是最新在前，
// total_lines 是过滤后的匹配总行数。过去的形状（lines/count/offset/limit/file_size/
// log_file/level）与前端声明的分页信封不是同一个类型，前端按 items 取数一律落空。
//
// 页码越界不是错误：返回空 items 与真实的 total_lines/total_pages，前端据此把页码
// 收回最后一页。契约在这里没有可编的失败码，而「你要的那一页没有」是一次成功查询的
// 读数。
func (h *APIHandlers) GetLogs(w http.ResponseWriter, r *http.Request) {
	logFile := ""
	if h.logFilePath != nil {
		logFile = h.logFilePath()
	}
	if logFile == "" {
		WriteServiceUnavailable(w, "日志文件未配置")
		return
	}

	query, err := parseLogQuery(r)
	if err != nil {
		WriteCode(w, httpcontract.Code40005, "日志查询参数非法："+err.Error())
		return
	}

	// 第一遍只数不存：得到过滤后的总行数。total_lines 必须来自整份文件，任何「只扫
	// 尾部若干字节」的近似都会让前端算出一个不存在的最后一页。
	totalLines, scanErr := countLogMatches(logFile, query.filter)
	if scanErr != nil {
		h.writeLogReadError(w, logFile, scanErr)
		return
	}

	pageSize := uint64(query.pageSize)
	totalPages := uint32((totalLines + pageSize - 1) / pageSize)

	start := uint64(query.page-1) * pageSize
	var items []LogEntry
	if start < totalLines {
		n := pageSize
		if totalLines-start < n {
			n = totalLines - start
		}
		// 第二遍只保留这一页的行：内存上界是 page_size 条，而不是整份日志。
		items, scanErr = collectLogWindow(logFile, query.filter, totalLines, start, n)
		if scanErr != nil {
			h.writeLogReadError(w, logFile, scanErr)
			return
		}
	}
	if items == nil {
		// 空页也要写成 `[]`：契约的 items 是 Vec，前端对 null 没有分支。
		items = []LogEntry{}
	}

	WriteSuccess(w, LogPageResponse{
		Items:      items,
		TotalLines: totalLines,
		Page:       query.page,
		PageSize:   query.pageSize,
		TotalPages: totalPages,
	})
}

// writeLogReadError 把一次文件读取失败摊成契约给这条路由编的两个码之一。
//
// 文件不存在 = 依赖未就绪（50003），与 StreamLogs 同一条判断：配置里写了路径而文件不在，
// 不是「你要的日志行不存在」，更不是服务端 bug；其余读失败才是 50002。
func (h *APIHandlers) writeLogReadError(w http.ResponseWriter, logFile string, err error) {
	if os.IsNotExist(err) {
		WriteServiceUnavailable(w, "日志文件不可读: "+logFile)
		return
	}
	h.server.logger.Error("读取日志文件失败", "path", logFile, "error", err)
	WriteInternalError(w, "读取日志失败")
}

// logFilter 是一次查询的三个过滤条件（都已归一：level/keyword 小写，since 零值 = 不过滤）。
type logFilter struct {
	level   string
	keyword string
	since   time.Time
}

// keep 报告一行日志是否属于这次查询的结果。
//
// 三个条件之间是「与」：级别与关键词都在 matchesLogLevel / strings.Contains 一层解决，
// 不引入第二个匹配语言——那会变成前端要防的第三种形状。
func (f logFilter) keep(line string) bool {
	if f.level != "" && !matchesLogLevel(line, f.level) {
		return false
	}
	if f.keyword != "" && !strings.Contains(strings.ToLower(line), f.keyword) {
		return false
	}
	if !f.since.IsZero() {
		if ts, ok := parseLogLineTime(line); ok && ts.Before(f.since) {
			return false
		}
	}
	return true
}

// parseLogLineTime 从一行日志里取出时间戳。
//
// 两种现场格式都要认：内部 logger 的 JSON 行（`{"ts":"2026-10-11T06:03:00.123Z",…}`，
// UTC 带 Z）与 slog 文本 handler 的行（`time=2026-10-11T06:03:00.123+08:00 …`）。
// 解不出时间戳的行**不算**被 since 过滤掉：日志里混着非结构化的多行文本（进程横幅、
// 外部程序的输出），按「没有时间就不显示」处理会把它们整段抹掉。
func parseLogLineTime(line string) (time.Time, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	var stamp string
	switch {
	case strings.HasPrefix(trimmed, "{"):
		const key = `"ts":"`
		i := strings.Index(trimmed, key)
		if i < 0 {
			return time.Time{}, false
		}
		rest := trimmed[i+len(key):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			return time.Time{}, false
		}
		stamp = rest[:j]
	default:
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "time=") {
			return time.Time{}, false
		}
		stamp = strings.TrimPrefix(fields[0], "time=")
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if ts, err := time.Parse(layout, stamp); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

// forEachLogLine 顺序扫描整份日志文件，对每一行调用 visit（行号从 1 起）。
//
// 不做「只读尾部若干 MB」的近似：那会让 line_number 变成相对窗口起点的偏移，而前端把
// 行号显示给用户，用户拿它去 grep 同一个文件。整份扫描的代价与文件大小成正比，这是
// total_lines 与真实行号唯一诚实的算法。
func forEachLogLine(path string, visit func(lineNumber uint64, text string) (bool, error)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLineBytes)

	var lineNumber uint64
	for scanner.Scan() {
		lineNumber++
		cont, err := visit(lineNumber, scanner.Text())
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}
	return scanner.Err()
}

// countLogMatches 返回过滤后的匹配行数。
func countLogMatches(path string, filter logFilter) (uint64, error) {
	var matched uint64
	err := forEachLogLine(path, func(_ uint64, line string) (bool, error) {
		if filter.keep(line) {
			matched++
		}
		return true, nil
	})
	return matched, err
}

// collectLogWindow 取出「最新在前」序列里第 [start, start+n) 条匹配行。
//
// totalLines 必须来自 countLogMatches（同一次查询的第一遍），否则无法把「从新到旧的
// 偏移」换算成文件里的绝对位置。两遍之间新追加的行不会出现在这一页里——它属于下一页，
// 面板上表现为 total_lines 比上一页多几条，这是可观察的实时性而不是错乱。
func collectLogWindow(path string, filter logFilter, totalLines, start, n uint64) ([]LogEntry, error) {
	// 文件顺序（旧→新）上的保留区间：[lo, hi)。
	hi := totalLines - start
	lo := hi - n
	if lo < 0 {
		lo = 0
	}

	var matched uint64
	collected := make([]LogEntry, 0, n)
	err := forEachLogLine(path, func(lineNumber uint64, line string) (bool, error) {
		if !filter.keep(line) {
			return true, nil
		}
		index := matched
		matched++
		if index >= lo && index < hi {
			collected = append(collected, LogEntry{LineNumber: lineNumber, Content: line})
		}
		// 收满就停：后面的行比这一页更新，不在这个窗口里。
		return index < hi-1, nil
	})
	if err != nil {
		return nil, err
	}

	// 反成最新在前：与前端 Logs 面板的阅读顺序一致（第一眼看到刚发生的事）。
	out := make([]LogEntry, 0, len(collected))
	for i := len(collected) - 1; i >= 0; i-- {
		out = append(out, collected[i])
	}
	return out, nil
}

// StreamLogs 经 `/api/v1/logs/stream` 推送实时日志行。
//
// 接入名额、握手帧、心跳与 503 全部由 streamSSE 统一处理（与 `/api/v1/events` 同一套
// 语义、各自独立的上限），这里只负责「把文件末尾之后的新行写成 log 帧」。
//
// 文件在占名额**之前**就打开并定位：流一旦写出响应头就无法再改状态码，而契约给这条流
// 只声明了 200 与 503，所以预检失败一律 503，不开 404 这种契约上没有的口子。
func (h *APIHandlers) StreamLogs(w http.ResponseWriter, r *http.Request) {
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

	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	if level != "" && !isKnownLogLevel(level) {
		// 这条流在契约里只编了 50003（依赖未就绪），没有「查询参数非法」那个码可用，
		// 所以认不出来的级别退化成不过滤，并把这件事记进服务端日志而不是把流关掉。
		h.server.logger.Warn("日志流级别过滤参数无法识别，本次连接不按级别过滤", "level", level)
		level = ""
	}
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

	// 单行上限与 forEachLogLine 一致：一条超长的 JSON 记录不该整条丢掉。
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

// matchesLogLevel 检查日志行是否匹配指定级别。
//
// 支持两种格式：
//   - JSON 格式: {"level":"info",...}
//   - 纯文本格式: time=... level=INFO ...
//
// 调用方负责先验级别（REST 走 parseLogQuery 的 40005，日志流走 normalizeLogLevel）：
// default 分支的「不过滤」只服务后者，不是一种供人挑选的宽松匹配语义。
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
