package http

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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

// GetLogs 按契约的分页与过滤查询日志文件（GET /api/v2/logs）。
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
		h.server.logger.Warn("日志文件不存在", "path", logFile)
		WriteServiceUnavailable(w, "日志文件不可用")
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
	// hi 和 lo 均为 uint64，调用方已保证 start+n <= totalLines，无需下溢保护。
	hi := totalLines - start
	lo := hi - n
	if n > hi {
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

// StreamLogs 经 `/api/v2/logs/stream` 推送实时日志行。
//
// 接入名额、握手帧、心跳与 503 全部由 streamSSE 统一处理（与 `/api/v2/events` 同一套
// 语义、各自独立的上限），这里只负责「把文件末尾之后的新行写成 log 帧」。
//
// 文件在 attach 回调内打开：streamSSE 有三条早退路径（Flusher 断言失败、关停中、名额满）
// 在 attach 之前就 return，若提前打开文件会导致 fd 泄漏。把打开推迟到 attach 内，虽然
// 文件打开失败时已写过 200 响应头、无法再改 503，但这种情况罕见且客户端会因无数据而
// 超时断开，比泄漏 fd 直到耗尽进程配额要好。
func (h *APIHandlers) StreamLogs(w http.ResponseWriter, r *http.Request) {
	logFile := ""
	if h.logFilePath != nil {
		logFile = h.logFilePath()
	}
	if logFile == "" {
		WriteServiceUnavailable(w, "日志文件未配置")
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
			f, err := os.Open(logFile)
			if err != nil {
				logger.Warn("日志流打开文件失败", "path", logFile, "error", err)
				return false
			}
			// 定位到末尾：这条流推的是「从这里开始的未来」，历史行由 GET /api/v2/logs 负责。
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				logger.Warn("日志文件定位失败", "path", logFile, "error", err)
				_ = f.Close()
				return false
			}
			go tailLogs(r.Context(), logFile, f, level, &sseConn{out: out}, done, logger)
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

// logTailSource 是日志流当前跟随的文件句柄与路径。
//
// 守护进程的日志 sink 按大小自行轮转：rename 轮转把当前片改名 `.<n>` 后新建同名文件，
// 只留一片（maxFiles=1）时则原地 Truncate(0)。两种情况下旧 fd 的偏移都读不到新行——
// rename 之后旧 fd 永远 EOF，截断之后要等文件重新长过旧偏移才恢复。故每拍先核对
// 「路径现在指向的 inode 是否还是我持有的那个、长度是否还够」，失配就重开路径从头读。
type logTailSource struct {
	path string
	file *os.File
}

// stale 报告是否该重开：inode 变了（rename 轮转）、文件变短（原地截断），或路径被换成
// 非普通文件。路径暂时不可见（轮转窗口内）不算，下一拍再看。截断后在同一拍内又长过旧
// 偏移的情况无法从元数据分辨，与 tail -F 的检测窗口同一范围。
func (s *logTailSource) stale() bool {
	meta, err := os.Lstat(s.path)
	if err != nil {
		return false
	}
	if !meta.Mode().IsRegular() {
		return true
	}
	cur, err := s.file.Stat()
	if err != nil {
		return true
	}
	offset, err := s.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return true
	}
	return !os.SameFile(meta, cur) || meta.Size() < offset
}

// reopen 换到路径当前指向的文件；失败时保留旧句柄，下一拍再试。
func (s *logTailSource) reopen(logger *slog.Logger) bool {
	next, err := os.Open(s.path)
	if err != nil {
		logger.Debug("轮转后重开日志文件失败，沿用旧句柄", "path", s.path, "error", err)
		return false
	}
	if err := s.file.Close(); err != nil {
		logger.Debug("轮转后关闭旧日志句柄失败", "error", err)
	}
	s.file = next
	return true
}

// tailLogs 轮询日志文件，把新增行按 `log` 事件写给这一条连接。
//
// 每连接一个 goroutine 而不是共用一个读取器扇出：这条流的每一帧只属于发起请求的那个
// 客户端，且各连接的 level 过滤不同，共享读取要么重复扫描要么互相串数据。
//
// 退出时关闭发送通道：streamSSE 见到它关闭就返回，名额随之释放。少了这一步，读取失败
// （文件被删、权限变化）之后连接会只剩心跳、一直占着名额直到客户端主动断开。
func tailLogs(ctx context.Context, path string, f *os.File, level string, conn *sseConn, done chan struct{}, logger *slog.Logger) {
	src := &logTailSource{path: path, file: f}
	defer func() {
		if err := src.file.Close(); err != nil {
			logger.Warn("日志流关闭文件失败", "error", err)
		}
		close(conn.out)
	}()

	ticker := time.NewTicker(logTailPollInterval)
	defer ticker.Stop()

	// 不能用 bufio.Scanner 跨轮复用：它第一次读到 EOF 就把自己标记为 done，之后的
	// Scan 不再读文件。这条流面对的恰恰是「attach 时在末尾、之后不断追加」的文件，
	// 正常情况第一轮读到的就是 EOF——用 Scanner 等于只推第一秒写入的行，之后永久静默。
	// 这里每轮把文件当前位置到 EOF 的新增字节全部读出，跨轮保留未换行的半行。
	var pending []byte
	buf := make([]byte, 64*1024)

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
		}

		if src.stale() && src.reopen(logger) {
			// 旧文件的半行不属于新文件，拼上去只会造出一条错位记录。
			pending = pending[:0]
		}

		for {
			n, err := src.file.Read(buf)
			if n > 0 {
				pending = append(pending, buf[:n]...)
				var cont bool
				pending, cont = emitLogLines(pending, level, conn, logger)
				if !cont {
					return
				}
			}
			if err == nil {
				continue
			}
			if !errors.Is(err, io.EOF) {
				// 前端把 error 帧的 data 当人类可读文本直接显示，所以这里给纯文本而不是对象。
				// 不暴露底层错误细节，只给通用提示。
				_ = conn.writeFrame("error", sseRaw("读取日志文件失败"))
				return
			}
			break
		}
		// 单行上限与 forEachLogLine 一致：一条始终等不到换行的超长行不该让连接无限攒内存。
		if len(pending) > maxLogLineBytes {
			_ = conn.writeFrame("error", sseRaw("读取日志文件失败"))
			return
		}
	}
}

// emitLogLines 把 pending 中所有以换行结尾的完整行写出，返回尚未收尾的尾部与是否继续。
//
// 半行留到下一轮：一次追加可能只写到这里（文件增长与读取并发），提前把它当一行推给
// 前端会得到截断的 JSON 记录。
func emitLogLines(pending []byte, level string, conn *sseConn, logger *slog.Logger) ([]byte, bool) {
	for {
		i := bytes.IndexByte(pending, '\n')
		if i < 0 {
			return pending, true
		}
		line := strings.TrimSuffix(string(pending[:i]), "\r")
		pending = pending[i+1:]
		if level != "" && !matchesLogLevel(line, level) {
			continue
		}
		// 原始行逐字进 data：前端 parseLine 收到的就是文件里的那条 JSON 记录。
		if err := conn.writeFrame("log", sseRaw(line)); err != nil {
			logger.Debug("日志流写出失败，停止推送", "error", err)
			return nil, false
		}
	}
}

// matchesLogLevel 检查日志行是否匹配指定级别。
//
// 支持两种格式：
//   - JSON 格式: {"level":"info",...}
//   - 纯文本格式: time=... level=INFO ...
//   - 独立级别标识: ERROR something happened（原始大小写）
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
			strings.Contains(line, "ERROR")
	case "warn", "warning":
		return strings.Contains(lower, `"level":"warn"`) ||
			strings.Contains(lower, "level=warn") ||
			strings.Contains(lower, "level=warning") ||
			strings.Contains(lower, "[warn]") ||
			strings.Contains(line, "WARN")
	case "info":
		return strings.Contains(lower, `"level":"info"`) ||
			strings.Contains(lower, "level=info") ||
			strings.Contains(lower, "[info]") ||
			strings.Contains(line, "INFO")
	case "debug":
		return strings.Contains(lower, `"level":"debug"`) ||
			strings.Contains(lower, "level=debug") ||
			strings.Contains(lower, "[debug]") ||
			strings.Contains(line, "DEBUG")
	default:
		return true
	}
}
