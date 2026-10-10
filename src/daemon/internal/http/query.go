// 查询参数面的具名载荷：契约里 kind = request 的分页/过滤参数块。
//
// 与 payload.go 同样的规矩——struct 名 = 契约类型名，json 标签 = 契约声明的线上拼写。
// 这里的标签描述的是**查询串里的参数名**（这些结构体从不进 JSON 体），但拼写必须与
// 契约逐字一致，否则跨层核对在这一层没有锚点。
//
// 字段全用指针，因为契约把它们声明成 Option<…>，而「没带这个参数」与「带了但值读不懂」
// 在不同路由上的处理**不一样**：GET /api/v1/bans 只编了 code 0，读不懂只能回落默认；
// GET /api/v1/logs 编了 40005，读不懂必须报错。值类型分不出这两种情形。
package http

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PaginationParams 是列表类端点的分页/排序查询参数（契约 request PaginationParams）。
type PaginationParams struct {
	Page     *uint32 `json:"page"`
	PageSize *uint32 `json:"page_size"`
	SortBy   *string `json:"sort_by"`
}

// LogQueryParams 是 GET /api/v1/logs 的查询参数（契约 request LogQueryParams）。
//
// 与 PaginationParams 同形但**不共用**：契约把它们分成两个 request 块，日志多出
// level/keyword/since 三个过滤项。合并成一个 Go 结构体等于宣布两个契约类型是一个。
type LogQueryParams struct {
	Page     *uint32 `json:"page"`
	PageSize *uint32 `json:"page_size"`
	Level    *string `json:"level"`
	Keyword  *string `json:"keyword"`
	Since    *string `json:"since"`
}

// queryPagination 从查询串读出 PaginationParams。
//
// 读不懂的数字、空串一律当「这个参数没带」（留 nil）：这条路由在契约里没有失败码，
// 任何「参数非法」的分支都要新造一个契约上不存在的业务码。
func queryPagination(r *http.Request) PaginationParams {
	query := r.URL.Query()
	var p PaginationParams
	if n, ok := parsePositiveUint(query.Get("page")); ok {
		p.Page = &n
	}
	if n, ok := parsePositiveUint(query.Get("page_size")); ok {
		p.PageSize = &n
	}
	if s := strings.TrimSpace(query.Get("sort_by")); s != "" {
		p.SortBy = &s
	}
	return p
}

// pageOr 取页码（1 起），未提供或非法时用 def。
func (p PaginationParams) pageOr(def uint32) uint32 {
	if p.Page != nil {
		return *p.Page
	}
	return def
}

// pageSizeOr 取每页条数，超过 max 时**夹到 max**（而不是退回 def）：请求 5000 条的人
// 要的是「尽量多」，给他 100 条比给他 20 条更接近意图。max=0 表示不设上限。
func (p PaginationParams) pageSizeOr(def, max uint32) uint32 {
	if p.PageSize == nil {
		return def
	}
	if max > 0 && *p.PageSize > max {
		return max
	}
	return *p.PageSize
}

// sortByOr 取排序键，未提供时返回空串（调用方按契约回落 banned_at_desc）。
func (p PaginationParams) sortByOr() string {
	if p.SortBy == nil {
		return ""
	}
	return *p.SortBy
}

// parsePositiveUint 解一个 >=1 的无符号十进制数；空值、垃圾、0、溢出都算「没带」。
func parsePositiveUint(raw string) (uint32, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(trimmed, 10, 32)
	if err != nil || n < 1 {
		return 0, false
	}
	return uint32(n), true
}

// logSinceLayouts 是 since 参数接受的几种写法，按精确度从宽到窄尝试。
//
// 前端 Logs.tsx 传的是 `formatDatetime(cutoff).replace(' ', 'T')`，即本地时区的
// 「2026-10-11T06:03:00」；带时区的 RFC3339 同样接受，运维手搓 curl 不必改格式。
// 只有日期的写法按当天 00:00（本地）起算。
var logSinceLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// logQuery 是一次日志查询的完整读数：契约参数 + 已经落成具体值的部分。
type logQuery struct {
	params   LogQueryParams
	filter   logFilter
	page     uint32
	pageSize uint32
}

// parseLogQuery 解析并校验 GET /api/v1/logs 的查询参数。
//
// 与封禁列表的宽容处理相反，这里**任何**读不懂的值都回错：契约给这条路由编了
// 40005「日志查询参数非法」。默默按默认值查更糟——运维以为自己在看第 5000 页，
// 实际拿到的是第 1 页，而这两页的内容差了几万行。
func parseLogQuery(r *http.Request) (logQuery, error) {
	query := r.URL.Query()
	var q logQuery

	if raw := strings.TrimSpace(query.Get("page")); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || n < 1 {
			return q, fmt.Errorf("page=%q 不是从 1 起的页码", raw)
		}
		page := uint32(n)
		q.params.Page = &page
	}
	if raw := strings.TrimSpace(query.Get("page_size")); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil || n < 1 {
			return q, fmt.Errorf("page_size=%q 不是从 1 起的条数", raw)
		}
		if n > logMaxPageSize {
			return q, fmt.Errorf("page_size=%d 超过上限 %d", n, logMaxPageSize)
		}
		size := uint32(n)
		q.params.PageSize = &size
	}
	if raw := query.Get("level"); raw != "" {
		level := strings.ToLower(raw)
		if !isKnownLogLevel(level) {
			return q, fmt.Errorf("level=%q 不是 error/warn/info/debug 之一", raw)
		}
		q.params.Level = &level
	}
	if raw := query.Get("keyword"); raw != "" {
		keyword := raw
		q.params.Keyword = &keyword
	}
	if raw := strings.TrimSpace(query.Get("since")); raw != "" {
		since, err := parseLogSince(raw)
		if err != nil {
			return q, err
		}
		q.params.Since = &raw
		q.filter.since = since
	}

	q.page = logDefaultPage
	if q.params.Page != nil {
		q.page = *q.params.Page
	}
	q.pageSize = logDefaultPageSize
	if q.params.PageSize != nil {
		q.pageSize = *q.params.PageSize
	}
	if q.params.Level != nil {
		q.filter.level = *q.params.Level
	}
	if q.params.Keyword != nil {
		q.filter.keyword = strings.ToLower(*q.params.Keyword)
	}
	return q, nil
}

// parseLogSince 按 logSinceLayouts 逐个尝试，**按本地时区**解释不带时区的写法。
//
// 时区口径与仪表盘上「今日封禁」一致（见契约 StatsResponse.today_bans 的窗口定义）：
// 日志里读的是运维此刻盯着的那段时间，跟他的日历走，不跟 UTC 走。
func parseLogSince(raw string) (time.Time, error) {
	for _, layout := range logSinceLayouts {
		if ts, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("since=%q 无法解析（支持 RFC3339 或 2006-01-02T15:04:05）", raw)
}

// isKnownLogLevel 报告 level 是否是 matchesLogLevel 真的认识的写法。
func isKnownLogLevel(level string) bool {
	switch level {
	case "error", "err", "warn", "warning", "info", "debug":
		return true
	default:
		return false
	}
}
