// 资源面的具名响应载荷：封禁 / 白名单 / 配置 / 日志 / SSE 诊断。
//
// 这里的每一个 struct 都**逐字**对应 contract/http.fwidl 的一个 type 块：结构体名 =
// 契约类型名，json tag = 契约字段的线上 key。这不是为了好看，而是契约门禁的锚点——
// verify_http.py 的载荷核对按类型名在 Go 源码里找 struct，再把两边的 key 做双向差集。
// 用 map[string]any 写字面量时，字段没有任何具名承载，跨层核对在这一层失去锚点
// （缺口基线里那条 type-unmapped 说的就是这件事），前端 types.ts 改个名也不会红。
//
// 因此新增响应一律**加 struct**，不要回到 map：
//   - key 拼写与顺序由 struct 声明顺序决定（encoding/json 按声明顺序输出）；
//   - 可选字段用指针或显式零值，按契约那句「失败时 data 为 null」的口径给值；
//   - 字段含义写在这里，契约的 type 块写它的注释，两边各留一份说明而不是互相引用。
package http

import (
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

// PaginatedResponse 是列表类端点的统一分页信封（契约 PaginatedResponse<T>）。
//
// total 是**过滤前的全集条数**，items 是当前页；total_pages 由 total 与 page_size
// 向上取整得出。读侧只需要 items 也要把四个数写全：前端分页控件按 total_pages 决定
// 尾页，缺了它就只能把「这一页有几条」当总数显示。
type PaginatedResponse[T any] struct {
	Items      []T    `json:"items"`
	Total      uint64 `json:"total"`
	Page       uint32 `json:"page"`
	PageSize   uint32 `json:"page_size"`
	TotalPages uint32 `json:"total_pages"`
}

// BanResponse 是封禁表里一条活跃封禁（GET /api/v1/bans 的 items 元素）。
type BanResponse struct {
	IP               string `json:"ip"`
	Jail             string `json:"jail"`
	BannedAt         int64  `json:"banned_at"`
	RemainingSeconds int64  `json:"remaining_seconds"`
	Reason           string `json:"reason"`
	BanCount         uint32 `json:"ban_count"`
	IsPermanent      bool   `json:"is_permanent"`
}

// BanDetailResponse 是单个 IP 的封禁详情（GET /api/v1/bans/:ip/detail）。
//
// **未封禁不是错误**：is_banned=false 的 200 响应照样带历史与信誉读数（契约给这条路由
// 只编了 40006 = IP 非法）。前端详情面板正是靠这个形状在「解封之后还想看历史」时可用。
type BanDetailResponse struct {
	IP                   string  `json:"ip"`
	IsBanned             bool    `json:"is_banned"`
	JailName             string  `json:"jail_name"`
	Reason               string  `json:"reason"`
	BannedAt             int64   `json:"banned_at"`
	ExpiresAt            int64   `json:"expires_at"`
	IsPermanent          bool    `json:"is_permanent"`
	FailCount            uint32  `json:"fail_count"`
	BanCount             uint32  `json:"ban_count"`
	LastUnbannedAt       int64   `json:"last_unbanned_at"`
	WasPermanent         bool    `json:"was_permanent"`
	ProgressiveLevel     string  `json:"progressive_level"`
	NextBanDuration      string  `json:"next_ban_duration"`
	ReputationScore      uint32  `json:"reputation_score"`
	ReputationMultiplier float64 `json:"reputation_multiplier"`
}

// BanOperationResponse 是单条封禁/解封操作的结果（POST /api/v1/bans、
// DELETE /api/v1/bans/:ip、POST /api/v1/bans/unban-temporary）。
type BanOperationResponse struct {
	IP           string  `json:"ip"`
	Action       string  `json:"action"`
	Permanent    bool    `json:"permanent"`
	DurationSecs *uint64 `json:"duration_seconds"`
}

// BatchOperationResponse 是批量操作的汇总（POST /api/v1/bans/batch）。
//
// details 逐条给出失败原因（与请求里的 ips 同序），条数可以少于 total——只为失败的
// 那几条留原文，成功条目没有需要解释的东西。
type BatchOperationResponse struct {
	Total       uint64   `json:"total"`
	Succeeded   uint64   `json:"succeeded"`
	FailedCount uint64   `json:"failed_count"`
	Details     []string `json:"details"`
}

// CreateBanRequest 是 POST /api/v1/bans 的请求体。
//
// duration 用指针：契约把它声明成 Option<u64>，Go 侧要能原样表达「字段缺席」——单条封禁
// 里缺席与显式 0 同为永久（契约的这条路由就是这么定义的），但指针是契约类型本身，
// 用值类型会把「没写」读成「写了 0」，批量那条路由的缺省语义就不是 0 了。
type CreateBanRequest struct {
	IP       string  `json:"ip"`
	Duration *uint64 `json:"duration"`
	Reason   *string `json:"reason"`
}

// BatchBanRequest 是 POST /api/v1/bans/batch 的请求体。
//
// 与单条那条路由**共用不了**这个 struct 的地方是 duration 的缺省语义：这里缺席或 0 都是
// 「3600 秒的有时长封禁」，永不升格为永久（缺陷 HTTP_BATCH_BAN_BECOMES_PERMANENT 的
// resolution）。批量入口一旦把缺省读成永久，/api/v1/bans/unban-temporary 就看不见这批
// 条目（它只解临时），用户没有批量退路。
type BatchBanRequest struct {
	IPs      []string `json:"ips"`
	Duration *uint64  `json:"duration"`
	Reason   *string  `json:"reason"`
}

// WhitelistEntryResponse 是白名单的一条（前端 interface 名为 WhitelistEntry）。
type WhitelistEntryResponse struct {
	CIDR   string `json:"cidr"`
	Device string `json:"device"`
}

// WhitelistOperationResponse 是白名单增删操作的结果。
type WhitelistOperationResponse struct {
	CIDR   string `json:"cidr"`
	Action string `json:"action"`
}

// CreateWhitelistRequest 是 POST /api/v1/whitelist 的请求体。
type CreateWhitelistRequest struct {
	CIDR string `json:"cidr"`
}

// LogEntry 是一行日志：line_number 是它在文件里的物理行号（1 起）。
//
// 行号而不是数组下标：前端把 content 直接贴进 <pre>，用户要能拿行号去 grep 同一个文件。
type LogEntry struct {
	LineNumber uint64 `json:"line_number"`
	Content    string `json:"content"`
}

// LogPageResponse 是 GET /api/v1/logs 的分页载荷。
//
// total_lines 是**过滤后**的匹配行数（level/keyword/since 之后），前端据此算可翻页数；
// 与 PaginatedResponse.total 同义，但契约给日志单独起了名字，这里就照契约的形状写。
type LogPageResponse struct {
	Items      []LogEntry `json:"items"`
	TotalLines uint64     `json:"total_lines"`
	Page       uint32     `json:"page"`
	PageSize   uint32     `json:"page_size"`
	TotalPages uint32     `json:"total_pages"`
}

// SseStreamStatus 是一条 SSE 流的连接诊断。
//
// 两个计数在契约里是 usize，Go 侧对应 `int`（同为机器字长）——不是随手挑的无符号窄类型：
// 读数是 SSEStream 自己维护的名额账本，换类型只会多一次没有意义的转换。
type SseStreamStatus struct {
	CurrentConnections int  `json:"current_connections"`
	MaxConnections     int  `json:"max_connections"`
	LimitReached       bool `json:"limit_reached"`
}

// SseStatusResponse 是两条流各一份的诊断（GET /api/v1/stats/sse-status）。
//
// events 与 logs 的上限独立（10 / 5），limit_reached 由**所属流**判定：用一条流的上限
// 推断另一条，前端会在日志流被拒时判成「还没满」，把 503 当网络故障无限重连。
type SseStatusResponse struct {
	Events SseStreamStatus `json:"events"`
	Logs   SseStreamStatus `json:"logs"`
}

// banToResponse 把内存镜像的一条封禁映射成契约载荷。
//
// remaining_seconds 对永久封禁写 0：契约该字段是 i64 且没有 null 形状，而前端把
// is_permanent 当「不显示倒计时」的开关，剩余秒数在永久条目上没有读者。
func banToResponse(info bans.BanInfo, now int64) BanResponse {
	remaining := int64(0)
	if !info.IsPermanent && info.ExpiresAt > now {
		remaining = info.ExpiresAt - now
	}
	return BanResponse{
		IP:               info.IP,
		Jail:             info.JailName,
		BannedAt:         info.BannedAt,
		RemainingSeconds: remaining,
		Reason:           info.Reason,
		BanCount:         info.BanCount,
		IsPermanent:      info.IsPermanent,
	}
}

// banResponses 把整张活跃封禁表映射成契约载荷（REST 全集与 SSE bans 域共用）。
func banResponses(infos []bans.BanInfo, now int64) []BanResponse {
	out := make([]BanResponse, 0, len(infos))
	for _, info := range infos {
		out = append(out, banToResponse(info, now))
	}
	return out
}
