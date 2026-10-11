// 封禁面：POST/DELETE /api/v1/bans 与其子路由。错误一律走契约声明的业务码。
//
// 这里没有一处 `r.Method` 自查：路由按 `"GET /api/v1/bans"` 这种带方法的模式注册，
// 动词不符由 ServeMux 直接回 405（契约 errmodel FRAMEWORK_DEFAULT）。handler 里再查
// 一遍等于写两份 405，而且那份永远不会被执行——契约的 405 是纯文本，信封版 405 反而
// 会让前端两种形状都要防。
package http

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// KernelBan 是内核封禁下发与解封的最小接口。
//
// 由组合根注入 banSink 实现；接口定义在 http 包以避免循环依赖。
// 为 nil 时封禁仅写入缓存与数据库，不下发 netfilter。
type KernelBan interface {
	Send(addr netip.Addr, prefixLen uint8, durationSecs uint32, reason string) error
	Remove(addr netip.Addr, prefixLen uint8) error
}

// batchBanMaxIPs 是 POST /api/v1/bans/batch 的单批上限（契约 code 40005 的 text 写死 100）。
const batchBanMaxIPs = 100

// 封禁列表的分页缺省与上限（契约 HTTP_BANS_DUAL_SHAPE 的 resolution 写死这三个数）。
//
// 这里的分页是**宽容**的：读不懂的 page/page_size 当作没带（见 query.go 的
// queryPagination），因为契约给 GET /api/v1/bans 只编了 code 0，没有「分页参数非法」
// 这个失败码可用。日志那条路由编了 40005，所以它才做严格校验（parseLogQuery）——两边的
// 宽容度是契约分别定的，不是实现随手挑的。
const (
	banDefaultPage      = 1
	banDefaultPageSize  = 20
	banMaxPageSize      = 100
	banDefaultBatchSecs = 3600
)

// banSortKeys 是 GET /api/v1/bans 的 sort_by 合法取值（契约 HTTP_BAN_SORT_DOC_INCOMPLETE
// 要求注释、代码分支与前端 BanSortKey 三者逐字一致，未识别的值回落 banned_at_desc）。
var banSortKeys = map[string]func(a, b BanResponse) bool{
	"banned_at_desc": func(a, b BanResponse) bool { return a.BannedAt > b.BannedAt },
	"banned_at_asc":  func(a, b BanResponse) bool { return a.BannedAt < b.BannedAt },
	"ip_asc":         func(a, b BanResponse) bool { return a.IP < b.IP },
	"ip_desc":        func(a, b BanResponse) bool { return a.IP > b.IP },
	"jail_asc":       func(a, b BanResponse) bool { return a.Jail < b.Jail },
	"remaining_asc":  func(a, b BanResponse) bool { return a.RemainingSeconds < b.RemainingSeconds },
	"remaining_desc": func(a, b BanResponse) bool { return a.RemainingSeconds > b.RemainingSeconds },
}

// ListBans 返回分页后的活跃封禁表（GET /api/v1/bans）。
//
// 单一形状：任何情况下都是 PaginatedResponse<BanResponse>，没有「不带 query 就写裸数组」
// 的分支。前端 Bans 页过去按客户端分页取全量，现在改为把 page/page_size/sort_by 交给
// 服务端——裸数组那一支留着只会让两侧同时存在两种返回类型（缺陷 HTTP_BANS_DUAL_SHAPE）。
func (h *APIHandlers) ListBans(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()
	items := banResponses(bans.GlobalCache().All(), now)

	params := queryPagination(r)
	less, ok := banSortKeys[params.sortByOr()]
	if !ok {
		// 未识别的取值（含缺席）回落 banned_at_desc：最新封禁排在第一页，
		// 运维打开页面看到的就是刚刚发生的事。
		less = banSortKeys["banned_at_desc"]
	}
	sort.SliceStable(items, func(i, j int) bool { return less(items[i], items[j]) })

	total := uint64(len(items))
	page := params.pageOr(banDefaultPage)
	pageSize := params.pageSizeOr(banDefaultPageSize, banMaxPageSize)
	totalPages := uint32((total + uint64(pageSize) - 1) / uint64(pageSize))

	// 页内区间在 uint64 上算：page 最大可以到 uint32 上限，用 uint32 乘 pageSize 会回绕
	// 成一个落在范围内的假起点，把第 4 亿页显示成第 1 页。
	start := uint64(page-1) * uint64(pageSize)
	if start > total {
		start = total
	}
	end := start + uint64(pageSize)
	if end > total {
		end = total
	}

	WriteSuccess(w, PaginatedResponse[BanResponse]{
		Items:      items[start:end],
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	})
}

// durationSeconds 把 CreateBanRequest.duration 的三态压成一个数与一个永久标记。
//
// 缺席与显式 0 都是永久（契约的 Option<u64> 加前端 types.ts 那句「0 或省略 = 永久」）；
// 这里用指针把它们与「显式给了时长」分开，负数在 uint64 下根本解不进来。
func durationSeconds(p *uint64) (secs int64, permanent bool) {
	if p == nil || *p == 0 {
		return 0, true
	}
	return int64(*p), false
}

// CreateBan 落一条封禁：镜像 → 内核 → 历史 → 推送，任一步失败都回业务码 40001。
//
// 契约给 POST /api/v1/bans 只编了一个失败码（40001，text 覆盖「内核未确认、IP 非法、
// 内核返回错误」三种情形），区分它们靠 message，不靠临时新造数字。
func (h *APIHandlers) CreateBan(w http.ResponseWriter, r *http.Request) {
	var req CreateBanRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		WriteCode(w, httpcontract.Code40001, "封禁失败：IP 非法 "+req.IP)
		return
	}

	duration, isPermanent := durationSeconds(req.Duration)
	reason := "manual"
	if req.Reason != nil && *req.Reason != "" {
		reason = *req.Reason
	}

	now := time.Now().Unix()
	info := bans.BanInfo{
		IP:          req.IP,
		Reason:      reason,
		BannedAt:    now,
		IsPermanent: isPermanent,
	}
	if !isPermanent {
		info.ExpiresAt = now + duration
	}

	if !bans.GlobalCache().TryInsert(info) {
		WriteCode(w, httpcontract.Code40001, "封禁失败：该 IP 已在封禁表中 "+req.IP)
		return
	}

	// 下发内核 netfilter。失败必须回滚镜像：留着缓存里那条，面板会显示一个 netfilter
	// 里不存在的封禁，而运维按面板判断拦截是否生效。
	if h.kernelBan != nil {
		durationSecs := uint32(0)
		if !isPermanent {
			durationSecs = uint32(duration)
		}
		prefixLen := bans.FullPrefixLen(addr)
		if sendErr := h.kernelBan.Send(addr, prefixLen, durationSecs, reason); sendErr != nil {
			h.server.logger.Error("内核封禁下发失败", "ip", req.IP, "error", sendErr)
			bans.GlobalCache().Remove(req.IP)
			WriteCode(w, httpcontract.Code40001, "封禁失败：内核未确认（"+sendErr.Error()+"）")
			return
		}
	}

	if h.db != nil {
		// 先写历史、再拿它返回的累计序号写事件：手工封禁没有判定层告诉这里「这是第几封」，
		// 序号只能出自 ban_history。写死 1 会让重复手工封禁的地址在分级成效里永远停在
		// 第 1 级，复发统计也认不出它。历史写失败时退化成 1（底账不能因为上一步失败就整条不记）。
		historyCount, err := h.db.RecordBanHistory(req.IP, isPermanent)
		if err != nil {
			h.server.logger.Error("record ban history", "error", err)
			historyCount = 1
		}
		if err := h.db.RecordBanEvent(req.IP, "api", historyCount, isPermanent, info.PlannedDuration()); err != nil {
			h.server.logger.Error("record ban event", "error", err)
		}
	}

	h.publishBans()

	// action 只说做成了什么动作，永久与否由 permanent 表达——再造一个 "banned_permanent"
	// 会让读侧同时比较两个维度，而这两个维度说的是同一件事。
	resp := BanOperationResponse{IP: req.IP, Action: "banned", Permanent: isPermanent}
	if !isPermanent {
		secs := uint64(duration)
		resp.DurationSecs = &secs
	}
	WriteCreated(w, resp)
}

// DeleteBan 撤一条封禁，失败回业务码 40002（契约给这条路由只编了这一个码）。
func (h *APIHandlers) DeleteBan(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		WriteCode(w, httpcontract.Code40002, "解封失败：IP 非法 "+ip)
		return
	}

	if !bans.GlobalCache().Remove(ip) {
		WriteCode(w, httpcontract.Code40002, "解封失败：该 IP 不在封禁表中 "+ip)
		return
	}

	// 下发内核解封。这里的失败**不回滚**也不改状态码：镜像已经撤了，netfilter 里那条
	// 会在 TTL 到点自行消失；把它记成一次日志而不是 400，是因为调用方要的效果（不再
	// 拦截）已经达到了。
	if h.kernelBan != nil {
		prefixLen := bans.FullPrefixLen(addr)
		if err := h.kernelBan.Remove(addr, prefixLen); err != nil {
			h.server.logger.Error("内核解封下发失败", "ip", ip, "error", err)
		}
	}

	// 记下解封时刻：GET /api/v1/bans/:ip/detail 的 last_unbanned_at 只有这一个来源
	// （见 persist.RecordUnbanHistory）。写失败只记日志——封禁已经撤掉了，不能因为
	// 一条审计时间戳把响应改成 40002。
	if h.db != nil {
		if err := h.db.RecordUnbanHistory(ip); err != nil {
			h.server.logger.Error("record unban history", "ip", ip, "error", err)
		}
	}

	h.publishBans()

	WriteSuccess(w, BanOperationResponse{IP: ip, Action: "unbanned"})
}

// UnbanAllTemporary 撤掉所有临时封禁；有 IP 的内核解封下发失败就回业务码 40003。
//
// 失败时镜像里的封禁已经撤掉、响应不再是成功：契约给这条路由编的码就是「批量解封临时
// 封禁失败」，把部分失败包成 200 + fail_count 会让运维以为拦截已全部撤除，而面板上
// 看不见的 netfilter 规则还在生效。
func (h *APIHandlers) UnbanAllTemporary(w http.ResponseWriter, r *http.Request) {
	ips := bans.GlobalCache().UnbanTemporaryWithIPs()

	var failed []string
	if h.kernelBan != nil {
		for _, ip := range ips {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				failed = append(failed, ip+"（IP 非法）")
				continue
			}
			prefixLen := bans.FullPrefixLen(addr)
			if err := h.kernelBan.Remove(addr, prefixLen); err != nil {
				h.server.logger.Error("批量内核解封失败", "ip", ip, "error", err)
				failed = append(failed, ip+"（"+err.Error()+"）")
			}
		}
	}

	// 与 DeleteBan 同一口径：镜像里已被撤掉的临时封禁逐条记解封时刻。
	// failed 只说明 netfilter 那条规则没撤成（它到 TTL 会自己消失），不影响这里记账。
	if h.db != nil {
		for _, ip := range ips {
			if err := h.db.RecordUnbanHistory(ip); err != nil {
				h.server.logger.Error("record unban history", "ip", ip, "error", err)
			}
		}
	}

	h.publishBans()

	if len(failed) > 0 {
		WriteCode(w, httpcontract.Code40003, fmt.Sprintf(
			"批量解封临时封禁失败：%d/%d 条未下发内核，首个原因 %s", len(failed), len(ips), failed[0]))
		return
	}

	WriteSuccess(w, BatchOperationResponse{
		Total:       uint64(len(ips)),
		Succeeded:   uint64(len(ips)),
		FailedCount: 0,
		Details:     []string{},
	})
}

// BatchBan 一次落多条封禁。参数非法（列表为空或超过 100 条）回业务码 40005。
//
// 批量**永远不产生永久封禁**：请求里的 duration 缺席或为 0 一律按 3600 秒下发（缺陷
// HTTP_BATCH_BAN_BECOMES_PERMANENT 的现场就是「确认弹窗承诺 3600 秒、实际把整批永久
// 封了」，而 /api/v1/bans/unban-temporary 只解临时封禁，永久条目没有批量退路）。
// 单条 POST /api/v1/bans 仍按契约保留「缺席/0 = 永久」——那是运维逐条点下的决定。
func (h *APIHandlers) BatchBan(w http.ResponseWriter, r *http.Request) {
	var req BatchBanRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if len(req.IPs) == 0 {
		WriteCode(w, httpcontract.Code40005, "批量封禁参数非法：列表为空")
		return
	}
	if len(req.IPs) > batchBanMaxIPs {
		WriteCode(w, httpcontract.Code40005, fmt.Sprintf(
			"批量封禁参数非法：单批最多 %d 条，实际 %d", batchBanMaxIPs, len(req.IPs)))
		return
	}

	duration := uint64(banDefaultBatchSecs)
	if req.Duration != nil && *req.Duration > 0 {
		duration = *req.Duration
	}
	reason := "manual"
	if req.Reason != nil && *req.Reason != "" {
		reason = *req.Reason
	}

	now := time.Now().Unix()
	var successCount, failCount int
	details := make([]string, 0, len(req.IPs))
	for _, ip := range req.IPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			failCount++
			details = append(details, ip+": IP 非法")
			continue
		}

		info := bans.BanInfo{
			IP:          ip,
			Reason:      reason,
			BannedAt:    now,
			IsPermanent: false,
			ExpiresAt:   now + int64(duration),
		}

		if !bans.GlobalCache().TryInsert(info) {
			failCount++
			details = append(details, ip+": 该 IP 已在封禁表中")
			continue
		}

		// 下发内核 netfilter；失败回滚这一条的镜像（同 CreateBan）。
		if h.kernelBan != nil {
			prefixLen := bans.FullPrefixLen(addr)
			if sendErr := h.kernelBan.Send(addr, prefixLen, uint32(duration), reason); sendErr != nil {
				h.server.logger.Error("batch ban kernel send failed", "ip", ip, "error", sendErr)
				bans.GlobalCache().Remove(ip)
				failCount++
				details = append(details, ip+": 内核未确认（"+sendErr.Error()+"）")
				continue
			}
		}

		successCount++
		if h.db != nil {
			// 批量封禁同样要进 ban_events：这一张表是分析面（复发率、周期攻击、时长直方图、
			// 分级成效）唯一的底账。只写 ban_history 的话，从面板批量封的那批地址在分析里
			// 等于没发生过——两个表各写一半是旧实现留下的裂缝。序号取 ban_history 加完之后的
			// 累计值（同 CreateBan），写死 1 会把重复批量封禁读成「每次都只封了一次」。
			historyCount, err := h.db.RecordBanHistory(ip, false)
			if err != nil {
				h.server.logger.Error("record ban history", "ip", ip, "error", err)
				historyCount = 1
			}
			if err := h.db.RecordBanEvent(ip, "api", historyCount, false, info.PlannedDuration()); err != nil {
				h.server.logger.Error("record ban event", "ip", ip, "error", err)
			}
		}
	}

	h.publishBans()

	WriteCreated(w, BatchOperationResponse{
		Total:       uint64(len(req.IPs)),
		Succeeded:   uint64(successCount),
		FailedCount: uint64(failCount),
		Details:     details,
	})
}

// BanDetail 报单个 IP 的封禁详情与历史记录（GET /api/v1/bans/{ip}/detail）。
//
// **未被封禁不是错误**：契约给这条路由只编了 40006，而它的 text 写的是「封禁详情查询失败
// （IP 非法）」——「这个 IP 目前没被封」是查询成功后的一个读数，不是查询失败。载荷里的
// is_banned 正是为此存在的：运维刚点完解封、还想看这个 IP 的历史与信誉分时，面板要的正是
// 这份 is_banned=false 的 200。把「不在封禁表中」写成 40006 会让整块详情变成一句错误提示，
// 而调用方手上的信息其实是完整的。
//
// 历史库读失败**不改状态码**：这条路由没编 50002，缺项由 struct 零值表达（时间戳 0 =
// 无记录，前端 types.ts 对每个零值都写了自己的显示口径），并在服务端留一条日志。
func (h *APIHandlers) BanDetail(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")

	if _, err := netip.ParseAddr(ip); err != nil {
		WriteCode(w, httpcontract.Code40006, "封禁详情查询失败：IP 非法 "+ip)
		return
	}

	detail := BanDetailResponse{IP: ip}

	if h.db != nil {
		if history, err := h.db.GetBanHistory(ip); err != nil {
			h.server.logger.Warn("读取封禁历史失败", "ip", ip, "error", err)
		} else if history != nil {
			detail.BanCount = uint32(history.BanCount)
			detail.WasPermanent = history.IsPermanent
			detail.LastUnbannedAt = history.LastUnbannedAt
		}
		if rep, err := h.db.GetIPReputation(ip); err != nil {
			h.server.logger.Warn("读取 IP 信誉分失败", "ip", ip, "error", err)
		} else if rep != nil {
			detail.ReputationScore = uint32(rep.Score)
		}
	}

	// 当前封禁状态来自内存镜像（与内核 LIST 对账后的那份），它是 is_banned 的唯一依据。
	if info, banned := bans.GlobalCache().Get(ip); banned {
		detail.IsBanned = true
		detail.Reason = info.Reason
		detail.BannedAt = info.BannedAt
		detail.ExpiresAt = info.ExpiresAt
		detail.IsPermanent = info.IsPermanent
		detail.FailCount = info.FailCount
		detail.JailName = info.JailName
		if info.BanCount > detail.BanCount {
			detail.BanCount = info.BanCount
		}
	}

	// jail 归属：未在封禁中（或封禁条目没带 jail）时退回最近一次封禁事件。
	// 面板上的「Jail」与「下次封禁时长」都要靠它知道该查哪份配置。
	if detail.JailName == "" && h.db != nil {
		if events, err := h.db.GetBanEventsByIP(ip, 1); err == nil && len(events) > 0 {
			detail.JailName = events[0].JailName
		}
	}

	banTime, jailKnown := h.jailBaseDuration(detail.JailName)
	detail.ProgressiveLevel = progressiveLevel(detail.BanCount)
	detail.NextBanDuration = nextBanDuration(banTime, jailKnown, detail.BanCount)
	detail.ReputationMultiplier = decision.ReputationMultiplier(detail.ReputationScore)

	WriteSuccess(w, detail)
}

// jailBaseDuration 取某个 jail 配置的封禁时长（秒，-1 = 配置级永久）。
//
// 第二个返回值报告「这个 jail 到底在不在配置里」：缺席时不能把 BanTime 的零值当
// 「封 0 秒」报出去——面板上出现「下次封禁 0 秒」是运维能看到的最误导人的读数。
func (h *APIHandlers) jailBaseDuration(name string) (banTime int32, known bool) {
	if name == "" || h.getCurrentConfig == nil {
		return 0, false
	}
	cfg := h.getCurrentConfig()
	if cfg == nil {
		return 0, false
	}
	jail := cfg.FindJail(name)
	if jail == nil {
		return 0, false
	}
	return jail.BanTime, true
}

// progressiveLevel 把累计封禁次数说成一句等级文案。
//
// BanDetailResponse.progressive_level 在契约里是 String 而不是枚举：它给面板读，
// 不参与判定。分档与 decision.ProgressiveDuration 的 0/1/2/≥3 四档同一，两处一旦
// 分叉，等级就不再能解释旁边那个时长。
func progressiveLevel(banCount uint32) string {
	switch banCount {
	case 0:
		return "尚无封禁记录"
	case 1:
		return "初次封禁"
	case 2:
		return "二次封禁（累犯）"
	case 3:
		return "三次封禁（高频累犯）"
	default:
		return "四次及以上（永久封禁档）"
	}
}

// nextBanDuration 说出「这个 IP 再被封一次会封多久」，算式与 decision.PlanBan 同一条：
// jail 查不到 = 未知，ban_time 为负 = 配置级永久，第 4 次起渐进式升到永久。
//
// prior 用**已经发生过的次数**（detail.BanCount）：第 1 次被封之后 ban_count=1，下一次
// 就是 ProgressiveDuration(base, 1) = 1800 秒，与真实判定链路的取值一致。
func nextBanDuration(banTime int32, known bool, priorBanCount uint32) string {
	if !known {
		return "未知"
	}
	if banTime < 0 {
		return "永久封禁"
	}
	next := decision.ProgressiveDuration(uint32(banTime), priorBanCount)
	if next == 0 {
		// 0 有两个来源：第 4 次起（永久），或 ban_time == 0 的退化配置——PlanBan 在
		// 后者兜底为至少 1 秒，这里按同一判据分岔，不说出「0 秒」。
		if priorBanCount >= 3 {
			return "永久封禁"
		}
		return "1 秒"
	}
	return fmt.Sprintf("%d 秒", next)
}
