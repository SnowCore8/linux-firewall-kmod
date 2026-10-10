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
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
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

type BanRequest struct {
	IP       string `json:"ip"`
	Duration int64  `json:"duration,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type UnbanRequest struct {
	IP string `json:"ip"`
}

// batchBanMaxIPs 是 POST /api/v1/bans/batch 的单批上限（契约 code 40005 的 text 写死 100）。
const batchBanMaxIPs = 100

func (h *APIHandlers) ListBans(w http.ResponseWriter, r *http.Request) {
	banList := bans.GlobalCache().List()
	WriteSuccess(w, banList)
}

// CreateBan 落一条封禁：镜像 → 内核 → 历史 → 推送，任一步失败都回业务码 40001。
//
// 契约给 POST /api/v1/bans 只编了一个失败码（40001，text 覆盖「内核未确认、IP 非法、
// 内核返回错误」三种情形），区分它们靠 message，不靠临时新造数字。
func (h *APIHandlers) CreateBan(w http.ResponseWriter, r *http.Request) {
	var req BanRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		WriteCode(w, httpcontract.Code40001, "封禁失败：IP 非法 "+req.IP)
		return
	}

	isPermanent := req.Duration == 0
	duration := req.Duration
	if duration <= 0 {
		duration = 3600
	}

	now := time.Now().Unix()
	info := bans.BanInfo{
		IP:          req.IP,
		Reason:      req.Reason,
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
		if sendErr := h.kernelBan.Send(addr, prefixLen, durationSecs, req.Reason); sendErr != nil {
			h.server.logger.Error("内核封禁下发失败", "ip", req.IP, "error", sendErr)
			bans.GlobalCache().Remove(req.IP)
			WriteCode(w, httpcontract.Code40001, "封禁失败：内核未确认（"+sendErr.Error()+"）")
			return
		}
	}

	if h.db != nil {
		if err := h.db.RecordBanHistory(req.IP, isPermanent); err != nil {
			h.server.logger.Error("record ban history", "error", err)
		}
		if err := h.db.RecordBanEvent(req.IP, "api", 1, isPermanent); err != nil {
			h.server.logger.Error("record ban event", "error", err)
		}
	}

	h.publishBans()

	WriteSuccess(w, map[string]any{
		"ip":       req.IP,
		"duration": duration,
		"status":   "banned",
	})
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

	h.publishBans()

	WriteSuccess(w, map[string]any{
		"ip":     ip,
		"status": "unbanned",
	})
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

	h.publishBans()

	if len(failed) > 0 {
		WriteCode(w, httpcontract.Code40003, fmt.Sprintf(
			"批量解封临时封禁失败：%d/%d 条未下发内核，首个原因 %s", len(failed), len(ips), failed[0]))
		return
	}

	WriteSuccess(w, map[string]any{
		"unbanned_count": len(ips),
	})
}

// BatchBan 一次落多条封禁。参数非法（列表为空或超过 100 条）回业务码 40005。
func (h *APIHandlers) BatchBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs      []string `json:"ips"`
		Duration int64    `json:"duration,omitempty"`
		Reason   string   `json:"reason,omitempty"`
	}
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

	isPermanent := req.Duration == 0
	duration := req.Duration
	if duration <= 0 {
		duration = 3600
	}

	now := time.Now().Unix()
	var successCount, failCount int
	for _, ip := range req.IPs {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			failCount++
			continue
		}

		info := bans.BanInfo{
			IP:          ip,
			Reason:      req.Reason,
			BannedAt:    now,
			IsPermanent: isPermanent,
		}
		if !isPermanent {
			info.ExpiresAt = now + duration
		}

		if !bans.GlobalCache().TryInsert(info) {
			failCount++
			continue
		}

		// 下发内核 netfilter；失败回滚这一条的镜像（同 CreateBan）。
		if h.kernelBan != nil {
			durationSecs := uint32(0)
			if !isPermanent {
				durationSecs = uint32(duration)
			}
			prefixLen := bans.FullPrefixLen(addr)
			if sendErr := h.kernelBan.Send(addr, prefixLen, durationSecs, req.Reason); sendErr != nil {
				h.server.logger.Error("batch ban kernel send failed", "ip", ip, "error", sendErr)
				bans.GlobalCache().Remove(ip)
				failCount++
				continue
			}
		}

		successCount++
		if h.db != nil {
			if err := h.db.RecordBanHistory(ip, isPermanent); err != nil {
				h.server.logger.Error("record ban history", "error", err)
			}
		}
	}

	h.publishBans()

	WriteSuccess(w, map[string]any{
		"success_count": successCount,
		"fail_count":    failCount,
	})
}

// BanDetail 报单个 IP 的封禁详情与历史记录（GET /api/v1/bans/{ip}/detail）。
//
// 两个失败分支共用业务码 40006：契约给这条路由只编了这一个码，靠 message 区分
// 「IP 写错了」与「这个 IP 目前没被封」。
func (h *APIHandlers) BanDetail(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")

	if _, err := netip.ParseAddr(ip); err != nil {
		WriteCode(w, httpcontract.Code40006, "封禁详情查询失败：IP 非法 "+ip)
		return
	}

	info, ok := bans.GlobalCache().Get(ip)
	if !ok {
		WriteCode(w, httpcontract.Code40006, "封禁详情查询失败：该 IP 不在封禁表中 "+ip)
		return
	}

	detail := map[string]any{
		"ip":           ip,
		"reason":       info.Reason,
		"banned_at":    info.BannedAt,
		"expires_at":   info.ExpiresAt,
		"is_permanent": info.ExpiresAt == 0,
	}

	if h.db != nil {
		if history, err := h.db.GetBanHistory(ip); err == nil && history != nil {
			detail["ban_count"] = history.BanCount
			detail["last_banned_at"] = history.LastBannedAt
		}
		if rep, err := h.db.GetIPReputation(ip); err == nil && rep != nil {
			detail["reputation_score"] = rep.Score
		}
	}

	WriteSuccess(w, detail)
}
