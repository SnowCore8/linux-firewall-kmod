package http

import (
	"net/http"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
)

// ListJails 返回当前配置的 jail 清单（GET /api/v1/jails）。
//
// 单个 jail 的详情与统计没有契约路由：契约只在 /api/v1/jails 汇总这一层暴露 jail，
// 逐 jail 的计数器因此都并进这里的载荷（配置值 + 运行时读数 + 判定层系数）。
//
// 三类数各自的原点不同，载荷里必须能看出来：
//   - max_retries / findtime / ban_time 是**配置**（可热重载，故每次现取而非启动快照）；
//   - ban_count 是**当前活跃**封禁（内存镜像，与 stats 的 current_bans 同源），不是历史累计；
//   - lines_parsed … bans_triggered 是本进程解析日志以来的累计计数，进程重启即归零。
func (h *APIHandlers) ListJails(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, h.jailResponses())
}

// jailResponses 把 jail 配置快照折成 JailResponse 数组（按配置顺序，不排序）。
//
// REST 与 SSE 的 jails 域共用这一个函数：两条路读的是同一份快照，若各自拼一遍载荷，
// 「刷新后开关弹回原位」就会以另一种形式回来——SSE 帧里的 enabled 与 REST 里的不一样。
func (h *APIHandlers) jailResponses() []JailResponse {
	jails := config.GetActiveJails()
	active := bans.GlobalCache().CountByJail()
	peak := decision.IsPeakHours(uint32(time.Now().UTC().Hour()))

	out := make([]JailResponse, 0, len(jails))
	for _, j := range jails {
		resp := JailResponse{
			Name:       j.Name,
			Enabled:    j.Enabled,
			BanCount:   active[j.Name],
			MaxRetries: j.MaxRetries,
			// 内网系数按**来源地址**生效、信誉系数按该地址的分数生效，都不属于 jail，
			// 所以 jail 级只折高峰期这一项（其余两个系数原样给出，让读侧知道自己那档是多少）。
			EffectiveMaxRetries:  decision.EffectiveThreshold(j.MaxRetries, peak, false, 100),
			Findtime:             j.FindTime,
			BanTime:              j.BanTime,
			IsPeakHours:          peak,
			PeakHoursMultiplier:  decision.PeakHoursMultiplier,
			InternalIPMultiplier: decision.InternalSourceMultiplier,
		}
		if stats, ok := config.GetJailStats(j.Name); ok && stats != nil {
			resp.LinesParsed = stats.LinesParsed
			resp.RegexMatches = stats.RegexMatches
			resp.IPsExtracted = stats.IPsExtracted
			resp.FailedAttempts = stats.FailedAttempts
			resp.BansTriggered = stats.BansTriggered
		}
		out = append(out, resp)
	}
	return out
}
