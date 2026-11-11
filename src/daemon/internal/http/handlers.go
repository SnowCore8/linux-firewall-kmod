// 历史库分析面的 handler：复发、信誉、周期/联动/网段、预测与两类调参建议，
// 以及三条按契约**在 200 信封内降级**的统计（分级成效、时长直方图、攻击源地理）。
//
// 两条纪律：
//   - 载荷一律走 analysis_payload.go 的具名 struct，不写 map[string]any；
//   - 契约给某条路由没编 codes（ban-effectiveness / ban-duration-histogram / attack-geo），
//     意思就是「这条路由不向调用方报业务错误」：读不到数据时在 200 里给出**空读数 +
//     一句 summary**，而不是 500。其余各条按契约编的 50002（库未初始化）/50003（查询失败）
//     如实报错——把「查不到」伪造成「一切正常但没有数据」会让面板替运维做决定。
package http

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/geoip"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

func parseLimit(r *http.Request, defaultLimit, maxLimit int) int {
	limit := defaultLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= maxLimit {
			limit = n
		}
	}
	return limit
}

// jailParams 是配置里活跃 jail 的当前调参值，喂给两个建议分析。
//
// 为什么由读侧现取而不是一次注入：jail 配置可以热重载，建议面板要回答的是
// 「相对**现在**的阈值/时长该往哪改」，用启动时的快照会在改过配置之后继续给旧建议。
type jailParams struct {
	thresholds map[string]int
	durations  map[string]int64
}

func currentJailParams() jailParams {
	jails := config.GetActiveJails()
	params := jailParams{
		thresholds: make(map[string]int, len(jails)),
		durations:  make(map[string]int64, len(jails)),
	}
	for _, j := range jails {
		params.thresholds[j.Name] = int(j.MaxRetries)
		// BanTime 为负 = 配置级永久封禁，分析层据此跳过该 jail（见 RecommendBanDurations）。
		params.durations[j.Name] = int64(j.BanTime)
	}
	return params
}

// known 报告 jail 是否还在配置里。
//
// 事件表里的 jail 名可能来自已删除的 jail，或来自 API 手工封禁那条路径（固定写 "api"，
// 它不是一个有阈值可調的 jail）。对它们谈「把阈值从几改到几」没有落点，而分析层对查不到
// 的 jail 会给一个兜底默认值——载荷读起来和真读数一样，所以在这里滤掉。
func (p jailParams) known(jail string) bool {
	_, ok := p.thresholds[jail]
	return ok
}

// Recidivism 返回复发统计（GET /api/v2/stats/recidivism）。
//
// permanent_bans 取自 ban_history（**当前**标记为永久的地址数），与前三项取自
// ban_events（累计封禁底账）不同源——两个表回答的是两个问题，契约的字段注释各写各自的口径。
func (h *APIHandlers) Recidivism(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	totalIPs, recidivistIPs, rate, err := h.db.GetRecidivismStats()
	if err != nil {
		h.server.logger.Error("query recidivism stats", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	top, err := h.db.GetTopRecidivists(10)
	if err != nil {
		h.server.logger.Error("query top recidivists", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	_, _, permanentBans, err := h.db.GetBanHistoryStats()
	if err != nil {
		h.server.logger.Error("query ban history stats", "error", err)
		WriteInternalError(w, "internal error")
		return
	}

	resp := RecidivismResponse{
		TotalIPs:       uint64(clampInt(totalIPs)),
		RecidivistIPs:  uint64(clampInt(recidivistIPs)),
		RecidivismRate: rate,
		PermanentBans:  uint64(clampInt(permanentBans)),
		TopRecidivists: make([]RecidivistEntry, 0, len(top)),
	}
	for _, e := range top {
		resp.TopRecidivists = append(resp.TopRecidivists, RecidivistEntry{
			IP:           e.IP,
			BanCount:     uint32(clampInt(e.BanCount)),
			LastBannedAt: e.BannedAt,
			WasPermanent: e.IsPermanent,
		})
	}
	WriteSuccess(w, resp)
}

// Reputation 返回低信誉地址清单（GET /api/v2/stats/reputation）。
//
// 阈值固定 80：那是判定层信誉调整的第一档分界（ReputationAdjustment 在 80 分以下才开始
// 收紧阈值），面板上「需要看一眼的名单」因此与判定层实际改行为的分界同源。
func (h *APIHandlers) Reputation(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 20, 1000)
	reps, err := h.db.GetLowReputationIPs(80, limit)
	if err != nil {
		h.server.logger.Error("query low reputation IPs", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, mapReputationEntries(reps))
}

// PeriodicAttackers 返回等间隔复现的扫描源（GET /api/v2/stats/periodic-attackers）。
func (h *APIHandlers) PeriodicAttackers(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 20, 1000)
	findings, err := analysis.DetectPeriodicAttackers(h.db, 3, limit, 10000)
	if err != nil {
		h.server.logger.Error("detect periodic attackers", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, mapPeriodicAttackers(findings))
}

// CollaborativeAttacks 返回同窗口多源联动（GET /api/v2/stats/collaborative-attacks）。
func (h *APIHandlers) CollaborativeAttacks(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 20, 1000)
	findings, err := analysis.DetectCollaborativeAttacks(h.db, 300, 3, limit, 10000)
	if err != nil {
		h.server.logger.Error("detect collaborative attacks", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, mapCollaborativeAttacks(findings))
}

// NetworkDistribution 返回同网段的封禁聚合（GET /api/v2/stats/network-distribution）。
func (h *APIHandlers) NetworkDistribution(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 50, 1000)
	rows, err := analysis.AnalyzeNetworkDistribution(h.db, 7, limit)
	if err != nil {
		h.server.logger.Error("analyze network distribution", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, mapNetworkBlocks(rows))
}

// AttackPredictions 返回下次动手的估计（GET /api/v2/stats/attack-predictions）。
func (h *APIHandlers) AttackPredictions(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	limit := parseLimit(r, 15, 100)
	summary, err := analysis.PredictAttacks(h.db, limit)
	if err != nil {
		h.server.logger.Error("predict attacks", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	// remaining_secs 以本次读取的时刻为基准：它是「相对现在还剩多久」，
	// 在分析层算就会把时刻钉死在采样时间上。
	WriteSuccess(w, mapPredictions(summary, time.Now()))
}

// BanDurationRecommendations 返回封禁时长建议（GET /api/v2/stats/ban-duration-recommendations）。
func (h *APIHandlers) BanDurationRecommendations(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	params := currentJailParams()
	findings, err := analysis.RecommendBanDurations(h.db, params.durations)
	if err != nil {
		h.server.logger.Error("recommend ban durations", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, mapBanDurationRecommendations(findings, params.known))
}

// ThresholdRecommendations 返回失败阈值建议（GET /api/v2/stats/threshold-recommendations）。
func (h *APIHandlers) ThresholdRecommendations(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteServiceUnavailable(w, "history database not initialized")
		return
	}
	params := currentJailParams()
	findings, err := analysis.RecommendThresholds(h.db, params.thresholds)
	if err != nil {
		h.server.logger.Error("recommend thresholds", "error", err)
		WriteInternalError(w, "internal error")
		return
	}
	WriteSuccess(w, mapThresholdRecommendations(findings, params.known))
}

// BanEffectiveness 返回渐进式封禁各级的成效（GET /api/v2/stats/ban-effectiveness）。
//
// 契约没给这条路由编 codes，所以库缺失与查询失败都在 200 里降级（空 levels + 一句
// summary），并只在服务端留日志。summary 会说清是「没有底账」还是「查不动」：
// 面板上同一句「无样本」背后的两种原因必须能分开，否则运维不知道是该等数据还是该修库。
func (h *APIHandlers) BanEffectiveness(w http.ResponseWriter, r *http.Request) {
	empty := BanEffectivenessResponse{
		Levels:         []BanLevelEffectiveness{},
		TotalUniqueIPs: 0,
		Summary:        "历史库未初始化：没有封禁底账，分级成效无从计算",
	}
	if h.db == nil {
		WriteSuccess(w, empty)
		return
	}
	rows, err := h.db.GetBanLevelRows()
	if err != nil {
		h.server.logger.Error("query ban level rows", "error", err)
		resp := empty
		resp.Summary = "封禁底账查询失败：本次没有分级成效读数"
		WriteSuccess(w, resp)
		return
	}
	WriteSuccess(w, mapBanEffectiveness(rows))
}

// BanDurationHistogram 返回封禁时长的分布直方图（GET /api/v2/stats/ban-duration-histogram）。
//
// 桶形状恒定（6 格：5 个时长档 + 永久），没有可读时长时全为 0。契约没给这条路由编 codes，
// 因此同样在 200 内降级。
//
// total 只数「有 duration 读数的事件 + 永久事件」：迁移前写的旧行没有这一列，
// 把它们算进任何一桶都是造数据（列形状见 persist 的 ban_events.duration_secs）。
func (h *APIHandlers) BanDurationHistogram(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		WriteSuccess(w, mapBanDurationHistogram(nil))
		return
	}
	samples, err := h.db.BanDurationSamples(banDurationSampleLimit)
	if err != nil {
		h.server.logger.Error("query ban duration samples", "error", err)
		WriteSuccess(w, mapBanDurationHistogram(nil))
		return
	}
	WriteSuccess(w, mapBanDurationHistogram(samples))
}

// banDurationSampleLimit 是直方图一次读多少条事件。
//
// 与其余分析取同一量级（10000）：直方图是**分布**，样本太薄时各桶的相对高度没有意义，
// 而再多就被 limit 本身的成本超过了——这一列没有索引可走，读的是全表尾部。
const banDurationSampleLimit = 10000

// attackGeoEventLimit 是地理分布一次读取的封禁事件条数。
//
// 与其余分析同量级（2000）：事件表按时间倒序取尾部，再按 IP 去重后逐条查库；
// 读得更多只会把同一批高频攻击 IP 重复计入，不会增加地图上的点。
const attackGeoEventLimit = 2000

// attackGeoPointLimit 是地图一次返回的定位点上限（按封禁次数取前 N 个）。
const attackGeoPointLimit = 200

// AttackGeo 返回攻击源地理分布（GET /api/v2/stats/attack-geo）。
//
// 数据源：近 attackGeoEventLimit 条封禁事件按 IP 去重，逐个用 mmdb 定位；同一定位桶
// （坐标保留两位小数）聚合出 unique_ips / total_bans / top_ip / last_banned_at。
// 未配置 geoip_db_path 或库打不开时 geoip_enabled=false、points 空、两个计数 0；
// 库在场但事件读不到时同样是 200 空读数（契约没给这条路由编错误码）。
//
// 本机坐标三件套：配置给出坐标为 "config"；配置没给且出口探测成功为 "detected"；
// 都没有则 source="none"、经纬度为 null。source/config 的取值由组合根算好放在
// config.ServerCoordsSource，这里只做投影，不在这里探测网络。
func (h *APIHandlers) AttackGeo(w http.ResponseWriter, r *http.Request) {
	resp := AttackGeoResponse{
		GeoipEnabled:         h.geoIP != nil,
		Points:               []GeoPoint{},
		ServerLocationSource: "none",
	}
	if cfg := h.currentConfig(); cfg != nil {
		src := cfg.ServerCoordsSource
		if src == "" {
			src = "none"
			if cfg.ServerCoordsSet {
				src = "config"
			}
		}
		// 热重载可能把配置里的坐标撤掉：来源标着 config 但坐标已不在时按无坐标处理。
		if src == "config" && !cfg.ServerCoordsSet {
			src = "none"
		}
		if src != "none" {
			lat := cfg.ServerLatitude
			lon := cfg.ServerLongitude
			resp.ServerLatitude = &lat
			resp.ServerLongitude = &lon
			resp.ServerLocationSource = src
		}
	}

	if h.geoIP == nil || h.db == nil {
		WriteSuccess(w, resp)
		return
	}
	events, err := h.db.GetBanEvents(attackGeoEventLimit)
	if err != nil {
		h.server.logger.Error("读取封禁事件失败，攻击源地理分布为空", "error", err)
		WriteSuccess(w, resp)
		return
	}

	points, total, located := h.aggregateGeo(events)
	resp.Points = points
	resp.TotalIPs = total
	resp.LocatedIPs = located
	WriteSuccess(w, resp)
}

// aggregateGeo 把封禁事件聚合成地图定位点。
//
// 返回 (points, 去重后的封禁 IP 总数, 其中有定位的 IP 数)。点按 total_bans 降序，
// 超过 attackGeoPointLimit 时只留前 N 个（计数仍按全量算，面板标题与点集不矛盾）。
func (h *APIHandlers) aggregateGeo(events []persist.BanEvent) ([]GeoPoint, uint32, uint32) {
	type ipStat struct {
		bans uint32
		last int64
	}
	byIP := make(map[netip.Addr]*ipStat, len(events))
	for _, ev := range events {
		addr, err := netip.ParseAddr(ev.IP)
		if err != nil || !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		st := byIP[addr]
		if st == nil {
			st = &ipStat{}
			byIP[addr] = st
		}
		st.bans++
		if ev.BannedAt > st.last {
			st.last = ev.BannedAt
		}
	}

	type bucket struct {
		loc     geoip.Location
		ips     uint32
		bans    uint32
		topIP   string
		topBans uint32
		last    int64
	}
	buckets := make(map[string]*bucket)
	var located uint32
	for addr, st := range byIP {
		loc, ok := h.geoIP.Lookup(addr)
		if !ok {
			continue
		}
		located++
		// 两位小数约 1 公里：City 级库的相邻地址本就落在同一个定位桶里，
		// 不压缩的话一座城市会碎成成百上千个几乎重合的点。
		key := fmt.Sprintf("%.2f,%.2f", loc.Latitude, loc.Longitude)
		b := buckets[key]
		if b == nil {
			b = &bucket{loc: loc, last: st.last}
			buckets[key] = b
		}
		b.ips++
		b.bans += st.bans
		if st.bans > b.topBans {
			b.topBans = st.bans
			b.topIP = addr.String()
		}
		if st.last > b.last {
			b.last = st.last
		}
	}

	points := make([]GeoPoint, 0, len(buckets))
	for _, b := range buckets {
		points = append(points, GeoPoint{
			Latitude:     b.loc.Latitude,
			Longitude:    b.loc.Longitude,
			CountryCode:  b.loc.CountryCode,
			Country:      b.loc.Country,
			City:         b.loc.City,
			Subdivision:  b.loc.Subdivision,
			UniqueIPs:    b.ips,
			TotalBans:    b.bans,
			TopIP:        b.topIP,
			LastBannedAt: b.last,
		})
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].TotalBans != points[j].TotalBans {
			return points[i].TotalBans > points[j].TotalBans
		}
		if points[i].UniqueIPs != points[j].UniqueIPs {
			return points[i].UniqueIPs > points[j].UniqueIPs
		}
		return points[i].LastBannedAt > points[j].LastBannedAt
	})
	if len(points) > attackGeoPointLimit {
		points = points[:attackGeoPointLimit]
	}
	return points, uint32(len(byIP)), located
}
