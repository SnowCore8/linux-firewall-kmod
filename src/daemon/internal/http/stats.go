// 统计总览面：GET /api/v1/stats 的装配与它的「今日 / 近 5 分钟」窗口缓存。
//
// 每一个字段都写清它来自哪一路真源，因为这张面板上的数字会被当成结论用：
//   - current_bans / total_bans / total_unbans / whitelist_count / packets_* 来自内核统计
//     快照的最新一刻（链路断开时它们是**陈旧值**，新鲜度由 /health 的链路字段判断——
//     契约把这条路由归在只读快照面，没有为「读数陈旧」编造错误码）；
//   - today_bans 与 threat_level.recent_bans 来自历史库 ban_events 的真实时间窗；
//   - failed_attempts 与速率类读数是**本进程**的累计与平滑结果，重启归零。
//
// 这条路由在契约里只声明 code 0：历史库缺席、查询失败都降级为「那一项没有读数」，不回
// 50002/50003。总览是首屏，一半数字拿不到时也要把另一半画出来。
package http

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/kernel"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

const (
	// statsWindowTTL 是「今日封禁 / 近 5 分钟封禁」两个窗口的缓存时长。
	//
	// 契约在 StatsResponse.today_bans 的注释里把这个数写死成 30 秒：午夜切换最多晚 30 秒，
	// 换来的是首屏一次请求不会打三条 SQL。
	statsWindowTTL = 30 * time.Second

	// trendDays 是趋势图与热力图回溯的自然日数（两者共用同一次活动行读取）。
	trendDays = 7

	// recentBanWindow 是 threat_level.recent_bans 的窗口（前端 types.ts 同口径写「最近 5 分钟」）。
	recentBanWindow = 5 * time.Minute
)

// threatLevels 是 score 0..4 的等级名，与前端 types.ts 的取值逐字一致。
var threatLevels = []string{"safe", "low", "medium", "high", "critical"}

// dayLabel 是趋势图的横轴标签格式（本地时区的月-日）。
const dayLabel = "01-02"

// Stats 返回总览面板的一次读数（GET /api/v1/stats）。
func (h *APIHandlers) Stats(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, h.buildStats(time.Now()))
}

// buildStats 装配 StatsResponse。
//
// REST 与 SSE 的 stats 域共用它：两条读法各自装配一次会让面板上的同一个数字取决于它是
// 从哪条路来的。
func (h *APIHandlers) buildStats(now time.Time) StatsResponse {
	snap := h.kernelSnapshot()
	today, recentBans := h.banWindows(now)
	// 趋势与热力图共用一次活动行读取：两条查询拿的是同一批 ban_events。
	activity := h.banActivity(now)

	return StatsResponse{
		DaemonVersion: config.Version,
		KernelVersion: h.kernelModuleVersion(),
		TodayBans:     today,

		FailedAttempts: totalFailedAttempts(),
		DdosEvents:     h.ddosEvents(),
		UptimeSeconds:  h.uptimeSeconds(now),

		BanTrend:            dailyBanChart(activity, now),
		JailDistribution:    jailBanChart(),
		FailureReasons:      jailFailureChart(),
		FailedAttemptsTrend: emptySeries(dayLabels(now)),

		CurrentBans:     snap.Stats.CurrentBans,
		TotalBans:       snap.Stats.TotalBans,
		TotalUnbans:     snap.Stats.TotalUnbans,
		WhitelistCount:  snap.Stats.WhitelistCount,
		PacketsDropped:  snap.Stats.PacketsDropped,
		PacketsAccepted: snap.Stats.PacketsAccepted,

		ThreatLevel: h.buildThreatLevel(snap, now, recentBans),
	}
}

// Heatmap 返回 24 小时热力图（GET /api/v1/stats/heatmap）。
func (h *APIHandlers) Heatmap(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, h.buildHeatmap(time.Now()))
}

// buildHeatmap 把封禁活动按 hour-of-day 归并成长度 24 的定长数组。
//
// 缺数据的小时也要占位（契约把 hours 定成 [HourlyBucket; 24]）：面板按下标读小时，
// 跳过空洞等于把 04 点画到 03 点上。
func (h *APIHandlers) buildHeatmap(now time.Time) HourlyHeatmap {
	var out HourlyHeatmap
	bans := hourlyBanCounts(h.banActivity(now), now)
	for hour := 0; hour < 24; hour++ {
		out.Hours[hour] = HourlyBucket{
			Hour: uint32(hour),
			Bans: bans[hour],
			// 失败尝试与 DDoS 事件没有按小时的持久化历史（契约 defect
			// HTTP_FAILURE_HISTORY_NOT_PERSISTED）：报 0 而不是猜一个数。
			FailedAttempts: 0,
			DdosEvents:     0,
		}
	}
	return out
}

// windowCache 缓存两个时间窗口的封禁计数（今日 + 近 5 分钟）。
//
// 两个窗口一起刷新而不是各存一份到期时刻：它们来自同一批 ban_events，分开刷新会让面板
// 上「今日封禁」与「最近 5 分钟」出自不同时刻，读数之间出现无法解释的倒挂。
type windowCache struct {
	mu        sync.Mutex
	dayStart  time.Time
	today     uint64
	recent5   uint64
	fetchedAt time.Time
	// valid 区分「缓存里是零因为是查出来的」与「还没查过」：只看零值会把没查过的状态
	// 当成一次有效读数。
	valid bool
}

// banWindows 给出今日封禁数与近 5 分钟封禁数。
//
// 历史库缺席时报 0（契约给这条路由只编了 code 0）；查询失败**不刷新**到期时刻，下一位
// 读取者会重试，而不是把一份可能永远好不了的零值当成 30 秒内的有效读数。
func (h *APIHandlers) banWindows(now time.Time) (today, recent5 uint64) {
	if h.db == nil {
		return 0, 0
	}
	dayStart := startOfToday(now)
	// 上界取「下一秒起」而不是 now：banned_at 是整秒，半开区间 [dayStart, now) 会把落在
	// 当前这一秒内的封禁漏掉。
	end := now.Add(time.Second)

	h.statsWindow.mu.Lock()
	defer h.statsWindow.mu.Unlock()

	if h.statsWindow.valid &&
		h.statsWindow.dayStart.Equal(dayStart) &&
		now.Sub(h.statsWindow.fetchedAt) < statsWindowTTL {
		return h.statsWindow.today, h.statsWindow.recent5
	}

	count, err := h.db.CountBanEventsBetween(dayStart, end)
	if err != nil {
		h.server.logger.Error("统计今日封禁数失败", "error", err)
		return h.statsWindow.today, h.statsWindow.recent5
	}
	recent, err := h.db.CountBanEventsBetween(now.Add(-recentBanWindow), end)
	if err != nil {
		h.server.logger.Error("统计近 5 分钟封禁数失败", "error", err)
		recent = 0
	}

	h.statsWindow.dayStart = dayStart
	h.statsWindow.today = count
	h.statsWindow.recent5 = recent
	h.statsWindow.fetchedAt = now
	h.statsWindow.valid = true
	return count, recent
}

// banActivity 取回趋势与热力图需要的封禁活动行（最近 trendDays 个自然日）。
//
// 历史库缺席或查询失败时报 nil：图上是一片空白，而不是画一排假的零。
func (h *APIHandlers) banActivity(now time.Time) []persist.BanActivity {
	if h.db == nil {
		return nil
	}
	rows, err := h.db.GetBanActivitySince(startOfToday(now).AddDate(0, 0, -(trendDays - 1)))
	if err != nil {
		h.server.logger.Error("读取封禁活动失败", "error", err)
		return nil
	}
	return rows
}

// startOfToday 返回 t 所在**本地时区**自然日的 00:00。
//
// 契约把 today_bans 的窗口写死成「本地时区自然日 00:00 起，刻意不用 UTC」：看板上的
// 「今日」要跟运维的日历一致，按 UTC 日起算会把凌晨的封禁算到昨天。
func startOfToday(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// dayLabels 给出最近 trendDays 个自然日的标签（n-1 天前 → 今天，升序）。
func dayLabels(now time.Time) []string {
	first := startOfToday(now).AddDate(0, 0, -(trendDays - 1))
	out := make([]string, 0, trendDays)
	for i := 0; i < trendDays; i++ {
		out = append(out, first.AddDate(0, 0, i).Format(dayLabel))
	}
	return out
}

// dailyBanChart 把活动行归到自然日桶。
//
// 归桶用「本地日历日」而不是「距起点多少个 24 小时」：跨夏令时的那一天是 23 或 25 小时，
// 按小时除会让后面所有桶整体错位一天。标签在 7 天窗口内唯一，可以直接当下标键。
func dailyBanChart(rows []persist.BanActivity, now time.Time) ChartData {
	labels := dayLabels(now)
	index := make(map[string]int, len(labels))
	for i, l := range labels {
		index[l] = i
	}
	counts := make([]uint64, len(labels))
	for _, row := range rows {
		day := time.Unix(row.BannedAt, 0).Local()
		if i, ok := index[day.Format(dayLabel)]; ok {
			counts[i]++
		}
	}
	return chart(labels, counts)
}

// hourlyBanCounts 把活动行归到 hour-of-day（0..23）桶。
func hourlyBanCounts(rows []persist.BanActivity, now time.Time) [24]uint64 {
	var out [24]uint64
	start := startOfToday(now).AddDate(0, 0, -(trendDays - 1))
	for _, row := range rows {
		at := time.Unix(row.BannedAt, 0).Local()
		if at.Before(start) {
			continue
		}
		out[at.Hour()]++
	}
	return out
}

// emptySeries 产出一条「有标签、没数据」的趋势线。
//
// 用于 failed_attempts_trend：契约要求这个字段是 ChartData，而失败尝试只有本进程的累计
// 计数，没有按天的持久化历史（契约 defect HTTP_FAILURE_HISTORY_NOT_PERSISTED）。报空而
// 不是拿当前累计值平摊到 7 天：平摊出来的是一条凭空造的斜线，读图的人会当趋势看。
func emptySeries(labels []string) ChartData {
	return chart(labels, make([]uint64, len(labels)))
}

// jailBanChart 按 jail 归集**活跃**封禁数（与 current_bans、JailResponse.ban_count 同源：
// 内存镜像的 byJail 索引）。
func jailBanChart() ChartData {
	return namedCountChart(bans.GlobalCache().CountByJail())
}

// jailFailureChart 按 jail 归集失败尝试计数（守护进程侧的每 jail 运行时读数）。
//
// 契约里这个字段叫 failure_reasons，Go 侧唯一可归集的「失败」维度就是 jail：日志解析只
// 按 jail 的正则计数，没有第二套「原因」分类。这一点写进契约的 route note，不留成
// 读代码才能发现的秘密。
func jailFailureChart() ChartData {
	counts := map[string]uint64{}
	for _, jail := range config.GetActiveJails() {
		stats, ok := config.GetJailStats(jail.Name)
		if !ok || stats == nil {
			continue
		}
		counts[jail.Name] = stats.FailedAttempts
	}
	return namedCountChart(counts)
}

// totalFailedAttempts 是所有 jail 失败尝试计数之和（StatsResponse.failed_attempts）。
func totalFailedAttempts() uint64 {
	var total uint64
	for _, jail := range config.GetActiveJails() {
		stats, ok := config.GetJailStats(jail.Name)
		if !ok || stats == nil {
			continue
		}
		total += stats.FailedAttempts
	}
	return total
}

// namedCountChart 把「名字 → 计数」折成降序的 ChartData，只保留非零项。
//
// 排序按数量降序、同数按名字升序：内存镜像与配置注册表都是无序集合，不排序的话同一份
// 数据两次刷新会给出一排乱窜的柱子。零项不进图：面板要的是「哪几个在发生」，一排 0 会
// 把有信息的那两根挤下去。
func namedCountChart(counts map[string]uint64) ChartData {
	type entry struct {
		name  string
		value uint64
	}
	entries := make([]entry, 0, len(counts))
	for name, value := range counts {
		if value == 0 {
			continue
		}
		entries = append(entries, entry{name: name, value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].value != entries[j].value {
			return entries[i].value > entries[j].value
		}
		return entries[i].name < entries[j].name
	})
	labels := make([]string, 0, len(entries))
	values := make([]uint64, 0, len(entries))
	for _, e := range entries {
		labels = append(labels, e.name)
		values = append(values, e.value)
	}
	return chart(labels, values)
}

// buildThreatLevel 把三路信号折成威胁评估。
//
// 判据与分档写在这里，契约的 route note 抄一份口径说明：两侧都要能看到「什么样的数算
// critical」，否则面板上的红黄绿就成了实现细节。等级取三路的**最大值**而不是求和：三者
// 量纲不同（速率倍数、表占用率、封禁增速），相加会让两路中等变成一路严重。
func (h *APIHandlers) buildThreatLevel(snap telemetry.Snapshot, now time.Time, recentBans uint64) ThreatLevel {
	pps := snap.Windows.PPS
	ratio := pps.ShortBurstRatio()
	currentPps := uint64(math.Round(pps.Short))

	usage := 0.0
	if capacity := h.banTableCapacity(); capacity > 0 {
		usage = float64(snap.Stats.CurrentBans) / float64(capacity)
		if usage > 1 {
			usage = 1
		}
	}

	signals := []struct {
		score  int
		factor string
	}{
		{bandRatio(ratio), ratioText(ratio, pps.EffectiveBaseline)},
		{bandUsage(usage), usageText(usage)},
		{bandRecentBans(recentBans), recentText(recentBans)},
	}
	score := 0
	factors := make([]string, 0, len(signals))
	for _, s := range signals {
		if s.score > score {
			score = s.score
		}
		if s.score > 0 && s.factor != "" {
			factors = append(factors, s.factor)
		}
	}
	if len(factors) == 0 {
		factors = append(factors, "一切正常")
	}
	if score >= len(threatLevels) {
		score = len(threatLevels) - 1
	}

	return ThreatLevel{
		// factors 只列触发了等级判定的那几路（score>0）：全塞进去会让面板在「一切正常」
		// 时也显示一串「速率 0.0 倍、占用 0%」这类没有读者的读数。
		Level:          threatLevels[score],
		Score:          uint8(score),
		Factors:        factors,
		CurrentPps:     currentPps,
		PpsRatio:       ratio,
		BanTableUsage:  usage,
		RecentBans:     recentBans,
		BaselineFrozen: pps.Frozen,
		PeakHours:      analysis.PeakHours(now),
	}
}

// 三路的分档：0 正常、1 值得关注、2 警告、3 严重、4 危急（占用率最高到 3）。
func bandRatio(ratio float64) int {
	switch {
	case ratio >= 5:
		return 4
	case ratio >= 3:
		return 3
	case ratio >= 1.5:
		return 2
	case ratio >= 1:
		return 1
	default:
		return 0
	}
}

func bandUsage(usage float64) int {
	switch {
	case usage >= 0.95:
		return 3
	case usage >= 0.8:
		return 2
	case usage >= 0.5:
		return 1
	default:
		return 0
	}
}

func bandRecentBans(recent uint64) int {
	switch {
	case recent >= 50:
		return 4
	case recent >= 20:
		return 3
	case recent >= 5:
		return 2
	case recent >= 1:
		return 1
	default:
		return 0
	}
}

// ratioText 在基线还没建立时也给文案：ShortBurstRatio 在 EffectiveBaseline<=0 时返回 0，
// 于是 bandRatio 给 0 分、这句不进 factors——「还没学会基线」不会伪装成「一切正常」以外的
// 任何结论，读侧看 baseline_frozen 与速率图就能看出是没数据。
func ratioText(ratio, baseline float64) string {
	if ratio < 1 {
		return ""
	}
	return fmt.Sprintf("流量速率达基线 %.1f 倍（基线 %.0f pps）", ratio, baseline)
}

func usageText(usage float64) string {
	if usage < 0.5 {
		return ""
	}
	return fmt.Sprintf("封禁表占用 %.0f%%", usage*100)
}

func recentText(recent uint64) string {
	if recent == 0 {
		return ""
	}
	return fmt.Sprintf("最近 5 分钟新增 %d 条封禁", recent)
}

// ddosEvents 读事件泵累计的 DDoS 命中计数。
//
// 计数名取自 kernel 包唯一的那个常量：写入者（事件泵）与读取者（本端点）共用一个拼写，
// 改名不会退化成「读到一个新的恒零计数器」。
func (h *APIHandlers) ddosEvents() uint64 {
	if h.metrics == nil {
		return 0
	}
	if v := h.metrics.Counter(kernel.CounterDdosEvents).Load(); v > 0 {
		return uint64(v)
	}
	return 0
}

// uptimeSeconds 是本进程的运行时长。
//
// 起点来自组合根，不是 handler 构造时刻：装配要读配置、开历史库，那些时间也算「启动了
// 多久」。起点缺席（测试里的零值）时报 0，而不是拿 time.Zero 去减出一个天文数字。
func (h *APIHandlers) uptimeSeconds(now time.Time) uint64 {
	if h.startedAt.IsZero() || now.Before(h.startedAt) {
		return 0
	}
	return uint64(now.Sub(h.startedAt).Seconds())
}

// banTableCapacity 是封禁表占用率的分母。
//
// 内核没有把实时上限带进 netlink 统计响应，占用率因此按**守护进程配置的条目上限**算
// （config.Capacity.MaxBanEntries，与下发给模块的 fw_max_ban_entries 同一个值）。配置
// 缺席或上限为 0 时占用率报 0，不做除零保护以外的猜测。
func (h *APIHandlers) banTableCapacity() uint64 {
	cfg := h.currentConfig()
	if cfg == nil {
		return 0
	}
	return uint64(cfg.Capacity.MaxBanEntries)
}

// kernelSnapshot 读内核观测快照；链路未装配时给零值而不是 nil。
func (h *APIHandlers) kernelSnapshot() telemetry.Snapshot {
	if h.getKernelSnapshot == nil {
		return telemetry.Snapshot{Link: telemetry.Link{Lease: telemetry.LeaseNone}}
	}
	return h.getKernelSnapshot()
}

// kernelModuleVersion 读内核模块自报的版本号；未加载或读不到时报空串。
//
// 空串在面板上就是「内核 」（没有版本号），这是要的形状：拿守护进程版本或 "unknown"
// 顶上去，会让运维以为模块在跑但版本没读到。
func (h *APIHandlers) kernelModuleVersion() string {
	if h.kernelVersion == nil {
		return ""
	}
	return h.kernelVersion()
}
