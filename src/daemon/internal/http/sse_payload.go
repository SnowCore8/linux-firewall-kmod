// SSE 域载荷：把「某个域变了」落成与该域 REST **同形**的一帧。
//
// 前端按域名订阅并把 data 直接当 REST 的类型解析（frontend/src/hooks/useSse.ts 里
// 五处 `JSON.parse(data) as StatsResponse | BanResponse[] | JailResponse[] |
// RateResponse[] | WhitelistEntry[]`）。于是帧的形状不是「数据源的原样」而是
// 「契约给这一域定的载荷」，两件事必须锁在一起：
//
//   - 数据源各归其主。stats/rates 出自内核观测快照（事件泵是唯一写入者），bans/whitelist
//     出自两份内存镜像，jails 出自执行体发布的 jail 配置快照；
//   - 形状只有一处生产者。这里每个方法调的都是同一条 REST 路径上那个函数
//     （buildStats / ratesCurrent / banResponses / whitelistEntries / jailResponses），
//     不在这里重拼一遍字段。
//
// 为什么由表现层而不是泵来定形状：kernel 不得依赖 internal/http（http 反过来要读内核
// 快照，那是循环依赖），泵只能把**变更时机**与**它自己拥有的镜像内容**交出来，
// 折成什么 JSON 是表现层的事。泵侧的接口见 kernel.DomainMirror。
//
// 载荷类型是 `any`：本包的结构体不需要为了让泵认识它们而套上某层的接口——接口定义在
// 泵那一侧，Go 的结构类型自动满足，这里连 import 都不需要。
package http

import (
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

// SSEReplicas 是事件泵用的五个域载荷装配器。零值不可用，须经 APIHandlers.SSEReplicas 取。
type SSEReplicas struct {
	h *APIHandlers
}

// SSEReplicas 返回接好线的域载荷装配器（每次取都是同一个 handler 的视图，无副作用）。
func (h *APIHandlers) SSEReplicas() *SSEReplicas {
	return &SSEReplicas{h: h}
}

// Bans 把封禁镜像整表折成 bans 域载荷。
//
// entries 由调用方给出而不是在这里读全局缓存：泵可以被装配成用自己那份镜像
// （PumpDeps.Cache），载荷必须反映**那张表**的内容。排序与分页属于 REST
// （GET /api/v1/bans 报的是 PaginatedResponse），帧报的是全表镜像——前端拿它整表替换
// 本地状态，分页参数由 REST 那一侧自己重取。
func (r *SSEReplicas) Bans(entries []bans.BanInfo) any {
	return banResponses(entries, time.Now().Unix())
}

// Whitelist 把白名单镜像的键折成 whitelist 域载荷。
func (r *SSEReplicas) Whitelist(cidrs []string) any {
	return whitelistEntries(cidrs)
}

// Stats 装配 stats 域载荷，与 GET /api/v1/stats 同一个 buildStats。
//
// 泵在每次采样「统计变了」之后才调这里，所以一帧就是一次首屏读数：内核快照 + 历史库
// 时间窗 + 本进程计数三路合到同一个函数上，仪表盘不需要区分数字是从哪条路来的。
// 历史库那几项自带 30 秒缓存，采样周期（5 秒）不会把它打成每五秒一次全表查询。
func (r *SSEReplicas) Stats() any {
	return r.h.buildStats(time.Now())
}

// Rates 装配 rates 域载荷，与 GET /api/v1/rates/current 同一条折表路径
// （含按 pps 降序与地址族不识别时的跳过）。
func (r *SSEReplicas) Rates() any {
	return r.h.ratesCurrent(r.h.kernelSnapshot())
}

// Jails 装配 jails 域载荷，与 GET /api/v1/jails 同一个 jailResponses。
//
// 泵不参与这一域：jail 配置的所有权在入站执行体，变更触发由它的快照发布点喊一声
// （见 runtime.JailSnapshotListener 与 APIHandlers.PublishJails）。
func (r *SSEReplicas) Jails() any {
	return r.h.jailResponses()
}
