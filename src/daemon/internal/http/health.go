// 就绪探针面：契约里唯一「HTTP 状态码即语义」的端点。
//
// `/health` 与 `/healthz` 返回裸的 RuntimeSnapshot（不套信封），未就绪时状态码是 503
// 而响应体仍是同一份结构。缺陷 HTTP_HEALTH_NOT_ENVELOPED 把这件事记成**有意保留**：
// 套信封会把「就绪与否」压回 200 + code 字段，k8s/负载均衡就没法按状态码判定了。
package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

// RuntimeSnapshot 是探针的裸载荷，字段与线上 JSON key 由契约的 type RuntimeSnapshot 定。
//
// status 只有两个取值：ok（就绪）与 degraded（未就绪）。就绪的判据只有一条——内核租约
// 已持有；其余字段是排障用的证据，不参与判定，否则一个降级但仍在工作的进程会被判成死掉。
type RuntimeSnapshot struct {
	Status                string `json:"status"`
	NetlinkReady          bool   `json:"netlink_ready"`
	KmodProcPresent       bool   `json:"kmod_proc_present"`
	BanCacheInitialized   bool   `json:"ban_cache_initialized"`
	BanHistoryInitialized bool   `json:"ban_history_initialized"`
	ActiveBans            int    `json:"active_bans"`
	LeaseState            string `json:"lease_state"`
	LeaseLosses           uint64 `json:"lease_losses"`
}

// 探针 status 的两个取值，与前端 types.ts 的 'ok' | 'degraded' 逐字一致。
const (
	statusOK       = "ok"
	statusDegraded = "degraded"
)

// Health 写就绪快照，供 GET /health 与 GET /healthz 共用。
//
// 两条注册指向同一个 handler：契约让两者同函数，探针客户端因此不需要猜哪个路径更权威。
// 方法不匹配由 ServeMux 的 "GET …" 模式回 405，这里不再自查动词。
func (h *APIHandlers) Health(w http.ResponseWriter, r *http.Request) {
	snap := h.runtimeSnapshot()
	status := http.StatusServiceUnavailable
	if snap.NetlinkReady {
		status = http.StatusOK
	}
	// 裸写出，不经 WriteSuccess/WriteError：见本文件开头那条有意保留的偏离。
	writeJSON(w, status, snap)
}

// runtimeSnapshot 把散在各处的运行事实折成一份探针载荷。
//
// 每个字段都来自它的**权威源**：租约与链路来自内核观测快照（唯一写入者是事件泵），封禁数
// 来自活跃封禁镜像，历史库是否就绪来自 handler 自己的 db 句柄。内核链路未装配时快照保持
// 零值，于是 lease_state 是 "none"、active_bans 是 0——读侧不需要区分「没有内核」与
// 「内核还没答」。
func (h *APIHandlers) runtimeSnapshot() RuntimeSnapshot {
	var snap telemetry.Snapshot
	if h.getKernelSnapshot != nil {
		snap = h.getKernelSnapshot()
	} else {
		// 链路未装配：等价于「还没注册过」，而不是「注册失败」。
		snap = telemetry.Snapshot{Link: telemetry.Link{Lease: telemetry.LeaseNone}}
	}

	kmodPresent := false
	if h.kmodPresent != nil {
		kmodPresent = h.kmodPresent()
	}

	ready := snap.Link.Lease == telemetry.LeaseHeld
	state := string(snap.Link.Lease)
	if state == "" {
		state = string(telemetry.LeaseNone)
	}

	status := statusDegraded
	if ready {
		status = statusOK
	}

	cache := bans.GlobalCache()
	active := 0
	if cache != nil {
		active = len(cache.List())
	}
	return RuntimeSnapshot{
		Status:       status,
		NetlinkReady: ready,
		// 内核 procfs 接口存在是「模块已加载」的唯一证据，与租约是两件事：模块在但
		// 租约没拿到，说明指令会被丢弃；租约在但 procfs 不见了，说明模块刚被重载。
		KmodProcPresent: kmodPresent,
		// 两个 initialized 说的是「承载它的对象建好了」：封禁镜像是进程级单例，构造即
		// 就绪；历史库要真开成功才算。
		BanCacheInitialized:   cache != nil,
		BanHistoryInitialized: h.db != nil,
		ActiveBans:            active,
		LeaseState:            state,
		LeaseLosses:           snap.Link.LeaseLosses,
	}
}
