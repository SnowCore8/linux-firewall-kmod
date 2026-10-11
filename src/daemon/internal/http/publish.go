// 写入点之后的域事件推送。
//
// 契约给 `/api/v1/events` 声明的事件名只有一套：connected、stats、bans、jails、
// whitelist、rates。handler 改完状态之后推的必须是**域名**，载荷是该域的当前镜像——
// 而不是 `ban` / `whitelist_add` / `jail_updated` 这类「动作名 + 动作参数」。前端按域名
// 订阅（`es.addEventListener('bans', …)`），动作名的帧没有任何监听者；即便有人听，动作
// 参数也只够描述这一次操作，不足以让界面把列表画对（旧实现每 tick 全量重发 5 个域，
// 掩盖了「推送的帧根本不是镜像」这件事）。
//
// 镜像取自各域唯一的权威源，并且**与该域 REST 走同一个折表函数**（见 sse_payload.go）：
// bans 与 whitelist 读进程级镜像（这两域的写入点就在本包），jails 读执行体发布的 jail
// 配置快照（推送点不在本包，见 PublishJails），stats 与 rates 由内核事件泵按采样周期触发。
package http

import (
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

// publishBans 推 bans 域镜像。
func (h *APIHandlers) publishBans() {
	if h.sse == nil {
		return
	}
	h.sse.Publish("bans", h.SSEReplicas().Bans(bans.GlobalCache().All()))
}

// publishWhitelist 推 whitelist 域镜像。
func (h *APIHandlers) publishWhitelist() {
	if h.sse == nil {
		return
	}
	h.sse.Publish("whitelist", h.SSEReplicas().Whitelist(bans.GlobalWhitelist().List()))
}

// PublishJails 推 jails 域镜像：这是这一域唯一的推送点。
//
// 调用方是组合根接进来的 runtime.JailSnapshotListener——jail 配置的所有权在入站执行体，
// 快照换了形状的那一刻（初始装配、热重载、回滚、内核配置指令、启用状态同步）才是
// jails 域的真实变更触发。HTTP 侧的开关写入点**不**推这一帧：它改的是期望状态，
// 快照要到执行体同步时才换，此刻推出去的是改动前的形状（见 UpdateJail 的注释）。
//
// 缺了这一声，前端订阅的 jails 域只在整页刷新时重收首帧，SIGHUP 或内核侧改完配置后
// 界面继续显示旧形状——即契约缺陷 HTTP_SSE_JAILS_NO_PUBLISHER 的现场。
func (h *APIHandlers) PublishJails() {
	if h.sse == nil {
		return
	}
	h.sse.Publish("jails", h.SSEReplicas().Jails())
}
