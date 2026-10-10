// 写入点之后的域事件推送。
//
// 契约给 `/api/v1/events` 声明的事件名只有一套：connected、stats、bans、jails、
// whitelist、rates。handler 改完状态之后推的必须是**域名**，载荷是该域的当前镜像——
// 而不是 `ban` / `whitelist_add` / `jail_updated` 这类「动作名 + 动作参数」。前端按域名
// 订阅（`es.addEventListener('bans', …)`），动作名的帧没有任何监听者；即便有人听，动作
// 参数也只够描述这一次操作，不足以让界面把列表画对（旧实现每 tick 全量重发 5 个域，
// 掩盖了「推送的帧根本不是镜像」这件事）。
//
// 镜像取自各域唯一的权威源，与同域 REST 完全同源：bans 与 whitelist 读进程级缓存，
// jails 读配置注册表，stats/rates 由内核事件泵按采样周期推（见 kernel/consumer.go）。
package http

import (
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// publishBans 推 bans 域镜像。
func (h *APIHandlers) publishBans() {
	if h.sse == nil {
		return
	}
	h.sse.Publish("bans", bans.GlobalCache().All())
}

// publishWhitelist 推 whitelist 域镜像。
func (h *APIHandlers) publishWhitelist() {
	if h.sse == nil {
		return
	}
	h.sse.Publish("whitelist", bans.GlobalWhitelist().List())
}

// publishJails 推 jails 域镜像。
//
// 这是 jails 目前唯一的变更触发生产者：jail 开关写进配置注册表后立即整表重推。内核侧
// jail 配置变化还没有对应的泵域（缺陷 HTTP_SSE_JAILS_NO_PUBLISHER 因此仍记 open）。
func (h *APIHandlers) publishJails() {
	if h.sse == nil {
		return
	}
	h.sse.Publish("jails", config.GetActiveJails())
}
