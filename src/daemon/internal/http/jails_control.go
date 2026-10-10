package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// UpdateJail 启用或禁用指定 jail（PUT /api/v1/jails/{name}）。
//
// 请求体：{"enabled": true/false}
//
// 状态变更通过 JailController 写入权威源，InboundExecutor 在下一个 poll 周期自动同步
// 并重建监视集合。
//
// 名字不在配置里回**信封 404 + 业务码 404**（契约给这条路由编的就是这个码），而不是
// ServeMux 自产的纯文本 404：路径确实匹配了模式，只是那个 jail 不存在。两种 404 的含义
// 由形状区分——信封是「资源存在性失败」，纯文本是「这条路由根本没接」。
func (h *APIHandlers) UpdateJail(w http.ResponseWriter, r *http.Request) {
	if h.jailController == nil {
		WriteServiceUnavailable(w, "jail 控制器缺席，无法改启用状态")
		return
	}

	name := r.PathValue("name")
	if _, ok := config.GetJail(name); !ok {
		WriteCode(w, httpcontract.Code404, "Jail 不存在: "+name)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	h.jailController.SetEnabled(name, req.Enabled)

	h.publishJails()

	h.server.logger.Info("Jail 启用状态已更新", "jail", name, "enabled", req.Enabled)
	WriteSuccess(w, map[string]any{
		"name":    name,
		"enabled": req.Enabled,
		"status":  "updated",
	})
}
