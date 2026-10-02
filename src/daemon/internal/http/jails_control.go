package http

import (
	"encoding/json"
	"net/http"
	"strings"
)

// UpdateJail 启用或禁用指定 jail。
//
// 路径格式：PUT /api/v1/jails/{name}
// 请求体：{"enabled": true/false}
//
// 状态变更通过 JailController 写入权威源，InboundExecutor 在下一个 poll 周期
// 自动同步并重建监视集合。
func (h *APIHandlers) UpdateJail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "PUT only")
		return
	}

	if h.jailController == nil {
		WriteServiceUnavailable(w, "jail controller not available")
		return
	}

	// 从路径提取 jail 名称：/api/v1/jails/{name}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/jails/")
	if name == "" {
		WriteBadRequest(w, "jail name required")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	h.jailController.SetEnabled(name, req.Enabled)

	if h.sse != nil {
		h.sse.Publish("jail_updated", map[string]any{
			"name":    name,
			"enabled": req.Enabled,
		})
	}

	h.server.logger.Info("Jail 启用状态已更新", "jail", name, "enabled", req.Enabled)
	WriteSuccess(w, map[string]any{
		"name":    name,
		"enabled": req.Enabled,
		"status":  "updated",
	})
}
