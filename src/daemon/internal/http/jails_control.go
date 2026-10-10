package http

import (
	"encoding/json"
	"net/http"
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

	// jail 名来自路径段：/api/v1/jails/{name}
	name := r.PathValue("name")
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

	h.publishJails()

	h.server.logger.Info("Jail 启用状态已更新", "jail", name, "enabled", req.Enabled)
	WriteSuccess(w, map[string]any{
		"name":    name,
		"enabled": req.Enabled,
		"status":  "updated",
	})
}
