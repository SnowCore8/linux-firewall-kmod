package http

import (
	"encoding/json"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

// GetConfig 返回当前运行配置的 JSON 快照。
//
// 敏感字段（MetricsPassword）在序列化前清零，避免凭据泄露到前端。
func (h *APIHandlers) GetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	if h.getCurrentConfig == nil {
		WriteServiceUnavailable(w, "config not available")
		return
	}
	cfg := h.getCurrentConfig()
	// 敏感字段清零
	cfg.MetricsPassword = ""
	WriteSuccess(w, cfg)
}

// UpdateConfig 接收新配置并写入磁盘，触发文件监视器自动重载。
//
// 流程：校验认证 → 校验 JSON → 转换为 YAML → 写入配置文件 → 返回成功。
// 实际重载由 InboundExecutor 的 inotify 监视器检测到文件变化后自动触发。
func (h *APIHandlers) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "PUT only")
		return
	}
	if h.getConfigPath == nil || h.getConfigPath() == "" {
		WriteError(w, http.StatusServiceUnavailable, "config_write_unavailable",
			"配置文件路径不可用")
		return
	}

	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		WriteBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	// JSON → 通用 Go 值 → YAML
	var generic any
	if err := json.Unmarshal(body, &generic); err != nil {
		WriteBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	yamlData, err := yaml.Marshal(generic)
	if err != nil {
		h.server.logger.Error("JSON 转 YAML 失败", "error", err)
		WriteInternalError(w, "config conversion failed")
		return
	}

	configPath := h.getConfigPath()
	if err := os.WriteFile(configPath, yamlData, 0o644); err != nil {
		h.server.logger.Error("写入配置文件失败", "path", configPath, "error", err)
		WriteInternalError(w, "failed to write config: "+err.Error())
		return
	}

	h.server.logger.Info("配置文件已通过 API 更新", "path", configPath)
	WriteSuccess(w, map[string]any{
		"status":  "updated",
		"message": "配置文件已写入，等待自动重载",
	})
}
