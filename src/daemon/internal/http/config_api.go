package http

import (
	"net/http"
	"os"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"gopkg.in/yaml.v3"
)

// GetConfig 返回当前运行配置的 JSON 快照。
//
// 敏感字段（MetricsPassword）在序列化前清零，避免凭据泄露到前端。
func (h *APIHandlers) GetConfig(w http.ResponseWriter, r *http.Request) {
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
// 流程：校验认证（注册面已保证）→ 解析 JSON → 转 YAML → 写配置文件 → 成功。
// 实际重载由 InboundExecutor 的 inotify 监视器检测到文件变化后自动触发。
//
// 写失败回业务码 40004（契约给这条路由编的码），而不是 50002：配置没落盘是「这次更新
// 没生效」，运维要看的是它为什么没生效并改完再试一次，不是把它当服务端 bug 报警。
func (h *APIHandlers) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	if h.getConfigPath == nil || h.getConfigPath() == "" {
		WriteServiceUnavailable(w, "配置文件路径不可用")
		return
	}

	// 直接解成通用 map：JSON 与 YAML 的值域在这里是同一套（string/float64/bool/切片/
	// map），先解成 json.RawMessage 再 Unmarshal 一遍只是把同一次解析做两次。
	var generic map[string]any
	if !decodeJSON(w, r, &generic) {
		return
	}

	yamlData, err := yaml.Marshal(generic)
	if err != nil {
		h.server.logger.Error("JSON 转 YAML 失败", "error", err)
		WriteCode(w, httpcontract.Code40004, "更新配置失败：转换为 YAML 失败（"+err.Error()+"）")
		return
	}

	configPath := h.getConfigPath()
	if err := os.WriteFile(configPath, yamlData, 0o644); err != nil {
		h.server.logger.Error("写入配置文件失败", "path", configPath, "error", err)
		WriteCode(w, httpcontract.Code40004, "更新配置失败：写入 "+configPath+" 失败（"+err.Error()+"）")
		return
	}

	h.server.logger.Info("配置文件已通过 API 更新", "path", configPath)
	WriteSuccess(w, map[string]any{
		"status":  "updated",
		"message": "配置文件已写入，等待自动重载",
	})
}
