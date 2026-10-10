package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// ListJails 返回当前配置的 jail 清单（GET /api/v1/jails）。
//
// 单个 jail 的详情与统计没有契约路由：契约只在 /api/v1/jails 汇总这一层暴露 jail，
// 逐 jail 的计数器走 /metrics 与 SSE 的 jails 域，因此这里不再有 /api/v1/jails/{name}
// 的 GET handler。
func (h *APIHandlers) ListJails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	jails := config.GetActiveJails()
	WriteSuccess(w, jails)
}
