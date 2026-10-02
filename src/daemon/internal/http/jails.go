package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

func (h *APIHandlers) ListJails(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	jails := config.GetActiveJails()
	WriteSuccess(w, jails)
}

func (h *APIHandlers) GetJail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		WriteBadRequest(w, "name parameter required")
		return
	}

	jail, ok := config.GetJail(name)
	if !ok {
		WriteNotFound(w, "jail not found: "+name)
		return
	}

	WriteSuccess(w, jail)
}

func (h *APIHandlers) JailStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		WriteBadRequest(w, "name parameter required")
		return
	}

	stats, ok := config.GetJailStats(name)
	if !ok {
		WriteNotFound(w, "jail not found: "+name)
		return
	}

	WriteSuccess(w, stats)
}
