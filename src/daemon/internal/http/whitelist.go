package http

import (
	"encoding/json"
	"net/http"
	"net/netip"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

type WhitelistRequest struct {
	CIDR string `json:"cidr"`
}

func (h *APIHandlers) ListWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	entries := bans.GlobalWhitelist().List()
	WriteSuccess(w, entries)
}

func (h *APIHandlers) AddWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	var req WhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	prefix, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		addr, addrErr := netip.ParseAddr(req.CIDR)
		if addrErr != nil {
			WriteBadRequest(w, "invalid CIDR or IP: "+req.CIDR)
			return
		}
		if addr.Is4() {
			prefix = netip.PrefixFrom(addr, 32)
		} else {
			prefix = netip.PrefixFrom(addr, 128)
		}
	}

	if !bans.GlobalWhitelist().Add(prefix) {
		WriteError(w, http.StatusConflict, "already_whitelisted", "CIDR already in whitelist")
		return
	}

	if h.sse != nil {
		h.sse.Publish("whitelist_add", map[string]any{
			"cidr": prefix.String(),
		})
	}

	WriteSuccess(w, map[string]any{
		"cidr":   prefix.String(),
		"status": "added",
	})
}

func (h *APIHandlers) RemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "DELETE only")
		return
	}

	cidr := r.URL.Query().Get("cidr")
	if cidr == "" {
		WriteBadRequest(w, "cidr parameter required")
		return
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		WriteBadRequest(w, "invalid CIDR: "+cidr)
		return
	}

	if !bans.GlobalWhitelist().Remove(prefix) {
		WriteNotFound(w, "CIDR not in whitelist: "+cidr)
		return
	}

	if h.sse != nil {
		h.sse.Publish("whitelist_remove", map[string]any{
			"cidr": cidr,
		})
	}

	WriteSuccess(w, map[string]any{
		"cidr":   cidr,
		"status": "removed",
	})
}

func (h *APIHandlers) WhitelistStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	stats := bans.GlobalWhitelist().Stats()
	WriteSuccess(w, stats)
}
