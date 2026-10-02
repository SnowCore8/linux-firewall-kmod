package http

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

type BanRequest struct {
	IP       string `json:"ip"`
	Duration int64  `json:"duration,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type UnbanRequest struct {
	IP string `json:"ip"`
}

func (h *APIHandlers) ListBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}
	banList := bans.GlobalCache().List()
	WriteSuccess(w, banList)
}

func (h *APIHandlers) CreateBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	var req BanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	_, err := netip.ParseAddr(req.IP)
	if err != nil {
		WriteBadRequest(w, "invalid IP: "+req.IP)
		return
	}

	isPermanent := req.Duration == 0
	duration := req.Duration
	if duration <= 0 {
		duration = 3600
	}

	info := bans.BanInfo{
		IP:          req.IP,
		Reason:      req.Reason,
		BannedAt:    time.Now().Unix(),
		ExpiresAt:   time.Now().Add(time.Duration(duration) * time.Second).Unix(),
		IsPermanent: isPermanent,
	}

	if !bans.GlobalCache().TryInsert(info) {
		WriteError(w, http.StatusConflict, "already_banned", "IP already banned")
		return
	}

	if h.db != nil {
		if err := h.db.RecordBanHistory(req.IP, isPermanent); err != nil {
			h.server.logger.Error("record ban history", "error", err)
		}
		if err := h.db.RecordBanEvent(req.IP, "api", 1, isPermanent); err != nil {
			h.server.logger.Error("record ban event", "error", err)
		}
	}

	if h.sse != nil {
		h.sse.Publish("ban", map[string]any{
			"ip":       req.IP,
			"duration": duration,
			"reason":   req.Reason,
		})
	}

	WriteSuccess(w, map[string]any{
		"ip":       req.IP,
		"duration": duration,
		"status":   "banned",
	})
}

func (h *APIHandlers) DeleteBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "DELETE only")
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		WriteBadRequest(w, "ip parameter required")
		return
	}

	_, err := netip.ParseAddr(ip)
	if err != nil {
		WriteBadRequest(w, "invalid IP: "+ip)
		return
	}

	if !bans.GlobalCache().Remove(ip) {
		WriteNotFound(w, "IP not banned: "+ip)
		return
	}

	if h.sse != nil {
		h.sse.Publish("unban", map[string]any{
			"ip": ip,
		})
	}

	WriteSuccess(w, map[string]any{
		"ip":     ip,
		"status": "unbanned",
	})
}

func (h *APIHandlers) UnbanAllTemporary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	count := bans.GlobalCache().UnbanTemporary()

	if h.sse != nil {
		h.sse.Publish("unban_all_temporary", map[string]any{
			"count": count,
		})
	}

	WriteSuccess(w, map[string]any{
		"unbanned_count": count,
	})
}

func (h *APIHandlers) BatchBan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST only")
		return
	}

	var req struct {
		IPs      []string `json:"ips"`
		Duration int64    `json:"duration,omitempty"`
		Reason   string   `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid JSON: "+err.Error())
		return
	}

	if len(req.IPs) > 1000 {
		WriteBadRequest(w, "max 1000 IPs per batch")
		return
	}

	isPermanent := req.Duration == 0
	duration := req.Duration
	if duration <= 0 {
		duration = 3600
	}

	var successCount, failCount int
	for _, ip := range req.IPs {
		_, err := netip.ParseAddr(ip)
		if err != nil {
			failCount++
			continue
		}

		info := bans.BanInfo{
			IP:          ip,
			Reason:      req.Reason,
			BannedAt:    time.Now().Unix(),
			ExpiresAt:   time.Now().Add(time.Duration(duration) * time.Second).Unix(),
			IsPermanent: isPermanent,
		}

		if bans.GlobalCache().TryInsert(info) {
			successCount++
			if h.db != nil {
				if err := h.db.RecordBanHistory(ip, duration == 0); err != nil {
					h.server.logger.Error("record ban history", "error", err)
				}
			}
		} else {
			failCount++
		}
	}

	if h.sse != nil {
		h.sse.Publish("batch_ban", map[string]any{
			"success": successCount,
			"failed":  failCount,
		})
	}

	WriteSuccess(w, map[string]any{
		"success_count": successCount,
		"fail_count":    failCount,
	})
}

func (h *APIHandlers) BanStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	stats := bans.GlobalCache().Stats()
	WriteSuccess(w, stats)
}

func (h *APIHandlers) BanDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET only")
		return
	}

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		WriteBadRequest(w, "ip parameter required")
		return
	}

	_, err := netip.ParseAddr(ip)
	if err != nil {
		WriteBadRequest(w, "invalid IP: "+ip)
		return
	}

	info, ok := bans.GlobalCache().Get(ip)
	if !ok {
		WriteNotFound(w, "IP not banned: "+ip)
		return
	}

	detail := map[string]any{
		"ip":           ip,
		"reason":       info.Reason,
		"banned_at":    info.BannedAt,
		"expires_at":   info.ExpiresAt,
		"is_permanent": info.ExpiresAt == 0,
	}

	if h.db != nil {
		if history, err := h.db.GetBanHistory(ip); err == nil && history != nil {
			detail["ban_count"] = history.BanCount
			detail["last_banned_at"] = history.LastBannedAt
		}
		if rep, err := h.db.GetIPReputation(ip); err == nil && rep != nil {
			detail["reputation_score"] = rep.Score
		}
	}

	WriteSuccess(w, detail)
}
