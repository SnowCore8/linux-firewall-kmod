package runtime

import (
	"log/slog"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

type maintenanceHooks struct {
	db            *persist.DB
	logger        *slog.Logger
	retentionDays int
}

func NewMaintenanceHooks(db *persist.DB, logger *slog.Logger) MaintenanceHooks {
	if db == nil {
		return nil
	}
	return &maintenanceHooks{db: db, logger: logger, retentionDays: 7}
}

// SetRetentionDays 设置数据保留天数（由组合根在装配时按配置调用）。
func (h *maintenanceHooks) SetRetentionDays(days int) {
	if days > 0 {
		h.retentionDays = days
	}
}

// RecordHistorySnapshot 将当前封禁统计快照写入 ban_history 表。
//
// 每次调用时获取 ban_history 统计信息（总 IP 数、总封禁数、永久封禁数），
// 记录到日志以便趋势分析。实际持久化已由 Pipeline 路径上的 RecordBanHistory
// 逐条完成，此处作为周期聚合点补充全局视图。
func (h *maintenanceHooks) RecordHistorySnapshot(now int64) {
	if h == nil || h.db == nil {
		return
	}
	totalIPs, totalBans, permanentBans, err := h.db.GetBanHistoryStats()
	if err != nil {
		h.logger.Error("获取封禁统计快照失败", "error", err)
		return
	}
	h.logger.Debug("封禁统计快照",
		"timestamp", now,
		"total_ips", totalIPs,
		"total_bans", totalBans,
		"permanent_bans", permanentBans,
	)
}

// PerformDataCleanup 清理超过保留期的封禁事件、信誉分与历史记录，
// 防止数据库无限增长。
func (h *maintenanceHooks) PerformDataCleanup() {
	if h == nil || h.db == nil {
		return
	}
	if err := h.db.CleanupExpired(h.retentionDays); err != nil {
		h.logger.Error("数据清理失败", "error", err)
	}
}
