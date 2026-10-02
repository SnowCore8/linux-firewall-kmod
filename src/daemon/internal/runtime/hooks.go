package runtime

import (
	"log/slog"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

type maintenanceHooks struct {
	db     *persist.DB
	logger *slog.Logger
}

func NewMaintenanceHooks(db *persist.DB, logger *slog.Logger) MaintenanceHooks {
	if db == nil {
		return nil
	}
	return &maintenanceHooks{db: db, logger: logger}
}

// TODO: 实现历史快照记录——定期将当前封禁统计、信誉分等写入持久化存储，
// 用于趋势分析和重启后恢复。当前仅记录调试日志。
func (h *maintenanceHooks) RecordHistorySnapshot(now int64) {
	if h == nil || h.db == nil {
		return
	}
	h.logger.Debug("recording history snapshot", "timestamp", now)
}

// TODO: 实现数据清理——删除超过保留期的封禁事件、过期信誉分记录等，
// 防止数据库无限增长。当前仅记录调试日志。
func (h *maintenanceHooks) PerformDataCleanup() {
	if h == nil || h.db == nil {
		return
	}
	h.logger.Debug("performing data cleanup")
}
