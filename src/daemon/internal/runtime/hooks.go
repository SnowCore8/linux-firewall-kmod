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

func (h *maintenanceHooks) RecordHistorySnapshot(now int64) {
	if h == nil || h.db == nil {
		return
	}
	h.logger.Debug("recording history snapshot", "timestamp", now)
}

func (h *maintenanceHooks) PerformDataCleanup() {
	if h == nil || h.db == nil {
		return
	}
	h.logger.Debug("performing data cleanup")
}
