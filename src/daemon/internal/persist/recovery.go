package persist

import (
	"time"
)

// StartReputationRecoveryScheduler 启动周期性恢复信誉分的后台任务。
// 返回的通道在 goroutine 退出后关闭；调用方应先等它关闭再关数据库，防止恢复操作写到已关闭的连接。
func (db *DB) StartReputationRecoveryScheduler(interval time.Duration, recoveryRate int, maxScore int, stopCh <-chan struct{}) <-chan struct{} {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	if recoveryRate <= 0 {
		recoveryRate = 1
	}
	if maxScore <= 0 {
		maxScore = 100
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				recovered, err := db.RecoverReputation(recoveryRate, maxScore)
				if err != nil {
					db.logger.Error("reputation recovery failed", "error", err)
				} else if recovered > 0 {
					db.logger.Info("reputation recovered", "count", recovered)
				}
			}
		}
	}()
	return done
}
