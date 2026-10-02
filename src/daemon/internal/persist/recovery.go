package persist

import (
	"time"
)

func (db *DB) StartReputationRecoveryScheduler(interval time.Duration, recoveryRate int, maxScore int, stopCh <-chan struct{}) {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	if recoveryRate <= 0 {
		recoveryRate = 1
	}
	if maxScore <= 0 {
		maxScore = 100
	}
	go func() {
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
}
