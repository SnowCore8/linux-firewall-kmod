package telemetry

import (
	"testing"
	"time"
)

// TestLeaseRefusedSurvivesFailedAttempt 回归：内核明确拒绝后，一次注册发送失败
// 不能把 refused 降级成 idle，否则运维无法区分「被别的守护进程占着」与「还没试」。
func TestLeaseRefusedSurvivesFailedAttempt(t *testing.T) {
	s := NewStore()
	s.SetLeaseRefused()
	s.MarkLeaseAttemptFailed()

	link := s.Snapshot().Link
	if link.Lease != LeaseRefused {
		t.Fatalf("lease = %q，期望 %q", link.Lease, LeaseRefused)
	}
	if link.Registered {
		t.Fatal("refused 状态下 Registered 应为 false")
	}
}

// TestLeaseHeldFailsToLost 保留既有语义：持有过的失败进入 lost 并计一次失联。
func TestLeaseHeldFailsToLost(t *testing.T) {
	s := NewStore()
	s.SetLinkRegistered(time.Now())
	s.MarkLeaseAttemptFailed()

	link := s.Snapshot().Link
	if link.Lease != LeaseLost {
		t.Fatalf("lease = %q，期望 %q", link.Lease, LeaseLost)
	}
	if link.LeaseLosses != 1 {
		t.Fatalf("LeaseLosses = %d，期望 1", link.LeaseLosses)
	}
}
