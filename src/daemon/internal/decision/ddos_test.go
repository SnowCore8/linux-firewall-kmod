package decision

import (
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

func ddosCfg() config.DdosConfig {
	cfg := config.DefaultDdosConfig()
	cfg.AutoBanThreshold = 3
	cfg.AutoBanDuration = 3600
	return cfg
}

// nil logger 必须可用（构造期未初始化日志的路径），且不得复用可变全局状态。
func TestNewDdosEngineAcceptsNilLogger(t *testing.T) {
	engine := NewDdosEngine(ddosCfg(), nil)
	if engine == nil {
		t.Fatal("nil logger 不应导致返回 nil 引擎")
	}
	if engine.TrackedIPs() != 0 {
		t.Errorf("新引擎不应有跟踪条目: %d", engine.TrackedIPs())
	}
}

// 内核已完成封禁，引擎只记账：事件计数、跟踪条目数都要反映出来。
func TestHandleEventCountsEventsAndTracksIP(t *testing.T) {
	engine := NewDdosEngine(ddosCfg(), nil)
	ip := addr(t, "203.0.113.7")

	engine.HandleEvent(ip, "syn_flood", 5000, 1000)

	got := engine.Stats().Snapshot()
	if got.EventsDetected != 1 {
		t.Errorf("EventsDetected=%d, want 1", got.EventsDetected)
	}
	if got.TrackedIPs != 1 {
		t.Errorf("TrackedIPs=%d, want 1", got.TrackedIPs)
	}
	if got.AutoBansTriggered != 0 {
		t.Errorf("内核自己封禁，守护进程不应累加 AutoBansTriggered: %d", got.AutoBansTriggered)
	}
	if engine.TrackedIPs() != 1 {
		t.Errorf("TrackedIPs()=%d, want 1", engine.TrackedIPs())
	}
}

// 同一 IP 重复事件只占一个条目，但事件数逐条累加。
func TestHandleEventRepeatedIPKeepsOneTracker(t *testing.T) {
	engine := NewDdosEngine(ddosCfg(), nil)
	ip := addr(t, "203.0.113.7")

	for i := 0; i < 5; i++ {
		engine.HandleEvent(ip, "syn_flood", 5000, 1000)
	}
	engine.HandleEvent(addr(t, "203.0.113.8"), "udp_flood", 7000, 1000)

	got := engine.Stats().Snapshot()
	if got.EventsDetected != 6 {
		t.Errorf("EventsDetected=%d, want 6", got.EventsDetected)
	}
	if got.TrackedIPs != 2 {
		t.Errorf("TrackedIPs=%d, want 2", got.TrackedIPs)
	}
}

func TestCleanupStaleDropsOnlyIdleTrackers(t *testing.T) {
	engine := NewDdosEngine(ddosCfg(), nil)
	stale := addr(t, "203.0.113.7")
	fresh := addr(t, "203.0.113.8")

	engine.HandleEvent(stale, "syn_flood", 5000, 1000)
	engine.HandleEvent(fresh, "syn_flood", 5000, 1000)

	// 恰好落在窗口边界上：cutoff 判据是严格小于，边界条目应保留。
	boundary := int64(1000) + int64(5*60)
	if removed := engine.CleanupStale(boundary); removed != 0 {
		t.Errorf("边界处不应回收: removed=%d", removed)
	}

	if removed := engine.CleanupStale(boundary + 1); removed != 2 {
		t.Errorf("两条都超时后应回收 2 条: removed=%d", removed)
	}
	if engine.TrackedIPs() != 0 {
		t.Errorf("回收后跟踪数应为 0: %d", engine.TrackedIPs())
	}
	if got := engine.Stats().Snapshot(); got.TrackedIPs != 0 {
		t.Errorf("统计中的跟踪数应同步归零: %d", got.TrackedIPs)
	}
	if got := engine.Stats().Snapshot(); got.EventsDetected != 2 {
		t.Errorf("回收不得抹掉历史事件计数: %d", got.EventsDetected)
	}
}

// 活动中的 IP 会刷新 lastViolation，因此不会被回收。
func TestCleanupStaleKeepsRecentlyActive(t *testing.T) {
	engine := NewDdosEngine(ddosCfg(), nil)
	ip := addr(t, "203.0.113.7")

	engine.HandleEvent(ip, "syn_flood", 5000, 1000)
	engine.HandleEvent(ip, "syn_flood", 5000, 1000+int64(4*60))

	if removed := engine.CleanupStale(1000 + int64(5*60) + 1); removed != 0 {
		t.Errorf("近期活动的 IP 不应被回收: removed=%d", removed)
	}
}

func TestUpdateConfigIsVisibleToReaders(t *testing.T) {
	engine := NewDdosEngine(ddosCfg(), nil)

	next := ddosCfg()
	next.AutoBanThreshold = 7
	next.AutoBanDuration = 60
	engine.UpdateConfig(next)

	got := engine.Config()
	if got.AutoBanThreshold != 7 || got.AutoBanDuration != 60 {
		t.Errorf("配置更新未生效: %+v", got)
	}

	// 事件处理读到的阈值应随配置变化，不再使用构造期的 3。
	engine.HandleEvent(addr(t, "203.0.113.7"), "syn_flood", 5000, 1000)
	if got := engine.Stats().Snapshot(); got.EventsDetected != 1 {
		t.Errorf("EventsDetected=%d, want 1", got.EventsDetected)
	}
}
