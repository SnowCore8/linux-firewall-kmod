package risk

import (
	"fmt"
	"testing"
	"time"
)

func TestEngine_RecordEvent(t *testing.T) {
	engine := NewEngine(DefaultDimensionWeights())

	vec := engine.RecordEvent("192.168.1.1", EventFailure, 5.0)
	if vec.Failure != 5.0 {
		t.Errorf("RecordEvent() Failure = %v, want 5.0", vec.Failure)
	}

	vec = engine.RecordEvent("192.168.1.1", EventScan, 3.0)
	if vec.Failure != 5.0 {
		t.Errorf("RecordEvent() Failure after second event = %v, want 5.0", vec.Failure)
	}
	if vec.Scan != 3.0 {
		t.Errorf("RecordEvent() Scan = %v, want 3.0", vec.Scan)
	}
}

func TestEngine_GetVector(t *testing.T) {
	engine := NewEngine(DefaultDimensionWeights())

	_, ok := engine.GetVector("192.168.1.1")
	if ok {
		t.Error("GetVector() should return false for non-existent IP")
	}

	engine.RecordEvent("192.168.1.1", EventFailure, 10.0)

	vec, ok := engine.GetVector("192.168.1.1")
	if !ok {
		t.Error("GetVector() should return true after RecordEvent")
	}
	if vec.Failure < 9.0 || vec.Failure > 10.0 {
		t.Errorf("GetVector() Failure = %v, want ~10.0", vec.Failure)
	}
}

func TestEngine_ComputeEffectiveThreshold(t *testing.T) {
	engine := NewEngine(DefaultDimensionWeights())

	tests := []struct {
		name            string
		baseThreshold   uint32
		peakHours       bool
		internal        bool
		reputationScore uint32
		want            uint32
	}{
		{
			name:            "base case",
			baseThreshold:   5,
			peakHours:       false,
			internal:        false,
			reputationScore: 100,
			want:            5,
		},
		{
			name:            "peak hours",
			baseThreshold:   5,
			peakHours:       true,
			internal:        false,
			reputationScore: 100,
			want:            7,
		},
		{
			name:            "internal",
			baseThreshold:   5,
			peakHours:       false,
			internal:        true,
			reputationScore: 100,
			want:            8,
		},
		{
			name:            "internal + peak",
			baseThreshold:   5,
			peakHours:       true,
			internal:        true,
			reputationScore: 100,
			want:            10,
		},
		{
			name:            "low reputation",
			baseThreshold:   5,
			peakHours:       false,
			internal:        false,
			reputationScore: 30,
			want:            3,
		},
		{
			name:            "internal + low reputation (bug fix)",
			baseThreshold:   5,
			peakHours:       false,
			internal:        true,
			reputationScore: 30,
			want:            6,
		},
		{
			name:            "minimum threshold",
			baseThreshold:   1,
			peakHours:       false,
			internal:        false,
			reputationScore: 0,
			want:            1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.ComputeEffectiveThreshold(
				"192.168.1.1",
				tt.baseThreshold,
				tt.peakHours,
				tt.internal,
				tt.reputationScore,
			)
			if got != tt.want {
				t.Errorf("ComputeEffectiveThreshold() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEngine_ShouldBan(t *testing.T) {
	engine := NewEngine(DefaultDimensionWeights())

	engine.RecordEvent("192.168.1.1", EventFailure, 10.0)

	if !engine.ShouldBan("192.168.1.1", 5, false, false, 100) {
		t.Error("ShouldBan() should return true when vector >= threshold")
	}

	if engine.ShouldBan("192.168.1.1", 15, false, false, 100) {
		t.Error("ShouldBan() should return false when vector < threshold")
	}

	if engine.ShouldBan("192.168.1.2", 5, false, false, 100) {
		t.Error("ShouldBan() should return false for non-existent IP")
	}
}

func TestReputationAdjustment(t *testing.T) {
	tests := []struct {
		score uint32
		want  int
	}{
		{100, 0},
		{80, 0},
		{79, -1},
		{50, -1},
		{49, -2},
		{0, -2},
	}

	for _, tt := range tests {
		got := ReputationAdjustment(tt.score)
		if got != tt.want {
			t.Errorf("ReputationAdjustment(%v) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

func TestSetVector_TriggerEviction(t *testing.T) {
	engine := NewEngine(DefaultDimensionWeights())
	engine.maxSize = 20

	// Insert 25 unique IPs, exceeding maxSize.
	for i := 0; i < 25; i++ {
		engine.SetVector(fmt.Sprintf("10.0.0.%d", i), RiskVector{Failure: 1.0}, time.Now().Unix())
	}

	// After eviction, cache size must not exceed maxSize.
	if engine.Size() > engine.maxSize {
		t.Errorf("SetVector: cache size %d exceeds maxSize %d after eviction", engine.Size(), engine.maxSize)
	}
}

func TestSetVector_OverwriteNoEviction(t *testing.T) {
	engine := NewEngine(DefaultDimensionWeights())
	engine.maxSize = 10

	// Fill cache to capacity.
	for i := 0; i < 10; i++ {
		engine.SetVector(fmt.Sprintf("10.0.0.%d", i), RiskVector{Failure: 1.0}, time.Now().Unix())
	}
	if engine.Size() != 10 {
		t.Fatalf("setup: expected 10 entries, got %d", engine.Size())
	}

	// Overwrite an existing IP; this must NOT trigger eviction.
	engine.SetVector("10.0.0.5", RiskVector{Failure: 99.0}, time.Now().Unix())

	if engine.Size() != 10 {
		t.Errorf("SetVector overwrite: cache size changed to %d, want 10 (no eviction expected)", engine.Size())
	}

	// Verify the value was actually overwritten.
	vec, ok := engine.GetVector("10.0.0.5")
	if !ok {
		t.Fatal("SetVector overwrite: IP not found after overwrite")
	}
	if vec.Failure != 99.0 {
		t.Errorf("SetVector overwrite: Failure = %v, want 99.0", vec.Failure)
	}
}

func TestEvictLocked_RemovesOldest(t *testing.T) {
	engine := NewEngine(DefaultDimensionWeights())
	engine.maxSize = 10

	now := time.Now()
	// Insert 10 entries with staggered expiresAt (earliest = index 0).
	for i := 0; i < 10; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		engine.vectors[ip] = &cachedVector{
			vector:    RiskVector{Failure: float64(i)},
			lastEvent: now.Unix(),
			expiresAt: now.Add(time.Duration(i) * time.Minute),
		}
	}
	// Insert one more to trigger eviction (11 > maxSize=10).
	// target = maxSize/10 = 1, so the single oldest entry should be evicted.
	engine.SetVector("10.0.0.99", RiskVector{Failure: 100.0}, now.Unix())

	// "10.0.0.0" had the earliest expiresAt (now+0), so it should be the eviction target.
	if _, ok := engine.vectors["10.0.0.0"]; ok {
		t.Error("evictLocked: expected 10.0.0.0 (oldest expiresAt) to be evicted, but it is still present")
	}

	// "10.0.0.99" (the newly inserted IP) must survive.
	if _, ok := engine.vectors["10.0.0.99"]; !ok {
		t.Error("evictLocked: newly inserted IP 10.0.0.99 was unexpectedly evicted")
	}

	// Total entries: 10 original - 1 evicted + 1 new = 10.
	if engine.Size() != 10 {
		t.Errorf("evictLocked: cache size = %d, want 10", engine.Size())
	}
}

func BenchmarkEngine_RecordEvent(b *testing.B) {
	engine := NewEngine(DefaultDimensionWeights())
	for i := 0; i < b.N; i++ {
		engine.RecordEvent("192.168.1.1", EventFailure, 1.0)
	}
}

func BenchmarkEngine_ComputeEffectiveThreshold(b *testing.B) {
	engine := NewEngine(DefaultDimensionWeights())
	for i := 0; i < b.N; i++ {
		engine.ComputeEffectiveThreshold("192.168.1.1", 5, true, true, 50)
	}
}
