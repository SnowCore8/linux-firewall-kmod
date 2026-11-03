package risk

import (
	"math"
	"testing"
)

func TestDecayFactor(t *testing.T) {
	tests := []struct {
		name string
		days float64
		want float64
		tol  float64
	}{
		{"zero days", 0, 1.0, 1e-9},
		{"negative days", -5, 1.0, 1e-9},
		{"half life", 7, 0.5, 1e-9},
		{"two half lives", 14, 0.25, 1e-9},
		{"30 days", 30, math.Pow(0.5, 30.0/7.0), 1e-6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DecayFactor(tt.days)
			if math.Abs(got-tt.want) > tt.tol {
				t.Errorf("DecayFactor(%v) = %v, want %v (tolerance %v)", tt.days, got, tt.want, tt.tol)
			}
		})
	}
}

func TestDaysSince(t *testing.T) {
	tests := []struct {
		name        string
		now         int64
		lastEventAt int64
		want        float64
		tol         float64
	}{
		{"same time", 1000, 1000, 0, 1e-9},
		{"now before last", 999, 1000, 0, 1e-9},
		{"one day", 86400 + 1000, 1000, 1.0, 1e-9},
		{"seven days", 7*86400 + 1000, 1000, 7.0, 1e-9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DaysSince(tt.now, tt.lastEventAt)
			if math.Abs(got-tt.want) > tt.tol {
				t.Errorf("DaysSince(%v, %v) = %v, want %v (tolerance %v)", tt.now, tt.lastEventAt, got, tt.want, tt.tol)
			}
		})
	}
}

func BenchmarkDecayFactor(b *testing.B) {
	for i := 0; i < b.N; i++ {
		DecayFactor(7.5)
	}
}
