package risk

import (
	"testing"
)

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name          string
		eventType     string
		payload       map[string]any
		wantType      EventType
		wantIncrement float64
	}{
		{
			name:          "ssh failure default",
			eventType:     "ssh_failure",
			payload:       nil,
			wantType:      EventFailure,
			wantIncrement: 1.0,
		},
		{
			name:          "ssh failure high count",
			eventType:     "ssh_failure",
			payload:       map[string]any{"count": 15},
			wantType:      EventFailure,
			wantIncrement: 5.0,
		},
		{
			name:          "port scan",
			eventType:     "port_scan",
			payload:       map[string]any{"ports": 50},
			wantType:      EventScan,
			wantIncrement: 3.0,
		},
		{
			name:          "port scan high",
			eventType:     "port_scan",
			payload:       map[string]any{"ports": 150},
			wantType:      EventScan,
			wantIncrement: 10.0,
		},
		{
			name:          "directory traversal",
			eventType:     "http_scan",
			payload:       map[string]any{"path": "/../../etc/passwd"},
			wantType:      EventScan,
			wantIncrement: 5.0,
		},
		{
			name:          "bruteforce default",
			eventType:     "bruteforce",
			payload:       nil,
			wantType:      EventBruteforce,
			wantIncrement: 5.0,
		},
		{
			name:          "bruteforce high rate",
			eventType:     "bruteforce",
			payload:       map[string]any{"rate": 150.0},
			wantType:      EventBruteforce,
			wantIncrement: 10.0,
		},
		{
			name:          "ddos default",
			eventType:     "ddos",
			payload:       nil,
			wantType:      EventDDoS,
			wantIncrement: 10.0,
		},
		{
			name:          "ddos high pps",
			eventType:     "ddos",
			payload:       map[string]any{"pps": 15000},
			wantType:      EventDDoS,
			wantIncrement: 20.0,
		},
		{
			name:          "geo foreign",
			eventType:     "geo_anomaly",
			payload:       map[string]any{"foreign": true},
			wantType:      EventGeo,
			wantIncrement: 3.0,
		},
		{
			name:          "cluster malicious",
			eventType:     "cluster",
			payload:       map[string]any{"malicious": true},
			wantType:      EventCluster,
			wantIncrement: 5.0,
		},
		{
			name:          "ban permanent",
			eventType:     "ban",
			payload:       map[string]any{"permanent": true},
			wantType:      EventBan,
			wantIncrement: 10.0,
		},
		{
			name:          "ban temporary",
			eventType:     "ban",
			payload:       map[string]any{"permanent": false},
			wantType:      EventBan,
			wantIncrement: 5.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotIncrement := ClassifyFailure(tt.eventType, tt.payload)
			if gotType != tt.wantType {
				t.Errorf("ClassifyFailure() type = %v, want %v", gotType, tt.wantType)
			}
			if gotIncrement != tt.wantIncrement {
				t.Errorf("ClassifyFailure() increment = %v, want %v", gotIncrement, tt.wantIncrement)
			}
		})
	}
}

func BenchmarkClassifyFailure(b *testing.B) {
	payload := map[string]any{"count": 5}
	for i := 0; i < b.N; i++ {
		ClassifyFailure("ssh_failure", payload)
	}
}
