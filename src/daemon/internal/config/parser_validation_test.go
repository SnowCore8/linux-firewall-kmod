package config

import (
	"strings"
	"testing"
)

func TestApplyWebuiValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "sse_push_interval zero rejected",
			yaml: `webui:
  sse_push_interval: 0`,
			wantErr: "webui.sse_push_interval",
		},
		{
			name: "sse_push_interval too large rejected",
			yaml: `webui:
  sse_push_interval: 100`,
			wantErr: "webui.sse_push_interval",
		},
		{
			name: "rate_warning >= rate_critical rejected",
			yaml: `webui:
  rate_warning_pps: 1000
  rate_critical_pps: 500`,
			wantErr: "rate_warning_pps",
		},
		{
			name: "max_ban_entries zero rejected",
			yaml: `webui:
  max_ban_entries: 0`,
			wantErr: "webui.max_ban_entries",
		},
		{
			name: "max_rate_entries zero rejected",
			yaml: `webui:
  max_rate_entries: 0`,
			wantErr: "webui.max_rate_entries",
		},
		{
			name: "valid config accepted",
			yaml: `webui:
  sse_push_interval: 5
  rate_warning_pps: 100
  rate_critical_pps: 1000
  max_ban_entries: 10000
  max_rate_entries: 100000`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			err := ParseConfig(tt.yaml, &cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}

func TestApplyCapacityValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "max_ban_entries zero rejected",
			yaml: `capacity:
  max_ban_entries: 0`,
			wantErr: "capacity.max_ban_entries",
		},
		{
			name: "max_whitelist_entries zero rejected",
			yaml: `capacity:
  max_whitelist_entries: 0`,
			wantErr: "capacity.max_whitelist_entries",
		},
		{
			name: "max_rate_entries zero rejected",
			yaml: `capacity:
  max_rate_entries: 0`,
			wantErr: "capacity.max_rate_entries",
		},
		{
			name: "max_local_ip_cache zero rejected",
			yaml: `capacity:
  max_local_ip_cache: 0`,
			wantErr: "capacity.max_local_ip_cache",
		},
		{
			name: "valid config accepted",
			yaml: `capacity:
  max_ban_entries: 10000
  max_whitelist_entries: 1000
  max_rate_entries: 100000
  max_local_ip_cache: 5000`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			err := ParseConfig(tt.yaml, &cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}
