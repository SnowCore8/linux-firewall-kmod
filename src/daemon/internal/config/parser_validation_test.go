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

func TestValidateThreatFeedURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{name: "valid https", url: "https://example.com/feed.txt", wantErr: ""},
		{name: "valid http", url: "http://lists.example.com/blocklist.txt", wantErr: ""},
		{name: "empty string", url: "", wantErr: "URL 不能为空"},
		{name: "file protocol rejected", url: "file:///etc/passwd", wantErr: "不支持的协议"},
		{name: "ftp protocol rejected", url: "ftp://example.com/feed.txt", wantErr: "不支持的协议"},
		{name: "javascript rejected", url: "javascript:alert(1)", wantErr: "不支持的协议"},
		{name: "data URI rejected", url: "data:text/plain,hello", wantErr: "不支持的协议"},
		{name: "missing host", url: "http:///path/only", wantErr: "URL 缺少主机名"},
		{name: "bare scheme no host", url: "http://", wantErr: "URL 缺少主机名"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateThreatFeedURL(tt.url)
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

func TestCheckYAMLAliasBomb(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "no anchors or aliases",
			content: "key: value\nother: data\n",
			wantErr: "",
		},
		{
			name:    "normal anchors within ratio",
			content: "a: &anchor1 value\nb: *anchor1\n",
			wantErr: "",
		},
		{
			name:    "aliases exceed 1000",
			content: "a: &x val\n" + strings.Repeat("b: *x\n", 1001),
			wantErr: "别名引用数",
		},
		{
			name:    "aliases far exceed anchors times 10",
			content: "a: &x val\n" + strings.Repeat("b: *x\n", 50),
			wantErr: "别名数",
		},
		{
			name:    "zero anchors with aliases",
			content: strings.Repeat("*x\n", 20),
			wantErr: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkYAMLAliasBomb(tt.content)
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

func TestValidateJailName(t *testing.T) {
	tests := []struct {
		name    string
		jail    string
		wantErr string
	}{
		{name: "valid name", jail: "sshd", wantErr: ""},
		{name: "valid with hyphen", jail: "my-jail", wantErr: ""},
		{name: "valid with underscore", jail: "my_jail_v2", wantErr: ""},
		{name: "empty string", jail: "", wantErr: "不能为空"},
		{name: "too long 65 chars", jail: strings.Repeat("a", 65), wantErr: "超过上限"},
		{name: "exactly 64 chars ok", jail: strings.Repeat("b", 64), wantErr: ""},
		{name: "contains forward slash", jail: "my/jail", wantErr: "非法字符"},
		{name: "contains backslash", jail: `my\jail`, wantErr: "非法字符"},
		{name: "contains null byte", jail: "my\x00jail", wantErr: "非法字符"},
		{name: "contains control char", jail: "my\njail", wantErr: "非法字符"},
		{name: "contains tab", jail: "my\tjail", wantErr: "非法字符"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJailName(tt.jail)
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

func TestDdosBounds(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "auto_ban_duration zero rejected",
			yaml: `ddos:
  auto_ban_duration: 0`,
			wantErr: "ddos.auto_ban_duration",
		},
		{
			name: "auto_ban_duration above 86400 rejected",
			yaml: `ddos:
  auto_ban_duration: 86401`,
			wantErr: "ddos.auto_ban_duration",
		},
		{
			name: "auto_ban_duration boundary 1 accepted",
			yaml: `ddos:
  auto_ban_duration: 1`,
			wantErr: "",
		},
		{
			name: "auto_ban_duration boundary 86400 accepted",
			yaml: `ddos:
  auto_ban_duration: 86400`,
			wantErr: "",
		},
		{
			name: "auto_ban_threshold zero rejected",
			yaml: `ddos:
  auto_ban_threshold: 0`,
			wantErr: "ddos.auto_ban_threshold",
		},
		{
			name: "auto_ban_threshold above 1000000 rejected",
			yaml: `ddos:
  auto_ban_threshold: 1000001`,
			wantErr: "ddos.auto_ban_threshold",
		},
		{
			name: "auto_ban_threshold boundary accepted",
			yaml: `ddos:
  auto_ban_threshold: 100`,
			wantErr: "",
		},
		{
			name: "max_bans_per_second zero rejected",
			yaml: `ddos:
  max_bans_per_second: 0`,
			wantErr: "ddos.max_bans_per_second",
		},
		{
			name: "max_bans_per_second above 10000 rejected",
			yaml: `ddos:
  max_bans_per_second: 10001`,
			wantErr: "ddos.max_bans_per_second",
		},
		{
			name: "max_bans_per_second boundary accepted",
			yaml: `ddos:
  max_bans_per_second: 5000`,
			wantErr: "",
		},
		{
			name: "global_conn_rate zero rejected",
			yaml: `ddos:
  global_conn_rate: 0`,
			wantErr: "ddos.global_conn_rate",
		},
		{
			name: "check_interval above 3600 rejected",
			yaml: `ddos:
  check_interval: 3601`,
			wantErr: "ddos.check_interval",
		},
		{
			name: "max_syn_per_second zero rejected",
			yaml: `ddos:
  max_syn_per_second: 0`,
			wantErr: "ddos.max_syn_per_second",
		},
		{
			name: "max_rate_entries zero rejected",
			yaml: `ddos:
  max_rate_entries: 0`,
			wantErr: "ddos.max_rate_entries",
		},
		{
			name: "valid ddos config accepted",
			yaml: `ddos:
  enabled: true
  auto_ban_duration: 3600
  auto_ban_threshold: 500
  max_bans_per_second: 100
  global_conn_rate: 10000
  check_interval: 10
  max_syn_per_second: 100000
  max_rate_entries: 50000`,
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

func TestApplyRiskEngineValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "half_life_days zero rejected",
			yaml: `risk_engine:
  half_life_days: 0`,
			wantErr: "risk_engine.half_life_days",
		},
		{
			name: "half_life_days negative rejected",
			yaml: `risk_engine:
  half_life_days: -5`,
			wantErr: "risk_engine.half_life_days",
		},
		{
			name: "half_life_days too large rejected",
			yaml: `risk_engine:
  half_life_days: 400`,
			wantErr: "risk_engine.half_life_days",
		},
		{
			name: "weight negative rejected",
			yaml: `risk_engine:
  weights:
    ssh: -1.0`,
			wantErr: "risk_engine.weights[ssh]",
		},
		{
			name: "weight too large rejected",
			yaml: `risk_engine:
  weights:
    ssh: 150.0`,
			wantErr: "risk_engine.weights[ssh]",
		},
		{
			name: "valid config accepted",
			yaml: `risk_engine:
  enabled: true
  half_life_days: 14
  weights:
    ssh: 2.5
    http: 1.0`,
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
