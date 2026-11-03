package main

import "testing"

func TestBindsBeyondLoopback(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"", false},
		{"   ", false},
		{"127.0.0.1", false},
		{"127.5.6.7", false},
		{"::1", false},
		{"[::1]", false},
		{"localhost", false},
		{"LOCALHOST", false},
		{" 127.0.0.1 ", false},
		{"0.0.0.0", true},
		{"::", true},
		{"192.168.1.10", true},
		{"203.0.113.1", true},
		{"example.com", true},
		// 带端口的写法不是 ListenAddress 接受的 host，按无法解析处理。
		{"127.0.0.1:9119", true},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := bindsBeyondLoopback(tt.host); got != tt.want {
				t.Errorf("bindsBeyondLoopback(%q) = %v，期望 %v", tt.host, got, tt.want)
			}
		})
	}
}
