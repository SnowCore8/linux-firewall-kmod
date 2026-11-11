package geoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func newProbeServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDetectEgressKeys(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{`{"ip":"203.0.113.7"}`, "203.0.113.7"},
		{`{"query":"198.51.100.9"}`, "198.51.100.9"},
		{`{"address":"192.0.2.4"}`, "192.0.2.4"},
		{`{"ip":"not-an-ip","query":"198.51.100.10"}`, "198.51.100.10"},
		{`{"ip":" 203.0.113.8 ","query":"198.51.100.10"}`, "203.0.113.8"},
		{`{"address":"2001:db8::1"}`, "2001:db8::1"},
	}
	for _, tc := range cases {
		srv := newProbeServer(t, tc.body)
		got, err := DetectEgress(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("body %s: %v", tc.body, err)
		}
		if got != netip.MustParseAddr(tc.want) {
			t.Fatalf("body %s: got %v want %s", tc.body, got, tc.want)
		}
	}
}

func TestDetectEgressErrors(t *testing.T) {
	if _, err := DetectEgress(context.Background(), "ftp://example.test/ip"); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if _, err := DetectEgress(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty URL")
	}
	if _, err := DetectEgress(context.Background(), "http://"); err == nil {
		t.Fatal("expected error for URL without host")
	}

	badJSON := newProbeServer(t, "not json")
	if _, err := DetectEgress(context.Background(), badJSON.URL); err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	noIP := newProbeServer(t, `{"country":"NL"}`)
	if _, err := DetectEgress(context.Background(), noIP.URL); err == nil {
		t.Fatal("expected error when no key holds an IP")
	}

	non200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer non200.Close()
	if _, err := DetectEgress(context.Background(), non200.URL); err == nil {
		t.Fatal("expected error for non-2xx status")
	}

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"` + strings.Repeat("1", egressBodyLimit) + `"}`))
	}))
	defer oversized.Close()
	if _, err := DetectEgress(context.Background(), oversized.URL); err == nil {
		t.Fatal("expected error for oversized body")
	}
}

func TestDetectEgressHonorsContext(t *testing.T) {
	srv := newProbeServer(t, `{"ip":"203.0.113.7"}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DetectEgress(ctx, srv.URL); err == nil {
		t.Fatal("expected error for canceled context")
	}
}

// TestDetectEgressRejectsNonPublicAddrs 钉住「探测结果必须是公网地址」：被劫持或配置错误的
// 探测服务返回本机/内网地址时，不能把它当成服务器出口写进定位数据。
func TestDetectEgressRejectsNonPublicAddrs(t *testing.T) {
	for _, raw := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1",
		"169.254.10.20", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"::1", "fe80::1", "fd00::1", "::", "ff02::1", "::ffff:10.0.0.1",
	} {
		srv := newProbeServer(t, `{"ip":"`+raw+`"}`)
		if got, err := DetectEgress(context.Background(), srv.URL); err == nil {
			t.Fatalf("地址 %s 应被拒绝，实际返回 %v", raw, got)
		}
	}
}

// TestDetectEgressSkipsNonPublicKeys 验证非公网地址只是跳过，同一响应里的公网地址仍可用。
func TestDetectEgressSkipsNonPublicKeys(t *testing.T) {
	srv := newProbeServer(t, `{"ip":"127.0.0.1","query":"8.8.8.8"}`)
	got, err := DetectEgress(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("DetectEgress: %v", err)
	}
	if want := netip.MustParseAddr("8.8.8.8"); got != want {
		t.Fatalf("got %v want %v", got, want)
	}
}
