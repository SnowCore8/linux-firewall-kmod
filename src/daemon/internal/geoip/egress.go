package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	// egressBodyLimit 是探测响应的最大读取字节数。
	egressBodyLimit = 1 << 20
	// egressTimeout 是探测请求的总超时。
	egressTimeout = 10 * time.Second
)

// egressKeys 是探测响应中可接受公网 IP 的键，按优先级排列。
var egressKeys = []string{"ip", "query", "address"}

// DetectEgress 请求 probeURL 并返回响应 JSON 中报告的公网出口 IP。
// 依次尝试 "ip"、"query"、"address" 三个键，第一个可解析的 IP 胜出。
// 只接受 http/https，响应体上限 1 MiB，遵守调用方 ctx，客户端超时 10 秒。
func DetectEgress(ctx context.Context, probeURL string) (netip.Addr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := url.Parse(probeURL)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("geoip: parse probe URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return netip.Addr{}, fmt.Errorf("geoip: unsupported probe scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return netip.Addr{}, errors.New("geoip: probe URL has no host")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("geoip: build probe request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: egressTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("geoip: probe request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return netip.Addr{}, fmt.Errorf("geoip: probe returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, egressBodyLimit+1))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("geoip: read probe response: %w", err)
	}
	if len(body) > egressBodyLimit {
		return netip.Addr{}, fmt.Errorf("geoip: probe response exceeds %d bytes", egressBodyLimit)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return netip.Addr{}, fmt.Errorf("geoip: decode probe response: %w", err)
	}
	for _, key := range egressKeys {
		s, ok := payload[key].(string)
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, errors.New("geoip: probe response contains no valid IP")
}
