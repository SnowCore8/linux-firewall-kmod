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
	// egressTimeout 是单次探测请求的总超时。
	egressTimeout = 10 * time.Second
	// egressAttempts 是探测的最大尝试次数（含首次）。
	egressAttempts = 3
	// egressRetryBase 是首次重试前的等待，之后按倍数递增（300ms、600ms）。
	egressRetryBase = 300 * time.Millisecond
)

// egressKeys 是探测响应中可接受公网 IP 的键，按优先级排列。
var egressKeys = []string{"ip", "query", "address"}

// DetectEgress 请求 probeURL 并返回响应 JSON 中报告的公网出口 IP。
// 依次尝试 "ip"、"query"、"address" 三个键，第一个可解析且属于公网单播地址的 IP 胜出；
// 私有、环回、链路本地等地址会被跳过，不会污染服务器定位数据。
// 只接受 http/https，响应体上限 1 MiB，遵守调用方 ctx，单次请求超时 10 秒。
//
// 传输层错误（连不上、DNS 暂时失败、超时）与 5xx/429 会按指数退避重试，最多
// egressAttempts 次；4xx、解析失败等确定性错误立即返回，不浪费时间重试。
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

	client := &http.Client{Timeout: egressTimeout}
	var lastErr error
	for attempt := 0; attempt < egressAttempts; attempt++ {
		if attempt > 0 {
			delay := egressRetryBase << (attempt - 1)
			select {
			case <-ctx.Done():
				return netip.Addr{}, ctx.Err()
			case <-time.After(delay):
			}
		}
		addr, retryable, err := probeEgressOnce(ctx, client, probeURL)
		if err == nil {
			return addr, nil
		}
		lastErr = err
		if !retryable || ctx.Err() != nil {
			break
		}
	}
	return netip.Addr{}, lastErr
}

// probeEgressOnce 执行一次探测；retryable 表示该错误是否值得重试。
func probeEgressOnce(ctx context.Context, client *http.Client, probeURL string) (netip.Addr, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return netip.Addr{}, false, fmt.Errorf("geoip: build probe request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// 传输层失败：网络瞬断、DNS 暂时失败、连接超时都可能在重试后成功。
		// 调用方主动取消（ctx.Err() != nil）不重试，由外层统一判断。
		return netip.Addr{}, true, fmt.Errorf("geoip: probe request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// 5xx 与 429 视为探测服务的瞬时故障；其余 4xx 是确定性拒绝。
		retryable := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return netip.Addr{}, retryable, fmt.Errorf("geoip: probe returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, egressBodyLimit+1))
	if err != nil {
		return netip.Addr{}, true, fmt.Errorf("geoip: read probe response: %w", err)
	}
	if len(body) > egressBodyLimit {
		return netip.Addr{}, false, fmt.Errorf("geoip: probe response exceeds %d bytes", egressBodyLimit)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return netip.Addr{}, false, fmt.Errorf("geoip: decode probe response: %w", err)
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
		if !isPublicEgressAddr(addr) {
			continue
		}
		return addr, false, nil
	}
	return netip.Addr{}, false, errors.New("geoip: probe response contains no valid public IP")
}

// nonPublicPrefixes 列出标准库分类未覆盖、但同样不能当作公网出口的网段。
//
// 0.0.0.0/8 是「本网络」段，100.64.0.0/10 是运营商级 NAT，192.0.0.0/24 是 IETF 协议
// 分配段，192.0.2.0/24、198.51.100.0/24、203.0.113.0/24 是文档示例段（TEST-NET-1/2/3），
// 192.88.99.0/24 是已废弃的 6to4 中继任播，198.18.0.0/15 是基准测试段，240.0.0.0/4 是
// 保留段（含有限广播 255.255.255.255）。IPv6 侧 100::/64 是丢弃前缀、2001:2::/48 是
// 基准测试段、2001:db8::/32 是文档示例段。探测服务返回这些地址只可能是响应被伪造或来自
// 内网，拿它定位会把地理数据污染成服务器自己所在的网段。
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// isNonPublicPrefix 报告 addr 是否落在上述保留/特殊用途网段内。
func isNonPublicPrefix(addr netip.Addr) bool {
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// isPublicEgressAddr 报告 addr 是否为可作服务器出口的公网单播地址。
//
// 探测服务被劫持或配置错误时可能返回本机/内网地址，拿它做定位会把地理数据污染成
// 服务器自己所在的网段，因此私有、环回、链路本地、未指定、组播以及保留/特殊用途网段
// 一律拒收。
func isPublicEgressAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	// ::ffff:10.0.0.1 这类 IPv4-mapped 地址按 IPv4 判定，否则内网 IPv4 会绕过检查。
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() ||
		isNonPublicPrefix(addr) {
		return false
	}
	// 有限广播地址不属于上面的任何分类，但它不是可路由的单播地址。
	if addr.Is4() && addr == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	return true
}
