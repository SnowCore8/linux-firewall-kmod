package threatfeeds

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// HTTPClient 封装了带超时和重试的 HTTP 请求。
type HTTPClient struct {
	client     *http.Client
	maxRetries int
	userAgent  string
}

// maxFeedResponseBytes 是单个情报源响应体的上限：100 MiB。
//
// 正常情报源列表远小于此（IPsum 约 2-5 MiB，FireHOL Level 1 约 50 KiB）。
// 上限存在的意义是把「远端被攻陷或配置错误返回数 GB 数据」从内存耗尽降级成一次
// 错误返回，而不是让守护进程被 OOM killer 干掉。安全基础设施本身不能成为 DoS 入口。
const maxFeedResponseBytes = 100 << 20

// NewHTTPClient 创建新的 HTTP 客户端。
func NewHTTPClient(timeout time.Duration, maxRetries int) *HTTPClient {
	// 自定义 DialContext：DNS 解析后检查目标 IP，防止 DNS rebinding SSRF
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	safeDialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 分离 host 和 port
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("解析地址失败: %w", err)
		}
		// 解析 DNS
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS 解析失败: %w", err)
		}
		// 检查所有解析出的 IP，任一为私有地址则拒绝；可连接的地址单独收集
		candidates, err := dialTargets(host, ips, port)
		if err != nil {
			return nil, err
		}
		// 只会连到已校验过的地址；不能直接取 ips[0]，那可能是被跳过的未校验项
		return dialer.DialContext(ctx, network, candidates[0])
	}

	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: safeDialContext,
			},
			// 禁止自动跟随重定向，防止重定向到内网地址
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("重定向次数过多")
				}
				if err := validateURL(req.URL); err != nil {
					return err
				}
				return nil
			},
		},
		maxRetries: maxRetries,
		userAgent:  "Firewall-ThreatFeeds/1.0",
	}
}

// dialTargets 把 DNS 解析结果转成可连接地址，并拒绝任何私有地址。
//
// 返回空列表意味着没有任何地址通过校验，调用方必须按错误处理：直接索引 ips[0]
// 会在空结果上 panic，也可能连到被跳过的未校验项。
func dialTargets(host string, ips []net.IPAddr, port string) ([]string, error) {
	targets := make([]string, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		if isPrivateAddr(addr) {
			return nil, fmt.Errorf("DNS 解析到私有地址 %s，拒绝连接（SSRF 防护）", ip.IP)
		}
		targets = append(targets, net.JoinHostPort(addr.Unmap().String(), port))
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("DNS 解析 %s 未返回可用地址", host)
	}
	return targets, nil
}

// validateURL 校验 URL 是否允许访问。
//
// 判据与配置解析期同一份（config.ValidateThreatFeedURL：https + 域名白名单），两边各写
// 一套时，配置期放行、拉取期拒收的 URL 会让源「配置成功却从未同步」。
func validateURL(u *url.URL) error {
	return config.ValidateThreatFeedURL(u.String())
}

// nonPublicPrefixes 列出标准库分类未覆盖、但同样不能作为 SSRF 目标的网段。
//
// 100.64.0.0/10 是运营商级 NAT，192.0.0.0/24 是 IETF 协议分配段，198.18.0.0/15 是
// 基准测试段，240.0.0.0/4 是保留段（含有限广播 255.255.255.255）：它们都不是可路由的
// 公网单播地址，连过去只会打到内网设备或本机协议栈。
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
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

// isPrivateAddr 检查 IP 是否为不可作为公网目标的地址。
func isPrivateAddr(addr netip.Addr) bool {
	// ::ffff:10.0.0.1 这类 IPv4-mapped 地址按 IPv4 判定，否则内网 IPv4 会绕过检查。
	addr = addr.Unmap()
	return addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() ||
		isNonPublicPrefix(addr)
}

// Fetch 从指定 URL 拉取数据，带重试逻辑。
func (c *HTTPClient) Fetch(ctx context.Context, urlStr string) ([]byte, error) {
	// 校验 URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}
	if err := validateURL(u); err != nil {
		return nil, fmt.Errorf("URL 校验失败: %w", err)
	}

	var lastErr error
	// 负数 maxRetries 按 0 处理，避免跳过循环返回包装 nil 的错误
	maxRetries := c.maxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// 指数退避：1s, 2s, 4s, 8s, 16s，上限 30s
			// 防止 attempt>=64 时 1<<uint(attempt-1) 溢出为 0 导致零延迟重试风暴
			shift := attempt - 1
			if shift > 4 {
				shift = 4 // 上限 2^4 = 16s
			}
			backoff := time.Duration(1<<uint(shift)) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		data, err := c.fetchOnce(ctx, u)
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("拉取 %s 失败（重试 %d 次）: %w", urlStr, c.maxRetries, lastErr)
}

// fetchOnce 执行单次 HTTP 请求。
func (c *HTTPClient) fetchOnce(ctx context.Context, u *url.URL) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/plain, text/csv, */*")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP 状态码 %d", resp.StatusCode)
	}

	// 限制读取量，防止远端返回超大响应导致 OOM
	limited := io.LimitReader(resp.Body, maxFeedResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	if int64(len(data)) > maxFeedResponseBytes {
		return nil, fmt.Errorf("响应体超过 %d MiB 上限", maxFeedResponseBytes>>20)
	}
	return data, nil
}
