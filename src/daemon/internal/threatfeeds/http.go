package threatfeeds

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// allowedFeedHosts 是允许拉取的情报源域名白名单。
// 防止 SSRF：只允许访问已知的威胁情报源域名。
var allowedFeedHosts = map[string]bool{
	"raw.githubusercontent.com": true, // IPsum, FireHOL
	"www.dshield.org":           true, // DShield
	"lists.blocklist.de":        true, // Blocklist.de
	"feodotracker.abuse.ch":     true, // Feodo Tracker
}

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
		// 检查所有解析出的 IP，任一为私有地址则拒绝
		for _, ip := range ips {
			addr, ok := netip.AddrFromSlice(ip.IP)
			if !ok {
				continue
			}
			if isPrivateAddr(addr) {
				return nil, fmt.Errorf("DNS 解析到私有地址 %s，拒绝连接（SSRF 防护）", ip.IP)
			}
		}
		// 使用第一个非私有 IP 连接
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
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

// validateURL 校验 URL 是否允许访问。
func validateURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("只允许 HTTPS 协议: %s", u.Scheme)
	}
	host := strings.ToLower(u.Host)
	// 移除端口
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	if !allowedFeedHosts[host] {
		return fmt.Errorf("域名不在白名单中: %s", host)
	}
	return nil
}

// isPrivateAddr 检查 IP 是否为私有/回环/未指定地址。
func isPrivateAddr(addr netip.Addr) bool {
	return addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
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
