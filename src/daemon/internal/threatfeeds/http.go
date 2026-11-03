package threatfeeds

import (
	"context"
	"fmt"
	"io"
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

// NewHTTPClient 创建新的 HTTP 客户端。
func NewHTTPClient(timeout time.Duration, maxRetries int) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
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

// isPrivateAddr 检查 IP 是否为私有/回环地址。
func isPrivateAddr(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
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
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// 指数退避：1s, 2s, 4s
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %w", err)
	}
	return data, nil
}
