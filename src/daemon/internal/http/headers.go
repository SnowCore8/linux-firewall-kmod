// 安全头中间件：契约 header 段声明的四个响应头，对**所有**路由统一施加。
//
// 放在 ServeMux 之前而不是每个 handler 里写一遍：漏一条路由的后果是「面板能打开、某个
// API 没有 CSP」，而这种缺口从行为上看不出来，只有对着契约逐条核才看得见。
//
// 头名与取值都引用生成物常量（`httpcontract.Header*`），实现里没有第二份字符串——
// 逐条显式写 Set 而不是遍历 SecurityHeaders，是因为「谁写了哪个头」必须是可核对的：
// 遍历一张表在读代码的人眼里成立，在门禁的扫描器里等于一个头都没发。
package http

import (
	"net/http"
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// webUIPaths 与 webUIPrefixes 是面板自身的落点：SPA 壳、静态资源、Service Worker。
//
// 判据直接由生成物路由表推出来，不在这份代码里抄一遍路径清单——契约里 auth=none 且载荷
// 不是 JSON（returns != type）的那一组就是面板：它返回 HTML 壳或资源字节。/health 虽然
// 也在 auth=none 组里，但它回 JSON，因此落进「非面板」一侧，拿最严的 CSP。
var webUIPaths, webUIPrefixes = collectWebUIPaths()

func collectWebUIPaths() (map[string]bool, []string) {
	paths := map[string]bool{}
	var prefixes []string
	for _, route := range httpcontract.Routes {
		if route.Auth != httpcontract.AuthNone {
			continue
		}
		if route.Returns == httpcontract.ReturnsType {
			continue
		}
		// 参数槽结尾（`/static/{path...}`）代表一段前缀而不是一个具体路径。
		if i := strings.IndexByte(route.Path, '{'); i >= 0 {
			prefixes = append(prefixes, route.Path[:i])
			continue
		}
		paths[route.Path] = true
	}
	return paths, prefixes
}

// isWebUIPath 判断请求路径是否属于面板。
//
// 按**路径**判而不是按最终 Content-Type 判：CSP 必须在写出响应头之前定下来，而那时还
// 不知道 handler 会写什么。
func isWebUIPath(path string) bool {
	if webUIPaths[path] {
		return true
	}
	for _, prefix := range webUIPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// securityHeaders 给每条响应装上契约声明的四个头。
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webui := isWebUIPath(r.URL.Path)

		// MIME 嗅探会把一个 JSON 或纯文本响应解释成脚本，nosniff 是这一条的开关。
		w.Header().Set(httpcontract.HeaderXContentTypeOptions,
			httpcontract.HeaderXContentTypeOptionsValue)
		// 面板不需要被任何第三方页面框起来。
		w.Header().Set(httpcontract.HeaderXFrameOptions,
			httpcontract.HeaderXFrameOptionsValue)
		// CSP 有两个值：面板要加载自己的脚本与样式（契约的 value_webui），其余响应
		// 只回 JSON / 纯文本，default-src 'none' 之下任何脚本执行都是异常。
		if webui {
			w.Header().Set(httpcontract.HeaderContentSecurityPolicy,
				httpcontract.HeaderContentSecurityPolicyValueWebUI)
		} else {
			w.Header().Set(httpcontract.HeaderContentSecurityPolicy,
				httpcontract.HeaderContentSecurityPolicyValue)
		}
		// 封禁表、配置、日志都是会过期的状态，缓存一份就等于让面板显示已经不存在的封禁。
		w.Header().Set(httpcontract.HeaderCacheControl,
			httpcontract.HeaderCacheControlValue)

		next.ServeHTTP(w, r)
	})
}
