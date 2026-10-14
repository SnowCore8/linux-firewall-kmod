// 静态面板与 SPA 外壳：契约里 14 条 auth=none 路由的落点。
//
// 这些路由返回的都是**不含运行时数据**的静态壳，公开不泄露状态；把它们放进认证组反而
// 会让页面打不开（浏览器直接输入地址、加载子资源、注册 Service Worker 都不带凭据）。
package http

import (
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// 静态未命中的文本是契约 errmodel STATIC_NOT_FOUND 的 body 原文；拆开写让
// "404 Not Found" 逐字出现在源码里（门禁按它核对），尾换行由纯文本写法补上。
const (
	staticNotFoundText = "404 Not Found"
	staticNotFoundBody = staticNotFoundText + "\n"
)

// Go 的内建 MIME 表没有 `.webmanifest`（PWA 清单的规范扩展名），`mime.TypeByExtension`
// 对它回空串，writeAsset 于是落到 `application/octet-stream`：浏览器拿不到清单类型，
// 「添加到主屏幕」少一份可读的 manifest，E2E 的 content-type 断言也直接失败（本轮就是在
// 实跑的 E2E 里暴露的）。在这里注册一次，扩展名推断仍是唯一的内容类型来源——不在每条
// 路由上手写 Content-Type，避免出现第二个来源。
func init() {
	// 两个入参都是常量字面量：AddExtensionType 只在扩展名或类型写法非法时报错，这里不可能失败。
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
}

// spaRoutes 是 SPA 的 9 个页面路径 → 同一个 index.html。
//
// 注册必须逐条写： ServeMux 的模式与契约的注册串是核对锚点，用循环遍历生成物表会让
// 扫描器看不到任何一条注册（它只认字面量与 `Route*` 常量标识符），等于 57 条路由都缺失。
func (s *Server) RegisterStaticFiles(fsys fs.FS) {
	// GET / → 303 /dashboard。**必须原样保留 query string**：/?access_token=<token>
	// 直达是登录页与外部跳转的唯一凭据入口，丢掉 query 就等于丢掉凭据。
	// 状态码固定 303（不是 302）：它明确表达「响应是另一个资源、原请求无副作用」。
	s.HandleFunc(httpcontract.RouteGet, redirectRoot)

	s.HandleFunc(httpcontract.RouteGetDashboard, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetBans, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetWhitelist, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetJails, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetDdos, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetGlobe, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetLogs, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetSettings, spaShell(fsys))
	s.HandleFunc(httpcontract.RouteGetMore, spaShell(fsys))

	s.HandleFunc(httpcontract.RouteGetStaticPath, serveAsset(fsys))

	// Service Worker 必须待在认证组外：浏览器注册 SW 时不带交互式凭据，包进认证就 401。
	// 这里**不**再自己写 Cache-Control：契约把它的取值定成 no-store 且 scope=all，
	// 中间件已经给了；handler 再覆盖一次就会出现「同一个头两个来源」，而 SW 的更新检查
	// 本来就走 bypass-cache，no-store 不会让它更难拿到新版本。
	s.HandleFunc(httpcontract.RouteGetSwJs, serviceWorker(fsys))
}

// redirectRoot 把 `GET /` 303 到 /dashboard，**原样保留 query string**：/?access_token=
// <token> 直达是登录页与外部跳转的唯一凭据入口，丢掉 query 就等于丢掉凭据。
//
// 状态码固定 303（不是 302）：它明确表达「响应是另一个资源、原请求无副作用」。
//
// `GET /` 在 ServeMux 里是**子树模式**：任何没被更具体模式接住的 GET 都会落到这里，
// 于是 `/api/v1/typo` 读到的是 303 + 面板外壳，而契约说「路径无匹配模式 → 框架自产
// 404，body `404 page not found`」（contract/http.fwidl 的 FRAMEWORK_DEFAULT）。所以
// 只有真正的根路径才重定向，其余交给 net/http 自己的 404 生产者——不手写响应体，
// 保持契约「daemon 源码里不该有 404 构造点」这句话成立。
func redirectRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	target := "/dashboard"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusSeeOther)
}

// serviceWorker 交出 sw.js，并显式声明 Service-Worker-Allowed: / 把 SW 的作用域抬到根。
//
// 它必须待在认证组外：浏览器注册 SW 时不带交互式凭据，包进认证就 401。这里**不**再自己写
// Cache-Control：契约把它的取值定成 no-store 且 scope=all，中间件已经给了；handler 再覆盖
// 一次就会出现「同一个头两个来源」，而 SW 的更新检查本来就走 bypass-cache。
func serviceWorker(fsys fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Service-Worker-Allowed", "/")
		writeAsset(w, r, fsys, "sw.js", "application/javascript")
	}
}

// spaShell 返回「把 index.html 原样交出去」的 handler：9 个页面路径共用它。
//
// 前端用 hash 路由，服务端不需要按路径改写内容——它要做的只是让每个页面路径都能拿到壳。
func spaShell(fsys fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		index, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			// 面板资源随二进制一起 embed，读不到是装配错误，不是用户可通过的 404。
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	}
}

// serveAsset 从 embed 目录里取 `GET /static/*path` 命中的那份资源。
func serveAsset(fsys fs.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeAsset(w, r, fsys, r.PathValue("path"), "")
	}
}

// writeAsset 写出资源字节；未命中一律回契约声明的纯文本 404。
//
// contentType 为空时按扩展名推断（mime.TypeByExtension），推断不出来回落
// application/octet-stream——把未知二进制标成 text/plain 会让浏览器把它当文本渲染。
//
// 路径先过 fs.ValidPath：ServeMux 的 `*path` 通配能带出 ".." 与绝对路径片段，而
// io/fs 的契约是「仅接受相对且已规整的路径」。这里显式挡下来，而不是指望 ReadFile
// 的失败信息读起来像安全缺陷。
func writeAsset(w http.ResponseWriter, r *http.Request, fsys fs.FS, name, contentType string) {
	if name == "" || !fs.ValidPath(name) || strings.Contains(name, "..") {
		staticText404(w)
		return
	}
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		staticText404(w)
		return
	}
	if contentType == "" {
		if guessed := mime.TypeByExtension(path.Ext(name)); guessed != "" {
			contentType = guessed
		} else {
			contentType = "application/octet-stream"
		}
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}

// staticText404 写 errmodel STATIC_NOT_FOUND 的响应体。
//
// 不用 http.NotFound / http.Error：它们写的是框架文本 `404 page not found`，与契约声明
// 的 "404 Not Found\n" 不同——面板据此区分「资源不存在」与「路由没接上」。
func staticText404(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(staticNotFoundBody))
}
