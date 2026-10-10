// 安全头中间件的行为核对：契约 header 段的四个头对**每一条**响应都施加，CSP 按契约的
// value_webui 分支取值。
//
// 期望值一律从生成物表 httpcontract.SecurityHeaders 读，测试里不抄头名与取值：抄一份
// 就等于给「契约改了、实现没改」留一条能通过的路。
package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// getThrough 从装配了安全头中间件的链上打一次请求。
//
// 只装 securityHeaders 而不装 connectionLimiter：本文件关心的是「头有没有发」，配额那一层
// 单独用一个用例覆盖（它绕过 mux，正是最容易漏头的出口）。
func getThrough(t *testing.T, s *Server, path string, authed bool) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authed {
		req.Header.Set("Authorization", authHeader())
	}
	w := httptest.NewRecorder()
	s.securityHeaders(s.mux).ServeHTTP(w, req)
	return w
}

// assertContractHeaders 按契约表逐个头核对取值。webui 为真时，声明了 value_webui 的头
// 用面板值，其余仍用通用值。
func assertContractHeaders(t *testing.T, w *httptest.ResponseRecorder, path string, webui bool) {
	t.Helper()

	checked := 0
	for _, d := range httpcontract.SecurityHeaders {
		want := d.Value
		if webui && d.ValueWebUI != "" {
			want = d.ValueWebUI
		}
		got := w.Header().Get(d.Name)
		if got != want {
			t.Errorf("%s 的 %s = %q，契约声明 %q", path, d.Name, got, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("生成物的 SecurityHeaders 是空的，本用例没核对任何东西")
	}
}

// TestCSPHasTwoDistinctValues 立住分支的前提：面板值与通用值确实不同。
// 两者相同时下面的分支用例全部失去意义，所以这条必须先看住。
func TestCSPHasTwoDistinctValues(t *testing.T) {
	if httpcontract.HeaderContentSecurityPolicyValueWebUI == httpcontract.HeaderContentSecurityPolicyValue {
		t.Fatal("CSP 的两个契约值相同，webui 分支不存在，相关用例应删除而不是留着空转")
	}
}

// TestPanelResponsesUseWebUICSP 覆盖契约里 auth=none 且载荷不是 JSON 的全部路径：那些
// 就是面板本体，响应必须带面板用的 CSP。
//
// 逐条遍历生成物路由表而不是列一份路径清单：新增一条面板路由时，这里自动纳入核对；抄
// 一份清单则会变成「新页面没有宽 CSP 也没人知道」。
func TestPanelResponsesUseWebUICSP(t *testing.T) {
	s, _ := newTestServer(t, nil)

	paths := []string{}
	for _, route := range httpcontract.Routes {
		if route.Auth != httpcontract.AuthNone || route.Returns == httpcontract.ReturnsType {
			continue
		}
		if strings.ContainsAny(route.Path, "{") {
			// 通配槽（/static/{path...}）用一个真存在的资源路径代替。
			paths = append(paths, concretePath(t, route.Pattern))
			continue
		}
		paths = append(paths, route.Path)
	}
	if len(paths) < 5 {
		t.Fatalf("面板路径只有 %d 条，生成物路由表可能没带上静态面", len(paths))
	}

	for _, path := range paths {
		w := getThrough(t, s, path, false)
		assertContractHeaders(t, w, path, true)
	}
}

// TestProbeAndAPIResponsesUseStrictCSP 核对「按载荷种类分档」而不是「按认证组分档」：
// /health 与面板同在 auth=none 组里，但它回 JSON，因此拿最严的那份 CSP。
func TestProbeAndAPIResponsesUseStrictCSP(t *testing.T) {
	s, _ := newTestServer(t, nil)

	for _, path := range []string{
		httpcontract.RouteGetHealth[strings.Index(httpcontract.RouteGetHealth, " ")+1:],
		httpcontract.RouteGetHealthz[strings.Index(httpcontract.RouteGetHealthz, " ")+1:],
		httpcontract.RouteGetApiV1Bans[strings.Index(httpcontract.RouteGetApiV1Bans, " ")+1:],
	} {
		w := getThrough(t, s, path, true)
		assertContractHeaders(t, w, path, false)
	}
}

// TestSecurityHeadersOnErrorResponses 核对两种「不是 handler 正常return」的响应也带安全
// 头：中间件排在 mux 之外，框架自产的 405 与 handler 自产的 404 都从它下面出去。
//
// 404 只有静态资源这一条路可达：`GET /` 在 ServeMux 里是一棵兜住所有路径的子树（契约用
// 它做面板深链的重定向），所以任何路径至少匹配到一个模式——路径不符才是 404，而这里没有
// 「不符的路径」；动词不符则一律 405。
func TestSecurityHeadersOnErrorResponses(t *testing.T) {
	s, _ := newTestServer(t, nil)

	// 静态面缺资源：handler 自产的纯文本 404，路径在 /static/ 前缀下 → 面板 CSP 档。
	notFound := getThrough(t, s, "/static/nope.js", false)
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("缺失资源状态码 %d，期望 404", notFound.Code)
	}
	assertContractHeaders(t, notFound, "/static/nope.js", true)

	// 匿名请求的 401 由 RequireAuth 写，同样在中间件之内。
	denied := getThrough(t, s,
		httpcontract.RouteGetApiV1Bans[strings.Index(httpcontract.RouteGetApiV1Bans, " ")+1:], false)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("匿名请求状态码 %d，期望 401", denied.Code)
	}
	assertContractHeaders(t, denied, "/api/v1/bans", false)

	methodNotAllowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete,
		httpcontract.RouteGetApiV1Bans[strings.Index(httpcontract.RouteGetApiV1Bans, " ")+1:], nil)
	req.Header.Set("Authorization", authHeader())
	s.securityHeaders(s.mux).ServeHTTP(methodNotAllowed, req)
	if methodNotAllowed.Code != http.StatusMethodNotAllowed {
		t.Fatalf("未声明的动词状态码 %d，期望 405", methodNotAllowed.Code)
	}
	assertContractHeaders(t, methodNotAllowed, "/api/v1/bans", false)
}

// TestSecurityHeadersSurviveConnectionLimit 是中间件顺序的行为断言：安全头必须排在连接
// 配额**外面**。配额满时响应由 connectionLimiter 用 http.Error 直接写、根本不进 mux，
// 中间件排在里面就等于「限额告知没有 CSP/nosniff」。
func TestSecurityHeadersSurviveConnectionLimit(t *testing.T) {
	s := &Server{mux: http.NewServeMux(), logger: discardLogger(), maxConns: 0}

	w := httptest.NewRecorder()
	s.securityHeaders(s.connectionLimiter(s.mux)).
		ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("配额为 0 时状态码 %d，期望 503", w.Code)
	}
	assertContractHeaders(t, w, "/health", false)
}

// TestPanelPathsComeFromTheContract 守住 webUIPaths 的来源：中间件里那份面板路径集合
// 必须与生成物路由表判出来的集合一致，谁另存一份都会在这里分叉。
func TestPanelPathsComeFromTheContract(t *testing.T) {
	want, wantPrefixes := collectWebUIPaths()
	if len(want) == 0 || len(wantPrefixes) == 0 {
		t.Fatalf("面板路径集合空（exact=%d prefix=%d），CSP 分支等于没接线",
			len(want), len(wantPrefixes))
	}
	for _, path := range []string{"/dashboard", "/logs", "/sw.js"} {
		if !isWebUIPath(path) {
			t.Errorf("%q 没被判成面板路径", path)
		}
	}
	for _, prefix := range wantPrefixes {
		if isWebUIPath(strings.TrimSuffix(prefix, "/")) {
			t.Errorf("前缀 %q 的父路径被判成面板：前缀匹配漏了边界", prefix)
		}
	}
	// API 与探针必须在严格档一侧。
	for _, path := range []string{"/health", "/api/v1/bans", "/metrics"} {
		if isWebUIPath(path) {
			t.Errorf("%q 被判成面板路径，会拿到更宽的 CSP", path)
		}
	}
}
