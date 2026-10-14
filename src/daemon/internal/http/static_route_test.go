package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRootRedirectDoesNotSwallowUnmatchedPaths 钉住 `GET /` 这条注册串在 ServeMux 里
// 的真实语义。
//
// 「GET /」是**子树模式**：任何没被更具体模式接住的 GET 都会落到 redirectRoot，于是
// /api/v1/nonexistent 读到的是 303 + 一个指向面板的 Location，而契约（contract/http.fwidl
// 的 FRAMEWORK_DEFAULT）说「路径无匹配模式 → 框架自产 404，body `404 page not found`」。
// 虚机上跑 daemon-up 形态的 test_16.7 就是这么撞出来的（断言 404，实得 303）。
// 拼错的 API 路径被重定向前端外壳，客户端拿到的是 HTML 而不是 404，等于把「这条路不存在」
// 这个事实藏起来。
func TestRootRedirectDoesNotSwallowUnmatchedPaths(t *testing.T) {
	s, _ := newTestServer(t, nil)

	// 根路径的行为一个都不能动：/?access_token=<令牌> 是免登录直达的唯一凭据入口。
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/?access_token=abc", nil))
	if w.Code != http.StatusSeeOther {
		t.Errorf("GET /?access_token=abc 状态码 = %d，期望 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/dashboard?access_token=abc" {
		t.Errorf("Location = %q，期望 \"/dashboard?access_token=abc\"（query 必须原样带上）", got)
	}

	for _, path := range []string{"/api/v1/nonexistent", "/nonexistent-page", "/dashboard/extra"} {
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s 状态码 = %d，期望 404（无匹配模式时由框架自产）", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "404 page not found") {
			t.Errorf("GET %s 的响应体 = %q，期望框架自产的那句 404", path, w.Body.String())
		}
	}
}
