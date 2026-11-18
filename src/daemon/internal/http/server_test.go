// 连接限额的响应形状：配额满时也必须走契约信封（code 50003），不能是裸 text/plain。
package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// TestConnectionLimitReturnsEnvelope503 直接打中间件（不起真端口）：占满唯一名额后，
// 下一条请求必须回 503 的 JSON 信封。裸 http.Error 会让前端解析信封失败，只能看到
// text/plain 的 "connection limit reached"。
func TestConnectionLimitReturnsEnvelope503(t *testing.T) {
	s := &Server{mux: http.NewServeMux(), logger: discardLogger(), maxConns: 1}
	release := make(chan struct{})
	entered := make(chan struct{})
	s.HandleFunc("GET /hold", func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	})
	s.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	limited := s.connectionLimiter(s.mux)

	done := make(chan struct{})
	go func() {
		defer close(done)
		limited.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/hold", nil))
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("占位请求没有进入 handler")
	}

	w := httptest.NewRecorder()
	limited.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	close(release)
	<-done

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d，期望 503（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q，期望 JSON（裸 text/plain 会让前端解析信封失败）", ct)
	}
	var env struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("503 响应体不是 JSON: %q（%v）", w.Body.Bytes(), err)
	}
	if env.Code != httpcontract.Code50003 {
		t.Errorf("业务码 = %d，期望 %d", env.Code, httpcontract.Code50003)
	}
	if string(env.Data) != "null" {
		t.Errorf("失败信封 data = %s，期望 null", env.Data)
	}
}
