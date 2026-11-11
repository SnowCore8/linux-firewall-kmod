// SSE 长连接与 HTTP 服务器写超时的边界：流一旦建立，必须清掉请求级的写截止时间，
// 否则连接会在 WriteTimeout 到点时因心跳写失败被 handler 主动结束。
package http

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// deadlineRecorder 同时实现 http.ResponseWriter、http.Flusher 与 SetWriteDeadline，
// 让 http.ResponseController 能找到写截止入口并记录调用。
type deadlineRecorder struct {
	header   http.Header
	called   bool
	deadline time.Time
}

func (d *deadlineRecorder) Header() http.Header         { return d.header }
func (d *deadlineRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (d *deadlineRecorder) WriteHeader(int)             {}
func (d *deadlineRecorder) Flush()                      {}
func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.called = true
	d.deadline = t
	return nil
}

func TestStreamSSEClearsWriteDeadline(t *testing.T) {
	stream := NewSSEStream("events", 10, 15, nil)
	rec := &deadlineRecorder{header: http.Header{}}

	// 已取消的上下文让 streamSSE 写完响应头后立即退出循环，用例无需等待心跳。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/api/v2/events", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}

	streamSSE(rec, req, stream,
		func(chan []byte) bool { return true },
		func(chan []byte) {},
		nil)

	if !rec.called {
		t.Fatal("streamSSE 未清除写截止：连接仍会被 WriteTimeout 掐断")
	}
	if !rec.deadline.IsZero() {
		t.Errorf("写截止 = %v，期望零值（无截止）", rec.deadline)
	}
}
