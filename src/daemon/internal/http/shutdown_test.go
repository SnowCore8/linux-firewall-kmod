// 关停路径的行为规格：SSE 长连接必须让 HTTP 服务器能立刻收敛，而不是等超时。
//
// 断言的是「Stop 之后关服务器会不会带超时错误回来」，不是某个耗时阈值：关停变快这件事
// 只有换成「是否等满预算」才可判定，掐表只会被机器负载影响。
package http

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// openSSE 连上测试服务器的这条流并把响应头读回来。SSE 的响应头一写出，这条连接就进入
// 「服务器认为它还在忙」的状态，正是关停要处理的那种连接。
func openSSE(t *testing.T, addr, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("请求 %s 失败: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// newShutdownTestServer 起一个只监听回环随机端口的服务器；ShutdownTimeout 就是关停预算，
// 用例靠它区分「连接已停，立刻收敛」与「连接没停，等满预算后强制关闭」。
func newShutdownTestServer(t *testing.T, shutdownTimeout time.Duration) *Server {
	t.Helper()
	srv, err := NewServer(Config{Address: "127.0.0.1:0", ShutdownTimeout: shutdownTimeout})
	if err != nil {
		t.Fatalf("新建测试服务器失败: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})
	return srv
}

// sseEndpoint 把一条测试流接到服务器上：attach 一律放行，因为这条用例关心的是关停，
// 不是名额；握手留空，让连接停在「已写响应头、正在等待帧」的形态。
func sseEndpoint(srv *Server, stream *SSEStream) {
	srv.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		streamSSE(w, r, stream,
			func(chan []byte) bool { return true },
			func(chan []byte) {},
			nil)
	})
}

// TestStoppedStreamLetsServerShutDownImmediately 是这次修复的正题：流一停，
// 服务器关停立刻返回且不带超时错误。
func TestStoppedStreamLetsServerShutDownImmediately(t *testing.T) {
	stream := NewSSEStream("events", 10, 15, nil)
	srv := newShutdownTestServer(t, 2*time.Second)
	sseEndpoint(srv, stream)

	resp := openSSE(t, srv.Addr(), "/api/v1/events")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE 握手状态码 = %d，期望 200", resp.StatusCode)
	}

	stream.Stop()
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("流已停，服务器关停仍返回错误: %v", err)
	}
}

// TestServerShutDownForceClosesLingeringConnections 覆盖兜底那一步：预算用尽时不是返回
// 错误就了事，必须把还在忙的连接强制关掉。
//
// 这条断言的落点是「连接上的处理函数有没有被告知结束」，不是端口能否重 bind——监听套
// 接字在 Shutdown 一开始就关了，端口是否已释放区分不出改前改后；真正会让紧接着的
// 重启撞上 busy 的，是旧进程带着未结束的请求迟迟不退出。
func TestServerShutDownForceClosesLingeringConnections(t *testing.T) {
	stream := NewSSEStream("events", 10, 15, nil)
	srv := newShutdownTestServer(t, 150*time.Millisecond)
	released := make(chan struct{})
	srv.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		streamSSE(w, r, stream,
			func(chan []byte) bool { return true },
			func(chan []byte) {},
			nil)
		close(released)
	})
	addr := srv.Addr()

	if resp := openSSE(t, addr, "/api/v1/events"); resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE 握手状态码 = %d，期望 200", resp.StatusCode)
	}

	// 流没停：连接还在忙，Shutdown 只能等满预算。此时 Stop 必须返回错误并强制关闭。
	done := make(chan error, 1)
	go func() { done <- srv.Stop(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("连接未停时 Stop 返回 nil，强制关闭那一步没有被走到")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Stop 超出预算后仍未返回")
	}

	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Errorf("Stop 返回后连接上的处理函数仍未结束：强制关闭没有生效")
	}

	// 端口必须已释放：能重新 bind 才算重启不撞车。
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("关停后端口 %s 仍不可复用: %v", addr, err)
	}
	ln.Close()
}

// TestStoppedStreamRejectsNewConnections：关停中的流不再握手，也不再占名额。
func TestStoppedStreamRejectsNewConnections(t *testing.T) {
	stream := NewSSEStream("events", 10, 15, nil)
	srv := newShutdownTestServer(t, time.Second)
	sseEndpoint(srv, stream)
	stream.Stop()

	resp := openSSE(t, srv.Addr(), "/api/v1/events")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("关停中的流仍接受新连接: 状态码 = %d，期望 503", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读 503 响应体失败: %v", err)
	}
	var envelope struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("503 响应体不是契约的信封: %q（%v）", body, err)
	}
	if envelope.Code != httpcontract.Code50003 {
		t.Errorf("503 业务码 = %d，期望契约的 %d", envelope.Code, httpcontract.Code50003)
	}
	if stream.Active() != 0 {
		t.Errorf("关停期间新连接仍占了名额: Active = %d", stream.Active())
	}
}

// TestBrokerStopIsRepeatableAndEndsClients：重复 Stop 不 panic，在线连接收到通道关闭，
// 关停与扇出并发时不会向已关闭的通道发送。
func TestBrokerStopIsRepeatableAndEndsClients(t *testing.T) {
	broker := NewEventsBroker(nil)

	conns := map[string]chan []byte{"首条": make(chan []byte, 8), "次条": make(chan []byte, 8)}
	for name, ch := range conns {
		if !broker.attach(ch) {
			t.Fatalf("%s attach 被拒，测试前提不成立", name)
		}
	}
	// 广播帧排在 Stop 之前：要么写完，要么被 stopped 标志挡掉，
	// 唯独不能落到「向已关闭的通道发送」上（那会直接 panic 掉进程）。
	for i := 0; i < 8; i++ {
		broker.Publish("stats", map[string]any{"seq": i})
	}
	broker.Stop()
	broker.Stop()

	for name, ch := range conns {
		if !waitForClose(ch, 2*time.Second) {
			t.Errorf("%s 连接没有因 Stop 收到通道关闭", name)
		}
	}
	if broker.Active() != 0 {
		t.Errorf("Stop 后仍占着名额: Active = %d", broker.Active())
	}
	if broker.attach(make(chan []byte, 1)) {
		t.Errorf("Stop 之后 attach 仍成功，扇出会写进已关停的循环")
	}
}

// waitForClose 读到通道被关闭返回 true；关停前已排队的帧直接丢弃。
func waitForClose(ch chan []byte, within time.Duration) bool {
	deadline := time.After(within)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return true
			}
		case <-deadline:
			return false
		}
	}
}
