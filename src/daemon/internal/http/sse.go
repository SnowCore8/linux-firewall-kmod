package http

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SSEBroker struct {
	mu         sync.Mutex
	clients    map[chan []byte]bool
	register   chan sseRegRequest
	unregister chan chan []byte
	broadcast  chan []byte
	stopCh     chan struct{}
	logger     *slog.Logger
	maxClients int

	// VerifyToken 校验 SSE 认证 token。非 nil 时 ServeHTTP 在建立连接前校验。
	// 依次检查 URL query ?access_token= 与 Authorization: Bearer 头。
	VerifyToken func(token string) bool
}

// sseRegRequest 是 SSE 客户端注册请求。
//
// 把「客户端数量上限检查」与「注册」合并到 run() goroutine 内，由写锁一次性保护，
// 消除 ServeHTTP 中 RLock 检查 → 异步注册之间的竞态窗口。
type sseRegRequest struct {
	ch chan []byte
	ok chan bool
}

func NewSSEBroker(maxClients int, logger *slog.Logger) *SSEBroker {
	if maxClients <= 0 {
		maxClients = 32
	}
	if logger == nil {
		logger = slog.Default()
	}

	broker := &SSEBroker{
		clients:    make(map[chan []byte]bool),
		register:   make(chan sseRegRequest),
		unregister: make(chan chan []byte),
		broadcast:  make(chan []byte, 256),
		stopCh:     make(chan struct{}),
		logger:     logger,
		maxClients: maxClients,
	}

	go broker.run()
	return broker
}

func (b *SSEBroker) Stop() {
	close(b.stopCh)
	b.mu.Lock()
	for client := range b.clients {
		close(client)
	}
	b.clients = make(map[chan []byte]bool)
	b.mu.Unlock()
}

func (b *SSEBroker) run() {
	for {
		select {
		case <-b.stopCh:
			return
		case req := <-b.register:
			b.mu.Lock()
			if len(b.clients) >= b.maxClients {
				b.mu.Unlock()
				req.ok <- false
				continue
			}
			b.clients[req.ch] = true
			b.mu.Unlock()
			req.ok <- true
			b.logger.Debug("SSE client connected", "active", len(b.clients))

		case client := <-b.unregister:
			b.mu.Lock()
			if _, ok := b.clients[client]; ok {
				delete(b.clients, client)
				close(client)
			}
			b.mu.Unlock()
			b.logger.Debug("SSE client disconnected", "active", len(b.clients))

		case message := <-b.broadcast:
			b.mu.Lock()
			for client := range b.clients {
				select {
				case client <- message:
				default:
					delete(b.clients, client)
					close(client)
				}
			}
			b.mu.Unlock()
		}
	}
}

func (b *SSEBroker) Publish(eventType string, data any) {
	payload := map[string]any{
		"event": eventType,
		"data":  data,
		"ts":    time.Now().Unix(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		b.logger.Error("marshal SSE payload", "error", err)
		return
	}
	select {
	case b.broadcast <- raw:
	default:
		b.logger.Warn("SSE broadcast queue full, dropping message")
	}
}

func (b *SSEBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Token 认证：优先 query 参数，其次 Authorization header
	if b.VerifyToken != nil {
		token := r.URL.Query().Get("access_token")
		if token == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if token == "" || !b.VerifyToken(token) {
			WriteError(w, http.StatusUnauthorized, "unauthorized", "SSE 认证失败")
			return
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	messageChan := make(chan []byte, 16)
	regReq := sseRegRequest{ch: messageChan, ok: make(chan bool, 1)}
	b.register <- regReq

	if !<-regReq.ok {
		WriteServiceUnavailable(w, "SSE connection limit reached")
		return
	}

	defer func() {
		b.unregister <- messageChan
	}()

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case msg, ok := <-messageChan:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()

		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (b *SSEBroker) ActiveClients() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.clients)
}

func (b *SSEBroker) MaxClients() int {
	return b.maxClients
}

func (b *SSEBroker) AtLimit() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.clients) >= b.maxClients
}
