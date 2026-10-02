package http

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type SSEBroker struct {
	mu         sync.RWMutex
	clients    map[chan []byte]bool
	register   chan chan []byte
	unregister chan chan []byte
	broadcast  chan []byte
	stopCh     chan struct{}
	logger     *slog.Logger
	maxClients int
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
		register:   make(chan chan []byte),
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
		case client := <-b.register:
			b.mu.Lock()
			b.clients[client] = true
			b.mu.Unlock()
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
			b.mu.RLock()
			for client := range b.clients {
				select {
				case client <- message:
				default:
					b.mu.RUnlock()
					b.mu.Lock()
					delete(b.clients, client)
					close(client)
					b.mu.Unlock()
					b.mu.RLock()
				}
			}
			b.mu.RUnlock()
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
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	b.mu.RLock()
	if len(b.clients) >= b.maxClients {
		b.mu.RUnlock()
		WriteServiceUnavailable(w, "SSE connection limit reached")
		return
	}
	b.mu.RUnlock()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	messageChan := make(chan []byte, 16)
	b.register <- messageChan

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
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

func (b *SSEBroker) MaxClients() int {
	return b.maxClients
}

func (b *SSEBroker) AtLimit() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients) >= b.maxClients
}
