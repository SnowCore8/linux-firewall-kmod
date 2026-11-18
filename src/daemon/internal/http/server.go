package http

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	httpServer *http.Server
	listener   net.Listener
	mux        *http.ServeMux
	logger     *slog.Logger
	addr       string

	mu              sync.RWMutex
	activeConns     int
	maxConns        int
	shutdownTimeout time.Duration
}

type Config struct {
	Address         string
	MaxConnections  int
	ShutdownTimeout time.Duration
	Logger          *slog.Logger
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Address == "" {
		cfg.Address = "127.0.0.1:9119"
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 32
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.Address, err)
	}

	mux := http.NewServeMux()
	s := &Server{
		listener:        listener,
		mux:             mux,
		logger:          cfg.Logger,
		addr:            cfg.Address,
		maxConns:        cfg.MaxConnections,
		shutdownTimeout: cfg.ShutdownTimeout,
	}

	s.httpServer = &http.Server{
		// 安全头在连接配额**外面**：配额满时由 connectionLimiter 直接写 503 信封，那条
		// 响应不经过 mux，中间件排在里面就等于限额告知没有 CSP/nosniff。
		Handler:           s.securityHeaders(s.connectionLimiter(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout 只约束普通响应；SSE 长连接在 streamSSE 里清掉写截止（sse.go）。
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

func (s *Server) Handle(pattern string, handler http.Handler) {
	s.mux.Handle(pattern, handler)
}

func (s *Server) HandleFunc(pattern string, handler http.HandlerFunc) {
	s.mux.HandleFunc(pattern, handler)
}

func (s *Server) Start() error {
	s.logger.Info("HTTP server starting", "addr", s.addr)
	if err := s.httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// Stop 关停 HTTP 服务器：先按 ctx 的预算等活跃连接变空闲，等不到就强制关掉。
//
// 强制那一步不能省：`http.Server.Shutdown` 超时会返回 ctx 的错误但**不**替调用方关闭
// 仍在忙的连接，监听端口于是继续被占着，紧接着的重启就撞 `bind: address already in use`。
// 由 Start 的执行体在关停令牌置位后调用本方法，配合先停 SSE 流，正常路径几乎瞬时返回。
// 重复调用安全：底层 Shutdown/Close 都幂等。
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("HTTP server stopping")
	ctx, cancel := context.WithTimeout(ctx, s.shutdownTimeout)
	defer cancel()

	err := s.httpServer.Shutdown(ctx)
	if err != nil {
		s.logger.Warn("HTTP server graceful shutdown incomplete, forcing close", "error", err)
		if cerr := s.httpServer.Close(); cerr != nil {
			s.logger.Error("HTTP server force close failed", "error", cerr)
		}
		return err
	}
	s.logger.Info("HTTP server stopped")
	return nil
}

func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

func (s *Server) ActiveConnections() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeConns
}

func (s *Server) MaxConnections() int {
	return s.maxConns
}

func (s *Server) connectionLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		if s.activeConns >= s.maxConns {
			// 计数在锁内取值：解锁后再读 activeConns 会与其它连接的 ++/-- 竞争。
			active, max := s.activeConns, s.maxConns
			s.mu.Unlock()
			s.logger.Warn("connection limit reached", "active", active, "max", max)
			// 走统一信封（code 50003）：限额告知也是契约响应，不能是裸 text/plain。
			WriteServiceUnavailable(w, "连接数已达上限，请稍后重试")
			return
		}
		s.activeConns++
		s.mu.Unlock()

		defer func() {
			s.mu.Lock()
			s.activeConns--
			s.mu.Unlock()
		}()

		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	body, err := json.Marshal(data)
	if err != nil {
		slog.Error("json marshal failed", "error", err)
		http.Error(w, `{"code":50000,"message":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}
