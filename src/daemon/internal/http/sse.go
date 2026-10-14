// SSE 接入面：两条流各自的名额、心跳与帧格式。
//
// 契约把 `/api/v1/events`（上限 10，事件 connected/stats/bans/jails/whitelist/rates）
// 与 `/api/v1/logs/stream`（上限 5，事件 connected/log/error）声明成**两条互不相干的
// 流**：各自计数、各自回 503。共用一个上限会让「日志页开满 5 个连接」把实时事件流也
// 一起饿死，所以名额本身收进 SSEStream，由两条流各持一个实例。
package http

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// sseRaw 是一段**已经成型**的帧载荷，直接写进 `data:` 行，不再经 JSON 包装。
//
// 日志流用它：文件里每一行本身通常已经是一条 JSON 记录（`{"level":…,"ts":…,"msg":…}`），
// 再 marshal 一层会让前端收到的 data 是个带引号的字符串，结构化解析整页退化成原文。
type sseRaw string

// sseFrame 把一次事件序列化成 SSE 帧。
//
// 事件名写在 `event:` 行上——前端用 `es.addEventListener('<域名>', …)` 按域名订阅，
// 名字只写在 JSON 载荷里的帧会被投给默认的 `message` 监听器，等于所有域事件都丢失。
// 载荷为 nil 时省略 `data:` 行（纯命名事件）。
func sseFrame(event string, data any) ([]byte, error) {
	out := make([]byte, 0, 128)
	out = append(out, "event: "...)
	out = append(out, event...)
	out = append(out, '\n')
	switch payload := data.(type) {
	case nil:
		// 纯命名事件，没有 data 行。
	case sseRaw:
		out = append(out, "data: "...)
		out = append(out, payload...)
		out = append(out, '\n')
	default:
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		out = append(out, "data: "...)
		out = append(out, raw...)
		out = append(out, '\n')
	}
	return append(out, '\n'), nil
}

// SSEStream 是一条 SSE 流的接入名额与在线计数。
//
// 只做两件事：按契约的 max_connections 决定收不收这条连接，以及报告当前有几条。
// 名额记账刻意与「往哪些连接写字节」分开——后者是广播实现的私事，前者是契约声明的
// 可观测语义（sse-status 与 503 都读它）。
//
// keepalive 与流名、上限一样属于每条流：两条流的值都取自契约（同为 15 秒），但必须
// 各读各的常量，否则契约改了其中一条、另一条会跟着动。
type SSEStream struct {
	name      string
	max       int
	heartbeat time.Duration
	logger    *slog.Logger

	mu   sync.Mutex
	live map[chan struct{}]struct{}

	// stopOnce 与 stopCh 一起把「这条流不再接受也不再有连接」做成可等待的信号：
	// Stop 可重复调用（组合根的执行体路径与 defer 兜底两处都会调它），而 streamSSE 的
	// 选择循环挂在这条通道上，关停时才不会把连接留到 HTTP 层超时。
	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewSSEStream 建一条流：上限与心跳间隔一律取自生成物常量
// （httpcontract.SSEMaxConnections* / SSEKeepaliveSeconds*），不在这里留数字副本。
func NewSSEStream(name string, max int, keepaliveSecs int, logger *slog.Logger) *SSEStream {
	if logger == nil {
		logger = slog.Default()
	}
	if max <= 0 {
		// 契约不会给出 0/负上限；真出现说明调用点传错了，退化成 1 而不是「无限」。
		logger.Warn("SSE 流上限非法，按 1 处理", "stream", name, "max", max)
		max = 1
	}
	heartbeat := time.Duration(keepaliveSecs) * time.Second
	if heartbeat <= 0 {
		logger.Warn("SSE 心跳间隔非法，按 15 秒处理", "stream", name, "keepalive_secs", keepaliveSecs)
		heartbeat = 15 * time.Second
	}
	return &SSEStream{
		name:      name,
		max:       max,
		heartbeat: heartbeat,
		logger:    logger,
		live:      make(map[chan struct{}]struct{}),
		stopCh:    make(chan struct{}),
	}
}

// Stop 关掉这条流：之后不再接受新连接，已在线的连接由调用方（或 SSEBroker.Stop 的扇出）
// 逐个结束。重复调用无副作用。
func (s *SSEStream) Stop() { s.stopOnce.Do(func() { close(s.stopCh) }) }

// stopped 报告这条流是否已关停，供名额判定与连接循环使用。
func (s *SSEStream) stopped() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

// Acquire 占用一个名额，返回释放函数与是否成功。
//
// 满额时 ok=false：调用方按契约回 503（不是 429——契约把这条流的失败状态码声明成
// 503，前端据此停止重连而不是继续退避重试）。release 可安全重复调用，用 sync.Once
// 兜住「defer 释放 + 显式释放」两条路径同时存在的情况。
func (s *SSEStream) Acquire() (release func(), ok bool) {
	token := make(chan struct{})
	s.mu.Lock()
	if len(s.live) >= s.max {
		s.mu.Unlock()
		s.logger.Debug("SSE 连接被拒：已达上限", "stream", s.name, "active", len(s.live), "max", s.max)
		return nil, false
	}
	s.live[token] = struct{}{}
	s.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			if _, exists := s.live[token]; exists {
				delete(s.live, token)
				close(token)
			}
			s.mu.Unlock()
		})
	}, true
}

// Active 返回当前占着名额的连接数。
func (s *SSEStream) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// Max 返回这条流的契约上限。
func (s *SSEStream) Max() int { return s.max }

// Name 返回流名（events / logs），诊断与 sse-status 用它区分两条流。
func (s *SSEStream) Name() string { return s.name }

// AtLimit 报告名额是否已占满。
func (s *SSEStream) AtLimit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live) >= s.max
}

// SSEBroker 是 `/api/v1/events` 的广播实现：一条流一个实例，名额来自内嵌的 SSEStream。
//
// 两套锁是刻意的：SSEStream.mu 只记账名额，clientsMu 只保护扇出登记表。合成一把会让
// 「广播扇出」与「能不能再收一条连接」互相阻塞——Active() 在广播持锁期间要读名额，
// 而握手帧失败时释放名额又需要不碰扇出表。
type SSEBroker struct {
	*SSEStream
	clientsMu  sync.Mutex
	clients    map[chan []byte]bool
	register   chan chan []byte
	unregister chan chan []byte
	broadcast  chan []byte
	stopCh     chan struct{}
	stopOnce   sync.Once
	// stopped 在 clientsMu 下读写：它让 run() 的扇出与 Stop() 的 close 互斥，
	// 不然 select 会在「stopCh 已关闭」与「广播帧正好可读」之间任选一个。
	stopped bool
}

// NewSSEBroker 建事件流 broker。max/keepalive 由调用点从契约生成物取，
// 组合根（cmd/firewall-daemon）是唯一知道「这条流是 events」的地方。
func NewSSEBroker(name string, maxClients int, keepaliveSecs int, logger *slog.Logger) *SSEBroker {
	if logger == nil {
		logger = slog.Default()
	}

	broker := &SSEBroker{
		SSEStream:  NewSSEStream(name, maxClients, keepaliveSecs, logger),
		clients:    make(map[chan []byte]bool),
		register:   make(chan chan []byte),
		unregister: make(chan chan []byte),
		broadcast:  make(chan []byte, 256),
		stopCh:     make(chan struct{}),
	}

	go broker.run()
	return broker
}

// Stop 结束这条广播流：先停扇出循环，再逐个关掉在线连接的发送通道。
//
// 可重复调用（组合根的执行体关停路径与 defer 兜底都会调它），也不会与 run() 抢同一条
// 通道：closed 标志与 clients 表在同一把锁下改写，run() 在锁内先看标志再写扇出，
// 于是「已关闭的通道」不可能再被投递或二次 close。
func (b *SSEBroker) Stop() {
	b.SSEStream.Stop()
	b.stopOnce.Do(func() { close(b.stopCh) })
	b.clientsMu.Lock()
	b.stopped = true
	for client := range b.clients {
		close(client)
	}
	b.clients = make(map[chan []byte]bool)
	b.clientsMu.Unlock()
}

// run 是唯一的注册/注销/广播循环。
//
// 名额判定已在 ServeHTTP 的 Acquire 里完成（那条路径与广播无关），这里只维护扇出
// 登记表；写不进去的慢客户端被摘掉，名额随之释放。
func (b *SSEBroker) run() {
	for {
		select {
		case <-b.stopCh:
			return
		case ch := <-b.register:
			b.clientsMu.Lock()
			if b.stopped {
				// attach 与 Stop 竞争时 attach 可能仍返回 true（select 两个分支同时就绪
				// 是任选的）。这种连接不能进已停用的扇出表，直接关闭让它立刻结束。
				b.clientsMu.Unlock()
				close(ch)
				return
			}
			b.clients[ch] = true
			b.clientsMu.Unlock()
			b.logger.Debug("SSE client connected", "stream", b.name, "active", b.Active())

		case ch := <-b.unregister:
			b.clientsMu.Lock()
			// 关停后不再 close：这些通道已由 Stop() 关闭过，二次 close 会 panic。
			if b.stopped {
				b.clientsMu.Unlock()
				return
			}
			if _, ok := b.clients[ch]; ok {
				delete(b.clients, ch)
				close(ch)
			}
			b.clientsMu.Unlock()
			b.logger.Debug("SSE client disconnected", "stream", b.name, "active", b.Active())

		case frame := <-b.broadcast:
			b.clientsMu.Lock()
			if b.stopped {
				// 关停已经接管：扇出表由 Stop() 清空并关闭，这里再写就是 send on closed channel。
				b.clientsMu.Unlock()
				return
			}
			for client := range b.clients {
				select {
				case client <- frame:
				default:
					delete(b.clients, client)
					close(client)
				}
			}
			b.clientsMu.Unlock()
		}
	}
}

// Publish 把一次域通知投进广播队列。
//
// 序列化每事件一次而不是每个订阅者一次：事件名与载荷在这里就定形，run() 只做字节扇出。
// 队列满时丢最该丢的——一条积压的旧快照不如立即回退到 REST 读数，故记日志后丢弃，
// 不钉住发布方（事件泵与封禁下发路径都在它后面）。
func (b *SSEBroker) Publish(eventType string, data any) {
	frame, err := sseFrame(eventType, data)
	if err != nil {
		b.logger.Error("marshal SSE payload", "event", eventType, "error", err)
		return
	}
	select {
	case b.broadcast <- frame:
	default:
		b.logger.Warn("SSE broadcast queue full, dropping message", "stream", b.name, "event", eventType)
	}
}

func (b *SSEBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	streamSSE(w, r, b.SSEStream, b.attach, b.detach, func(conn sseConnWriter) error {
		return conn.writeFrame("connected", map[string]any{
			"stream":          b.name,
			"max_connections": b.Max(),
		})
	})
}

// attach 把连接登记进扇出表；停止中或已关闭时返回 false（名额由调用方的 defer 释放）。
func (b *SSEBroker) attach(ch chan []byte) bool {
	select {
	case b.register <- ch:
		return true
	case <-b.stopCh:
		return false
	}
}

// detach 注销连接。
func (b *SSEBroker) detach(ch chan []byte) {
	select {
	case b.unregister <- ch:
	case <-b.stopCh:
	}
}

// sseConn 是一条已建立连接的写入端：把事件帧塞进它自己的发送通道。
type sseConn struct {
	out chan []byte
}

// writeFrame 序列化并投递一帧；发送缓冲满说明客户端读不过来，按断开处理。
//
// 事件名在这里是**逐字面量**（`conn.writeFrame("connected", …)`）——契约的每个事件名
// 都要在 Go 侧有一个字面发布点，verify_http.py 按这个形式找发布点，写成变量就等于
// 「发布点不存在」。
func (c *sseConn) writeFrame(event string, data any) error {
	frame, err := sseFrame(event, data)
	if err != nil {
		return err
	}
	select {
	case c.out <- frame:
		return nil
	default:
		return fmt.Errorf("SSE 客户端读取不过来，连接按断开处理")
	}
}

// streamSSE 是两条流共用的连接生命周期：占名额 → 写响应头 → 握手帧 → 抄送帧 → 心跳。
//
// 抽成一个函数而不是两处各写一遍，是为了让「满了回 503」「心跳 15 秒」「先握手再放行」
// 这几条契约语义在两条流上必然一致。attach/detach 由流自己提供：广播流要登记扇出，
// 日志流不需要（它的帧只写给这一个连接）。
func streamSSE(
	w http.ResponseWriter,
	r *http.Request,
	stream *SSEStream,
	attach func(ch chan []byte) bool,
	detach func(ch chan []byte),
	handshake func(conn sseConnWriter) error,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		// 服务器不支持流式写出：这条流的存在意义就是持续推，降级没有意义。
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// 关停中的流不再握手：响应头一旦写出就改不了状态码，所以这条检查必须在写头之前，
	// 也在占名额之前——关停期间不该再有一条连接占住计数。
	select {
	case <-stream.stopCh:
		WriteServiceUnavailable(w, "SSE stream is shutting down")
		return
	default:
	}

	release, ok := stream.Acquire()
	if !ok {
		WriteServiceUnavailable(w, "SSE connection limit reached")
		return
	}
	defer release()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	out := make(chan []byte, 16)
	conn := sseConn{out: out}
	if !attach(out) {
		return
	}
	defer detach(out)

	if handshake != nil {
		if err := handshake(&conn); err != nil {
			stream.logger.Warn("SSE 握手帧写入失败", "stream", stream.name, "error", err)
			return
		}
	}
	flusher.Flush()

	ctx := r.Context()
	keepalive := time.NewTicker(stream.heartbeat)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stream.stopCh:
			return
		case frame, ok := <-out:
			if !ok {
				return
			}
			if _, err := w.Write(frame); err != nil {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			// 心跳写成注释行：它不是事件，放进事件集会让前端多订阅一个契约未声明的
			// 名字。契约那句「keep-alive 事件文本为 "keep-alive"」在这里落成注释文本。
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// sseConnWriter 是握手帧需要的最小写入口。
type sseConnWriter interface {
	writeFrame(event string, data any) error
}

// 两条流的名字：写进 connected 帧载荷，也让 sse-status 的两份读数与契约的两条路由对得上。
const (
	streamEvents = "events"
	streamLogs   = "logs"
)

// NewEventsBroker 建 `/api/v1/events` 的广播流：上限 10、心跳 15 秒都直接取自契约生成物。
//
// 两个构造函数各自读自己的常量，是「两条流互不共享名额」这件事在代码里的唯一证据——
// 合成一个共用上限会让日志页开满 5 个连接时把实时事件流一起饿死（缺陷
// HTTP_LOG_SSE_LIMIT_DOC_DRIFT 的现场）。
func NewEventsBroker(logger *slog.Logger) *SSEBroker {
	return NewSSEBroker(streamEvents,
		httpcontract.SSEMaxConnectionsApiV1Events,
		httpcontract.SSEKeepaliveSecondsApiV1Events,
		logger)
}

// NewLogsStream 建 `/api/v1/logs/stream` 的名额：上限 5、心跳 15 秒同样取自生成物。
//
// 这条流不需要 broker——每帧只写给发起请求的那一条连接，所以只有名额，没有扇出表。
func NewLogsStream(logger *slog.Logger) *SSEStream {
	return NewSSEStream(streamLogs,
		httpcontract.SSEMaxConnectionsApiV1LogsStream,
		httpcontract.SSEKeepaliveSecondsApiV1LogsStream,
		logger)
}
