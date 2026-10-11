// P4 契约面的行为核对：路由注册形状、认证组、框架默认状态码、两条 SSE 流各自的名额。
//
// 这里断言的每一条都来自 `contract/http.fwidl` 的声明，且一律经生成物
// `internal/httpcontract` 取路径与常量——测试里不复制第二份路径字符串，否则改了契约
// 而测试仍绿，等于测试在给旧形状背书。
package http

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

const (
	testUser = "panel"
	testPass = "s3cret"
)

// notYetRegistered 是契约里尚未接线的路由。
//
// 列在这里而不是「测试时跳过没注册的」：注册了却没从本表删除同样失败，这张表因此
// 不会悄悄变成过期清单。逐条对应 contract/http_gap_baseline.txt 的 route-missing。
//
// P5-b 接线了内核快照那一组（stats 总览、rates/current、rates/windows、heatmap、协议分布
// 与 Top-N、anomalies），P5-c 接线了历史库分析面剩下的三条（ban-effectiveness、
// ban-duration-histogram、attack-geo）——本表因此清空，契约里每条路由都有真实数据的实现。
// 保留这张表而不是删掉它：下次契约新增路由时，它是「新增即失败」的落点（新增的未接线
// 路由会同时打缺 route-missing 基线与本表）。
var notYetRegistered = map[string]bool{}

// paramSamples 给路径参数槽填入合法的样例值。
//
// CIDR 用百分号编码的 `/`：Go 的 ServeMux 按**转义后**的路径分段，`10.0.0.0/8` 原样写
// 进路径会被当成两段而 404（前端 endpoints.ts 的 encodeURIComponent 就是为此）。
var paramSamples = map[string]string{
	"ip":   "10.0.0.1",
	"cidr": "10.0.0.0%2F8",
	"name": "sshd",
}

// wildcardSlot 匹配生成物里的多段通配槽 `{path...}`（契约写法是 `*path`）。
var wildcardSlot = regexp.MustCompile(`\{\w+\.\.\.\}`)

// concretePath 把生成物里的路径（含 `{ip}` 槽与 `{path...}` 通配）换成可请求的具体路径。
func concretePath(t *testing.T, pattern string) string {
	t.Helper()
	path := pattern[strings.Index(pattern, " ")+1:]
	// 多段通配：契约写 `*path`，生成物写 `{path...}`（带方法前缀时前者只是字面量，
	// ServeMux 不当通配）。这里给一个 testFS 里真存在的资源段，形状核对不需要它存在。
	path = wildcardSlot.ReplaceAllString(path, "assets/app.js")
	for name, sample := range paramSamples {
		path = strings.ReplaceAll(path, "{"+name+"}", sample)
	}
	if strings.ContainsAny(path, "{}*") {
		t.Fatalf("路径 %q 还有没被样例覆盖的参数槽或通配", path)
	}
	return path
}

// discardLogger 让测试里的日志不淹没输出，同时保持 handler 里的 logger 非 nil。
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestServer 装一个不监听端口的 Server：路由用生产注册函数，依赖给最小可用集。
//
// 直接用 Server.mux 打请求，不起真端口——认证、方法匹配、404/405 这些都是 mux 与
// RequireAuth 的语义，与传输层无关；只有需要真流的 SSE 用例才起 httptest.Server。
func newTestServer(t *testing.T, mutate func(*APIConfig)) (*Server, *APIHandlers) {
	t.Helper()

	shell := fs.FS(mapFS{
		"index.html":           []byte("<!doctype html><title>panel</title>"),
		"sw.js":                []byte("// service worker"),
		"assets/app.js":        []byte("console.log(1)"),
		"manifest.webmanifest": []byte("{}"),
	})

	s := &Server{mux: http.NewServeMux(), logger: discardLogger()}
	cfg := APIConfig{
		Server:         s,
		SSE:            NewEventsBroker(s.logger),
		LogStream:      NewLogsStream(s.logger),
		Metrics:        NewMetrics(),
		Username:       testUser,
		Password:       testPass,
		JailController: fakeJails{},
		GetKernelSnapshot: func() telemetry.Snapshot {
			return telemetry.Snapshot{Link: telemetry.Link{Lease: telemetry.LeaseNone}}
		},
		KmodPresent: func() bool { return false },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	api := NewAPIHandlers(cfg)
	s.RegisterRoutes(api)
	s.RegisterStaticFiles(shell)
	t.Cleanup(cfg.SSE.Stop)
	return s, api
}

// mapFS 是最小内存文件系统：静态面只需要「有/没有这个 key」，不需要真磁盘。
type mapFS map[string][]byte

func (m mapFS) Open(name string) (fs.File, error) {
	data, ok := m[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &mapFile{data: data, name: name}, nil
}

type mapFile struct {
	data []byte
	name string
	off  int
}

func (f *mapFile) Stat() (fs.FileInfo, error) {
	return mapFileInfo{name: f.name, size: len(f.data)}, nil
}
func (f *mapFile) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}
func (f *mapFile) Close() error { return nil }

type mapFileInfo struct {
	name string
	size int
}

func (i mapFileInfo) Name() string       { return filepath.Base(i.name) }
func (i mapFileInfo) Size() int64        { return int64(i.size) }
func (i mapFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i mapFileInfo) ModTime() time.Time { return time.Time{} }
func (i mapFileInfo) IsDir() bool        { return false }
func (i mapFileInfo) Sys() any           { return nil }

// fakeJails 实现 JailController：本文件只核对路由与协议形状，开关落到哪里不重要。
type fakeJails struct{}

func (fakeJails) SetEnabled(string, bool) {}

func authHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(testUser+":"+testPass))
}

// queryToken 是 SSE 用的凭据来源：浏览器不能给 EventSource 设请求头。
func queryToken() string {
	return base64.StdEncoding.EncodeToString([]byte(testUser + ":" + testPass))
}

// TestContractRoutesAreRegisteredWithMethod 要求每条已接线的契约路由都以**带方法**的
// 模式注册：方法前缀是契约要的 405 由框架产生的前提，也保证注册串与生成物逐字相等。
//
// 判据是「mux 命中的模式逐字等于注册串」，不是「命中了某个 handler」：SPA 外壳注册在
// `GET /` 上，是一棵兜住所有路径的子树，未接线的分析端点同样能被它接住并回一张壳页面。
// 只看「有没有匹配」会把 15 条缺失路由全读成已注册。
func TestContractRoutesAreRegisteredWithMethod(t *testing.T) {
	s, _ := newTestServer(t, nil)

	missing := 0
	for _, route := range httpcontract.Routes {
		req := httptest.NewRequest(route.Method, concretePath(t, route.Pattern), nil)
		if route.Auth == httpcontract.AuthRequired {
			req.Header.Set("Authorization", authHeader())
		}
		_, pattern := s.mux.Handler(req)
		own := pattern == route.Pattern

		switch {
		case own && notYetRegistered[route.Pattern]:
			t.Errorf("%s 已注册但仍列在 notYetRegistered 里，请把它从该表删除", route.Pattern)
		case !own && !notYetRegistered[route.Pattern]:
			missing++
			t.Errorf("%s 没有以自己的模式注册（mux 命中 %q）", route.Pattern, pattern)
		}
	}
	if missing == 0 && len(httpcontract.Routes) == 0 {
		t.Fatal("生成物路由表为空，本用例没有核对任何东西")
	}
}

// TestUndeclaredMethodFallsToFramework405 核对「模式带方法」的回报：未声明的动词不进
// handler，由 ServeMux 回 405——契约的 FRAMEWORK_DEFAULT 错误模型就建立在这点上。
func TestUndeclaredMethodFallsToFramework405(t *testing.T) {
	s, _ := newTestServer(t, nil)

	cases := []struct{ method, pattern string }{
		{http.MethodDelete, httpcontract.RouteGetApiV1Bans},
		{http.MethodPatch, httpcontract.RouteGetApiV1Config},
		{http.MethodPost, httpcontract.RouteGetApiV1StatsSseStatus},
	}
	for _, c := range cases {
		path := c.pattern[strings.Index(c.pattern, " ")+1:]
		req := httptest.NewRequest(c.method, path, nil)
		req.Header.Set("Authorization", authHeader())
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s 期望 405，实际 %d", c.method, path, w.Code)
		}
	}
}

// TestRequiredGroupRejectsAnonymous 核对认证组的三件事：401、纯文本原文、不发
// WWW-Authenticate（那个头会让浏览器弹原生对话框并挂起 fetch）。
func TestRequiredGroupRejectsAnonymous(t *testing.T) {
	s, _ := newTestServer(t, nil)

	for _, pattern := range []string{
		httpcontract.RouteGetApiV1Bans,
		httpcontract.RouteGetApiV1Events,
		httpcontract.RouteGetMetrics,
		httpcontract.RouteGetApiV1Logs,
		httpcontract.RouteGetApiV1Whitelist,
	} {
		path := pattern[strings.Index(pattern, " ")+1:]
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))

		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s 匿名请求期望 401，实际 %d", pattern, w.Code)
		}
		if got := w.Body.String(); got != authUnauthorizedBody {
			t.Errorf("%s 的 401 响应体 = %q，契约要 %q", pattern, got, authUnauthorizedBody)
		}
		if w.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("%s 发了 WWW-Authenticate，契约声明有意不发", pattern)
		}
	}
}

// TestQueryTokenAuthenticatesSSE 核对 EventSource 那条凭据通道：同一个 Basic 凭据，
// 经 ?access_token 携带也必须放行（浏览器给不了请求头）。
func TestQueryTokenAuthenticatesSSE(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		httpcontract.RouteGetApiV1Bans[strings.Index(httpcontract.RouteGetApiV1Bans, " ")+1:]+
			"?"+httpcontract.AuthTokenQuery+"="+queryToken(), nil)
	s.mux.ServeHTTP(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("带 access_token 的请求被判 401，query 凭据通道没接上")
	}

	// 半配置凭据按失败处理：只填用户名时任何人都进不来。
	half := &Server{mux: http.NewServeMux(), logger: discardLogger()}
	api := NewAPIHandlers(APIConfig{Server: half, Username: testUser, Password: ""})
	half.HandleFunc(httpcontract.RouteGetApiV1Bans,
		RequireAuth(api.username, api.password, api.lockout, api.ListBans))
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/bans", nil)
	req2.SetBasicAuth(testUser, "")
	half.mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("半配置凭据期望 401，实际 %d", w2.Code)
	}
}

// TestRootRedirectKeepsQuery 核对 303 重定向保留 query：/?access_token=… 是外部跳转
// 与登录页的唯一凭据入口，丢掉 query 等于丢掉凭据。
func TestRootRedirectKeepsQuery(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/?"+httpcontract.AuthTokenQuery+"="+queryToken(), nil))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("GET / 期望 303，实际 %d", w.Code)
	}
	want := "/dashboard?" + httpcontract.AuthTokenQuery + "=" + queryToken()
	if got := w.Header().Get("Location"); got != want {
		t.Errorf("Location = %q，期望 %q", got, want)
	}
}

// TestMissingStaticAssetIsPlainText404 核对静态面的缺失资源：纯文本 404，不返回 SPA 壳。
//
// 把壳发给一个不存在的 .js，浏览器会把它当脚本解析并在控制台报语法错误——真正的资源
// 缺失就被藏起来了。
func TestMissingStaticAssetIsPlainText404(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/static/nope.js", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("缺失资源期望 404，实际 %d", w.Code)
	}
	if got := w.Body.String(); got != staticNotFoundBody {
		t.Errorf("404 响应体 = %q，契约要 %q", got, staticNotFoundBody)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("404 的 Content-Type = %q，期望纯文本", ct)
	}
}

// TestHealthIsRawSnapshotWithoutEnvelope 核对探针的两条偏离：响应不套信封（状态码即
// 语义），未就绪时 503 但载荷仍是同一份 RuntimeSnapshot。
func TestHealthIsRawSnapshotWithoutEnvelope(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("未持有租约时 /health 期望 503，实际 %d", w.Code)
	}

	var snap map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("响应体不是裸 JSON: %v（body=%s）", err, w.Body)
	}
	for _, key := range []string{"status", "netlink_ready", "kmod_proc_present",
		"ban_cache_initialized", "ban_history_initialized", "active_bans",
		"lease_state", "lease_losses"} {
		if _, ok := snap[key]; !ok {
			t.Errorf("RuntimeSnapshot 缺字段 %q（实际 key: %v）", key, keysOf(snap))
		}
	}
	for _, envelopeKey := range []string{"success", "code", "message", "data"} {
		if _, ok := snap[envelopeKey]; ok {
			t.Errorf("探针响应被套进了信封（出现 %q），契约要求裸写", envelopeKey)
		}
	}
	if snap["lease_state"] != string(telemetry.LeaseNone) {
		t.Errorf("lease_state = %v，链路未注册时应为 %q", snap["lease_state"], telemetry.LeaseNone)
	}
	if snap["status"] != statusDegraded {
		t.Errorf("status = %v，未就绪时应为 %q", snap["status"], statusDegraded)
	}
}

// TestHealthzIsTheSameHandler 核对 /healthz 与 /health 同函数：探针客户端不需要猜哪
// 条路径更权威。
func TestHealthzIsTheSameHandler(t *testing.T) {
	s, _ := newTestServer(t, nil)

	a := httptest.NewRecorder()
	b := httptest.NewRecorder()
	s.mux.ServeHTTP(a, httptest.NewRequest(http.MethodGet, "/health", nil))
	s.mux.ServeHTTP(b, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if a.Code != b.Code || a.Body.String() != b.Body.String() {
		t.Errorf("/healthz 与 /health 不同形：%d/%d 体相等=%v",
			a.Code, b.Code, a.Body.String() == b.Body.String())
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestStreamCapsAreIndependent 是缺陷 HTTP_LOG_SSE_LIMIT_DOC_DRIFT 的行为断言：两条流
// 各按契约上限计数，一条占满不影响另一条。
func TestStreamCapsAreIndependent(t *testing.T) {
	logger := discardLogger()
	events := NewEventsBroker(logger)
	defer events.Stop()
	logs := NewLogsStream(logger)

	if events.Max() != httpcontract.SSEMaxConnectionsApiV1Events {
		t.Errorf("事件流上限 %d，契约 %d", events.Max(), httpcontract.SSEMaxConnectionsApiV1Events)
	}
	if logs.Max() != httpcontract.SSEMaxConnectionsApiV1LogsStream {
		t.Errorf("日志流上限 %d，契约 %d", logs.Max(), httpcontract.SSEMaxConnectionsApiV1LogsStream)
	}
	if events.Max() == logs.Max() {
		t.Fatal("两条流上限相同，本用例无法证明它们各自独立")
	}

	release := make([]func(), 0, logs.Max())
	for i := 0; i < logs.Max(); i++ {
		rel, ok := logs.Acquire()
		if !ok {
			t.Fatalf("第 %d 条日志流连接被拒（上限 %d）", i+1, logs.Max())
		}
		release = append(release, rel)
	}
	if _, ok := logs.Acquire(); ok {
		t.Errorf("日志流占到第 %d 条仍放行，契约上限是 %d", logs.Max()+1, logs.Max())
	}
	if _, ok := events.Acquire(); !ok {
		t.Error("事件流在日志流占满后拿不到名额：两条流共用了账本")
	}
	if !logs.AtLimit() {
		t.Error("日志流已占满却没报 AtLimit")
	}
	release[0]()
	if _, ok := logs.Acquire(); !ok {
		t.Error("释放一个名额后仍拒绝新连接")
	}
	for _, rel := range release {
		rel()
	}
}

// TestAcquireRejectsNonPositiveMax 守住「非法上限退化成 1 而不是无限」。
func TestAcquireRejectsNonPositiveMax(t *testing.T) {
	s := NewSSEStream("probe", 0, 0, discardLogger())
	if s.Max() != 1 {
		t.Fatalf("max=0 应被抬到 1，实际 %d", s.Max())
	}
	if _, ok := s.Acquire(); !ok {
		t.Fatal("第一条连接应放行")
	}
	if _, ok := s.Acquire(); ok {
		t.Error("第二条连接不该放行")
	}
}

// TestSSEStatusReportsTwoStreams 是缺陷 HTTP_SSE_STATUS_INCOMPLETE 的行为断言：
// 两条流各自的 current/max/limit_reached。
func TestSSEStatusReportsTwoStreams(t *testing.T) {
	s, api := newTestServer(t, nil)
	rel, ok := api.logStream.Acquire()
	if !ok {
		t.Fatal("测试里拿不到日志流名额")
	}
	defer rel()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/sse-status", nil)
	req.Header.Set("Authorization", authHeader())
	s.mux.ServeHTTP(w, req)

	var body map[string]map[string]any
	if err := json.Unmarshal(unwrapData(t, w.Body.Bytes()), &body); err != nil {
		t.Fatalf("sse-status 载荷不是两份流状态: %v（body=%s）", err, w.Body)
	}
	for _, name := range []string{"events", "logs"} {
		stream, ok := body[name]
		if !ok {
			t.Fatalf("载荷缺 %q 一份", name)
		}
		if stream["current_connections"] == nil || stream["max_connections"] == nil {
			t.Errorf("%q 缺 current/max 字段: %v", name, stream)
		}
	}
	if got := body["logs"]["current_connections"]; got != float64(1) {
		t.Errorf("logs.current_connections = %v，占了一个名额应为 1", got)
	}
	if got := body["logs"]["max_connections"]; got != float64(httpcontract.SSEMaxConnectionsApiV1LogsStream) {
		t.Errorf("logs.max_connections = %v，契约 %d", got, httpcontract.SSEMaxConnectionsApiV1LogsStream)
	}
	if got := body["events"]["max_connections"]; got != float64(httpcontract.SSEMaxConnectionsApiV1Events) {
		t.Errorf("events.max_connections = %v，契约 %d", got, httpcontract.SSEMaxConnectionsApiV1Events)
	}
}

// unwrapData 从 ApiResponse 信封里取出 data；探针类端点没有信封时原样返回。
func unwrapData(t *testing.T, raw []byte) []byte {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("响应不是 JSON: %v", err)
	}
	if data, ok := envelope["data"]; ok {
		out, err := json.Marshal(data)
		if err != nil {
			t.Fatalf("重编码 data 失败: %v", err)
		}
		return out
	}
	return raw
}

// TestEventsStreamHandshakeAndDomainEvents 用真连接核对 `/api/v1/events` 的三件事：
// query 凭据放行、connected 握手帧带本流上限、Publish 的帧写成 `event: <域名>`。
func TestEventsStreamHandshakeAndDomainEvents(t *testing.T) {
	s, api := newTestServer(t, nil)
	srv := httptest.NewServer(s.mux)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/api/v1/events?" + httpcontract.AuthTokenQuery + "=" + queryToken())
	if err != nil {
		t.Fatalf("请求事件流失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("事件流状态码 %d，期望 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q", ct)
	}

	a := newSSEAccumulator(resp.Body)
	text := a.waitFor(t, "event: connected", 3*time.Second)
	want := fmt.Sprintf(`"max_connections":%d`, httpcontract.SSEMaxConnectionsApiV1Events)
	if !strings.Contains(text, want) {
		t.Errorf("connected 帧没带本流上限 %s，读到:\n%s", want, text)
	}

	// 握手之后才推域事件：早于服务端 attach 的发布进不到这条连接。
	api.sse.Publish("bans", []map[string]any{{"ip": "10.0.0.1"}})
	text = a.waitFor(t, "event: bans", 3*time.Second)
	if !strings.Contains(text, `"ip":"10.0.0.1"`) {
		t.Errorf("bans 帧的 data 不是发布的镜像，读到:\n%s", text)
	}
}

// TestLogsStreamSendsRawLine 核对日志流的帧载荷是**文件里的原始行**：那一行本身通常
// 已经是一条 JSON 记录，再包一层引号会让前端 Logs.tsx 的结构化视图整页退化成原文。
func TestLogsStreamSendsRawLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}
	defer f.Close()

	s, api := newTestServer(t, func(cfg *APIConfig) {
		cfg.LogFilePath = func() string { return path }
	})
	srv := httptest.NewServer(s.mux)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/api/v1/logs/stream?" +
		httpcontract.AuthTokenQuery + "=" + queryToken())
	if err != nil {
		t.Fatalf("请求日志流失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("日志流状态码 %d，期望 200", resp.StatusCode)
	}

	a := newSSEAccumulator(resp.Body)
	// 握手帧先到才说明服务端已 seek 到末尾，这一行是「之后写进来的」。
	a.waitFor(t, "event: connected", 3*time.Second)

	line := `{"level":"info","msg":"契约测试行"}`
	if _, err := fmt.Fprintln(f, line); err != nil {
		t.Fatalf("写日志失败: %v", err)
	}

	text := a.waitFor(t, "event: log", 5*time.Second)
	if !strings.Contains(text, "data: "+line+"\n") {
		t.Errorf("log 帧的 data 不是原始行，读到:\n%s", text)
	}
	if strings.Contains(text, `data: "`+line) {
		t.Errorf("log 帧把原始行又 JSON 包了一层")
	}
	if api.logStream.Active() != 1 {
		t.Errorf("流建立后 logStream.Active() = %d，期望 1", api.logStream.Active())
	}
}

// TestLogsStreamRejectsOverCap 核对日志流满额回 503（而不是 events 的 10 才拒）。
func TestLogsStreamRejectsOverCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(path, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("建日志文件失败: %v", err)
	}

	s, api := newTestServer(t, func(cfg *APIConfig) {
		cfg.LogFilePath = func() string { return path }
	})
	srv := httptest.NewServer(s.mux)
	defer srv.Close()

	url := srv.URL + "/api/v1/logs/stream?" + httpcontract.AuthTokenQuery + "=" + queryToken()
	for i := 0; i < api.logStream.Max(); i++ {
		resp, err := srv.Client().Get(url)
		if err != nil {
			t.Fatalf("第 %d 条连接失败: %v", i+1, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 条连接期望 200，实际 %d", i+1, resp.StatusCode)
		}
	}
	resp, err := srv.Client().Get(url)
	if err != nil {
		t.Fatalf("超额连接请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("占满 %d 条后的连接期望 503，实际 %d", api.logStream.Max(), resp.StatusCode)
	}
}

// sseAccumulator 持续读一条 SSE 流并累积字节，让多次断言共享同一份已读内容。
//
// 不能对同一个 body 起两个读取者，也不能「一次读到底」——流是长连接，读到超时才会停。
// 一个后台 goroutine 独占读取并把增量塞进 channel，等待方（只有测试 goroutine）从
// channel 取增量并累积，因此这里不需要锁。
type sseAccumulator struct {
	text  string
	chunk chan readChunk
}

type readChunk struct {
	text string
	err  error
}

func newSSEAccumulator(r io.Reader) *sseAccumulator {
	a := &sseAccumulator{chunk: make(chan readChunk, 16)}
	go func() {
		buf := make([]byte, 512)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				a.chunk <- readChunk{text: string(buf[:n])}
			}
			if err != nil {
				a.chunk <- readChunk{err: err}
				return
			}
		}
	}()
	return a
}

// waitFor 等到累积文本里出现 want，超时或流提前结束都带着已读内容失败。
func (a *sseAccumulator) waitFor(t *testing.T, want string, timeout time.Duration) string {
	t.Helper()

	deadline := time.After(timeout)
	for {
		if strings.Contains(a.text, want) {
			return a.text
		}
		select {
		case c := <-a.chunk:
			a.text += c.text
			if c.err != nil {
				t.Fatalf("流提前结束（want=%q）: %v\n已读到:\n%s", want, c.err, a.text)
			}
		case <-deadline:
			t.Fatalf("等待 %q 超时\n已读到:\n%s", want, a.text)
		}
	}
}
