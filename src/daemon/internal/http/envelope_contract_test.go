// 信封面的行为核对：key 顺序、三字段恒在、业务码 → HTTP 状态码，以及请求体的 415/422
// 两条分支。
//
// 断言一律对着生成物常量（httpcontract.EnvelopeFields / Code* / CodeHTTPStatus）与它的
// JSON 原文，测试里没有第二份数字：契约改码或改状态映射时，这些用例会跟着红，而不是
// 继续给旧形状背书。
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// authedGet 以带认证的 GET 打一条路径。
func authedGet(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(t, s, http.MethodGet, path, nil, "")
}

// authedSend 带上请求体与可选 Content-Type；contentType 为空表示**不带**该头（契约允许
// 的「客户端没说」形态）。
func authedSend(t *testing.T, s *Server, method, path, contentType string, body string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(t, s, method, path, strings.NewReader(body), contentType)
}

func serve(t *testing.T, s *Server, method, path string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Authorization", authHeader())
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	return w
}

// decodeEnvelope 把响应体解析成「字段名 → 原始 JSON」，这样 data 是否为字面 null、
// message 是否为空串都能按原文判，而不是被 Go 的零值悄悄补齐。
func decodeEnvelope(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()

	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("响应体不是 JSON 对象: %v（body=%s）", err, raw)
	}
	return env
}

// assertEnvelopeKeys 核对契约的三条规矩：三个 key 都在、顺序与 EnvelopeFields 一致。
//
// 用字节位置而不是解码后判序，因为 map 丢掉了顺序，而顺序正是契约声明的一项。样例载荷
// 里不含这三个 key 名，所以「第一个出现的位置」就是信封层的那一个。
func assertEnvelopeKeys(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()

	env := decodeEnvelope(t, raw)
	last := -1
	for _, key := range httpcontract.EnvelopeFields {
		fragment := []byte(`"` + key + `":`)
		at := bytes.Index(raw, fragment)
		if at < 0 {
			t.Errorf("信封缺字段 %q（body=%s）", key, raw)
			continue
		}
		if at < last {
			t.Errorf("字段 %q 出现在上一个字段之后：契约顺序 %v，body=%s", key,
				httpcontract.EnvelopeFields, raw)
		}
		last = at
		if _, ok := env[key]; !ok {
			t.Errorf("字段 %q 在原文里有、解码后没有：解码方式有问题", key)
		}
	}
	return env
}

// envelopeCode 取出信封里的业务码。
func envelopeCode(t *testing.T, env map[string]json.RawMessage) int {
	t.Helper()

	raw, ok := env["code"]
	if !ok {
		t.Fatalf("信封没有 code 字段: %v", env)
	}
	var code int
	if err := json.Unmarshal(raw, &code); err != nil {
		t.Fatalf("code 不是数字: %v（raw=%s）", err, raw)
	}
	return code
}

// assertNullData 核对契约的「失败时 data 必须存在且为 null」：键在、值是字面 null。
func assertNullData(t *testing.T, env map[string]json.RawMessage) {
	t.Helper()

	raw, ok := env["data"]
	if !ok {
		t.Errorf("失败信封里没有 data 字段，契约要求它存在且为 null（%v）", env)
		return
	}
	if string(raw) != "null" {
		t.Errorf("失败信封的 data = %s，契约要求 null", raw)
	}
}

// TestSuccessEnvelopeCarriesCode0AndEmptyMessage 核对成功响应：200、三字段齐全且有序、
// code 取契约的 CodeOK、message 是空串而不是被省略。
//
// 载荷取 sse-status：它返回一个对象，既能证明 data 有内容，又不会把 EnvelopeFields 里
// 的任何 key 名带进载荷、把顺序核对变成假阳性。
func TestSuccessEnvelopeCarriesCode0AndEmptyMessage(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := authedGet(t, s, httpcontract.RouteGetApiV1StatsSseStatus[strings.Index(httpcontract.RouteGetApiV1StatsSseStatus, " ")+1:])
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200（body=%s）", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q，期望 application/json", ct)
	}

	env := assertEnvelopeKeys(t, w.Body.Bytes())
	if got := envelopeCode(t, env); got != httpcontract.CodeOK {
		t.Errorf("成功响应的 code = %d，契约 CodeOK = %d", got, httpcontract.CodeOK)
	}
	var message string
	if err := json.Unmarshal(env["message"], &message); err != nil {
		t.Fatalf("message 不是字符串: %v（raw=%s）", err, env["message"])
	}
	if message != "" {
		t.Errorf("成功响应的 message = %q，契约要求空串", message)
	}
	if string(env["data"]) == "null" || len(env["data"]) == 0 {
		t.Errorf("成功响应的 data 是空的: %s", env["data"])
	}
}

// TestFailureEnvelopeCarriesBusinessCode 核对失败响应：HTTP 状态码由码查表得到、code 是
// 契约声明的业务码、data 为 null、message 说明原因。
//
// 40006 是「封禁详情查不到」这条路由唯一的失败码，选它是因为这条路径不会改动任何全局状态。
func TestFailureEnvelopeCarriesBusinessCode(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := authedGet(t, s, "/api/v1/bans/10.9.9.9/detail")
	wantStatus := httpcontract.CodeHTTPStatus[httpcontract.Code40006]
	if w.Code != wantStatus {
		t.Fatalf("状态码 %d，契约给 40006 编的是 %d（body=%s）", w.Code, wantStatus, w.Body)
	}

	env := assertEnvelopeKeys(t, w.Body.Bytes())
	if got := envelopeCode(t, env); got != httpcontract.Code40006 {
		t.Errorf("code = %d，契约这条路由只编了 %d", got, httpcontract.Code40006)
	}
	assertNullData(t, env)

	var message string
	if err := json.Unmarshal(env["message"], &message); err != nil || message == "" {
		t.Errorf("失败响应的 message 为空或不是字符串: %q（err=%v）", message, err)
	}
}

// TestWriteCodeMapsEveryDeclaredCodeToItsStatus 把生成物映射表整个走一遍：每个业务码都
// 按 CodeHTTPStatus 落状态码，且信封里的码与 data 形状一致。
//
// 逐码手写期望值就等于抄了一张表——抄的那份永远不会和原表分叉，因为它就是原表。
func TestWriteCodeMapsEveryDeclaredCodeToItsStatus(t *testing.T) {
	for code, want := range httpcontract.CodeHTTPStatus {
		w := httptest.NewRecorder()
		WriteCode(w, code, "探针")

		if w.Code != want {
			t.Errorf("业务码 %d 落成 %d，映射表说 %d", code, w.Code, want)
		}
		env := assertEnvelopeKeys(t, w.Body.Bytes())
		if got := envelopeCode(t, env); got != code {
			t.Errorf("业务码 %d 写成了 %d", code, got)
		}
		if code != httpcontract.CodeOK {
			assertNullData(t, env)
		}
	}
}

// TestWriteCodeWithUndeclaredCodeFailsLoudly 守住「传了契约里没有的码就显眼地失败」：
// 状态码必须是 500，而不是把陌生的码当成功回 200。
func TestWriteCodeWithUndeclaredCodeFailsLoudly(t *testing.T) {
	const unknown = 41999
	if _, ok := httpcontract.CodeHTTPStatus[unknown]; ok {
		t.Fatalf("生成物里居然有 %d，本用例的前提没了", unknown)
	}

	w := httptest.NewRecorder()
	WriteCode(w, unknown, "契约里没有的数字")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("未声明的码落成 %d，期望 500", w.Code)
	}
	if got := envelopeCode(t, decodeEnvelope(t, w.Body.Bytes())); got != unknown {
		t.Errorf("信封 code = %d，应当原样带上未声明的码好让现场可查", got)
	}
}

// TestNonJSONContentTypeIsEnveloped415 核对 415 的形状：它是 daemon 自己产的信封响应
// （契约 ENVELOPE_ERROR 模型），不是框架默认体。业务码 40008。
func TestNonJSONContentTypeIsEnveloped415(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := authedSend(t, s, http.MethodPost, "/api/v1/bans", "text/plain", `{"ip":"10.0.0.7"}`)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("状态码 %d，期望 415（body=%s）", w.Code, w.Body)
	}
	env := assertEnvelopeKeys(t, w.Body.Bytes())
	if got := envelopeCode(t, env); got != httpcontract.Code40008 {
		t.Errorf("code = %d，契约的媒体类型码是 %d", got, httpcontract.Code40008)
	}
	assertNullData(t, env)

	// 缺席的 Content-Type 不拒：curl 之类客户端常不带该头，body 照样是 JSON。
	ok := authedSend(t, s, http.MethodPost, "/api/v1/bans", "", `{"ip":"10.0.0.8"}`)
	t.Cleanup(func() { _ = removeBanForTest("10.0.0.8") })
	if ok.Code == http.StatusUnsupportedMediaType {
		t.Errorf("不带 Content-Type 的合法 JSON 被判 415，契约只拒「说了别的类型」")
	}
	if ok.Code != http.StatusOK {
		t.Errorf("不带 Content-Type 的合法 JSON 状态码 %d，期望 200（body=%s）",
			ok.Code, ok.Body)
	}
}

// TestMalformedOrOversizedBodyIsEnveloped422 核对 422 + 业务码 40007：体不是合法 JSON、
// 以及体超过 1 MiB 上限，两条都归「请求体解析失败」。
func TestMalformedOrOversizedBodyIsEnveloped422(t *testing.T) {
	s, _ := newTestServer(t, nil)

	cases := map[string]string{
		"残缺 JSON": `{"cidr":`,
		"空体":      "",
		"超限体":     `{"cidr":"` + strings.Repeat("a", maxRequestBodyBytes+1) + `"}`,
	}
	for name, body := range cases {
		w := authedSend(t, s, http.MethodPost, "/api/v1/whitelist", "application/json", body)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s：状态码 %d，期望 422（body=%s）", name, w.Code, truncate(w.Body.Bytes()))
			continue
		}
		env := assertEnvelopeKeys(t, w.Body.Bytes())
		if got := envelopeCode(t, env); got != httpcontract.Code40007 {
			t.Errorf("%s：code = %d，契约的请求体码是 %d", name, got, httpcontract.Code40007)
		}
		assertNullData(t, env)
	}
}

// TestJSONContentTypeVariantsAreAccepted 核对媒体类型判定的两个边界：带参数的
// `application/json; charset=utf-8` 要认，前缀碰巧相同的 `application/jsonml` 不能认。
//
// 只断言「不是 415」：两者都会因为 CIDR 非法落到 400/40003，那条分支自有用例核对。
func TestJSONContentTypeVariantsAreAccepted(t *testing.T) {
	s, _ := newTestServer(t, nil)

	body := `{"cidr":"not-a-prefix"}`
	for _, ct := range []string{"application/json; charset=utf-8", "APPLICATION/JSON", "application/api+json"} {
		w := authedSend(t, s, http.MethodPost, "/api/v1/whitelist", ct, body)
		if w.Code == http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q 被判 415，它是 JSON", ct)
		}
	}
	w := authedSend(t, s, http.MethodPost, "/api/v1/whitelist", "application/jsonml", body)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("application/jsonml 状态码 %d，期望 415：前缀相同不等于同一种媒体类型", w.Code)
	}
}

// TestBusinessCodesPerRoute 逐条核对「契约给这条路由编了哪个码，失败时就出哪个码」。
//
// 每条都选不会改动全局状态的路径：重复添加与移除都落在「非法输入」或「不在表中」分支上，
// 因此用例之间不需要清理顺序。
func TestBusinessCodesPerRoute(t *testing.T) {
	s, _ := newTestServer(t, nil)

	cases := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantCode    int
	}{
		{"解封非法 IP", http.MethodDelete, "/api/v1/bans/not-an-ip", "", "", httpcontract.Code40002},
		{"解封不在表中", http.MethodDelete, "/api/v1/bans/10.9.9.8", "", "", httpcontract.Code40002},
		{"批量封禁列表为空", http.MethodPost, "/api/v1/bans/batch", "application/json", `{"ips":[]}`, httpcontract.Code40005},
		{"添加白名单 CIDR 非法", http.MethodPost, "/api/v1/whitelist", "application/json", `{"cidr":"10.0.0.0/99"}`, httpcontract.Code40003},
		{"移除不在表中的网段", http.MethodDelete, "/api/v1/whitelist/203.0.113.0%2F24", "", "", httpcontract.Code40004},
		{"jail 不存在", http.MethodPut, "/api/v1/jails/no-such-jail", "application/json", `{"enabled":true}`, httpcontract.Code404},
		{"日志文件未配置", http.MethodGet, "/api/v1/logs", "", "", httpcontract.Code50003},
	}
	for _, c := range cases {
		w := authedSend(t, s, c.method, c.path, c.contentType, c.body)
		wantStatus := httpcontract.CodeHTTPStatus[c.wantCode]
		if w.Code != wantStatus {
			t.Errorf("%s：%d，期望 %d（body=%s）", c.name, w.Code, wantStatus, truncate(w.Body.Bytes()))
			continue
		}
		env := assertEnvelopeKeys(t, w.Body.Bytes())
		if got := envelopeCode(t, env); got != c.wantCode {
			t.Errorf("%s：code = %d，契约给这条路由编的是 %d", c.name, got, c.wantCode)
		}
		assertNullData(t, env)
	}
}

// TestBatchBanOverCap 核对「超过 100 条」这条真实边界：它在任何封禁落下之前就被拒，
// 所以失败不会留下半批状态。
func TestBatchBanOverCap(t *testing.T) {
	s, _ := newTestServer(t, nil)

	ips := make([]string, 0, batchBanMaxIPs+1)
	for i := 0; i <= batchBanMaxIPs; i++ {
		ips = append(ips, fmt.Sprintf("10.20.%d.%d", i/256, i%256))
	}
	body := `{"ips":[`
	for i, ip := range ips {
		if i > 0 {
			body += ","
		}
		body += `"` + ip + `"`
	}
	body += `],"duration":60}`

	w := authedSend(t, s, http.MethodPost, "/api/v1/bans/batch", "application/json", body)
	env := assertEnvelopeKeys(t, w.Body.Bytes())
	if got := envelopeCode(t, env); got != httpcontract.Code40005 {
		t.Fatalf("code = %d，期望 %d（body=%s）", got, httpcontract.Code40005, w.Body)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("状态码 %d，期望 400", w.Code)
	}
	for _, ip := range ips {
		if _, ok := bans.GlobalCache().Get(ip); ok {
			t.Errorf("超批量请求把 %s 落进了封禁表：契约的 40005 是整批拒掉，不是部分生效", ip)
			_ = removeBanForTest(ip)
		}
	}
}

// removeBanForTest 清掉用例往全局封禁镜像里塞的条目。镜像是进程级单例，留一条会让后面
// 的「重复封禁」用例拿到意料之外的状态。
func removeBanForTest(ip string) bool { return bans.GlobalCache().Remove(ip) }

// truncate 把过长的响应体压短，失败信息里 1 MiB 的体不该整段打出来。
func truncate(raw []byte) string {
	const keep = 200
	if len(raw) <= keep {
		return string(raw)
	}
	return string(raw[:keep]) + fmt.Sprintf("…（共 %d 字节）", len(raw))
}
