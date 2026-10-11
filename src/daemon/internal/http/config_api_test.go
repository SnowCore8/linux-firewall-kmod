package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// recordingKernelConfig 是 KernelConfig 的假实现：把每次下发的载荷按值存下来，
// rejected/err 用来扮演内核的两种回答（逐位拒绝 / 通道发不出去）。
type recordingKernelConfig struct {
	changes  []contract.SetConfig
	rejected contract.ConfigFlags
	err      error
}

func (r *recordingKernelConfig) ApplyConfig(change *contract.SetConfig) (contract.ConfigFlags, error) {
	if change != nil {
		// 存副本：调用方可以复用同一个变量，测试要断言的是「发出去的那一刻的内容」。
		r.changes = append(r.changes, *change)
	}
	return r.rejected, r.err
}

// successData 取成功信封里的 data 对象。
//
// 契约的信封在成功时 message 是空串、内容全在 data 里，所以断言一律从 data 读——拿
// envelopeMessage 会永远拿到 ""，看着像「响应没写 message」。
func successData(t *testing.T, env map[string]json.RawMessage) map[string]any {
	t.Helper()

	var data map[string]any
	if err := json.Unmarshal(env["data"], &data); err != nil {
		t.Fatalf("data 不是对象: %v（raw=%s）", err, env["data"])
	}
	return data
}

// dataNumber 取 data 里的一个数值字段，按契约的整数语义折成 uint64。
func dataNumber(t *testing.T, data map[string]any, key string) uint64 {
	t.Helper()

	v, ok := data[key]
	if !ok {
		t.Fatalf("data 里没有 %q: %v", key, data)
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("data[%q] 不是数值: %v", key, v)
	}
	return uint64(f)
}

// putConfig 带上合法 Content-Type 打一次 PUT /api/v1/config，返回解析后的信封与 HTTP 状态。
func putConfig(t *testing.T, s *Server, body string) (map[string]json.RawMessage, int) {
	t.Helper()

	w := authedSend(t, s, http.MethodPut, "/api/v1/config", "application/json", body)
	return decodeEnvelope(t, w.Body.Bytes()), w.Code
}

// configAPIFixture 把 PUT/GET /config 接到一个临时配置文件与一个假下发出口上。
//
// 预置内容里有**一个 jail**：PUT 会把 webui 段并回这份文件并按加载口径复核，而加载口径
// 要求 jail_count 落在 1..32（jail.Validate），没有 jail 的配置文件过不了复核。预置内容也
// 让「拒绝写入=文件保持原样」有原样可谈。
func configAPIFixture(t *testing.T, mutate func(*APIConfig)) (*Server, string, *config.Config, *recordingKernelConfig) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	original := "defaults:\n  max_retries: 3\n  findtime: 600\n  ban_time: 600\n" +
		"jails:\n  sshd:\n    enabled: true\n    log_files:\n      - /var/log/auth.log\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("预置配置文件失败: %v", err)
	}

	rec := &recordingKernelConfig{}
	live := config.Default()
	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.GetConfigPath = func() string { return path }
		cfg.GetCurrentConfig = func() *config.Config { return &live }
		cfg.KernelConfig = rec
		if mutate != nil {
			mutate(cfg)
		}
	})
	return s, path, &live, rec
}

// TestUpdateConfigAppliesPartialWebuiAndDeliversKernel 是这条写路径的主干：契约的局部更新
// 语义——只提交的字段被改，未提交的保持后端现值——同时新值落盘、并按投影表下发一次内核。
func TestUpdateConfigAppliesPartialWebuiAndDeliversKernel(t *testing.T) {
	s, path, live, rec := configAPIFixture(t, nil)

	// 只提交两个字段；rate_critical_pps 与 clear_logs_at 都没提交。
	env, status := putConfig(t, s, `{"rate_warning_pps":60000,"rate_warning_syn":2000}`)
	if status != http.StatusOK || envelopeCode(t, env) != httpcontract.CodeOK {
		t.Fatalf("PUT /config status=%d code=%d body=%s", status, envelopeCode(t, env), env["message"])
	}

	data := successData(t, env)
	if got := dataNumber(t, data, "rate_warning_pps"); got != 60000 {
		t.Errorf("响应 rate_warning_pps = %d，期望 60000", got)
	}
	if got := dataNumber(t, data, "rate_warning_syn"); got != 2000 {
		t.Errorf("响应 rate_warning_syn = %d，期望 2000", got)
	}
	// 未提交的字段保持后端现值（DefaultWebuiConfig 的 200000 / 5000），不是被清零。
	if got := dataNumber(t, data, "rate_critical_pps"); got != config.DefaultWebuiConfig().RateCriticalPPS {
		t.Errorf("响应 rate_critical_pps = %d，未提交的字段应保持现值 %d", got, config.DefaultWebuiConfig().RateCriticalPPS)
	}
	if v, ok := data["clear_logs_at"]; !ok || v != nil {
		t.Errorf("clear_logs_at = %v，未提交应为 null", v)
	}

	// 活配置被就地更新（后续 GET /config 读的就是这一份）。
	if live.Webui.RateWarningPPS != 60000 {
		t.Errorf("活配置 RateWarningPPS = %d，期望 60000", live.Webui.RateWarningPPS)
	}

	// 新值落盘，且其它段落原样保留。
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("配置文件没写成功: %v", err)
	}
	if !strings.Contains(string(written), "rate_warning_pps: 60000") {
		t.Errorf("写入内容里没有 rate_warning_pps: 60000:\n%s", written)
	}
	if !strings.Contains(string(written), "sshd") {
		t.Errorf("写入内容丢掉了 jails 段:\n%s", written)
	}

	if len(rec.changes) != 1 {
		t.Fatalf("下发记录 = %d 条，期望恰好一条", len(rec.changes))
	}
}

// TestUpdateConfigClearLogsAtPersistsAndReloads 定住 clear_logs_at 与其余 18 个字段走同一条
// 落盘路径：它随 webui 段写入配置文件，因此热重载能原值读回——这正是前端 Settings/Logs 页
// 「持久化该过滤起点」「重启后保留」所承诺的行为。
//
// 这条分支也是前端日志页的实际调用面（updateConfig({ clear_logs_at }))。
func TestUpdateConfigClearLogsAtPersistsAndReloads(t *testing.T) {
	s, path, live, rec := configAPIFixture(t, nil)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取预置配置失败: %v", err)
	}

	const ts = "2026-10-11T00:00:00"
	env, status := putConfig(t, s, `{"clear_logs_at":"`+ts+`"}`)
	if status != http.StatusOK || envelopeCode(t, env) != httpcontract.CodeOK {
		t.Fatalf("PUT /config status=%d code=%d body=%s", status, envelopeCode(t, env), env["message"])
	}

	data := successData(t, env)
	if v, ok := data["clear_logs_at"]; !ok || v != ts {
		t.Errorf("响应 clear_logs_at = %v，期望 %q", v, ts)
	}
	if live.Webui.ClearLogsAt != ts {
		t.Errorf("活配置 ClearLogsAt = %q，期望 %q", live.Webui.ClearLogsAt, ts)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("重读配置文件失败: %v", err)
	}
	if string(after) == string(before) {
		t.Errorf("clear_logs_at 应当写入文件，但文件未变：\n%s", after)
	}
	// 关键断言：写出的文件按加载口径能解析回同一个值——否则重载器会把过滤起点丢掉，
	// 前端的「持久化」承诺就是假的。
	var reloaded config.Config
	if err := config.ParseConfig(string(after), &reloaded); err != nil {
		t.Fatalf("写出的文件无法按加载口径解析: %v", err)
	}
	if reloaded.Webui.ClearLogsAt != ts {
		t.Errorf("重载后 ClearLogsAt = %q，期望 %q", reloaded.Webui.ClearLogsAt, ts)
	}
	// 与其余落盘字段同口径：这次更新顺带按投影表下发一次内核（幂等）。
	if len(rec.changes) != 1 {
		t.Errorf("clear_logs_at 落盘后应下发一次内核，实际 %d 条：%+v", len(rec.changes), rec.changes)
	}
}

// TestUpdateConfigRejectsInvalidValues 是写盘前校验的守卫：越界取值回 40004，文件保持原样、
// 不下发内核。校验看的是**合并后的最终状态**，所以「只改一个字段但破坏 warning<critical
// 关系」也被抓住。
func TestUpdateConfigRejectsInvalidValues(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"pps 告警不低于临界", `{"rate_warning_pps":300000}`, "rate_warning_pps"},
		{"syn 告警不低于临界", `{"rate_warning_syn":9999}`, "rate_warning_syn"},
		{"阈值不能为 0", `{"max_ban_entries":0}`, "max_ban_entries"},
		{"sse 间隔上界", `{"sse_push_interval":61}`, "sse_push_interval"},
		{"sse 间隔下界", `{"sse_push_interval":0}`, "sse_push_interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, path, _, rec := configAPIFixture(t, nil)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("读取预置配置失败: %v", err)
			}

			env, status := putConfig(t, s, tc.body)
			if want := httpcontract.CodeHTTPStatus[httpcontract.Code40004]; status != want {
				t.Errorf("HTTP 状态 = %d，契约 40004 对应 %d", status, want)
			}
			if code := envelopeCode(t, env); code != httpcontract.Code40004 {
				t.Errorf("code = %d，期望 40004", code)
			}
			if msg := envelopeMessage(t, env); !strings.Contains(msg, tc.want) {
				t.Errorf("message 没点名越界字段 %q: %q", tc.want, msg)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("重读配置文件失败: %v", err)
			}
			if string(after) != string(before) {
				t.Errorf("校验失败仍然改了文件：\n%s", after)
			}
			if len(rec.changes) != 0 {
				t.Errorf("校验失败却下发了内核：%+v", rec.changes)
			}
		})
	}
}

// TestUpdateConfigKernelDeliveryFailureIsDependencyNotReady 定住业务码的分界：
// 文件已经写对，坏的是通道，所以回 50003（依赖未就绪）而不是 40004。
//
// 同时定住内存/磁盘的一致性：回 50003 时文件已是新值，内存也必须跟着走——否则 GET /config
// 会一直回旧值，直到下一次热重载才「自己好起来」。
func TestUpdateConfigKernelDeliveryFailureIsDependencyNotReady(t *testing.T) {
	s, path, live, _ := configAPIFixture(t, func(cfg *APIConfig) {
		cfg.KernelConfig = &recordingKernelConfig{err: errors.New("netlink 发送超时")}
	})

	env, status := putConfig(t, s, `{"rate_warning_pps":60000}`)
	if want := httpcontract.CodeHTTPStatus[httpcontract.Code50003]; status != want {
		t.Errorf("HTTP 状态 = %d，契约 50003 对应 %d", status, want)
	}
	if code := envelopeCode(t, env); code != httpcontract.Code50003 {
		t.Errorf("code = %d，期望 50003", code)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("配置文件没写成功: %v", err)
	}
	if !strings.Contains(string(written), "rate_warning_pps: 60000") {
		t.Errorf("下发失败连带把文件写坏了:\n%s", written)
	}
	// 文件已落新值 → 活配置必须已是同一份，不靠后续重载兜底。
	if live.Webui.RateWarningPPS != 60000 {
		t.Errorf("活配置 RateWarningPPS = %d，文件已写 60000，内存应与之对齐", live.Webui.RateWarningPPS)
	}
}

// TestUpdateConfigWithoutKernelClient 定住「内核客户端未装配」不是错误：与封禁、白名单同口径，
// 文件照写、操作按成功回。
func TestUpdateConfigWithoutKernelClient(t *testing.T) {
	s, path, _, _ := configAPIFixture(t, func(cfg *APIConfig) { cfg.KernelConfig = nil })

	env, status := putConfig(t, s, `{"rate_warning_pps":60000}`)
	if status != http.StatusOK || envelopeCode(t, env) != httpcontract.CodeOK {
		t.Fatalf("没装内核客户端不该失败：status=%d code=%d", status, envelopeCode(t, env))
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("文件应当仍然写入: %v", err)
	}
}

// TestGetConfigReturnsContractShapeWithoutLeakingCredentials 盯住两件事：
//
//   - GET /api/v1/config 的载荷是契约的 WebuiConfigResponse——snake_case 的**扁平** 19 字段，
//     不是整份 config.Config（键名是 Go 字段名、形状是嵌套的）；
//   - config.Config 根上的凭据（MetricsPassword）根本不在载荷里。读路径只投影 cfg.Webui
//     这一段，因此凭据不在取值范围内，不靠「在副本上清零」。
func TestGetConfigReturnsContractShapeWithoutLeakingCredentials(t *testing.T) {
	live := config.Default()
	live.MetricsPassword = "s3cret-live"
	live.Webui.RateWarningPPS = 12345
	live.Webui.ClearLogsAt = ""
	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.GetCurrentConfig = func() *config.Config { return &live }
	})

	out := get[map[string]any](t, s, "/api/v1/config")

	if v, ok := out["rate_warning_pps"]; !ok || v != float64(12345) {
		t.Errorf("rate_warning_pps = %v，期望 12345（契约字段名与取值）", v)
	}
	for _, k := range []string{"metrics_password", "MetricsPassword"} {
		if _, ok := out[k]; ok {
			t.Errorf("载荷里出现了凭据字段 %q: %v", k, out[k])
		}
	}
	if _, ok := out["Webui"]; ok {
		t.Errorf("载荷是整份 config.Config 的嵌套形状，不是契约的扁平静荷: %v", out)
	}
	if v, ok := out["clear_logs_at"]; !ok || v != nil {
		t.Errorf("clear_logs_at = %v，空串应归一成 null", v)
	}
	if live.MetricsPassword != "s3cret-live" {
		t.Errorf("GET 改动了活配置的 MetricsPassword：%q", live.MetricsPassword)
	}
}
