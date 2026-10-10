// 载荷面的行为核对：REST 响应写出的 key 与形状必须等于契约声明的那些 type 块。
//
// 这些用例存在的原因不是「字段名好看」：前端按 `data.items` / `data.line_number` 取数，
// 服务端写的是裸数组或别的 key 时，两侧各自都能跑、拼在一起才是空白面板。契约门禁能
// 核对 struct 与 type 块逐字对齐，但「handler 真的返回了这个 struct」只有打一次请求
// 才知道——本文件就是这一层。
package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// decodeKeys 取出载荷里的一层 JSON 对象并返回它的 key 集合。
//
// 用 map 而不是解成 struct：解成 Go 的 struct 会让「服务端多写/少写一个字段」在解码
// 端被静默补零，而 key 集合的差异正是这里要抓的东西。
func decodeKeys(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("载荷不是 JSON 对象: %v（body=%s）", err, raw)
	}
	return obj
}

// requireKeys 核对载荷带着契约声明的这些 key（不多判：少一个就是前端取不到数）。
func requireKeys(t *testing.T, obj map[string]any, want ...string) {
	t.Helper()
	for _, key := range want {
		if _, ok := obj[key]; !ok {
			t.Errorf("载荷缺字段 %q（实际 key: %v）", key, keysOf(obj))
		}
	}
}

// TestListBansAlwaysReturnsPaginationEnvelope 是缺陷 HTTP_BANS_DUAL_SHAPE 的行为断言。
//
// 无论带不带 query，data 都是 PaginatedResponse<BanResponse> 那五个 key；特别是**不能**
// 是不带 query 时退化成裸数组——按 items 取数的调用在那一支会拿到 undefined。
func TestListBansAlwaysReturnsPaginationEnvelope(t *testing.T) {
	s, _ := newTestServer(t, nil)

	for _, path := range []string{"/api/v1/bans", "/api/v1/bans?page=1&page_size=5&sort_by=ip_asc"} {
		w := authedGet(t, s, path)
		if w.Code != http.StatusOK {
			t.Fatalf("%s 状态码 %d，期望 200", path, w.Code)
		}
		body := w.Body.Bytes()
		if trimmed := strings.TrimSpace(string(body)); strings.HasPrefix(trimmed, `{"code":0,"data":[`) {
			t.Errorf("%s 的 data 是裸数组，契约要分页信封: %s", path, truncate(body))
			continue
		}
		env := decodeEnvelope(t, body)
		data := decodeKeys(t, env["data"])
		requireKeys(t, data, "items", "total", "page", "page_size", "total_pages")
		if _, ok := data["items"].([]any); !ok {
			t.Errorf("%s 的 items 不是数组: %T", path, data["items"])
		}
	}
}

// TestListBansSortAndPaging 核对 sort_by 真的在服务端生效、分页算得对。
//
// 排序键必须在**切页之前**应用：先切后排在跨页时表现为「每页内部有序、整体乱序」，
// 而面板只看到当前页，永远发现不了。
func TestListBansSortAndPaging(t *testing.T) {
	cache := bans.GlobalCache()
	now := time.Now().Unix()
	seed := []bans.BanInfo{
		{IP: "10.0.0.9", JailName: "sshd", BannedAt: now - 30, ExpiresAt: now + 30},
		{IP: "10.0.0.5", JailName: "nginx", BannedAt: now - 10, ExpiresAt: now + 90},
		{IP: "10.0.0.7", JailName: "sshd", BannedAt: now - 20, IsPermanent: true},
	}
	for _, info := range seed {
		if !cache.TryInsert(info) {
			t.Fatalf("测试种子 %s 已在镜像里，用例前提不成立", info.IP)
		}
	}
	t.Cleanup(func() {
		for _, info := range seed {
			_ = removeBanForTest(info.IP)
		}
	})

	s, _ := newTestServer(t, nil)

	// 第 1 页 / 每页 2 条 / 按 ip_asc：全集按 IP 升序是 .5 .7 .9，切页后第一页是 .5 .7。
	w := authedGet(t, s, "/api/v1/bans?page=1&page_size=2&sort_by=ip_asc")
	data := decodeKeys(t, decodeEnvelope(t, w.Body.Bytes())["data"])
	items := data["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("第 1 页 %d 条，期望 2（body=%s）", len(items), truncate(w.Body.Bytes()))
	}
	first := items[0].(map[string]any)
	requireKeys(t, first, "ip", "jail", "banned_at", "remaining_seconds", "reason", "ban_count", "is_permanent")
	if first["ip"] != "10.0.0.5" {
		t.Errorf("ip_asc 第一页首条 = %v，期望 10.0.0.5（排序没有先于切页）", first["ip"])
	}
	if data["total"] != float64(3) || data["total_pages"] != float64(2) || data["page_size"] != float64(2) {
		t.Errorf("分页读数 total=%v total_pages=%v page_size=%v，期望 3 / 2 / 2",
			data["total"], data["total_pages"], data["page_size"])
	}

	// remaining_seconds：永久封禁写 0，临时封禁写真实剩余。
	w = authedGet(t, s, "/api/v1/bans?page=1&page_size=10&sort_by=ip_desc")
	items = decodeKeys(t, decodeEnvelope(t, w.Body.Bytes())["data"])["items"].([]any)
	byIP := map[string]map[string]any{}
	for _, raw := range items {
		item := raw.(map[string]any)
		byIP[item["ip"].(string)] = item
	}
	if p := byIP["10.0.0.7"]; p == nil || p["is_permanent"] != true || p["remaining_seconds"] != float64(0) {
		t.Errorf("永久封禁条目 = %v，期望 is_permanent=true 且 remaining_seconds=0", p)
	}
	if p := byIP["10.0.0.5"]; p == nil || p["remaining_seconds"].(float64) < 80 {
		t.Errorf("临时封禁剩余秒数 = %v，期望接近 90", p["remaining_seconds"])
	}

	// 未识别的取值回落 banned_at_desc（契约 HTTP_BAN_SORT_DOC_INCOMPLETE）。
	w = authedGet(t, s, "/api/v1/bans?sort_by=bogus_key")
	items = decodeKeys(t, decodeEnvelope(t, w.Body.Bytes())["data"])["items"].([]any)
	if top := items[0].(map[string]any); top["ip"] != "10.0.0.5" {
		t.Errorf("非法 sort_by 的首条 = %v，期望 banned_at_desc 回落后的 10.0.0.5（最晚封的那条）", top["ip"])
	}

	// page_size 超过上限 100 时夹到上限，而不是退回缺省 20。
	w = authedGet(t, s, "/api/v1/bans?page_size=1000")
	data = decodeKeys(t, decodeEnvelope(t, w.Body.Bytes())["data"])
	if data["page_size"] != float64(banMaxPageSize) {
		t.Errorf("page_size = %v，期望夹到 %d", data["page_size"], banMaxPageSize)
	}
}

// TestBatchBanNeverPermanent 是缺陷 HTTP_BATCH_BAN_BECOMES_PERMANENT 的行为断言。
//
// 确认弹窗承诺「统一使用 3600 秒」，那么不带 duration 的批量请求就必须落成 3600 秒的
// 临时封禁：/api/v1/bans/unban-temporary 只解临时封禁，批量升格成永久等于没有批量退路。
func TestBatchBanNeverPermanent(t *testing.T) {
	s, _ := newTestServer(t, nil)

	ips := []string{"10.30.0.1", "10.30.0.2"}
	body := `{"ips":["` + strings.Join(ips, `","`) + `"]}`
	w := authedSend(t, s, http.MethodPost, "/api/v1/bans/batch", "application/json", body)
	if w.Code != http.StatusCreated {
		t.Errorf("状态码 %d，契约给这条路由的成功状态码是 201（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}

	data := decodeKeys(t, decodeEnvelope(t, w.Body.Bytes())["data"])
	requireKeys(t, data, "total", "succeeded", "failed_count", "details")
	if data["total"] != float64(2) || data["succeeded"] != float64(2) || data["failed_count"] != float64(0) {
		t.Errorf("批量汇总读数 = %v，期望 2/2/0", data)
	}

	t.Cleanup(func() {
		for _, ip := range ips {
			_ = removeBanForTest(ip)
		}
	})
	for _, ip := range ips {
		info, ok := bans.GlobalCache().Get(ip)
		if !ok {
			t.Fatalf("%s 没进封禁镜像", ip)
		}
		if info.IsPermanent || info.ExpiresAt <= time.Now().Unix() {
			t.Errorf("%s 落成了永久/已过期封禁: %+v", ip, info)
		}
		if remain := info.ExpiresAt - info.BannedAt; remain != banDefaultBatchSecs {
			t.Errorf("%s 封禁时长 %d 秒，期望 %d", ip, remain, banDefaultBatchSecs)
		}
	}
}

// TestBanDetailUnbannedIPSucceeds 核对「未被封禁不是错误」这条契约语义。
//
// 契约给这条路由只编了 40006，text 写的是「封禁详情查询失败（IP 非法）」：把「这个 IP
// 现在没被封」也回成 400，前端详情面板就整块变成一句错误提示，而它手上的历史与信誉读数
// 其实是完整的。
func TestBanDetailUnbannedIPSucceeds(t *testing.T) {
	s, _ := newTestServer(t, nil)

	w := authedGet(t, s, "/api/v1/bans/10.9.9.9/detail")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d，未被封禁的合法 IP 期望 200（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	data := decodeKeys(t, decodeEnvelope(t, w.Body.Bytes())["data"])
	requireKeys(t, data,
		"ip", "is_banned", "jail_name", "reason", "banned_at", "expires_at", "is_permanent",
		"fail_count", "ban_count", "last_unbanned_at", "was_permanent", "progressive_level",
		"next_ban_duration", "reputation_score", "reputation_multiplier")
	if data["is_banned"] != false {
		t.Errorf("is_banned = %v，期望 false", data["is_banned"])
	}
	if data["next_ban_duration"] != "未知" {
		t.Errorf("next_ban_duration = %v，jail 无从确定时期望「未知」而不是 0 秒", data["next_ban_duration"])
	}

	// IP 非法才是 40006。
	bad := authedGet(t, s, "/api/v1/bans/not-an-ip/detail")
	wantStatus := httpcontract.CodeHTTPStatus[httpcontract.Code40006]
	if bad.Code != wantStatus {
		t.Errorf("非法 IP 状态码 %d，契约 40006 编的是 %d", bad.Code, wantStatus)
	}
	if got := envelopeCode(t, decodeEnvelope(t, bad.Body.Bytes())); got != httpcontract.Code40006 {
		t.Errorf("code = %d，期望 %d", got, httpcontract.Code40006)
	}
}

// TestBanDetailProgressiveFields 核对详情里的渐进式读数取自封禁历史与 jail 配置。
//
// 「下次封禁时长」是面板上唯一能解释「为什么这个人被越封越久」的读数，它必须与判定链路
// 用的是同一条算式（decision.ProgressiveDuration），不能在 HTTP 面再抄一份表。
func TestBanDetailProgressiveFields(t *testing.T) {
	dir := t.TempDir()
	db, err := persist.NewDB(persist.Config{Path: filepath.Join(dir, "detail.db"), Logger: discardLogger()})
	if err != nil {
		t.Fatalf("建测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	const ip = "10.31.0.1"
	if err := db.RecordBanHistory(ip, false); err != nil {
		t.Fatalf("记录封禁历史失败: %v", err)
	}
	if err := db.RecordBanEvent(ip, "sshd", 1, false); err != nil {
		t.Fatalf("记录封禁事件失败: %v", err)
	}
	if err := db.SetIPReputation(ip, 60); err != nil {
		t.Fatalf("写信誉分失败: %v", err)
	}

	cache := bans.GlobalCache()
	if !cache.TryInsert(bans.BanInfo{
		IP: ip, JailName: "sshd", Reason: "契约用例", BannedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Unix() + 600, BanCount: 1, FailCount: 5,
	}) {
		t.Fatalf("种子封禁 %s 已存在", ip)
	}
	t.Cleanup(func() { _ = removeBanForTest(ip) })

	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.DB = db
		cfg.GetCurrentConfig = func() *config.Config {
			return &config.Config{Jails: []config.Jail{{Name: "sshd", BanTime: 300, Enabled: true}}}
		}
	})

	data := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/bans/"+ip+"/detail").Body.Bytes())["data"])
	if data["is_banned"] != true || data["jail_name"] != "sshd" || data["reason"] != "契约用例" {
		t.Errorf("当前封禁状态读数 = %v", data)
	}
	if data["ban_count"] != float64(1) || data["fail_count"] != float64(5) {
		t.Errorf("ban_count/fail_count = %v/%v，期望 1/5", data["ban_count"], data["fail_count"])
	}
	if data["progressive_level"] != "初次封禁" {
		t.Errorf("progressive_level = %v，期望「初次封禁」", data["progressive_level"])
	}
	// ban_count=1 → 下一次是渐进式第二档（1800 秒），与 decision.ProgressiveDuration 一致。
	if data["next_ban_duration"] != "1800 秒" {
		t.Errorf("next_ban_duration = %v，期望「1800 秒」", data["next_ban_duration"])
	}
	if data["reputation_score"] != float64(60) || data["reputation_multiplier"] != 0.8 {
		t.Errorf("信誉读数 = %v/%v，期望 60 与 0.8（同一套映射，不是第二份表）",
			data["reputation_score"], data["reputation_multiplier"])
	}

	// 解封之后：is_banned 翻成 false，last_unbanned_at 落下真实时刻，历史仍在。
	del := authedSend(t, s, http.MethodDelete, "/api/v1/bans/"+ip, "", "")
	if del.Code != http.StatusOK {
		t.Fatalf("解封状态码 %d（body=%s）", del.Code, truncate(del.Body.Bytes()))
	}
	after := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/bans/"+ip+"/detail").Body.Bytes())["data"])
	if after["is_banned"] != false {
		t.Errorf("解封后 is_banned = %v，期望 false", after["is_banned"])
	}
	if stamp, ok := after["last_unbanned_at"].(float64); !ok || stamp <= 0 {
		t.Errorf("解封后 last_unbanned_at = %v，期望非零时刻", after["last_unbanned_at"])
	}
	if after["ban_count"] != float64(1) {
		t.Errorf("解封后 ban_count = %v，历史不该被抹掉", after["ban_count"])
	}
	if after["jail_name"] != "sshd" {
		t.Errorf("解封后 jail_name = %v，期望退回最近一次封禁事件的 sshd", after["jail_name"])
	}
}

// TestCreateBanDurationTriState 核对 duration 的三态：缺席与显式 0 都是永久，
// 显式正数才带 duration_seconds。
func TestCreateBanDurationTriState(t *testing.T) {
	s, _ := newTestServer(t, nil)

	cases := []struct {
		name        string
		body        string
		wantPersist bool
	}{
		{"省略 duration", `{"ip":"10.32.0.1"}`, true},
		{"显式 0", `{"ip":"10.32.0.2","duration":0}`, true},
		{"显式 120", `{"ip":"10.32.0.3","duration":120,"reason":"巡检"}`, false},
	}
	for _, c := range cases {
		w := authedSend(t, s, http.MethodPost, "/api/v1/bans", "application/json", c.body)
		if w.Code != http.StatusCreated {
			t.Errorf("%s：状态码 %d，契约给的成功状态码是 201（body=%s）",
				c.name, w.Code, truncate(w.Body.Bytes()))
			continue
		}
		data := decodeKeys(t, decodeEnvelope(t, w.Body.Bytes())["data"])
		requireKeys(t, data, "ip", "action", "permanent", "duration_seconds")
		if data["action"] != "banned" {
			t.Errorf("%s：action = %v，期望 banned（永久与否由 permanent 表达）", c.name, data["action"])
		}
		if data["permanent"] != c.wantPersist {
			t.Errorf("%s：permanent = %v，期望 %v", c.name, data["permanent"], c.wantPersist)
		}
		t.Cleanup(func() {
			_ = removeBanForTest(data["ip"].(string))
		})
	}
}

// TestGetLogsPaginatesWithLineNumbers 核对日志载荷是契约的 LogPageResponse，
// 且 line_number 是**文件里的物理行号**。
//
// 行号而不是数组下标：面板上把 content 贴进 <pre> 之后，运维拿它去 grep 同一个文件。
// 只读尾部若干字节再报相对偏移，会让这个 grep 落到错误的行上。
func TestGetLogsPaginatesWithLineNumbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	lines := []string{
		`{"ts":"2026-10-01T00:00:00Z","level":"INFO","msg":"第一行"}`,
		`{"ts":"2026-10-11T00:00:00Z","level":"WARN","msg":"关键词 here"}`,
		`{"ts":"2026-10-11T00:00:01Z","level":"ERROR","msg":"第三行"}`,
		`{"ts":"2026-10-11T00:00:02Z","level":"INFO","msg":"第四行"}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("写日志文件失败: %v", err)
	}

	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.LogFilePath = func() string { return path }
	})

	data := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/logs?page=1&page_size=2").Body.Bytes())["data"])
	requireKeys(t, data, "items", "total_lines", "page", "page_size", "total_pages")
	if data["total_lines"] != float64(4) || data["total_pages"] != float64(2) {
		t.Errorf("total_lines=%v total_pages=%v，期望 4/2", data["total_lines"], data["total_pages"])
	}
	items := data["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("第 1 页 %d 条，期望 2", len(items))
	}
	// 最新在前：第 4 行、第 3 行。
	first := items[0].(map[string]any)
	requireKeys(t, first, "line_number", "content")
	if first["line_number"] != float64(4) || items[1].(map[string]any)["line_number"] != float64(3) {
		t.Errorf("第 1 页行号 = %v/%v，期望 4/3（最新在前）",
			first["line_number"], items[1].(map[string]any)["line_number"])
	}
	if got := items[0].(map[string]any)["content"]; got != lines[3] {
		t.Errorf("content = %v，期望原文 %v", got, lines[3])
	}

	// 第二页拿到第 2、1 行。
	page2 := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/logs?page=2&page_size=2").Body.Bytes())["data"])
	items = page2["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["line_number"] != float64(2) {
		t.Fatalf("第 2 页 = %v，期望首条行号 2", items)
	}

	// 越界页：空 items 而不是报错（契约这条路由没有可编的「页码越界」码）。
	over := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/logs?page=99&page_size=2").Body.Bytes())["data"])
	if over["items"] == nil {
		t.Errorf("越界页的 items 缺失或为 null: %v", over["items"])
	}
	if arr, ok := over["items"].([]any); !ok || len(arr) != 0 {
		t.Errorf("越界页 items = %v，期望空数组", over["items"])
	}

	// level 过滤后 total_lines 是**过滤后**的行数。
	level := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/logs?level=info").Body.Bytes())["data"])
	if level["total_lines"] != float64(2) {
		t.Errorf("level=info 的 total_lines = %v，期望 2", level["total_lines"])
	}

	// keyword 过滤命中第 2 行。
	keyword := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/logs?keyword=here").Body.Bytes())["data"])
	items = keyword["items"].([]any)
	if keyword["total_lines"] != float64(1) || len(items) != 1 ||
		items[0].(map[string]any)["line_number"] != float64(2) {
		t.Errorf("keyword=here 读数 = %v（total_lines=%v），期望第 2 行一条", items, keyword["total_lines"])
	}

	// since 过滤掉 10-01 那一行（不带时区的写法按本地时区解释）。
	since := decodeKeys(t, decodeEnvelope(t,
		authedGet(t, s, "/api/v1/logs?since=2026-10-05T00:00:00").Body.Bytes())["data"])
	if since["total_lines"] != float64(3) {
		t.Errorf("since=2026-10-05 的 total_lines = %v，期望 3", since["total_lines"])
	}
}

// TestGetLogsRejectsInvalidQuery 核对 40005：契约给这条路由编了「日志查询参数非法」，
// 所以带了却读不懂的值必须回错，不能悄悄按第 1 页查。
func TestGetLogsRejectsInvalidQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(path, []byte(`{"ts":"2026-10-11T00:00:00Z","level":"INFO","msg":"x"}`+"\n"), 0o600); err != nil {
		t.Fatalf("写日志文件失败: %v", err)
	}
	s, _ := newTestServer(t, func(cfg *APIConfig) {
		cfg.LogFilePath = func() string { return path }
	})

	cases := map[string]string{
		"page 不是数字":     "/api/v1/logs?page=abc",
		"page 为 0":      "/api/v1/logs?page=0",
		"page_size 超上限": fmt.Sprintf("/api/v1/logs?page_size=%d", logMaxPageSize+1),
		"level 不认识":     "/api/v1/logs?level=critical",
		"since 读不懂":     "/api/v1/logs?since=last-week",
	}
	for name, path := range cases {
		w := authedGet(t, s, path)
		wantStatus := httpcontract.CodeHTTPStatus[httpcontract.Code40005]
		if w.Code != wantStatus {
			t.Errorf("%s：状态码 %d，期望 %d（body=%s）", name, w.Code, wantStatus, truncate(w.Body.Bytes()))
			continue
		}
		env := decodeEnvelope(t, w.Body.Bytes())
		if got := envelopeCode(t, env); got != httpcontract.Code40005 {
			t.Errorf("%s：code = %d，契约这条路由编的是 %d", name, got, httpcontract.Code40005)
		}
		assertNullData(t, env)
	}
}

// TestWhitelistPayloadIsNamed 核对白名单三个端点的载荷形状。
//
// GET 返回的是 {cidr, device} 对象数组而不是裸 CIDR 列表：前端 WhitelistEntry 有两列，
// 裸列表让 device 这一列在读侧根本不存在。
func TestWhitelistPayloadIsNamed(t *testing.T) {
	s, _ := newTestServer(t, nil)

	add := authedSend(t, s, http.MethodPost, "/api/v1/whitelist", "application/json", `{"cidr":"10.0.0.1/8"}`)
	if add.Code != http.StatusCreated {
		t.Errorf("添加白名单状态码 %d，契约给的成功状态码是 201（body=%s）",
			add.Code, truncate(add.Body.Bytes()))
	}
	data := decodeKeys(t, decodeEnvelope(t, add.Body.Bytes())["data"])
	requireKeys(t, data, "cidr", "action")
	if data["action"] != "added" {
		t.Errorf("action = %v，期望 added", data["action"])
	}
	// 归一后的键：输入带主机位也要回 10.0.0.0/8，调用方拿它再删一次才打得中表里那条。
	if data["cidr"] != "10.0.0.0/8" {
		t.Errorf("cidr = %v，期望归一后的 10.0.0.0/8", data["cidr"])
	}
	// 清理在用例外面解析：t.Fatalf 从 Cleanup 回调里调用会变成一次 panic 而不是可读的失败。
	prefix := mustPrefix(t, "10.0.0.0/8")
	t.Cleanup(func() { _ = bans.GlobalWhitelist().Remove(prefix) })

	list := decodeEnvelope(t, authedGet(t, s, "/api/v1/whitelist").Body.Bytes())
	var entries []map[string]any
	if err := json.Unmarshal(list["data"], &entries); err != nil {
		t.Fatalf("白名单载荷不是对象数组: %v（data=%s）", err, list["data"])
	}
	found := false
	for _, entry := range entries {
		if entry["cidr"] == "10.0.0.0/8" {
			found = true
			if _, ok := entry["device"]; !ok {
				t.Errorf("条目缺 device 字段: %v", entry)
			}
		}
	}
	if !found {
		t.Errorf("列表里没有刚加的 10.0.0.0/8: %v", entries)
	}

	rm := authedSend(t, s, http.MethodDelete, "/api/v1/whitelist/10.0.0.0%2F8", "", "")
	removed := decodeKeys(t, decodeEnvelope(t, rm.Body.Bytes())["data"])
	requireKeys(t, removed, "cidr", "action")
	if removed["action"] != "removed" || removed["cidr"] != "10.0.0.0/8" {
		t.Errorf("移除载荷 = %v，期望 cidr=10.0.0.0/8 action=removed", removed)
	}
}

// TestSSEStatusIsTypedPayload 核对 sse-status 的两份流状态还是同一个契约形状（改成
// struct 之后 key 拼写不能漂）。
func TestSSEStatusIsTypedPayload(t *testing.T) {
	s, _ := newTestServer(t, nil)

	data := decodeKeys(t, decodeEnvelope(t, authedGet(t, s, "/api/v1/stats/sse-status").Body.Bytes())["data"])
	for _, name := range []string{"events", "logs"} {
		stream, ok := data[name].(map[string]any)
		if !ok {
			t.Errorf("载荷缺 %q 一份: %v", name, data)
			continue
		}
		requireKeys(t, stream, "current_connections", "max_connections", "limit_reached")
	}
}

// mustPrefix 给清理用的白名单条目做解析：解析失败说明用例本身写错了，直接 fatal。
func mustPrefix(t *testing.T, cidr string) netip.Prefix {
	t.Helper()
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", cidr, err)
	}
	return prefix
}
