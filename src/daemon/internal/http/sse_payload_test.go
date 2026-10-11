// SSE 域载荷与同域 REST 的同形核对。
//
// 前端把每个域的帧 data 直接当 REST 的类型解析（frontend/src/hooks/useSse.ts 里五处
// `JSON.parse(data) as StatsResponse | BanResponse[] | JailResponse[] | RateResponse[] |
// WhitelistEntry[]`），所以「帧的形状」不是实现细节而是契约的一部分。这一轮接线之前，
// 泵发的是内核与配置的内部结构（stats 帧带的是 contract.StatsResponse 的 Go 字段名、
// rates 帧带快照条目、jails 帧带 config.Jail），REST 与 SSE 在同一页面上给出两套 key。
// 这里逐域钉住：两条读法是同一个函数、同一份数据源、同一个形状。
package http

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

// sseFixtureServer 装配一份四域都有读数的服务器。
func sseFixtureServer(t *testing.T, mutate func(*APIConfig)) (*Server, *APIHandlers) {
	t.Helper()

	snap := telemetry.Snapshot{
		Stats: contract.StatsResponse{
			CurrentBans: 2, TotalBans: 9, TotalUnbans: 3, WhitelistCount: 1,
			PacketsDropped: 40, PacketsAccepted: 4000,
		},
		Rates: telemetry.Rates{Entries: []contract.RateEntry{
			{AF: contract.AFInet, Addr: v4(10, 0, 0, 1), Packets: 5, Bytes: 500},
			{AF: contract.AFInet, Addr: v4(10, 0, 0, 2), Packets: 50, Bytes: 5000},
		}},
		Link: telemetry.Link{Lease: telemetry.LeaseHeld},
	}

	config.SetActiveJails([]config.Jail{
		{Name: "sse-sshd", Enabled: true, MaxRetries: 5, FindTime: 600, BanTime: 3600},
		{Name: "sse-mysql", Enabled: false, MaxRetries: 3, FindTime: 300, BanTime: -1},
	})

	now := time.Now().Unix()
	// 返回值在这里不作为断言：Upsert 报的是「内容变了没有」，同一个进程级镜像被多个用例
	// 重复写入时它本就返回 false。断言写在事后——条目必须在表里。
	bans.GlobalCache().Upsert(bans.BanInfo{
		IP:        "203.0.113.41",
		JailName:  "sse-sshd",
		Reason:    "5 次失败",
		BannedAt:  now - 60,
		ExpiresAt: now + 3540,
		BanCount:  1,
	})
	if _, ok := bans.GlobalCache().Get("203.0.113.41"); !ok {
		t.Fatal("测试封禁未能写进镜像")
	}
	// 返回值在这里不作为断言：白名单表按归一键去重，重复用例本就命中「已在表里」。
	// 断言写在事后——键必须在表里。
	bans.GlobalWhitelist().Add(mustPrefix(t, "198.51.100.0/24"))
	if !slices.Contains(bans.GlobalWhitelist().List(), "198.51.100.0/24") {
		t.Fatal("测试白名单条目未能写进镜像")
	}

	provideSnap := snapshotProvider(snap)
	return newTestServer(t, func(cfg *APIConfig) {
		provideSnap(cfg)
		if mutate != nil {
			mutate(cfg)
		}
	})
}

// TestSSEReplicaStatsMatchesREST 核对 stats 帧与 GET /api/v1/stats 同形同值。
func TestSSEReplicaStatsMatchesREST(t *testing.T) {
	s, api := sseFixtureServer(t, nil)

	rest := get[StatsResponse](t, s, "/api/v1/stats")
	payload := api.SSEReplicas().Stats()
	frame, ok := payload.(StatsResponse)
	if !ok {
		t.Fatalf("stats 帧载荷类型 = %T，期望 http.StatsResponse", payload)
	}
	// uptime_seconds 由两次各自的 time.Now() 决定（跨过一秒边界就差 1），与形状无关。
	rest.UptimeSeconds, frame.UptimeSeconds = 0, 0
	if !reflect.DeepEqual(rest, frame) {
		t.Errorf("stats 帧与 REST 读数不同形\n帧:   %+v\nREST: %+v", frame, rest)
	}
}

// TestSSEReplicaRatesMatchesREST 核对 rates 帧就是 GET /api/v1/rates/current 那份数组
// （含按 pps 降序与点分地址文本），而不是内核快照条目。
func TestSSEReplicaRatesMatchesREST(t *testing.T) {
	s, api := sseFixtureServer(t, nil)

	rest := get[[]RateResponse](t, s, "/api/v1/rates/current")
	payload := api.SSEReplicas().Rates()
	frame, ok := payload.([]RateResponse)
	if !ok {
		t.Fatalf("rates 帧载荷类型 = %T，期望 []http.RateResponse", payload)
	}
	if !reflect.DeepEqual(rest, frame) {
		t.Errorf("rates 帧与 REST 不同形\n帧:   %+v\nREST: %+v", frame, rest)
	}
	if len(frame) != 2 || frame[0].IP != "10.0.0.2" {
		t.Errorf("rates 帧 = %+v，期望两行且按 pps 降序", frame)
	}
}

// TestSSEReplicaJailsMatchesREST 核对 jails 帧是 JailResponse 而不是 config.Jail。
//
// config.Jail 没有 json tag，序列化出来是 Go 字段名（Name/Enabled/MaxRetries…）。前端按
// 契约 key（name/enabled/max_retries/ban_count）取值会全部落在 undefined，而它优先读
// sseJails——于是 jail 页在第一个帧到达后就被清空。
func TestSSEReplicaJailsMatchesREST(t *testing.T) {
	s, api := sseFixtureServer(t, nil)

	rest := get[[]JailResponse](t, s, "/api/v1/jails")
	payload := api.SSEReplicas().Jails()
	frame, ok := payload.([]JailResponse)
	if !ok {
		t.Fatalf("jails 帧载荷类型 = %T，期望 []http.JailResponse", payload)
	}
	if !reflect.DeepEqual(rest, frame) {
		t.Errorf("jails 帧与 REST 不同形\n帧:   %+v\nREST: %+v", frame, rest)
	}
	if len(frame) != 2 || frame[0].Name != "sse-sshd" || frame[1].BanTime != -1 {
		t.Fatalf("jails 帧 = %+v，期望按配置顺序给出两个 jail（第二个是永久封禁）", frame)
	}
	if frame[0].BanCount != 1 {
		t.Errorf("sse-sshd 的 ban_count = %d，期望镜像里那一条封禁算进来", frame[0].BanCount)
	}

	// 帧文本里的 key 必须是契约的线上 key。
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatalf("jails 帧序列化失败: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("jails 帧解码失败: %v", err)
	}
	for _, key := range []string{"name", "enabled", "ban_count", "max_retries",
		"effective_max_retries", "findtime", "ban_time", "is_peak_hours",
		"peak_hours_multiplier", "internal_ip_multiplier", "lines_parsed", "regex_matches",
		"ips_extracted", "failed_attempts", "bans_triggered"} {
		if _, ok := rows[0][key]; !ok {
			t.Errorf("jails 帧缺契约 key %q", key)
		}
	}
	if _, leaked := rows[0]["MaxRetries"]; leaked {
		t.Error("jails 帧带出了 Go 字段名，前端按契约 key 取值会全空")
	}
}

// TestSSEReplicaBansAndWhitelistMatchREST 核对两镜像域的帧形状。
//
// bans 的 REST 是分页对象、帧是全表镜像（前端整表替换本地状态），所以这里比的是条目
// 形状与内容，不是外层信封。RemainingSeconds 由两次各自的 time.Now() 决定，允许 1 秒误差。
func TestSSEReplicaBansAndWhitelistMatchREST(t *testing.T) {
	s, api := sseFixtureServer(t, nil)

	rest := get[map[string]any](t, s, "/api/v1/bans?page=1&page_size=100")
	items, ok := rest["items"].([]any)
	if !ok {
		t.Fatalf("REST 封禁载荷的 items 形状不符: %#v", rest["items"])
	}
	payload := api.SSEReplicas().Bans(bans.GlobalCache().All())
	frame, ok := payload.([]BanResponse)
	if !ok {
		t.Fatalf("bans 帧载荷类型 = %T，期望 []http.BanResponse", payload)
	}
	if len(frame) != len(items) {
		t.Fatalf("bans 帧 %d 行，REST 页内 %d 行（页大小 100 应已含全表）", len(frame), len(items))
	}
	if total, ok := rest["total"].(float64); !ok || uint64(total) != uint64(len(frame)) {
		t.Fatalf("bans 帧 %d 行，REST 报的总数 %#v", len(frame), rest["total"])
	}
	byKey := make(map[string]map[string]any, len(items))
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			t.Fatalf("REST 封禁条目形状不符: %#v", it)
		}
		ip, _ := m["ip"].(string)
		byKey[ip] = m
	}
	for _, row := range frame {
		item, ok := byKey[row.IP]
		if !ok {
			t.Fatalf("bans 帧里的 %q 在 REST 页内不存在", row.IP)
		}
		// 同形 = 同一批 key。帧少一个 key 就是前端那一列恒为空。
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("封禁条目序列化失败: %v", err)
		}
		var shaped map[string]any
		if err := json.Unmarshal(raw, &shaped); err != nil {
			t.Fatalf("封禁条目解码失败: %v", err)
		}
		if !reflect.DeepEqual(sortedKeys(shaped), sortedKeys(item)) {
			t.Errorf("%q 的条目 key 不同\n帧:   %v\nREST: %v", row.IP, shaped, item)
		}
		got, isNum := item["remaining_seconds"].(float64)
		if !isNum {
			t.Fatalf("%q 的 remaining_seconds 不是数值：%#v", row.IP, item["remaining_seconds"])
		}
		if diff := got - float64(row.RemainingSeconds); diff > 1 || diff < -1 {
			t.Errorf("%q 的 remaining_seconds：REST %v / 帧 %d", row.IP, got, row.RemainingSeconds)
		}
	}

	wlRest := get[[]WhitelistEntryResponse](t, s, "/api/v1/whitelist")
	wlPayload := api.SSEReplicas().Whitelist(bans.GlobalWhitelist().List())
	wlFrame, ok := wlPayload.([]WhitelistEntryResponse)
	if !ok {
		t.Fatalf("whitelist 帧载荷类型 = %T，期望 []http.WhitelistEntryResponse", wlPayload)
	}
	// 两侧都是无序集合（镜像按 map 迭代），比之前先按 cidr 排一次。
	sort.Slice(wlRest, func(i, j int) bool { return wlRest[i].CIDR < wlRest[j].CIDR })
	sort.Slice(wlFrame, func(i, j int) bool { return wlFrame[i].CIDR < wlFrame[j].CIDR })
	if !reflect.DeepEqual(wlRest, wlFrame) {
		t.Errorf("whitelist 帧与 REST 不同形\n帧:   %+v\nREST: %+v", wlFrame, wlRest)
	}
	if len(wlFrame) == 0 || wlFrame[0].Device != "" {
		t.Errorf("whitelist 帧 = %+v，期望至少一条且 device 是空串（本实现没有按网卡放行）", wlFrame)
	}
}

// TestPublishJailsFrameCarriesRESTPayload 走一遍真实的推送路径：PublishJails 经 broker
// 序列化的那一帧，事件名是域名、data 与 GET /api/v1/jails 的 data 语义相同。
//
// 前面的用例比的是返回值，这一条比的是**帧文本**——事件名与 data 行都在这里成形
// （sse.go 的 sseFrame），前端两行都读。
func TestPublishJailsFrameCarriesRESTPayload(t *testing.T) {
	broker := NewEventsBroker(discardLogger())
	// 不在这里再挂一次 Stop：newTestServer 已把 cfg.SSE.Stop 登记进 t.Cleanup，
	// 而 Stop 关掉的是 stopCh，第二次进来就是 close of closed channel。
	s, api := sseFixtureServer(t, func(cfg *APIConfig) { cfg.SSE = broker })

	out := make(chan []byte, 8)
	if !broker.attach(out) {
		t.Fatal("SSE 连接未能登记进扇出表")
	}
	defer broker.detach(out)

	api.PublishJails()

	var frame string
	select {
	case f := <-out:
		frame = string(f)
	case <-time.After(2 * time.Second):
		t.Fatal("PublishJails 之后没有帧到达连接")
	}

	if !strings.HasPrefix(frame, "event: jails\n") {
		t.Fatalf("帧的事件名行不对，期望以 %q 开头，实际帧：%q", "event: jails\n", frame)
	}
	data := frameData(t, frame)

	want := unwrapData(t, authedGet(t, s, "/api/v1/jails").Body.Bytes())
	var gotValue, wantValue any
	if err := json.Unmarshal([]byte(data), &gotValue); err != nil {
		t.Fatalf("帧的 data 不是合法 JSON: %v（data=%s）", err, data)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("REST 的 data 解码失败: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("jails 帧与 REST 载荷不同\n帧:   %s\nREST: %s", data, want)
	}
}

// sortedKeys 返回 map 的键集合（排序后），用于只比形状不比值。
// 包里另有一个不排序的 keysOf，这里需要可比对的确定顺序。
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// frameData 取帧里 `data:` 行的内容。
func frameData(t *testing.T, frame string) string {
	t.Helper()
	for _, line := range strings.Split(frame, "\n") {
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			return data
		}
	}
	t.Fatalf("帧里没有 data 行：%q", frame)
	return ""
}
