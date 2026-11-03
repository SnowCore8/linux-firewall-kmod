// 综合分析两个端点的行为核对（GET /api/v2/analysis/summary、GET /api/v2/analysis/ip/:ip）。
//
// 这一面钉住三件容易走样事：
//   - 历史库缺席时如实报 503/50003（契约给这两条路由编了这个码），不伪装成空读数；
//   - threat_level 与 /api/v2/stats 同源（buildThreatLevel），不是另抄一份常量；
//   - 未接线的维度按契约形状降级：Vec 给空数组、Option 给字面 null、计数给 0，
//     summary 文本如实说「无活跃攻击」而不是编一个威胁结论。
package http

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/risk"
)

// TestAnalysisSummaryUnavailableWithoutDB 核对库缺席时摘要端点报 503/50003。
func TestAnalysisSummaryUnavailableWithoutDB(t *testing.T) {
	s, _ := newTestServer(t, nil) // cfg.DB 为 nil

	for _, pattern := range []string{
		httpcontract.RouteGetApiV2AnalysisSummary,
		httpcontract.RouteGetApiV2AnalysisIpIp,
	} {
		path := analysisPath(pattern)
		if strings.Contains(path, "{ip}") {
			path = strings.Replace(path, "{ip}", "203.0.113.7", 1)
		}
		w := authedGet(t, s, path)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s 状态码 %d，期望 503（body=%s）", pattern, w.Code, truncate(w.Body.Bytes()))
			continue
		}
		if got := envelopeCode(t, decodeEnvelope(t, w.Body.Bytes())); got != httpcontract.Code50003 {
			t.Errorf("%s 信封 code = %d，期望 %d", pattern, got, httpcontract.Code50003)
		}
	}
}

// TestAnalysisSummaryDegradesInShape 核对库在场、检测子系统未接线时的降级形状。
func TestAnalysisSummaryDegradesInShape(t *testing.T) {
	db := newAnalysisDB(t, "summary.db")
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })

	data := dataOf(t, s, httpcontract.RouteGetApiV2AnalysisSummary)
	requireKeys(t, data, "threat_level", "top_risk_ips", "active_attacks", "anomalies_count",
		"collaborative_count", "summary", "timestamp")

	// threat_level 是对象且带 stats 面同款字段（同源 buildThreatLevel）。
	level, ok := data["threat_level"].(map[string]any)
	if !ok {
		t.Fatalf("threat_level = %v，期望对象", data["threat_level"])
	}
	requireKeys(t, level, "level", "score", "factors", "current_pps", "pps_ratio",
		"ban_table_usage", "recent_bans")

	// 未接线维度：Vec 空数组（不是 null）、计数 0、summary 如实报无攻击。
	if arr, ok := data["top_risk_ips"].([]any); !ok || len(arr) != 0 {
		t.Errorf("top_risk_ips = %v，期望空数组", data["top_risk_ips"])
	}
	for _, key := range []string{"active_attacks", "anomalies_count", "collaborative_count"} {
		if data[key] != float64(0) {
			t.Errorf("%s = %v，未接线时期望 0", key, data[key])
		}
	}
	if data["summary"] != "当前无活跃攻击或异常行为" {
		t.Errorf("summary = %v，三路计数为 0 时期望如实报无攻击", data["summary"])
	}
	ts, _ := data["timestamp"].(float64)
	if ts <= 0 {
		t.Errorf("timestamp = %v，期望非零时刻", data["timestamp"])
	}
}

// TestAnalysisIpValidation 核对 IP 路径参数：非法 IP 报 400/40006，合法 IP 给全形状。
func TestAnalysisIpValidation(t *testing.T) {
	db := newAnalysisDB(t, "analysis-ip.db")
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })

	w := authedGet(t, s, "/api/v2/analysis/ip/not-an-ip")
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法 IP 状态码 %d，期望 400（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	if got := envelopeCode(t, decodeEnvelope(t, w.Body.Bytes())); got != httpcontract.Code40006 {
		t.Errorf("非法 IP 信封 code = %d，期望 %d", got, httpcontract.Code40006)
	}

	// 合法 IP：ip 回显规范化形式，Option 字段给字面 null，Vec 给空数组。
	w = authedGet(t, s, "/api/v2/analysis/ip/203.0.113.7")
	if w.Code != http.StatusOK {
		t.Fatalf("合法 IP 状态码 %d，期望 200（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	env := decodeEnvelope(t, w.Body.Bytes())
	var data map[string]any
	if err := json.Unmarshal(env["data"], &data); err != nil {
		t.Fatalf("data 不是对象: %v（data=%s）", err, env["data"])
	}
	requireKeys(t, data, "ip", "risk", "ban_history", "reputation", "prediction", "is_whitelisted")
	raw := string(env["data"])
	for _, want := range []string{`"risk":null`, `"reputation":null`, `"prediction":null`, `"ban_history":[]`} {
		if !strings.Contains(raw, want) {
			t.Errorf("载荷缺 %s: %s", want, truncate(env["data"]))
		}
	}
	if !strings.Contains(raw, `"ip":"203.0.113.7"`) {
		t.Errorf("载荷没有回显规范化 IP: %s", truncate(env["data"]))
	}
	if !strings.Contains(raw, `"is_whitelisted":false`) {
		t.Errorf("is_whitelisted 缺席或不是 false: %s", truncate(env["data"]))
	}
}

// TestAnalysisIpPopulatedWiring 核对库里有真实读数时，综合分析确把它们接了出来——
// 风险向量 / 封禁历史 / 信誉 / 白名单命中都非降级值。降级形状由上面两个用例钉住，
// 这一条钉「接线到位」：桩改成真查库后，读数必须真的流到载荷里。
func TestAnalysisIpPopulatedWiring(t *testing.T) {
	db := newAnalysisDB(t, "populated.db")
	const ip = "203.0.113.7"

	// 风险向量：七维给定值，total_risk 应为各维之和 = 15。
	vec := risk.RiskVector{Failure: 1, Ban: 2, Scan: 3, Bruteforce: 4, DDoS: 5, Geo: 0, Cluster: 0}
	if err := db.UpsertRiskVector(ip, vec, 1_700_000_000); err != nil {
		t.Fatalf("写风险向量失败: %v", err)
	}
	// 封禁历史：一条临时封禁（计划 3600s），ban_count=2。
	dur := int64(3600)
	if err := db.RecordBanEvent(ip, "sshd", 2, false, &dur); err != nil {
		t.Fatalf("写封禁事件失败: %v", err)
	}
	// 信誉：score=30。
	if err := db.SetIPReputation(ip, 30); err != nil {
		t.Fatalf("写信誉失败: %v", err)
	}
	// 白名单：覆盖该 IP 的 /24。GlobalWhitelist 是全局单例，测后必须清理，别污染其他用例。
	prefix := mustPrefix(t, "203.0.113.0/24")
	bans.GlobalWhitelist().Add(prefix)
	t.Cleanup(func() { _ = bans.GlobalWhitelist().Remove(prefix) })

	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.DB = db })

	w := authedGet(t, s, "/api/v2/analysis/ip/"+ip)
	if w.Code != http.StatusOK {
		t.Fatalf("合法 IP 状态码 %d，期望 200（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	env := decodeEnvelope(t, w.Body.Bytes())
	var data map[string]any
	if err := json.Unmarshal(env["data"], &data); err != nil {
		t.Fatalf("data 不是对象: %v（data=%s）", err, env["data"])
	}

	riskObj, ok := data["risk"].(map[string]any)
	if !ok {
		t.Fatalf("risk = %v，期望对象（已写入风险向量，不该是 null）", data["risk"])
	}
	if got, _ := riskObj["total_risk"].(float64); got != 15 {
		t.Errorf("risk.total_risk = %v，期望 15（七维之和）", riskObj["total_risk"])
	}

	hist, ok := data["ban_history"].([]any)
	if !ok || len(hist) == 0 {
		t.Fatalf("ban_history = %v，期望非空（已写入一条封禁事件）", data["ban_history"])
	}
	first, _ := hist[0].(map[string]any)
	if first["jail"] != "sshd" {
		t.Errorf("ban_history[0].jail = %v，期望 sshd", first["jail"])
	}
	if got, _ := first["ban_count"].(float64); got != 2 {
		t.Errorf("ban_history[0].ban_count = %v，期望 2", first["ban_count"])
	}
	if got, _ := first["is_permanent"].(bool); got {
		t.Errorf("ban_history[0].is_permanent = %v，期望 false", first["is_permanent"])
	}

	rep, ok := data["reputation"].(map[string]any)
	if !ok {
		t.Fatalf("reputation = %v，期望对象（已写入信誉，不该是 null）", data["reputation"])
	}
	if got, _ := rep["score"].(float64); got != 30 {
		t.Errorf("reputation.score = %v，期望 30", rep["score"])
	}

	if data["is_whitelisted"] != true {
		t.Errorf("is_whitelisted = %v，期望 true（IP 落在 203.0.113.0/24）", data["is_whitelisted"])
	}

	// summary 的 top_risk_ips 也应含这条向量（同一 ip_risk_vectors 真源）。
	summary := dataOf(t, s, httpcontract.RouteGetApiV2AnalysisSummary)
	arr, ok := summary["top_risk_ips"].([]any)
	if !ok || len(arr) == 0 {
		t.Fatalf("top_risk_ips = %v，期望含已写入的向量", summary["top_risk_ips"])
	}
	found := false
	for _, item := range arr {
		m, _ := item.(map[string]any)
		if m["ip"] == ip {
			found = true
			if got, _ := m["total_risk"].(float64); got != 15 {
				t.Errorf("top_risk_ips[%s].total_risk = %v，期望 15", ip, m["total_risk"])
			}
		}
	}
	if !found {
		t.Errorf("top_risk_ips 未含 %s: %v", ip, arr)
	}
}
