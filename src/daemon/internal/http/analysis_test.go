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

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
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
