package risk

import "strings"

// toFloat64 把 payload 里的数值统一成 float64。
//
// JSON 反序列化后数字默认类型是 float64，但调用方也可能直接传 int。
// 两处都认，避免类型断言失败导致分类逻辑永远走默认分支。
func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	default:
		return 0, false
	}
}

// ClassifyFailure 根据事件类型和负载分类攻击事件，返回事件类型和向量增量。
//
// 纯函数，不依赖任何状态，便于测试。
//
// eventType 是日志解析后的事件类型（如 "ssh_failure"、"http_401"）。
// payload 是附加信息（如端口号、路径等），可用于细分事件。
//
// 返回值：
//   - EventType：分类后的事件类型（EventFailure、EventScan 等）
//   - float64：该事件对应的向量增量（典型值 1.0-10.0）
func ClassifyFailure(eventType string, payload map[string]any) (EventType, float64) {
	lower := strings.ToLower(eventType)

	switch {
	case strings.Contains(lower, "scan"):
		return EventScan, classifyScanIncrement(payload)
	case strings.Contains(lower, "brute") || strings.Contains(lower, "bruteforce"):
		return EventBruteforce, classifyBruteforceIncrement(payload)
	case strings.Contains(lower, "ddos") || strings.Contains(lower, "flood"):
		return EventDDoS, classifyDDoSIncrement(payload)
	case strings.Contains(lower, "geo") || strings.Contains(lower, "region"):
		return EventGeo, classifyGeoIncrement(payload)
	case strings.Contains(lower, "cluster") || strings.Contains(lower, "关联"):
		return EventCluster, classifyClusterIncrement(payload)
	case strings.Contains(lower, "ban"):
		return EventBan, classifyBanIncrement(payload)
	default:
		return EventFailure, classifyFailureIncrement(payload)
	}
}

// classifyFailureIncrement 根据负载判定认证失败的向量增量。
//
// 默认增量 1.0；高频失败（payload["count"] > 10）增量 5.0。
func classifyFailureIncrement(payload map[string]any) float64 {
	if payload == nil {
		return 1.0
	}
	if count, ok := payload["count"]; ok {
		if c, ok := toFloat64(count); ok && c > 10 {
			return 5.0
		}
	}
	return 1.0
}

// classifyScanIncrement 根据负载判定扫描行为的向量增量。
//
// 端口扫描（payload["ports"] > 100）增量 10.0；目录遍历增量 5.0；默认 3.0。
func classifyScanIncrement(payload map[string]any) float64 {
	if payload == nil {
		return 3.0
	}
	if ports, ok := payload["ports"]; ok {
		if p, ok := toFloat64(ports); ok && p > 100 {
			return 10.0
		}
	}
	if path, ok := payload["path"]; ok {
		if p, ok := path.(string); ok && (strings.Contains(p, "..") || strings.Contains(p, "%2e")) {
			return 5.0
		}
	}
	return 3.0
}

// classifyBruteforceIncrement 根据负载判定爆破行为的向量增量。
//
// 高频爆破（payload["rate"] > 100/min）增量 10.0；默认 5.0。
func classifyBruteforceIncrement(payload map[string]any) float64 {
	if payload == nil {
		return 5.0
	}
	if rate, ok := payload["rate"]; ok {
		if r, ok := toFloat64(rate); ok && r > 100 {
			return 10.0
		}
	}
	return 5.0
}

// classifyDDoSIncrement 根据负载判定 DDoS 行为的向量增量。
//
// 流量型攻击（payload["pps"] > 10000）增量 20.0；默认 10.0。
func classifyDDoSIncrement(payload map[string]any) float64 {
	if payload == nil {
		return 10.0
	}
	if pps, ok := payload["pps"]; ok {
		if p, ok := toFloat64(pps); ok && p > 10000 {
			return 20.0
		}
	}
	return 10.0
}

// classifyGeoIncrement 根据负载判定异常地域的向量增量。
//
// 境外访问增量 3.0；默认 2.0。
func classifyGeoIncrement(payload map[string]any) float64 {
	if payload == nil {
		return 2.0
	}
	if foreign, ok := payload["foreign"]; ok {
		if f, ok := foreign.(bool); ok && f {
			return 3.0
		}
	}
	return 2.0
}

// classifyClusterIncrement 根据负载判定关联集群的向量增量。
//
// 与已知恶意 IP 关联增量 5.0；默认 3.0。
func classifyClusterIncrement(payload map[string]any) float64 {
	if payload == nil {
		return 3.0
	}
	if malicious, ok := payload["malicious"]; ok {
		if m, ok := malicious.(bool); ok && m {
			return 5.0
		}
	}
	return 3.0
}

// classifyBanIncrement 根据负载判定封禁历史的向量增量。
//
// 永久封禁增量 10.0；临时封禁增量 5.0。
func classifyBanIncrement(payload map[string]any) float64 {
	if payload == nil {
		return 5.0
	}
	if permanent, ok := payload["permanent"]; ok {
		if p, ok := permanent.(bool); ok && p {
			return 10.0
		}
	}
	return 5.0
}
