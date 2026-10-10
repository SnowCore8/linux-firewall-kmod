// 速率历史读数面：GET /api/v1/rates/history。
//
// 数据源是守护进程侧的速率历史环（internal/telemetry/rate_history.go）：事件泵每成功
// 问一次内核速率表就落一个点，节奏 = 采样周期（当前 5 秒）。
//
// 这里曾经有一条「从 /proc/firewall/rates 读历史」的路径，它解析的
// `timestamp rate_pps type` 格式内核从来没有产出过（procfs 的 rates 文件是速率表的
// 当前快照，不是时间序列），于是那条路径恒返回解析空结果，端点看起来在工作、实际
// 一直在走降级分支。改读环之后，图上的每个点都对应一次真实的内核回答。
package http

import (
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

// 速率历史的取数上限。
//
// 两者相同：默认给一整段可回溯窗口（环容量，当前 720 点 ≈ 1 小时），显式 limit 只能
// 要得更少不能要得更多——要得更多时环里也没有，返回一批零等于伪造历史。
const (
	ratesHistoryDefault = telemetry.DefaultRateHistorySize
	ratesHistoryMax     = telemetry.DefaultRateHistorySize
)

// GetRatesHistory 返回全局速率的时间序列（GET /api/v1/rates/history）。
//
// 载荷是 RateHistoryResponse **数组**，按时间升序（最早在前）：折线图按 x 轴递增画，
// 倒序会让前端每次自己反转。查询参数 limit 取最近 n 个点。
//
// 采样中断（链路断开、内核未加载）留下的是**空洞**而不是补出来的零速率点：图上表现为
// 相邻两点间隔变长，这正确描述了「那段时间没人知道速率」。
func (h *APIHandlers) GetRatesHistory(w http.ResponseWriter, r *http.Request) {
	limit := parseLimit(r, ratesHistoryDefault, ratesHistoryMax)
	samples := h.rateSamples(limit)

	out := make([]RateHistoryResponse, 0, len(samples))
	for _, s := range samples {
		out = append(out, RateHistoryResponse{
			Timestamp:  uint64(s.At.Unix()),
			TotalPps:   s.TotalPPS,
			TotalBps:   s.TotalBPS,
			TrackedIps: s.TrackedIPs,
		})
	}
	WriteSuccess(w, out)
}
