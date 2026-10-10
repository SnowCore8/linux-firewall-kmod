// 全局速率采样环：/api/v1/rates/history 与异常检测的共同数据源。
//
// # 为什么在守护进程侧记，而不是读内核
//
// 内核的速率表只回答「自上次查询以来的平均速率」，它没有历史窗口，procfs 的 rates 文件
// 打印的也是**当前表**而不是时间序列（旧 Go 实现按 `timestamp rate_pps type` 三列文本去
// 解析它，那个格式从来不存在，解析结果恒为空）。事件泵每 5 秒问一次，问到的正好是一个
// 采样点——把它留在这里，历史就有了唯一且真实的来源。
//
// # 为什么固定容量
//
// 720 条 = 一小时（5 秒一条），比面板的折线图需求略多；再长只是把内存换成更旧的历史，
// 而真正的长期历史在 SQLite 的 ban_events 里，速率没有等价表，也不在这里假装有一张。
package telemetry

import (
	"sync"
	"time"
)

// DefaultRateHistorySize 是速率采样环的容量。
//
// 与 kernel.SampleInterval（5 秒）相乘即覆盖时间：720 条 ≈ 一小时。
const DefaultRateHistorySize = 720

// RateSample 是全局速率的一次采样点。
//
// 七个协议维度是**该时刻速率表的每秒速率之和**（内核填的是 smoothed_*，见
// fw_rate.c:fw_rate_fill_row），与 TotalPPS/TotalBPS 同源但通常更小：速率表按源地址逐条
// 平滑，全局值来自内核自己的全局计数，两者本就不是同一条流水线。异常检测按维度各自取
// 分位基线，所以维度必须留在样本里，只存总量就没法回答「是哪一类流量偏离了」。
type RateSample struct {
	// At 是采样时刻，即这一次速率查询成功的时刻。
	At time.Time

	TotalPPS uint64
	TotalBPS uint64

	SynPPS  uint64
	UdpPPS  uint64
	IcmpPPS uint64
	AckPPS  uint64
	RstPPS  uint64
	FinPPS  uint64

	// TrackedIPs 是本次采样时速率表的条目数（内核的全表规模，不是本页条数）。
	TrackedIPs uint32
}

// RateHistory 是固定容量的速率采样环。可并发使用：写入者是事件泵，读取者是 HTTP 线程。
//
// 与 Snapshot 的无锁发布不同，这里必须加锁——一次读取要跨越多个槽位，环形下标回绕时
// 不加锁会读到混合的新旧数据（同 ring.go 的理由）。
type RateHistory struct {
	mu    sync.Mutex
	size  int
	slots []RateSample
	// next 是下一次写入的下标。
	next int
	// count 是可回溯的条数（填满前等于已写入总数，填满后恒为 size）。
	count int
}

// NewRateHistory 建立容量为 size 的采样环；size <= 0 时取 DefaultRateHistorySize。
func NewRateHistory(size int) *RateHistory {
	if size <= 0 {
		size = DefaultRateHistorySize
	}
	return &RateHistory{size: size, slots: make([]RateSample, size)}
}

// Push 记一个采样点；At 为零值时补当前时间。
func (h *RateHistory) Push(s RateSample) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s.At.IsZero() {
		s.At = time.Now()
	}
	h.slots[h.next] = s
	h.next = (h.next + 1) % h.size
	if h.count < h.size {
		h.count++
	}
}

// Samples 返回最近 n 条，**按时间升序**（最旧在前），n <= 0 时返回环内全部。
//
// 升序而不是倒序：调用方是画折线和取分位数的，两者都按时间正向读；环里的物理顺序在
// 回绕处是断开的，所以这里按逻辑顺序重排而不是把内部布局泄漏出去。
func (h *RateHistory) Samples(n int) []RateSample {
	h.mu.Lock()
	defer h.mu.Unlock()
	avail := h.count
	if n <= 0 || n > avail {
		n = avail
	}
	if n == 0 {
		return nil
	}
	out := make([]RateSample, 0, n)
	// 最新一条在 (next-1)，往前取 n 条后按时间正向排列。n 已被 count 夹住，
	// 而 count 不超过 size，故加一个 size 再取模即可得到非负起点。
	start := (h.next - n + h.size) % h.size
	for i := 0; i < n; i++ {
		out = append(out, h.slots[(start+i)%h.size])
	}
	return out
}

// Len 返回环内当前可回溯的条数。
func (h *RateHistory) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// rateSampleFrom 由一次速率采样构造采样点。
//
// 单独成函数是为了让「协议维度求和」这件事只有一处：SetRates 之外没有第二个写入者，
// 而求和口径一旦和异常检测里的定义分叉，基线就会拿 A 口径、当前值拿 B 口径。
func rateSampleFrom(r Rates, at time.Time) RateSample {
	s := RateSample{
		At:         at,
		TotalPPS:   r.GlobalPPS,
		TotalBPS:   r.GlobalBPS,
		TrackedIPs: uint32(len(r.Entries)),
	}
	for _, e := range r.Entries {
		s.SynPPS += e.SynPackets
		s.UdpPPS += e.UDPPackets
		s.IcmpPPS += e.ICMPPackets
		s.AckPPS += e.ACKPackets
		s.RstPPS += e.RSTPackets
		s.FinPPS += e.FINPackets
	}
	return s
}
