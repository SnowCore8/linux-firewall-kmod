package telemetry

import (
	"sync"
	"time"
)

// DefaultRingSize 是最近事件环的容量。
//
// 512 条够用且上界明确：面板的「最近事件」列表一次取 50–100 条，断线重连后要补的历史
// 也就在这个量级；再大只是把内存换成更长的可回溯时间，而真正的历史在 SQLite 里。
const DefaultRingSize = 512

// 事件类别取值。写入者是事件泵，读取者是面板与诊断端点，因此这里是一份封闭清单，
// 新增类别必须同时给出写入点。
const (
	// EventBan 是内核封禁生效（含 procfs 手工封禁与内核自动封禁）。
	EventBan = "ban"
	// EventUnban 是内核解封。
	EventUnban = "unban"
	// EventWhitelistAdd 是白名单加入。
	EventWhitelistAdd = "whitelist_add"
	// EventWhitelistRemove 是白名单移除。
	EventWhitelistRemove = "whitelist_remove"
	// EventDdos 是速率/协议阈值命中。
	EventDdos = "ddos"
	// EventCommandError 是内核对本进程指令的失败回执（CmdResult）。
	EventCommandError = "command_error"
)

// Event 是一条已发生的内核事件。
//
// 字段是扁平的而不是 union：读侧（面板列表、阈值告警、诊断输出）几乎只看 Kind 与地址，
// 做成带指针的联合只会让每个读取者都要先判空。Value 承载该类别唯一的数值（ddos 的命中
// 速率、command_error 的 errno），无值时为 0。
type Event struct {
	// Seq 是进程内单调递增的序号，读侧可据此判重与增量拉取。
	Seq uint64 `json:"seq"`
	// Kind 是事件类别（见 Event* 常量）。
	Kind string `json:"kind"`
	// IP 是来源/目标地址文本；空串表示与地址无关。
	IP string `json:"ip,omitempty"`
	// PrefixLen 是与该地址配套的前缀长度（0 表示未知/不适用）。
	PrefixLen uint8 `json:"prefix_len,omitempty"`
	// Jail 是归属 jail 名（内核侧字段，可为空）。
	Jail string `json:"jail,omitempty"`
	// Reason 是人类可读原因或失败原文。
	Reason string `json:"reason,omitempty"`
	// Value 是该类别的数值载荷。
	Value uint64 `json:"value,omitempty"`
	// At 是事件被记录的时刻。
	At time.Time `json:"at"`
}

// Ring 是固定容量的事件环形缓冲。可并发使用。
//
// 与快照不同，这里必须加锁：写入者是事件泵，读取者是 HTTP 请求线程，而「一次读取」要
// 跨越多个槽位，非原子的拷贝在环形下标回绕时会读到混合的新旧数据。
type Ring struct {
	mu    sync.Mutex
	size  int
	slots []Event
	// next 是下一次写入的下标。
	next uint64
	// count 是已写入的总数（用于给出 Seq 与判断是否已填满）。
	count uint64
}

// NewRing 建立容量为 size 的事件环；size <= 0 时取 DefaultRingSize。
func NewRing(size int) *Ring {
	if size <= 0 {
		size = DefaultRingSize
	}
	return &Ring{size: size, slots: make([]Event, size)}
}

// Push 记一条事件并返回它带上序号的副本。At 为零值时补当前时间。
func (r *Ring) Push(e Event) Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	e.Seq = r.count
	if e.At.IsZero() {
		e.At = time.Now()
	}
	r.slots[r.next%uint64(r.size)] = e
	r.next++
	return e
}

// Latest 返回最近 n 条，按时间倒序（最新在前）。n 超过环内实际条数时返回全部。
func (r *Ring) Latest(n int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	// 可回溯的条数是 min(count, size)：按 count 夹会让 n 落到已被覆盖的槽位上，
	// 读出重复的最新事件而不是更早的历史。
	avail := int(r.count)
	if avail > r.size {
		avail = r.size
	}
	if avail == 0 || n <= 0 {
		return nil
	}
	if n > avail {
		n = avail
	}
	// next 指向下一个待写槽，故最新一条在 (next-1)；n 已被 avail 夹住，下标不会为负。
	out := make([]Event, 0, n)
	size := uint64(r.size)
	for i := 0; i < n; i++ {
		out = append(out, r.slots[(r.next-1-uint64(i))%size])
	}
	return out
}

// Len 返回环内当前可回溯的事件条数（不超过容量）。
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count < uint64(r.size) {
		return int(r.count)
	}
	return r.size
}

// Capacity 返回环容量。
func (r *Ring) Capacity() int { return r.size }
