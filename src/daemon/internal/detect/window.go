// Package detect 提供封禁判定所需的纯计算部件：失败时间戳滑动窗口、CIDR 归一化。
//
// 这些部件与 Rust 守护进程的 decision / state::cidr 语义对齐，且不持有锁、不做 IO，
// 便于单测与并发复用。
package detect

import "net/netip"

// MaxTimestampsPerIP 是单个 IP 保留的时间戳上限（超出时 FIFO 移出最旧）。
const MaxTimestampsPerIP = 100

// Verdict 是一次观测的结论。
type Verdict struct {
	// Recent 是窗口内（findtime 秒）的失败次数，已按 cap 截断。
	Recent uint32
	// ReachedCap 报告本次观测后窗口内计数是否已达到 cap（触发封禁）。
	ReachedCap bool
}

// FailureWindow 是单个 jail 的失败窗口表，由该 jail 的判定执行体独占，不需要锁。
type FailureWindow struct {
	entries map[netip.Addr][]int64
}

// NewFailureWindow 新建空窗口。
func NewFailureWindow() *FailureWindow {
	return &FailureWindow{entries: make(map[netip.Addr][]int64)}
}

// Len 返回当前被跟踪的 IP 数。
func (w *FailureWindow) Len() int { return len(w.entries) }

// IsEmpty 报告是否没有任何被跟踪的 IP。
func (w *FailureWindow) IsEmpty() bool { return len(w.entries) == 0 }

// Observe 记录一次失败并返回窗口内计数。
//
// findtime == 0 时直接返回零计数（不触发），但仍落一次时间戳，使「窗口为 0」的配置
// 不会静默丢弃观测。时间戳乱序（时钟回拨）时不做每轮过滤：过期与否由计数阶段按调用方
// 给的 now 判定，避免以更靠后的事件时间为准提前丢弃仍在窗口内的旧时间戳。
func (w *FailureWindow) Observe(ip netip.Addr, now int64, findtime, cap uint32) Verdict {
	window := int64(findtime)
	ts := w.entries[ip]

	// 与旧实现对齐：未满则直接追加；仅在满员时才 FIFO 淘汰并顺手过滤过期前缀。
	if len(ts) >= MaxTimestampsPerIP {
		copy(ts, ts[1:])
		ts = ts[:len(ts)-1]
		ts = append(ts, now)
		if window > 0 {
			oldestValid := now - window
			keep := ts[:0]
			for _, v := range ts {
				if v >= oldestValid {
					keep = append(keep, v)
				}
			}
			ts = keep
		}
	} else {
		ts = append(ts, now)
	}
	w.entries[ip] = ts

	if window <= 0 {
		return Verdict{}
	}

	recent := countRecent(ts, now, window, cap)
	return Verdict{Recent: recent, ReachedCap: recent >= cap}
}

// Peek 只读查询窗口内计数（不改动窗口），供 API / 诊断使用。
func (w *FailureWindow) Peek(ip netip.Addr, now int64, findtime, cap uint32) uint32 {
	ts, ok := w.entries[ip]
	if !ok || findtime == 0 {
		return 0
	}
	return countRecent(ts, now, int64(findtime), cap)
}

// Forget 弃该 IP 的窗口。封禁成功后调用，避免重复封禁计数。
func (w *FailureWindow) Forget(ip netip.Addr) { delete(w.entries, ip) }

// CleanupExpired 清理所有时间戳均已过期的条目，返回清理条数。
//
// 判据：窗口内无任何时间戳即删除（含空条目）。时间戳单调追加，故队尾即最新。
func (w *FailureWindow) CleanupExpired(now int64, findtime uint32) int {
	window := int64(findtime)
	removed := 0
	for ip, ts := range w.entries {
		if len(ts) == 0 || now-ts[len(ts)-1] > window {
			delete(w.entries, ip)
			removed++
		}
	}
	return removed
}

// Iter 遍历全部被跟踪的 IP 及其最新时间戳（顺序不保证），供快照导出。
func (w *FailureWindow) Iter(fn func(ip netip.Addr, latest int64, tracked bool)) {
	for ip, ts := range w.entries {
		if len(ts) == 0 {
			fn(ip, 0, false)
			continue
		}
		fn(ip, ts[len(ts)-1], true)
	}
}

// countRecent 统计 [now-window, now] 内的时间戳数，达到 cap 即停止累加。
//
// 只统计不晚于 now 的时间戳（时钟回拨时可能出现未来时间戳）。
func countRecent(ts []int64, now, window int64, cap uint32) uint32 {
	var recent uint32
	for _, t := range ts {
		if now >= t && now-t <= window {
			recent++
			if recent >= cap {
				break
			}
		}
	}
	return recent
}
