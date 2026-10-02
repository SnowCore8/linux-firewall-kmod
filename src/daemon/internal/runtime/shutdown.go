package runtime

import "sync/atomic"

// Shutdown 是一个「只置位、不撤销」的停机标志。
//
// 旧实现用一个跨线程共享的原子布尔量在组合根、信号处理与主循环之间传递停机意图；
// 这里把它封成类型而不是裸 bool：置位点可能有多个（信号、致命错误），轮询点只有主
// 循环一处，类型化后读写的意图更清楚，也避免误把标志当普通布尔传递。
type Shutdown struct {
	flag atomic.Bool
}

// NewShutdown 新建未置位的停机标志。
func NewShutdown() *Shutdown { return &Shutdown{} }

// Request 置位停机标志。重复调用无副作用。
func (s *Shutdown) Request() { s.flag.Store(true) }

// IsShutdown 报告是否已请求停机。
func (s *Shutdown) IsShutdown() bool { return s.flag.Load() }
