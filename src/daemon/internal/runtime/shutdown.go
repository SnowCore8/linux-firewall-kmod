package runtime

import "sync"

// Shutdown 是一个「只置位、不撤销」的停机标志。
//
// 旧实现用一个跨线程共享的原子布尔量在组合根、信号处理与主循环之间传递停机意图；
// 这里把它封成类型而不是裸 bool：置位点可能有多个（信号、致命错误），轮询点只有主
// 循环一处，类型化后读写的意图更清楚，也避免误把标志当普通布尔传递。
//
// 置位由 sync.Once 关闭一条通道完成：语义仍是布尔（重复 Request 无副作用、IsShutdown
// 单调），但等待方能 select 挂在 Done 上。执行体的关停路径要同时等「自己的循环返回」
// 与「停机请求」两件事，只能等通道的写法做不到——那需要轮询。
type Shutdown struct {
	once sync.Once
	done chan struct{}
}

// NewShutdown 新建未置位的停机标志。
func NewShutdown() *Shutdown { return &Shutdown{done: make(chan struct{})} }

// Request 置位停机标志。重复调用无副作用。
func (s *Shutdown) Request() { s.once.Do(func() { close(s.done) }) }

// IsShutdown 报告是否已请求停机。
func (s *Shutdown) IsShutdown() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// Done 在停机标志置位后关闭，供执行体与关停路径 select 等待，不用轮询。
func (s *Shutdown) Done() <-chan struct{} { return s.done }
