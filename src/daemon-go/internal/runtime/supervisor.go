package runtime

import "time"

// StopOutcome 是单个执行体的关停结果。
type StopOutcome int

const (
	// Joined 表示执行体已正常退出并被等待完成。
	Joined StopOutcome = iota
	// TimedOut 表示执行体超时未退出；其 goroutine 可能仍在运行。
	TimedOut
)

// StopResult 是一个执行体的关停回报；Name 供日志与断言使用。
type StopResult struct {
	Name    string
	Outcome StopOutcome
}

// Supervisor 登记执行体，并按依赖逆序逐段串行关停。
//
// 关停不变量是「上游完全停止后才允许下游收尾」（例如内核链路停稳后才 flush 持久化）。
// 要保证这一点就不能一次性通知所有执行体——那会让上下游同时开始收尾，前提失效。因此
// 每个执行体持有自己的 Shutdown 令牌，Shutdown 按登记逆序处理：对当前段 request 后等待
// 其结束，才处理下一段。
//
// 登记顺序即依赖顺序，下游先登记（最后停）；上游后登记（最先停）。逆序串行还消除了一类
// 死锁：上游若阻塞向队列投递，此时下游仍在消费，投递得以完成；上游排空退出后才轮到下游。
type Supervisor struct {
	executors []executorEntry
}

// executorEntry 是一个已登记的执行体。
type executorEntry struct {
	// name 是人类可读名字，用于日志与结果回报。
	name string
	// token 是该执行体专属的关停令牌。
	token *Shutdown
	// done 在执行体 body 返回后关闭，等价于 Rust 侧的 JoinHandle。
	done chan struct{}
}

// NewSupervisor 新建空登记表。
func NewSupervisor() *Supervisor { return &Supervisor{} }

// Len 返回已登记执行体数量。
func (s *Supervisor) Len() int { return len(s.executors) }

// IsEmpty 报告登记表是否为空。
func (s *Supervisor) IsEmpty() bool { return len(s.executors) == 0 }

// Spawn 登记一个执行体并启动其 goroutine。
//
// token 是该执行体专属的关停令牌，body 应监视它并自行退出。登记顺序即依赖顺序：先登记的
// 在关停时最后停。Go 的 goroutine 创建不会失败，故与 Rust 不同，这里不返回错误。
func (s *Supervisor) Spawn(name string, token *Shutdown, body func()) {
	if token == nil {
		token = NewShutdown()
	}
	done := make(chan struct{})
	s.executors = append(s.executors, executorEntry{name: name, token: token, done: done})
	go func() {
		defer close(done)
		body()
	}()
}

// Shutdown 按登记逆序逐段串行关停，每段等待上限 timeout。
//
// 返回结果顺序即实际关停顺序（最上游最先）。每段先置位其令牌，再等待该段结束，之后才处理
// 下一段——这是「上游完全停止后才轮到下游」的实现要点。
func (s *Supervisor) Shutdown(timeout time.Duration) []StopResult {
	results := make([]StopResult, 0, len(s.executors))
	for i := len(s.executors) - 1; i >= 0; i-- {
		exec := s.executors[i]
		exec.token.Request()
		results = append(results, StopResult{Name: exec.name, Outcome: joinWithTimeout(exec.done, timeout)})
	}
	s.executors = nil
	return results
}

// joinWithTimeout 在 timeout 内等待执行体结束；超时返回 TimedOut。
//
// 执行体 panic 不应让关停流程崩溃，故只等待完成信号、不传播 panic——goroutine 内未被
// recover 的 panic 会终止进程，这属于执行体自身的缺陷，不在关停路径上兜底。
func joinWithTimeout(done <-chan struct{}, timeout time.Duration) StopOutcome {
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return Joined
	case <-timer.C:
		return TimedOut
	}
}
