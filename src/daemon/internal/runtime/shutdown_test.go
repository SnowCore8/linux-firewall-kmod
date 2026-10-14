// 停机令牌的可等待面：执行体的关停路径要靠它，而不是轮询 IsShutdown。
package runtime

import (
	"testing"
	"time"
)

func TestShutdownDoneUnblocksWaiters(t *testing.T) {
	token := NewShutdown()
	if token.IsShutdown() {
		t.Fatalf("新建令牌已处于停机态")
	}
	select {
	case <-token.Done():
		t.Fatalf("未 Request 时 Done 就已关闭")
	default:
	}

	token.Request()
	select {
	case <-token.Done():
	case <-time.After(time.Second):
		t.Fatalf("Request 后 Done 未关闭")
	}
	if !token.IsShutdown() {
		t.Errorf("Request 后 IsShutdown 仍为 false")
	}
	// 重复置位是无副作用的：令牌已关闭，再 Request 不该 panic。
	token.Request()
}

// TestSupervisorJoinsExecutorWaitingOnToken 是被修掉的那个缺口的形状：执行体不再只跑
// 自己的循环，而是把「循环返回」与「停机请求」两件事一起等，因此监督器能在预算内 join。
func TestSupervisorJoinsExecutorWaitingOnToken(t *testing.T) {
	sup := NewSupervisor()
	token := NewShutdown()
	innerDone := make(chan struct{})
	sup.Spawn("waiter", token, func() {
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			<-innerDone // 模拟一个只有被告知才结束的内部循环
		}()
		select {
		case <-stopped:
		case <-token.Done():
			close(innerDone)
			<-stopped
		}
	})

	results := sup.Shutdown(time.Second)
	if len(results) != 1 || results[0].Outcome != Joined {
		t.Fatalf("关停回报 = %+v，期望 1 条 Joined", results)
	}
	select {
	case <-innerDone:
	default:
		t.Errorf("内部循环没有被关停路径关掉")
	}
}
