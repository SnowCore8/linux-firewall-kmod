package kernel

import (
	"errors"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/runtime"
)

// TestNewEventChannelUsesRequestedCapacity 验证事件通道容量按请求建立。
func TestNewEventChannelUsesRequestedCapacity(t *testing.T) {
	router, events := NewEventChannel(8)
	if router == nil {
		t.Fatal("路由器不应为空")
	}
	if cap(events) != 8 {
		t.Fatalf("事件通道容量 = %d，期望 8", cap(events))
	}
}

// TestNewEventChannelDefaultsCapacity 验证非正容量退回 EventQueue。
func TestNewEventChannelDefaultsCapacity(t *testing.T) {
	_, events := NewEventChannel(0)
	if cap(events) != EventQueue {
		t.Fatalf("默认容量 = %d，期望 %d", cap(events), EventQueue)
	}
}

// TestReactorRunExitsWhenAlreadyShutdown 验证已请求关停时接收回路立即退出并关闭路由器。
func TestReactorRunExitsWhenAlreadyShutdown(t *testing.T) {
	router, _ := NewEventChannel(EventQueue)
	shutdown := runtime.NewShutdown()
	shutdown.Request()

	// 关停已置位 ⇒ Run 的循环体一次也不执行，不会触达 socket，故零值 transport 安全。
	reactor := NewReactor(&Transport{}, router, shutdown, nil)
	reactor.Run()

	// Run 退出时必须关闭路由器：此后登记被拒。
	if _, err := router.Register(contract.MsgStatsResponse, 1); err == nil {
		t.Fatal("接收回路退出后路由器应已关闭，登记应被拒")
	}
}

// TestReactorLinkDownNotifiesHandlerOnce 验证链路断开时回调恰好被调用一次，
// 且接收回路随即退出并关闭路由器。
//
// epFd = -1 让 Poll 走「就绪观察未建立」的定时分支，SignalLinkDown 关闭的通道会
// 立即让它返回 EventLinkDown，无需真实 socket。
func TestReactorLinkDownNotifiesHandlerOnce(t *testing.T) {
	router, _ := NewEventChannel(EventQueue)
	shutdown := runtime.NewShutdown()
	transport := &Transport{fd: -1, epFd: -1, wakeFd: -1, linkDown: make(chan struct{})}

	calls := 0
	var got error
	reactor := NewReactor(transport, router, shutdown, nil, WithLinkDownHandler(func(err error) {
		calls++
		got = err
	}))
	transport.SignalLinkDown()
	reactor.Run()

	if calls != 1 {
		t.Fatalf("链路断开回调调用 %d 次，期望 1", calls)
	}
	if !errors.Is(got, ErrLinkDown) {
		t.Fatalf("回调错误 = %v，期望 ErrLinkDown", got)
	}
	if _, err := router.Register(contract.MsgStatsResponse, 1); err == nil {
		t.Fatal("接收回路退出后路由器应已关闭，登记应被拒")
	}
}
