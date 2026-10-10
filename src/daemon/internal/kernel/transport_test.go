package kernel

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newTestTransport 建立一条真实的 netlink 链路（不订阅广播组）。
//
// 这些测试观察的是「Poll 是否真的看 fd」，必须用真 fd——伪造的 fd 会让 epoll 注册直接
// 失败，测不出任何东西。生产链路的 groups=1 需要 CAP_NET_ADMIN，这里取 groups=0：普通
// 进程即可建链，于是 epoll/eventfd 这套就绪观察在开发机与 CI 上都能真跑，而不是整组跳过。
func newTestTransport(t *testing.T) *Transport {
	t.Helper()
	tr, err := openTransport(0)
	if err != nil {
		t.Skipf("无法建立 netlink 链路: %v", err)
	}
	t.Cleanup(tr.Close)
	return tr
}

// TestPollWakesOnLinkDownBeforeTimeout 验证链路断开能立刻打断等待中的 Poll。
//
// 这是 epoll + eventfd 那一对的存在理由：只看超时的旧实现里，Close 后接收回路仍要等到
// 自己的 PollInterval 走完才发现链路已断。
func TestPollWakesOnLinkDownBeforeTimeout(t *testing.T) {
	tr := newTestTransport(t)

	go func() {
		time.Sleep(20 * time.Millisecond)
		tr.SignalLinkDown()
	}()

	start := time.Now()
	ready, err := tr.Poll(10*time.Second, EventRx|EventLinkDown)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Poll 失败: %v", err)
	}
	if !ready.Has(EventLinkDown) {
		t.Fatalf("Poll 返回 %v，期望 EventLinkDown", ready)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("等待了 %v 才发现断开，唤醒未生效", elapsed)
	}
}

// TestPollReportsReadiness 验证对端发来报文时 Poll 报出 EventRx，且 TryRecv 能取到。
//
// 旧实现完全不看 fd：reactor 每 100ms 硬排空一次，报文到达延迟被轮询周期决定。
func TestPollReportsReadiness(t *testing.T) {
	tr := newTestTransport(t)

	pid, err := netlinkPortID(tr.Fd())
	if err != nil {
		t.Skipf("读取本进程 portid 失败: %v", err)
	}
	peer, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, netlinkProto)
	if err != nil {
		t.Skipf("无法建立对端 socket: %v", err)
	}
	defer unix.Close(peer)

	// netlink 要求用户态自带 nlmsghdr，故按 Transport.Send 的同样方式补头。
	payload := []byte("ready")
	buf := make([]byte, nlmsgHdrLen+len(payload))
	putU32NE(buf[0:4], uint32(len(buf)))
	copy(buf[nlmsgHdrLen:], payload)
	if err := unix.Sendto(peer, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: pid}); err != nil {
		t.Fatalf("对端发送失败: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		ready, err := tr.Poll(200*time.Millisecond, EventRx|EventLinkDown)
		if err != nil {
			t.Fatalf("Poll 失败: %v", err)
		}
		if ready.Has(EventLinkDown) {
			t.Fatal("链路意外断开")
		}
		if ready.Has(EventRx) {
			dg, ok, err := tr.TryRecv()
			if err != nil {
				t.Fatalf("TryRecv 失败: %v", err)
			}
			if !ok {
				t.Fatal("Poll 报可读但无数据")
			}
			// TryRecv 已剥掉 nlmsghdr，剩下的就是对端放的内容。
			if string(dg.Payload) != string(payload) {
				t.Fatalf("载荷 = %q，期望 %q", dg.Payload, payload)
			}
			// 非 0 的 portid 表示发送方是本机另一个进程而不是内核（内核恒为 0）。
			// 路由器据此把它整条丢掉并计数——见下面顺带钉住的这条。
			if dg.PortID == 0 {
				t.Fatal("对端报文的 portid 不应为 0")
			}
			router, events := NewEventChannel(4)
			router.HandleDatagram(dg)
			if got := router.Stats().ForeignPortID; got != 1 {
				t.Fatalf("外部 portid 未被计数: %d", got)
			}
			if len(events) != 0 {
				t.Fatal("不可信来源的报文进入了事件队列")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("3 秒内未观察到可读事件")
		}
	}
}

// TestPollHonorsInterestingMask 验证不索要可读性时保持纯定时语义。
func TestPollHonorsInterestingMask(t *testing.T) {
	tr := newTestTransport(t)
	ready, err := tr.Poll(30*time.Millisecond, EventLinkDown)
	if err != nil {
		t.Fatalf("Poll 失败: %v", err)
	}
	if ready != EventInterrupt {
		t.Fatalf("空闲等待返回 %v，期望 EventInterrupt", ready)
	}
}

// TestPollRespectsDeadline 验证 SetDeadline 的截止时间优先于 timeout。
func TestPollRespectsDeadline(t *testing.T) {
	tr := newTestTransport(t)
	tr.SetDeadline(20 * time.Millisecond)
	time.Sleep(40 * time.Millisecond)

	ready, err := tr.Poll(10*time.Second, EventRx|EventLinkDown)
	if err != nil {
		t.Fatalf("Poll 失败: %v", err)
	}
	if ready != EventDeadline {
		t.Fatalf("已过截止时间应返回 EventDeadline，实际 %v", ready)
	}

	tr.ClearDeadline()
	if ready, err := tr.Poll(20*time.Millisecond, EventRx|EventLinkDown); err != nil || ready != EventInterrupt {
		t.Fatalf("清除截止时间后 = (%v, %v)", ready, err)
	}
}

// TestClosedTransportReportsLinkDown 验证 Close 之后 Poll 不再等待。
func TestClosedTransportReportsLinkDown(t *testing.T) {
	tr := newTestTransport(t)
	tr.Close()
	ready, err := tr.Poll(5*time.Second, EventRx|EventLinkDown)
	if err != nil {
		t.Fatalf("Poll 失败: %v", err)
	}
	if !ready.Has(EventLinkDown) {
		t.Fatalf("已关闭的链路应报 EventLinkDown，实际 %v", ready)
	}
}

// TestResubscribeReplacesPendingWake 验证换接收方时旧的唤醒计数被清空。
//
// 不清空的话，新接收方的第一次 Poll 会立刻拿到上一轮的断开事件，看起来「一上线就断链」。
func TestResubscribeReplacesPendingWake(t *testing.T) {
	tr := newTestTransport(t)
	if err := tr.Subscribe(); err != nil {
		t.Fatalf("设置接收模式失败: %v", err)
	}
	tr.SignalLinkDown()
	// 先把唤醒消费掉一次，模拟旧接收方已见断开。
	if ready, err := tr.Poll(time.Second, EventRx|EventLinkDown); err != nil || !ready.Has(EventLinkDown) {
		t.Fatalf("首次断开未被观察到: (%v, %v)", ready, err)
	}
	tr.resetLinkDown()

	ready, err := tr.Poll(50*time.Millisecond, EventRx|EventLinkDown)
	if err != nil {
		t.Fatalf("Poll 失败: %v", err)
	}
	if ready.Has(EventLinkDown) {
		t.Fatal("重新武装后仍报告断开")
	}
}

// netlinkPortID 取 socket 的内核分配 portid（nl_pid）。
func netlinkPortID(fd int) (uint32, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return 0, err
	}
	nl, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return 0, errors.New("不是 netlink 地址")
	}
	return nl.Pid, nil
}
