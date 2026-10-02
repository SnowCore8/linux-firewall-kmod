package runtime

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// SignalKind 是主链路关心的控制信号类别。
type SignalKind int

const (
	// SignalTerminate 请求优雅退出（SIGTERM / SIGINT）。
	SignalTerminate SignalKind = iota
	// SignalReload 请求热重载配置（SIGHUP）。
	SignalReload
	// SignalRollback 请求回滚配置（SIGUSR1）。
	SignalRollback
)

// signalByte 把信号类别编成自管道里的一个字节。
func signalByte(kind SignalKind) byte { return byte(kind) }

// kindFromByte 把自管道里读出的字节还原成信号类别。
func kindFromByte(b byte) (SignalKind, bool) {
	switch SignalKind(b) {
	case SignalTerminate, SignalReload, SignalRollback:
		return SignalKind(b), true
	default:
		return 0, false
	}
}

// SignalSource 把进程信号桥接成一路可被 poll 等待的 fd。
//
// 旧实现用 signalfd 把信号并进事件循环：阻塞掩码、建 fd、再把 fd 交给 poll 一同等待。
// Go 不能照搬——运行时会自管信号处理，全线程阻塞信号会与运行时冲突——因此改为
// `signal.Notify` 收信号，再用自管道在收到信号时写入一字节唤醒 poll 循环。消费端看到
// 的仍是「一路可读 fd + 读出类别」，与 signalfd 的用法一致。
type SignalSource struct {
	ch   chan os.Signal
	done chan struct{}
	r    int
	w    int
}

// NewSignalSource 建立信号桥。返回错误表示自管道创建失败。
//
// 关注的信号：SIGTERM / SIGINT（退出）、SIGHUP（重载）、SIGUSR1（回滚）。SIGPIPE 不
// 在此列——HTTP/SSE 写端断开以 EPIPE 形式返回给写调用，不需要当成控制信号。
func NewSignalSource() (*SignalSource, error) {
	fds := []int{0, 0}
	if err := unix.Pipe2(fds, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return nil, err
	}
	s := &SignalSource{
		ch:   make(chan os.Signal, 8),
		done: make(chan struct{}),
		r:    fds[0],
		w:    fds[1],
	}
	signal.Notify(s.ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR1)
	go s.pump()
	return s, nil
}

// pump 把收到的信号转成一个字节写进自管道；退出时停止。
func (s *SignalSource) pump() {
	for {
		select {
		case <-s.done:
			return
		case sig := <-s.ch:
			kind, ok := classifySignal(sig)
			if !ok {
				continue
			}
			// 非阻塞写：管道满说明还有未消费的信号，丢掉这一次等价于内核把同类
			// 信号合并，语义上无损（消费端每次唤醒都会把存量读空）。
			_, _ = unix.Write(s.w, []byte{signalByte(kind)})
		}
	}
}

// classifySignal 把进程信号映射为控制类别。
func classifySignal(sig os.Signal) (SignalKind, bool) {
	switch sig {
	case syscall.SIGTERM, syscall.SIGINT:
		return SignalTerminate, true
	case syscall.SIGHUP:
		return SignalReload, true
	case syscall.SIGUSR1:
		return SignalRollback, true
	default:
		return 0, false
	}
}

// FD 返回读端 fd，供与其它 fd 一并 poll。
func (s *SignalSource) FD() int { return s.r }

// PollRead 非阻塞读出一个待处理信号；无待处理信号时 ok=false。
//
// 与旧实现「循环调用直到拿到 None」的用法对应：调用方在信号已就绪时应循环取空。
func (s *SignalSource) PollRead() (kind SignalKind, ok bool, err error) {
	var buf [1]byte
	n, err := unix.Read(s.r, buf[:])
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, false, nil
		}
		return 0, false, err
	}
	if n == 0 {
		return 0, false, nil
	}
	if k, valid := kindFromByte(buf[0]); valid {
		return k, true, nil
	}
	return 0, false, nil
}

// Close 停止转发并释放 fd。重复调用是安全的。
func (s *SignalSource) Close() {
	signal.Stop(s.ch)
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	if s.r >= 0 {
		_ = unix.Close(s.r)
		s.r = -1
	}
	if s.w >= 0 {
		_ = unix.Close(s.w)
		s.w = -1
	}
}
