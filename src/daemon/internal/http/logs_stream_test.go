// 日志流必须跟随日志 sink 的轮转：rename 轮转后旧 fd 永远 EOF，原地截断后旧偏移
// 要等文件重新长回去才恢复。两种情况不重开都表现为「流静默停住」。
package http

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startTail(t *testing.T, path string) (*sseConn, chan struct{}, context.CancelFunc) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("seek: %v", err)
	}

	conn := &sseConn{out: make(chan []byte, 16)}
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go tailLogs(ctx, path, f, "", conn, done, slog.Default())

	t.Cleanup(func() { cancel() })
	return conn, done, cancel
}

func waitFrame(t *testing.T, conn *sseConn) string {
	t.Helper()

	select {
	case frame := <-conn.out:
		return string(frame)
	case <-time.After(5 * time.Second):
		t.Fatal("等待日志帧超时")
		return ""
	}
}

func TestTailLogsFollowsRenameRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn, _, _ := startTail(t, path)

	// logrotate / fileSink 风格：先改名（旧 fd 跟着旧 inode），再新建同名文件。
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := os.WriteFile(path, []byte("after-rotate\n"), 0o600); err != nil {
		t.Fatalf("write new: %v", err)
	}

	frame := waitFrame(t, conn)
	if !strings.Contains(frame, "after-rotate") {
		t.Fatalf("轮转后未跟随新文件，收到帧: %q", frame)
	}
}

func TestTailLogsFollowsTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	// 初始内容要比截断后写入的多：只有「文件长度 < 当前偏移」才是元数据能分辨的截断，
	// 截断后又立刻长过旧偏移的情况无从察觉，不在本测试范围。
	if err := os.WriteFile(path, []byte("before-before-before-before\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn, _, _ := startTail(t, path)

	// maxFiles=1 的轮转是原地截断：inode 不变，偏移落在新长度之后。
	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	appendLine := func() {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("open append: %v", err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString("after-truncate\n"); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	appendLine()

	frame := waitFrame(t, conn)
	if !strings.Contains(frame, "after-truncate") {
		t.Fatalf("截断后未从头跟随，收到帧: %q", frame)
	}
}

// 生产者退出必须让连接收尾：streamSSE 靠发送通道关闭返回并释放名额。
func TestTailLogsClosesOutOnExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn, _, cancel := startTail(t, path)
	cancel()

	select {
	case _, ok := <-conn.out:
		if ok {
			t.Fatal("取消后发送通道仍可读到帧，期望已关闭")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后发送通道未关闭")
	}
}
