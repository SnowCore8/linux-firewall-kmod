package logger

import (
	"errors"
	"strings"
	"testing"
)

// failingSink 每次写都失败。
type failingSink struct{ calls int }

func (s *failingSink) Write([]byte) (int, error) { s.calls++; return 0, errors.New("写失败") }
func (s *failingSink) Close() error              { return nil }

// bufferSink 把 syncBuffer 适配成 sink。
type bufferSink struct{ *syncBuffer }

func (bufferSink) Close() error { return nil }

// closeErrSink 记录是否被关闭，并可返回关闭错误。
type closeErrSink struct {
	err    error
	closed bool
}

func (s *closeErrSink) Write(p []byte) (int, error) { return len(p), nil }
func (s *closeErrSink) Close() error                { s.closed = true; return s.err }

// TestFanoutKeepsGoingAfterSinkError 断言单个 sink 出错不阻断其余 sink——「文件写不进去但
// 系统日志照常」依赖的正是这一性质。
func TestFanoutKeepsGoingAfterSinkError(t *testing.T) {
	var buf syncBuffer
	bad := &failingSink{}
	w := fanout([]sink{bad, bufferSink{&buf}})

	line := "一行\n"
	n, err := w.Write([]byte(line))
	if err == nil {
		t.Fatal("应返回首个错误")
	}
	if bad.calls != 1 {
		t.Fatalf("每个 sink 应恰好被调用一次，实际 %d", bad.calls)
	}
	if buf.String() != line {
		t.Fatalf("其余 sink 仍应收到数据: %q", buf.String())
	}
	if n != len(line) {
		t.Fatalf("应返回已写出的最大字节数，实际 %d", n)
	}
}

// TestFanoutWritesEverySink 断言全部 sink 都收到同一份数据且无错误。
func TestFanoutWritesEverySink(t *testing.T) {
	var a, b syncBuffer
	w := fanout([]sink{bufferSink{&a}, bufferSink{&b}})
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if a.String() != "x" || b.String() != "x" {
		t.Fatalf("所有 sink 都应收到数据: %q %q", a.String(), b.String())
	}
}

// TestCloseAllReturnsFirstError 断言关闭全部 sink，并返回首个错误。
func TestCloseAllReturnsFirstError(t *testing.T) {
	want := errors.New("关闭失败")
	first := &closeErrSink{}
	second := &closeErrSink{err: want}

	err := closeAll([]sink{first, second})()
	if !errors.Is(err, want) {
		t.Fatalf("应返回首个关闭错误，实际 %v", err)
	}
	if !first.closed || !second.closed {
		t.Fatal("所有 sink 都应被关闭")
	}
}

// TestStderrSinkWritesToStderr 断言 stderr sink 直写进程 stderr，关闭是空操作。
func TestStderrSinkWritesToStderr(t *testing.T) {
	out := captureStderr(t, func() {
		s := newStderrSink()
		if _, err := s.Write([]byte("直写 stderr\n")); err != nil {
			t.Errorf("写入失败: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Errorf("关闭应为空操作: %v", err)
		}
	})
	if !strings.Contains(out, "直写 stderr") {
		t.Fatalf("stderr 未收到内容: %q", out)
	}
}

// TestWarnStderrWritesToStderr 断言初始化期告警直写 stderr。
func TestWarnStderrWritesToStderr(t *testing.T) {
	out := captureStderr(t, func() { warnStderr("打开 %s 失败: %d", "路径", 7) })
	if !strings.Contains(out, "警告: 打开 路径 失败: 7") {
		t.Fatalf("告警内容不符: %q", out)
	}
}
