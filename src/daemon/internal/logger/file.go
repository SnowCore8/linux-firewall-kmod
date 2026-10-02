package logger

import (
	"fmt"
	"os"
	"sync"
)

// rotatedPath 返回轮转片路径 `<base>.<n>`，n 越大越旧。
func rotatedPath(base string, n uint32) string {
	return fmt.Sprintf("%s.%d", base, n)
}

// stderrSink 写 stderr。与 Rust 版不同，Go 不需要 dup(2)：os.Stderr 由运行时持有，关闭本
// sink 不会关掉进程的 stderr，因此 Close 是空操作。
type stderrSink struct{}

func newStderrSink() sink { return stderrSink{} }

func (stderrSink) Write(p []byte) (int, error) { return os.Stderr.Write(p) }
func (stderrSink) Close() error                { return nil }

// fileSink 是按大小轮转的追加式文件 sink。
//
// 轮转与写入共用一把锁：改名、开新文件、重置字节计数都在锁内完成，避免并发写者看到中途的
// inode，或把一条记录切进两片。
type fileSink struct {
	mu       sync.Mutex
	file     *os.File
	path     string
	written  uint64
	maxBytes uint64
	maxFiles uint32
}

// newFileSink 打开（或创建）日志文件，并用其当前大小播种轮转计数。
//
// maxBytes 为 0 表示关闭轮转；maxFiles 至少为 1（1 表示只留当前片）。
func newFileSink(path string, maxBytes uint64, maxFiles uint32) (*fileSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	var written uint64
	if fi, statErr := f.Stat(); statErr == nil {
		written = uint64(fi.Size())
	}
	if maxFiles < 1 {
		maxFiles = 1
	}
	return &fileSink{file: f, path: path, written: written, maxBytes: maxBytes, maxFiles: maxFiles}, nil
}

// Write 单次写出整行；若本次会超出单片上限，先在锁内完成轮转。
//
// `written > 0` 这个前提有两重作用：刚打开的空文件不会立刻轮转，且单条超长记录不会被反复
// 轮转（始终允许至少写出一条）。
func (s *fileSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxBytes > 0 && s.written > 0 && s.written+uint64(len(p)) > s.maxBytes {
		if err := s.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := s.file.Write(p)
	s.written += uint64(n)
	return n, err
}

// Close 关闭当前文件句柄；重复调用是空操作。
//
// 关闭后不可再写入：生产路径不调用它（进程退出即释放句柄），调用方仅在测试里用完即弃。
func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// rotate 轮转一次：删最旧片 → 依次改名 → 当前片改名 `.1` → 开新文件。
//
// 片名范围 `.1`（最新）到 `.maxFiles-1`（最旧）。maxFiles 为 1 表示只保留当前片，没有历史
// 可留，直接截断。
func (s *fileSink) rotate() error {
	if s.maxFiles <= 1 {
		if err := s.file.Truncate(0); err != nil {
			return err
		}
		s.written = 0
		return nil
	}
	if err := os.Remove(rotatedPath(s.path, s.maxFiles-1)); err != nil && !os.IsNotExist(err) {
		return err
	}
	for i := s.maxFiles - 2; i >= 1; i-- {
		from := rotatedPath(s.path, i)
		if _, err := os.Stat(from); err != nil {
			continue
		}
		if err := os.Rename(from, rotatedPath(s.path, i+1)); err != nil {
			return err
		}
	}
	if err := os.Rename(s.path, rotatedPath(s.path, 1)); err != nil {
		return err
	}
	next, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_ = s.file.Close()
	s.file = next
	s.written = 0
	return nil
}
