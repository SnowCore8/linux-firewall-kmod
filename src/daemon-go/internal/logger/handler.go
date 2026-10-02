package logger

import (
	"io"
	"log/slog"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// sink 是一条输出通道：文件、syslog 或 stderr。
type sink interface {
	io.Writer
	Close() error
}

// fanoutWriter 把一次写分发给所有 sink，逐个尝试。
//
// 与 io.MultiWriter 不同，任一 sink 出错不会中断其余 sink——「文件写不进去但系统日志照常」
// 依赖的正是这一性质。返回值取已写出的最大字节数与首个错误，满足 io.Writer 契约。
type fanoutWriter []sink

func fanout(sinks []sink) io.Writer { return fanoutWriter(sinks) }

func (f fanoutWriter) Write(p []byte) (int, error) {
	written := 0
	var firstErr error
	for _, s := range f {
		n, err := s.Write(p)
		if n > written {
			written = n
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return written, firstErr
}

// newHandler 按配置的格式建立处理器。
func newHandler(format uint8, w io.Writer, level slog.Level) slog.Handler {
	if format == config.LogFormatJSON {
		return newJSONHandler(w, level)
	}
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
}

// closeAll 依次关闭所有 sink，返回首个错误。
func closeAll(sinks []sink) func() error {
	return func() error {
		var first error
		for _, s := range sinks {
			if err := s.Close(); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
}
