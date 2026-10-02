package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// syncBuffer 是并发安全的字节缓冲，用于捕获处理器输出。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// splitLines 去掉结尾换行后按换行拆分；中间空行保留——那是缺陷信号。
func splitLines(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// decodeJSON 解析一行 JSON 为映射；失败即测试失败。
func decodeJSON(t *testing.T, line string) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal([]byte(line), &fields); err != nil {
		t.Fatalf("非法 JSON 行 %q: %v", line, err)
	}
	return fields
}

// writeLine 向输出端写一整行。
func writeLine(t *testing.T, w io.Writer, line string) {
	t.Helper()
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
}

// rotationFiles 返回 `<base>` 与 `<base>.<n>` 的合集，按名字排序。
func rotationFiles(t *testing.T, path string) []string {
	t.Helper()
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("列目录失败: %v", err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base) {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	return files
}

// readFile 读回文本内容。
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return string(data)
}

// captureStderr 在 fn 执行期间把 os.Stderr 重定向到管道，返回写出的全部内容。
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	saved := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("创建管道失败: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = saved }()

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("关闭管道写端失败: %v", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("读取管道失败: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("关闭管道读端失败: %v", err)
	}
	return string(data)
}

// resetLogFilePath 清除已登记的日志文件路径，使各测试互不影响。
func resetLogFilePath() { logFilePath.Store(nil) }

// errDialFailed 表示测试中的连接尝试一律失败。
var errDialFailed = errors.New("模拟连接失败")

// failDialer 模拟 syslog / journald 不可用。
func failDialer(string, string) (*syslog.Writer, error) {
	return nil, errDialFailed
}
