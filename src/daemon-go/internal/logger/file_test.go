package logger

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"testing"
)

// fixedLine 返回宽度固定（含结尾换行）的一行，首字节为 tag，便于按片核对内容。
func fixedLine(tag byte, width int) string {
	line := make([]byte, width)
	line[0] = tag
	for i := 1; i < width-1; i++ {
		line[i] = '*'
	}
	line[width-1] = '\n'
	return string(line)
}

// mustFileSink 建立文件 sink，失败即测试失败。
func mustFileSink(t *testing.T, path string, maxBytes uint64, maxFiles uint32) *fileSink {
	t.Helper()
	s, err := newFileSink(path, maxBytes, maxFiles)
	if err != nil {
		t.Fatalf("建立文件 sink 失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// assertContent 断言文件内容与期望一致。
func assertContent(t *testing.T, path, want string) {
	t.Helper()
	if got := readFile(t, path); got != want {
		t.Fatalf("%s 内容不符:\n期望 %q\n实际 %q", path, want, got)
	}
}

// assertAbsent 断言路径不存在。
func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s 不应存在（err=%v）", path, err)
	}
}

// TestRotationRenamesCurrentToDot1InOrder 断言轮转把当前片整体改名为 `.1`，旧片依次后移。
func TestRotationRenamesCurrentToDot1InOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	// 每行 60 字节、单片上限 100 字节：第 2 行起每次都触发轮转。
	s := mustFileSink(t, path, 100, 4)

	for _, tag := range []byte{'A', 'B', 'C'} {
		writeLine(t, s, fixedLine(tag, 60))
	}

	assertContent(t, path, fixedLine('C', 60))
	assertContent(t, rotatedPath(path, 1), fixedLine('B', 60))
	assertContent(t, rotatedPath(path, 2), fixedLine('A', 60))
	assertAbsent(t, rotatedPath(path, 3))
}

// TestRotationKeepsAtMostMaxFiles 断言片数不超过 log_max_files，且丢弃的是最旧的片。
func TestRotationKeepsAtMostMaxFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	s := mustFileSink(t, path, 100, 3)

	for _, tag := range []byte{'A', 'B', 'C', 'D', 'E'} {
		writeLine(t, s, fixedLine(tag, 60))
	}

	files := rotationFiles(t, path)
	if len(files) != 3 {
		t.Fatalf("期望 3 个片，实际 %d: %v", len(files), files)
	}
	assertContent(t, path, fixedLine('E', 60))
	assertContent(t, rotatedPath(path, 1), fixedLine('D', 60))
	assertContent(t, rotatedPath(path, 2), fixedLine('C', 60))
}

// TestMaxBytesZeroDisablesRotation 断言上限为 0 时永不轮转，只保留当前片。
func TestMaxBytesZeroDisablesRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	s := mustFileSink(t, path, 0, 3)

	var want string
	for _, tag := range []byte{'A', 'B', 'C', 'D'} {
		writeLine(t, s, fixedLine(tag, 60))
		want += fixedLine(tag, 60)
	}

	files := rotationFiles(t, path)
	if len(files) != 1 {
		t.Fatalf("关闭轮转后不应产生历史片: %v", files)
	}
	assertContent(t, path, want)
}

// TestMaxFilesOneTruncatesCurrent 断言只留当前片时以截断代替轮转，且单行超上限也不反复轮转。
func TestMaxFilesOneTruncatesCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	s := mustFileSink(t, path, 100, 1)

	for _, tag := range []byte{'A', 'B', 'C'} {
		writeLine(t, s, fixedLine(tag, 60))
	}

	files := rotationFiles(t, path)
	if len(files) != 1 {
		t.Fatalf("max_files 为 1 时应只留当前片: %v", files)
	}
	assertContent(t, path, fixedLine('C', 60))

	// 单条记录长于上限时仍要写出：不允许因「写下去会超限」而把它丢掉。
	oversized := fixedLine('Z', 200)
	s2 := mustFileSink(t, filepath.Join(t.TempDir(), "big.log"), 10, 1)
	writeLine(t, s2, oversized)
	assertContent(t, s2.path, oversized)
}

// TestOversizedExistingFileRotatesOnFirstWrite 断言已存在的大文件在首次写入时就整体转出。
func TestOversizedExistingFileRotatesOnFirstWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	existing := fixedLine('O', 5000)
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatalf("预置文件失败: %v", err)
	}

	s := mustFileSink(t, path, 100, 3)
	writeLine(t, s, "line\n")

	assertContent(t, rotatedPath(path, 1), existing)
	assertContent(t, path, "line\n")
}

// TestRotatedSlicesRemainValidJSONL 断言轮转保留下来的记录仍是完整、连续的 JSON 行。
func TestRotatedSlicesRemainValidJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	s := mustFileSink(t, path, 200, 3)

	const total = 40
	for i := 1; i <= total; i++ {
		writeLine(t, s, fmt.Sprintf("{\"n\":%d}\n", i))
	}
	if err := s.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	var ids []int
	for _, file := range rotationFiles(t, path) {
		for _, line := range splitLines(readFile(t, file)) {
			fields := decodeJSON(t, line)
			n, ok := fields["n"].(float64)
			if !ok {
				t.Fatalf("%s 中的行结构不符: %s", file, line)
			}
			ids = append(ids, int(n))
		}
	}
	if len(ids) == 0 {
		t.Fatal("轮转后没有任何记录保留")
	}
	sort.Ints(ids)
	last := ids[len(ids)-1]
	if last != total {
		t.Fatalf("最新记录应为 %d，实际 %d", total, last)
	}
	for i, id := range ids {
		if want := last - len(ids) + 1 + i; id != want {
			t.Fatalf("保留的记录不连续：位置 %d 期望 %d 实际 %d（全部 %v）", i, want, id, ids)
		}
	}
}

// TestConcurrentWritesStayWhole 断言同一进程内并发写者不会把某一行切成两半。
func TestConcurrentWritesStayWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.log")
	s := mustFileSink(t, path, 0, 1)

	const workers, perWorker = 4, 300
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				line := fmt.Sprintf("{\"w\":%d,\"i\":%d}\n", w, i)
				if _, err := s.Write([]byte(line)); err != nil {
					t.Errorf("并发写入失败: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if err := s.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	assertDistinctLines(t, readFile(t, path), workers*perWorker)
}

// 子进程写入模式的环境变量：父进程用它们把本测试二进制再执行一遍作为独立写者。
const (
	envWriterPath  = "FIREWALL_LOGGER_TEST_WRITER_PATH"
	envWriterIndex = "FIREWALL_LOGGER_TEST_WRITER_INDEX"
	envWriterLines = "FIREWALL_LOGGER_TEST_WRITER_LINES"
)

// TestMultiProcessAppendStaysWhole 断言多进程同时追加时，O_APPEND 上的单次写仍按行原子。
//
// 进程内的互斥锁管不住另一个进程，跨进程只能靠「一条记录只 write 一次」这一性质，所以这里
// 真的重新执行本测试二进制作为写者，而不是靠单进程并发替代。
func TestMultiProcessAppendStaysWhole(t *testing.T) {
	if path := os.Getenv(envWriterPath); path != "" {
		writeLinesAsChild(t, path)
		return
	}

	path := filepath.Join(t.TempDir(), "fw.log")
	const children, lines = 4, 400
	for i := 0; i < children; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMultiProcessAppendStaysWhole$")
		cmd.Env = append(os.Environ(),
			envWriterPath+"="+path,
			envWriterIndex+"="+strconv.Itoa(i),
			envWriterLines+"="+strconv.Itoa(lines),
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("子进程 %d 写入失败: %v\n%s", i, err, out)
		}
	}

	assertDistinctLines(t, readFile(t, path), children*lines)
}

// assertDistinctLines 断言正文恰好是 want 行互不重复的 JSON 记录，且没有空行。
func assertDistinctLines(t *testing.T, body string, want int) {
	t.Helper()
	lines := splitLines(body)
	if len(lines) != want {
		t.Fatalf("期望 %d 行，实际 %d", want, len(lines))
	}
	seen := make(map[string]bool, want)
	for _, line := range lines {
		fields := decodeJSON(t, line)
		key := fmt.Sprintf("%v-%v", fields["w"], fields["i"])
		if seen[key] {
			t.Fatalf("重复的记录: %s", key)
		}
		seen[key] = true
	}
}

// writeLinesAsChild 是子进程分支：向共享文件追加指定行数的独立记录。
func writeLinesAsChild(t *testing.T, path string) {
	t.Helper()
	s, err := newFileSink(path, 0, 1)
	if err != nil {
		t.Fatalf("子进程建立文件 sink 失败: %v", err)
	}
	defer s.Close()

	index, err := strconv.Atoi(os.Getenv(envWriterIndex))
	if err != nil {
		t.Fatalf("子进程写入者编号无效: %v", err)
	}
	lines, err := strconv.Atoi(os.Getenv(envWriterLines))
	if err != nil {
		t.Fatalf("子进程行数无效: %v", err)
	}
	for i := 0; i < lines; i++ {
		if _, err := s.Write([]byte(fmt.Sprintf("{\"w\":%d,\"i\":%d}\n", index, i))); err != nil {
			t.Fatalf("子进程写入失败: %v", err)
		}
	}
}
