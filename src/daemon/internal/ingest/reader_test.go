package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

// newTempDir 在系统临时目录下建唯一子目录，避免污染仓库。
func newTempDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("建临时目录失败：%v", err)
	}
	return dir
}

func appendFile(t *testing.T, path string, data []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("追加打开失败：%v", err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatalf("追加失败：%v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("sync 失败：%v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭失败：%v", err)
	}
}

// TestOpenAtEndSkipsExistingHistory 覆盖启动语义：不回放历史。
func TestOpenAtEndSkipsExistingHistory(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, []byte("history-1\nhistory-2\n"), 0o644); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}

	r := NewSourceReader(nil)
	r.OpenAtEnd(path)
	if !r.IsOpen() {
		t.Fatal("启动期应成功打开")
	}
	if r.Offset() != 20 {
		t.Fatalf("启动偏移必须是文件末尾（20），实得 %d", r.Offset())
	}

	chunk, err := r.ReadNew(path)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	if len(chunk.Bytes) != 0 {
		t.Fatalf("启动后未追加时不应读出历史内容，实得 %q", chunk.Bytes)
	}

	appendFile(t, path, []byte("new-line\n"))
	chunk, err = r.ReadNew(path)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	if string(chunk.Bytes) != "new-line\n" {
		t.Fatalf("只应读出追加部分，实得 %q", chunk.Bytes)
	}
	if chunk.Rotated {
		t.Fatal("追加不构成轮转")
	}
	if r.Offset() != 29 {
		t.Fatalf("偏移应为 29，实得 %d", r.Offset())
	}
}

// TestReadBufferIsReusedAcrossReads 覆盖长驻读缓冲：不得每轮重新分配。
//
// 旧实现的 256 KiB 缓冲每批事件重建一次，这既是分配压力也是内存抖动来源。
func TestReadBufferIsReusedAcrossReads(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "a.log")
	appendFile(t, path, nil)

	r := NewSourceReader(nil)
	r.OpenAtEnd(path)

	appendFile(t, path, []byte("x\n"))
	if _, err := r.ReadNew(path); err != nil {
		t.Fatalf("读失败：%v", err)
	}
	base := &r.buffer[0]

	for i := 0; i < 8; i++ {
		appendFile(t, path, []byte("line\n"))
		if _, err := r.ReadNew(path); err != nil {
			t.Fatalf("读失败：%v", err)
		}
	}

	if &r.buffer[0] != base {
		t.Fatal("读缓冲不应每轮重新分配")
	}
	if len(r.buffer) != BatchReadMax {
		t.Fatalf("缓冲容量应为 %d，实得 %d", BatchReadMax, len(r.buffer))
	}
}

// TestTruncationResetsOffsetAndFlagsRotation 覆盖 copytruncate 风格轮转。
func TestTruncationResetsOffsetAndFlagsRotation(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, []byte("aaaa\nbbbb\n"), 0o644); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}

	r := NewSourceReader(nil)
	r.OpenAtEnd(path)
	appendFile(t, path, []byte("more\n"))
	first, err := r.ReadNew(path)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	if string(first.Bytes) != "more\n" {
		t.Fatalf("实得 %q", first.Bytes)
	}

	if err := os.WriteFile(path, []byte("fresh\n"), 0o644); err != nil {
		t.Fatalf("截断写失败：%v", err)
	}
	chunk, err := r.ReadNew(path)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	if !chunk.Rotated {
		t.Fatal("截断必须置 Rotated，调用方据此清半行缓冲")
	}
	if string(chunk.Bytes) != "fresh\n" {
		t.Fatalf("截断后应从 0 重读，实得 %q", chunk.Bytes)
	}
	if r.Offset() != 6 {
		t.Fatalf("偏移应为 6，实得 %d", r.Offset())
	}
}

// TestInodeChangeIsDetectedAsRotation 覆盖 logrotate 风格轮转。
func TestInodeChangeIsDetectedAsRotation(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}

	r := NewSourceReader(nil)
	r.OpenAtEnd(path)
	oldInode := r.Inode()
	if oldInode == 0 {
		t.Fatal("应取得 inode")
	}

	// logrotate 风格：改名后新建同名文件（新 inode）。
	if err := os.Rename(path, filepath.Join(dir, "a.log.1")); err != nil {
		t.Fatalf("改名失败：%v", err)
	}
	if err := os.WriteFile(path, []byte("brand-new\n"), 0o644); err != nil {
		t.Fatalf("建新文件失败：%v", err)
	}

	chunk, err := r.ReadNew(path)
	if err != nil {
		t.Fatalf("读失败：%v", err)
	}
	if !chunk.Rotated {
		t.Fatal("inode 变化必须置 Rotated")
	}
	if string(chunk.Bytes) != "brand-new\n" {
		t.Fatalf("实得 %q", chunk.Bytes)
	}
	if r.Inode() == oldInode {
		t.Fatal("应换用新 inode 的 fd")
	}
}

// TestSymlinkAfterStartupIsSoftSkip 覆盖「启动后文件被换成符号链接」。
//
// O_NOFOLLOW 必须拒读链接目标，否则日志路径可被替换成 /etc/shadow 之类的敏感
// 文件，解析器会把其中的内容当作日志行处理。
func TestSymlinkAfterStartupIsSoftSkip(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "a.log")
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("real\n"), 0o644); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}
	if err := os.WriteFile(target, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}

	r := NewSourceReader(nil)
	r.OpenAtEnd(path)

	if err := os.Remove(path); err != nil {
		t.Fatalf("删除失败：%v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("建符号链接失败：%v", err)
	}

	chunk, err := r.ReadNew(path)
	if err != nil {
		t.Fatalf("符号链接不应是硬错误：%v", err)
	}
	if len(chunk.Bytes) != 0 {
		t.Fatalf("不应读出符号链接目标内容，实得 %q", chunk.Bytes)
	}
}

// TestMissingFileIsSoftSkip 覆盖缺文件：保持未打开，下轮重试。
func TestMissingFileIsSoftSkip(t *testing.T) {
	dir := newTempDir(t)
	r := NewSourceReader(nil)
	chunk, err := r.ReadNew(filepath.Join(dir, "nope.log"))
	if err != nil {
		t.Fatalf("缺文件不应是硬错误：%v", err)
	}
	if len(chunk.Bytes) != 0 {
		t.Fatalf("实得 %q", chunk.Bytes)
	}
	if r.IsOpen() {
		t.Fatal("打不开时应保持未打开，下轮重试")
	}
}

// TestDirectoryReplacingTheFileIsTreatedAsRotation 覆盖路径被换成目录。
func TestDirectoryReplacingTheFileIsTreatedAsRotation(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "a.log")
	if err := os.WriteFile(path, []byte("data\n"), 0o644); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}

	r := NewSourceReader(nil)
	r.OpenAtEnd(path)
	if err := os.Remove(path); err != nil {
		t.Fatalf("删除失败：%v", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("建目录失败：%v", err)
	}

	chunk, err := r.ReadNew(path)
	if err != nil {
		t.Fatalf("不应是硬错误：%v", err)
	}
	if !chunk.Rotated {
		t.Fatal("非普通文件应置 Rotated")
	}
	if r.IsOpen() {
		t.Fatal("应回到未打开状态，下一轮若能打开则重新读取")
	}
}

// TestCloseIsIdempotent 覆盖重复关闭。
func TestCloseIsIdempotent(t *testing.T) {
	dir := newTempDir(t)
	path := filepath.Join(dir, "a.log")
	appendFile(t, path, []byte("x\n"))

	r := NewSourceReader(nil)
	r.OpenAtEnd(path)
	if err := r.Close(); err != nil {
		t.Fatalf("首次关闭失败：%v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("重复关闭应无害：%v", err)
	}
	if r.IsOpen() {
		t.Fatal("关闭后不应报告已打开")
	}
}
