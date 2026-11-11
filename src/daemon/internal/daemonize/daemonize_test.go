//go:build linux

package daemonize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsChild(t *testing.T) {
	t.Setenv(ChildEnv, "1")
	if !IsChild() {
		t.Fatal(`环境为 "1" 时应判定为子进程`)
	}
	t.Setenv(ChildEnv, "0")
	if IsChild() {
		t.Fatal(`环境为 "0" 时不应判定为子进程`)
	}
	t.Setenv(ChildEnv, "")
	if IsChild() {
		t.Fatal("环境为空时不应判定为子进程")
	}
}

func TestChildEnvSetsMarkerOnce(t *testing.T) {
	got := childEnv([]string{"PATH=/bin", ChildEnv + "=0", "HOME=/root"})

	var markers []string
	for _, kv := range got {
		if strings.HasPrefix(kv, ChildEnv+"=") {
			markers = append(markers, kv)
		}
	}
	if len(markers) != 1 || markers[0] != ChildEnv+"=1" {
		t.Fatalf("标记应唯一且值为 1，实际 %v", markers)
	}

	want := []string{"PATH=/bin", "HOME=/root", ChildEnv + "=1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("环境构造错误\n实际: %v\n期望: %v", got, want)
	}
}

func TestWritePIDFileContentAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := WritePIDFile(path, 1234); err != nil {
		t.Fatalf("写 pid 文件失败: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 pid 文件失败: %v", err)
	}
	if string(data) != "1234\n" {
		t.Fatalf("内容应为 %q，实际 %q", "1234\n", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pid 文件失败: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("权限应为 0644，实际 %#o", mode)
	}
}

func TestWritePIDFileOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := WritePIDFile(path, 1); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if err := WritePIDFile(path, 4321); err != nil {
		t.Fatalf("覆盖写入失败: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 pid 文件失败: %v", err)
	}
	if string(data) != "4321\n" {
		t.Fatalf("覆盖后内容应为 %q，实际 %q", "4321\n", data)
	}

	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), "*tmp*"))
	if err != nil {
		t.Fatalf("glob 失败: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("不应残留临时文件: %v", matches)
	}
}

func TestWritePIDFileMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "daemon.pid")
	if err := WritePIDFile(path, 1); err == nil {
		t.Fatal("父目录不存在时应返回错误")
	}
}

func TestRemovePIDFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := WritePIDFile(path, 9); err != nil {
		t.Fatalf("写 pid 文件失败: %v", err)
	}
	if err := RemovePIDFile(path); err != nil {
		t.Fatalf("删除 pid 文件失败: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("文件应已删除，stat 返回 %v", err)
	}
	if err := RemovePIDFile(path); err != nil {
		t.Fatalf("删除不存在的文件不应报错: %v", err)
	}
}
