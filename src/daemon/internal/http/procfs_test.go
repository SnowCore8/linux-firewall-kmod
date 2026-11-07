package http

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempStats 把内容写入临时文件并返回路径，模拟 /proc/firewall/stats。
func writeTempStats(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "stats")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp stats: %v", err)
	}
	return p
}

func TestReadStateSaveTruncated_NoFile(t *testing.T) {
	// 文件不存在时降级返回 0（模块未加载的正常情况）。
	if v := readStateSaveTruncated("/nonexistent/path/stats"); v != 0 {
		t.Errorf("expected 0 when procfs absent, got %d", v)
	}
}

func TestReadStateSaveTruncated_ParsesValue(t *testing.T) {
	p := writeTempStats(t, "current_bans 42\nstate_save_truncated 7\ntotal_bans 100\n")
	if v := readStateSaveTruncated(p); v != 7 {
		t.Errorf("expected 7, got %d", v)
	}
}

func TestReadStateSaveTruncated_MissingKey(t *testing.T) {
	p := writeTempStats(t, "current_bans 42\ntotal_bans 100\n")
	if v := readStateSaveTruncated(p); v != 0 {
		t.Errorf("expected 0 when key absent, got %d", v)
	}
}

func TestReadStateSaveTruncated_IgnoresSimilarKeys(t *testing.T) {
	// 精确匹配：state_save_truncated_foo 不应被当成 state_save_truncated。
	p := writeTempStats(t, "state_save_truncated_foo 99\nstate_save_truncated 3\n")
	if v := readStateSaveTruncated(p); v != 3 {
		t.Errorf("expected 3 (exact match), got %d", v)
	}
}

func TestReadStateSaveTruncated_MalformedValue(t *testing.T) {
	p := writeTempStats(t, "state_save_truncated notanumber\n")
	if v := readStateSaveTruncated(p); v != 0 {
		t.Errorf("expected 0 on malformed value, got %d", v)
	}
}

func TestReadStateSaveTruncated_EmptyFile(t *testing.T) {
	p := writeTempStats(t, "")
	if v := readStateSaveTruncated(p); v != 0 {
		t.Errorf("expected 0 on empty file, got %d", v)
	}
}
