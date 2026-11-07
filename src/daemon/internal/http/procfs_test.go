package http

import (
	"testing"
)

func TestReadStateSaveTruncated_NoFile(t *testing.T) {
	// /proc/firewall/stats 不存在时返回 0（模块未加载的正常情况）。
	// CI 环境通常没有内核模块加载，故这条路径是默认分支。
	if v := readStateSaveTruncated(); v != 0 {
		t.Errorf("expected 0 when procfs absent, got %d", v)
	}
}
