package contract

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestClampFixedStringFitsTheField 把「裁完必须编得进去」这条闭环钉死：putStr 对超长
// 是报错而不是截断，所以任何一个送进定长字段的标签都得先过这里。
func TestClampFixedStringFitsTheField(t *testing.T) {
	long := strings.Repeat("a", 40)
	cjk := "集群扫描: 203.0.113.0/24 命中 4 个源 IP（峰值 1 次）"

	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"没超长原样返回", "manual", FixedReasonLen, "manual"},
		{"恰好到上限原样返回", strings.Repeat("a", FixedReasonLen-1), FixedReasonLen, strings.Repeat("a", FixedReasonLen-1)},
		{"超长裁到上限", long, FixedReasonLen, strings.Repeat("a", FixedReasonLen-1)},
		{"中文字段不切半字", cjk, FixedReasonLen, "集群扫描: 203.0.113.0/24 "},
		{"上限 1 只留得下空串", "abc", 1, ""},
		{"上限 0 与负数同样为空", "abc", 0, ""},
	}

	for _, c := range cases {
		got := ClampFixedString(c.in, c.n)
		if got != c.want {
			t.Errorf("%s: 裁剪结果 %q，期望 %q", c.name, got, c.want)
		}
		if len(got) >= c.n && c.n > 1 {
			t.Errorf("%s: 结果仍占 %d 字节，字段上限 %d（含 NUL）", c.name, len(got), c.n)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: 结果不是合法 UTF-8: %q", c.name, got)
		}
		// 裁剪的唯一起点是「让编码别再因为标签失败」，所以必须真的编得进去。
		buf := make([]byte, c.n)
		if c.n > 1 {
			if err := putStr(buf, 0, c.n, got); err != nil {
				t.Errorf("%s: 裁剪后仍编码失败: %v", c.name, err)
			}
		}
	}
}
