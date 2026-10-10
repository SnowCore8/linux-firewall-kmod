// 直方图标签表的跨层核对：Go 侧的标签必须与内核采集代码的标签逐字、逐序一致。
//
// 这不是「以防万一」的重复检查：netlink 只传计数，标签是读侧加上去的。内核把某个桶的
// 边界一改（比如把 "1-1.5KB" 挪成 "1-2KB"）而 Go 没跟上，面板上那张图不会报错，只会把
// 每一格贴错名字——比崩掉难发现得多。
package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
)

// kernelTypesH / kernelProcfsC 是内核侧的两张来源表。
//
// 从测试文件位置往仓库根走：src/daemon/internal/contract → 仓库根是四层上级。路径写死
// 成相对层级而不是向上找 .git，是为了让「文件挪了」直接以 open 失败暴露，而不是悄悄
// 读到一个同名但不同处的源文件。
var (
	_, thisFile, _, _ = runtime.Caller(0)
	repoRoot          = filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".."))
	kernelTypesH      = filepath.Join(repoRoot, "src", "kernel-module", "fw_types.h")
	kernelProcfsC     = filepath.Join(repoRoot, "src", "kernel-module", "fw_procfs.c")
)

// cLabelTable 抓 `static const char *const <name>[N] = { "a", "b", ... };` 的字符串字面量。
var cLabelTable = regexp.MustCompile(`(?s)const char \*const\s+(\w+)\s*\[[^\]]*\]\s*=\s*\{([^}]*)\}`)

// kernelLabels 返回内核源里某张标签表的内容（按声明顺序）。
func kernelLabels(t *testing.T, src, table string) []string {
	t.Helper()
	for _, m := range cLabelTable.FindAllStringSubmatch(src, -1) {
		if m[1] != table {
			continue
		}
		return regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`).FindAllString(m[2], -1)
	}
	t.Fatalf("内核源里找不到标签表 %s", table)
	return nil
}

// TestAnalysisLabelsMatchKernel 核对两张直方图标签表：内容、顺序、条数三者都要一致。
func TestAnalysisLabelsMatchKernel(t *testing.T) {
	procfs := readFileOrFail(t, kernelProcfsC)
	types := readFileOrFail(t, kernelTypesH)

	cases := []struct {
		goLabels []string
		goBins   int
		cTable   string
		cCount   string
	}{
		{AnalysisPktSizeLabels[:], AnalysisPktSizeBins, "fw_pkt_size_labels", "FW_PKT_SIZE_BUCKETS"},
		{AnalysisTTLLabels[:], AnalysisTTLBins, "fw_ttl_labels", "FW_TTL_BUCKETS"},
	}
	for _, c := range cases {
		want := unquoteAll(t, kernelLabels(t, procfs, c.cTable))
		if len(want) != len(c.goLabels) {
			t.Errorf("%s: 内核有 %d 个标签，Go 侧有 %d 个", c.cTable, len(want), len(c.goLabels))
		}
		for i := range min(len(want), len(c.goLabels)) {
			if want[i] != c.goLabels[i] {
				t.Errorf("%s: 第 %d 个标签不符，内核 %q vs Go %q", c.cTable, i, want[i], c.goLabels[i])
			}
		}
		// 桶数宏与 Go 常量也要一致：标签对齐了但分桶宽度不同，同样会贴错名。
		n, ok := defineInt(t, types, c.cCount)
		if !ok {
			t.Errorf("%s: 在 fw_types.h 里找不到 #define %s", c.cTable, c.cCount)
		} else if n != c.goBins || n != len(c.goLabels) {
			t.Errorf("%s: 内核桶数 %d，Go 常量 %d、标签数 %d", c.cTable, n, c.goBins, len(c.goLabels))
		}
	}
}

// TestAnalysisPackCapacitiesMatchKernel 核对快照行数上限：AnalysisUDPPortCap /
// AnalysisICMPTypeCap / AnalysisScannerCap 就是内核打包进一条响应的最大行数，
// 读侧据此把「跟踪容量」与「本次带出的行数」分开报，两者混同会把截断藏起来。
func TestAnalysisPackCapacitiesMatchKernel(t *testing.T) {
	types := readFileOrFail(t, kernelTypesH)
	cases := []struct {
		macro string
		got   int
	}{
		{"FW_ANALYSIS_UDP_PACK_MAX", AnalysisUDPPortCap},
		{"FW_ANALYSIS_ICMP_PACK_MAX", AnalysisICMPTypeCap},
		{"PORT_SCAN_MAX_RESULTS", AnalysisScannerCap},
		{"SERVICE_PROBE_MAX_RESULTS", AnalysisScannerCap},
	}
	for _, c := range cases {
		n, ok := defineInt(t, types, c.macro)
		if !ok {
			t.Errorf("fw_types.h 里找不到 #define %s", c.macro)
			continue
		}
		if n != c.got {
			t.Errorf("%s = %d，但 Go 侧的快照行数常量是 %d（两者必须同源）", c.macro, n, c.got)
		}
	}
}

func readFileOrFail(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读内核源 %s 失败: %v", path, err)
	}
	return string(b)
}

// defineInt 取某个宏的整数值。宏写法允许 `#define N 5` 与 `#define N (5)` 两种。
func defineInt(t *testing.T, src, name string) (int, bool) {
	t.Helper()
	re := regexp.MustCompile(fmt.Sprintf(`(?m)^#define\s+%s\s+[^\S\n]*\(?\s*(\d+)\s*\)?`, name))
	m := re.FindStringSubmatch(src)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s 的值不是十进制整数: %q", name, m[1])
	}
	return n, true
}

// unquoteAll 把 FindAllString 带回的带引号字面量剥引号（内核侧不需要转义，标签都是纯 ASCII）。
func unquoteAll(t *testing.T, quoted []string) []string {
	t.Helper()
	out := make([]string, 0, len(quoted))
	for _, q := range quoted {
		s, err := strconv.Unquote(q)
		if err != nil {
			t.Fatalf("解析标签字面量 %s 失败: %v", q, err)
		}
		out = append(out, s)
	}
	return out
}
