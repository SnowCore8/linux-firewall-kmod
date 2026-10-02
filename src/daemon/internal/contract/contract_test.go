package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// layoutJSON 对应 contract/generated/netlink_layout.json 里测试需要的字段。
type layoutJSON struct {
	Source     string `json:"source"`
	Endianness string `json:"endianness"`
	Packed     bool   `json:"packed"`
	MsgLenMax  int    `json:"msg_len_max"`
	Magic      struct {
		Name  string `json:"name"`
		Value uint32 `json:"value"`
	} `json:"magic"`
	Enums map[string]struct {
		Width   string           `json:"width"`
		Members map[string]int64 `json:"members"`
	} `json:"enums"`
	Bits map[string]struct {
		Width   string           `json:"width"`
		Members map[string]int64 `json:"members"`
	} `json:"bits"`
	Layouts map[string]struct {
		Kind string `json:"kind"`
		Size int    `json:"size"`
		Tail *struct {
			Elem       string `json:"elem"`
			ElemSize   int    `json:"elem_size"`
			FixedSize  int    `json:"fixed_size"`
			MaxEntries int    `json:"max_entries"`
		} `json:"tail"`
		Fields []struct {
			Name   string `json:"name"`
			Offset int    `json:"offset"`
			Size   int    `json:"size"`
			Type   string `json:"type"`
			Tail   bool   `json:"tail"`
		} `json:"fields"`
	} `json:"layouts"`
}

// findUp 从当前测试文件所在目录逐级向上查找相对路径，避免在测试里硬编码绝对路径。
func findUp(t *testing.T, rel string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 失败，无法定位测试文件")
	}
	dir := filepath.Dir(thisFile)
	for {
		cand := filepath.Join(dir, rel)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("向上查找未找到 %s", rel)
		}
		dir = parent
	}
}

func loadLayout(t *testing.T) *layoutJSON {
	t.Helper()
	raw, err := os.ReadFile(findUp(t, filepath.Join("contract", "generated", "netlink_layout.json")))
	if err != nil {
		t.Fatalf("读取布局清单失败: %v", err)
	}
	var lj layoutJSON
	if err := json.Unmarshal(raw, &lj); err != nil {
		t.Fatalf("解析布局清单失败: %v", err)
	}
	return &lj
}

// TestWireLayoutMatchesContract 逐字段比对 Go 侧布局声明与契约生成的布局清单。
func TestWireLayoutMatchesContract(t *testing.T) {
	lj := loadLayout(t)

	if lj.Source != "netlink.fwidl" {
		t.Errorf("布局清单来源为 %q，期望 netlink.fwidl", lj.Source)
	}
	if lj.Endianness != Endianness {
		t.Errorf("字节序 %q 与 Go 侧常量 %q 不符", lj.Endianness, Endianness)
	}
	if !lj.Packed {
		t.Error("契约要求 packed 布局，布局清单却标为非 packed")
	}
	if lj.MsgLenMax != MsgLenMax {
		t.Errorf("msg_len 上限 %d 与 Go 侧常量 %d 不符", lj.MsgLenMax, MsgLenMax)
	}
	if lj.Magic.Value != Magic {
		t.Errorf("魔数 0x%08X 与 Go 侧常量 0x%08X 不符", lj.Magic.Value, Magic)
	}
	if lj.Magic.Name != "FW_NL_MAGIC" {
		t.Errorf("魔数常量名为 %q，期望 FW_NL_MAGIC", lj.Magic.Name)
	}

	if len(wireLayouts) != len(lj.Layouts) {
		t.Errorf("Go 侧声明 %d 个布局，契约有 %d 个", len(wireLayouts), len(lj.Layouts))
	}
	for name, cl := range lj.Layouts {
		gl, ok := wireLayouts[name]
		if !ok {
			t.Errorf("契约里的 %s 在 Go 侧没有布局声明", name)
			continue
		}
		if gl.size != cl.Size {
			t.Errorf("%s 定长大小：Go 声明 %d，契约 %d", name, gl.size, cl.Size)
		}
		if cl.Tail != nil {
			te, ok := tailElems[name]
			if !ok {
				t.Errorf("契约里的 %s 是分页响应，Go 侧没有尾部声明", name)
				continue
			}
			if te.elem != cl.Tail.Elem {
				t.Errorf("%s 尾部元素：Go 声明 %s，契约 %s", name, te.elem, cl.Tail.Elem)
			}
			if te.elemSize != cl.Tail.ElemSize {
				t.Errorf("%s 尾部元素大小：Go 声明 %d，契约 %d", name, te.elemSize, cl.Tail.ElemSize)
			}
			if cl.Tail.FixedSize != cl.Size {
				t.Errorf("%s 契约自相矛盾：fixed_size %d 与 size %d 不等", name, cl.Tail.FixedSize, cl.Size)
			}
			if want := (MsgLenMax - cl.Size) / cl.Tail.ElemSize; te.maxEntries != cl.Tail.MaxEntries || te.maxEntries != want {
				t.Errorf("%s 单页上限：Go 声明 %d，契约 %d，按 (65535-%d)/%d 算得 %d",
					name, te.maxEntries, cl.Tail.MaxEntries, cl.Size, cl.Tail.ElemSize, want)
			}
		}
		for _, f := range cl.Fields {
			if f.Tail {
				continue
			}
			got, ok := gl.offsets[f.Name]
			if !ok {
				t.Errorf("%s 缺少字段 %s 的偏移声明", name, f.Name)
				continue
			}
			if got != f.Offset {
				t.Errorf("%s.%s 偏移：Go 声明 %d，契约 %d", name, f.Name, got, f.Offset)
			}
		}
	}
}
