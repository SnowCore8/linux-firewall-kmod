package logparse

import (
	"bytes"
	"testing"
)

// collect 跑一次 Feed 并把回调收到的行复制收集出来（回调切片指向内部缓冲）。
func collect(s *LineSplitter, data []byte, st *SplitStats) [][]byte {
	var out [][]byte
	s.Feed(data, st, func(line []byte) { out = append(out, append([]byte(nil), line...)) })
	return out
}

func assertLines(t *testing.T, got [][]byte, want ...[]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("行数不符: got %d %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("第 %d 行不符: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestSplitsCompleteLinesAndKeepsTail(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	assertLines(t, collect(s, []byte("a\nbb\nccc"), &st), []byte("a"), []byte("bb"))
	if st.Emitted != 2 {
		t.Fatalf("Emitted=%d, want 2", st.Emitted)
	}
	if s.Pending() != 3 {
		t.Fatalf("Pending=%d, want 3（不成行的尾部应挂起）", s.Pending())
	}
}

func TestAcrossChunksJoinsThePartial(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	assertLines(t, collect(s, []byte("abc\nd"), &st), []byte("abc"))
	if s.Pending() != 1 {
		t.Fatalf("Pending=%d, want 1", s.Pending())
	}
	assertLines(t, collect(s, []byte("ef\n"), &st), []byte("def"))
	if st.Emitted != 2 || s.Pending() != 0 {
		t.Fatalf("Emitted=%d Pending=%d, want 2 / 0", st.Emitted, s.Pending())
	}
}

func TestEmptyLinesAreEmitted(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	assertLines(t, collect(s, []byte("\n\n"), &st), []byte{}, []byte{})
	if st.Emitted != 2 {
		t.Fatalf("Emitted=%d, want 2", st.Emitted)
	}
}

func TestCRLFKeepsCarriageReturn(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	assertLines(t, collect(s, []byte("a\r\n"), &st), []byte("a\r"))
}

func TestOversizedLineIsDroppedNotEmitted(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	line := append(bytes.Repeat([]byte{'x'}, MaxLineBytes), '\n')
	if got := collect(s, line, &st); len(got) != 0 {
		t.Fatalf("超长行不应交出: %q", got)
	}
	if st.Oversized != 1 || st.Emitted != 0 || s.Pending() != 0 {
		t.Fatalf("Oversized=%d Emitted=%d Pending=%d", st.Oversized, st.Emitted, s.Pending())
	}
}

func TestOversizedUnterminatedTailIsDroppedDeterministically(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	if got := collect(s, bytes.Repeat([]byte{'y'}, MaxLineBytes), &st); len(got) != 0 {
		t.Fatalf("超长残段不应交出: %q", got)
	}
	if st.Oversized != 1 {
		t.Fatalf("Oversized=%d, want 1", st.Oversized)
	}
	if s.Pending() != 0 {
		t.Fatalf("超长残段不得留在缓冲里: Pending=%d", s.Pending())
	}
}

// 超长行跨读批次时，后续残余必须一直丢弃到真正的换行：否则剩余半行会在下一批
// 被当成新行输出，伪造出一个 IP。
func TestOversizedLineAcrossBatchesStaysDiscardedUntilNewline(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats

	first := bytes.Repeat([]byte{'z'}, MaxLineBytes-1)
	if got := collect(s, first, &st); len(got) != 0 || st.Oversized != 0 {
		t.Fatalf("差 1 字节到上限时仍是半行: lines=%q oversized=%d", got, st.Oversized)
	}
	if s.Pending() != MaxLineBytes-1 {
		t.Fatalf("Pending=%d, want %d", s.Pending(), MaxLineBytes-1)
	}

	// 第二批无换行：触发超长丢弃并入「丢弃至换行」状态。
	if got := collect(s, bytes.Repeat([]byte{'z'}, 128), &st); len(got) != 0 || st.Oversized != 1 || s.Pending() != 0 {
		t.Fatalf("触发超长丢弃: lines=%q oversized=%d pending=%d", got, st.Oversized, s.Pending())
	}

	// 第三批仍无换行：整批丢弃，不重复计超长，也不产出伪造行。
	fake := []byte("Failed password for root from 198.51.100.7")
	if got := collect(s, fake, &st); len(got) != 0 || st.Oversized != 1 {
		t.Fatalf("无换行的后续批次必须整批丢弃: lines=%q oversized=%d", got, st.Oversized)
	}

	// 换行出现后恢复正常：前导残余属于超长行，只有换行后的内容成行。
	assertLines(t, collect(s, []byte(" tail\nok\n"), &st), []byte("ok"))
	if st.Oversized != 1 || st.Emitted != 1 {
		t.Fatalf("Oversized=%d Emitted=%d, want 1 / 1", st.Oversized, st.Emitted)
	}
}

// 若换行与后续正常行落在同一批，超长行只计一次，正常行照常交出。
func TestOversizedLineEndingInLaterBatchEmitsFollowingLines(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	collect(s, bytes.Repeat([]byte{'z'}, MaxLineBytes-1), &st)
	assertLines(t, collect(s, []byte("zzz\nnext\n"), &st), []byte("next"))
	if st.Oversized != 1 || st.Emitted != 1 {
		t.Fatalf("Oversized=%d Emitted=%d, want 1 / 1", st.Oversized, st.Emitted)
	}
}

// Flush 复位丢弃状态：关闭 / 轮转后不会把新文件内容继续当作超长行。
func TestFlushResetsOversizedDiscardState(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	collect(s, bytes.Repeat([]byte{'q'}, MaxLineBytes), &st)
	if st.Oversized != 1 {
		t.Fatalf("Oversized=%d, want 1", st.Oversized)
	}

	var out [][]byte
	s.Flush(&st, func(line []byte) { out = append(out, append([]byte(nil), line...)) })
	if len(out) != 0 {
		t.Fatalf("超长行挂起部分不得交出: %q", out)
	}
	assertLines(t, collect(s, []byte("after\n"), &st), []byte("after"))
}

// Clear 同样复位丢弃状态。
func TestClearResetsOversizedDiscardState(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	collect(s, bytes.Repeat([]byte{'q'}, MaxLineBytes), &st)
	s.Clear()
	assertLines(t, collect(s, []byte("fresh\n"), &st), []byte("fresh"))
}

func TestFlushEmitsTailThenStaysEmpty(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	if got := collect(s, []byte("partial"), &st); len(got) != 0 {
		t.Fatalf("无换行不应交出整行: %q", got)
	}

	var out [][]byte
	s.Flush(&st, func(line []byte) { out = append(out, append([]byte(nil), line...)) })
	assertLines(t, out, []byte("partial"))
	if st.Emitted != 1 {
		t.Fatalf("Emitted=%d, want 1", st.Emitted)
	}

	var again [][]byte
	s.Flush(&st, func(line []byte) { again = append(again, append([]byte(nil), line...)) })
	if len(again) != 0 || st.Emitted != 1 {
		t.Fatalf("重复 Flush 应为空操作: again=%q Emitted=%d", again, st.Emitted)
	}
}

func TestClearDropsPartial(t *testing.T) {
	s := NewLineSplitter()
	var st SplitStats
	if got := collect(s, []byte("stale-tail"), &st); len(got) != 0 {
		t.Fatalf("不应交出: %q", got)
	}
	s.Clear()
	if s.Pending() != 0 {
		t.Fatalf("Clear 后 Pending=%d, want 0", s.Pending())
	}
}

// 切分结果不得依赖读块边界：整体喂入与逐字节喂入必须产出相同的行序列。
func TestSplitIsIndependentOfChunkBoundaries(t *testing.T) {
	data := []byte("alpha\nbeta\ngamma")

	whole := NewLineSplitter()
	var ws SplitStats
	wholeLines := collect(whole, data, &ws)

	piecewise := NewLineSplitter()
	var ps SplitStats
	var piecewiseLines [][]byte
	for _, b := range data {
		piecewise.Feed([]byte{b}, &ps, func(line []byte) {
			piecewiseLines = append(piecewiseLines, append([]byte(nil), line...))
		})
	}

	assertLines(t, wholeLines, []byte("alpha"), []byte("beta"))
	assertLines(t, piecewiseLines, []byte("alpha"), []byte("beta"))
	if whole.Pending() != piecewise.Pending() {
		t.Fatalf("切分不得依赖读块边界: whole=%d piecewise=%d", whole.Pending(), piecewise.Pending())
	}
}
