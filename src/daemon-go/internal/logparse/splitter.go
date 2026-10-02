package logparse

// MaxLineBytes 是单行硬上限。用 `>=` 判超长，因此恰好 8192 字节的行视为超长。
const MaxLineBytes = 8192

// SplitStats 是一轮分割的计数结果。
type SplitStats struct {
	// Emitted 是交给回调的行数（含空行与 `\r\n` 行——空行过滤属调用方的语义）。
	Emitted uint64
	// Oversized 是被判为超长而丢弃的片段数。
	Oversized uint64
}

// LineSplitter 是单个日志源的行分割器，持有该源尚未成行的尾部字节。
//
// 缓冲挂在**源**上而非 jail 上：同一 jail 的多个日志源各持一个分割器，A 文件的
// 半行只与 A 文件的后续字节拼接。缓冲长驻，容量跨轮复用。
type LineSplitter struct {
	partial []byte
}

// NewLineSplitter 新建分割器。
func NewLineSplitter() *LineSplitter {
	return &LineSplitter{partial: make([]byte, 0, MaxLineBytes)}
}

// Pending 返回当前挂起的半行字节数。
func (s *LineSplitter) Pending() int { return len(s.partial) }

// Clear 丢弃挂起的半行。轮转 / 截断时调用：旧文件的半行不该与新文件的开头拼接。
func (s *LineSplitter) Clear() { s.partial = s.partial[:0] }

// Feed 喂入一批新字节，对每个完整行（不含换行符）调用一次 onLine。
//
// 完整行判据就是裸 `\n`，`\r\n` 行的 `\r` 会保留在行尾（调用方的正则与关键字
// 匹配对此不敏感，故不额外归一化）。超长行（`>= MaxLineBytes`）丢弃并计数。
//
// onLine 收到的切片指向本分割器的内部缓冲，仅在本次回调期间有效：需要留存时必须
// 自己复制，且回调内不得再次调用本分割器的方法。
func (s *LineSplitter) Feed(data []byte, stats *SplitStats, onLine func(line []byte)) {
	if len(data) == 0 {
		return
	}
	s.partial = append(s.partial, data...)

	lineStart := 0
	for scan := 0; scan < len(s.partial); scan++ {
		if s.partial[scan] != '\n' {
			continue
		}
		line := s.partial[lineStart:scan]
		if len(line) >= MaxLineBytes {
			stats.Oversized++
		} else {
			stats.Emitted++
			onLine(line)
		}
		lineStart = scan + 1
	}

	if lineStart > 0 {
		tailLen := len(s.partial) - lineStart
		copy(s.partial, s.partial[lineStart:])
		s.partial = s.partial[:tailLen]
	}

	// 尾部自身已达上限：它既不可能再成行，也无法与后续字节拼成合法行，
	// 确定性丢弃并记入 oversized。
	if len(s.partial) >= MaxLineBytes {
		s.partial = s.partial[:0]
		stats.Oversized++
	}
}

// Flush 把挂起的尾部当作一行取出（不再等待换行）。
//
// 文件关闭 / 轮转 / 截断之前调用，避免丢掉最后一个不完整行。取出后缓冲保留容量。
func (s *LineSplitter) Flush(stats *SplitStats, onLine func(line []byte)) {
	if len(s.partial) == 0 {
		return
	}
	tail := s.partial
	if len(tail) >= MaxLineBytes {
		stats.Oversized++
	} else {
		stats.Emitted++
		onLine(tail)
	}
	s.partial = tail[:0]
}
