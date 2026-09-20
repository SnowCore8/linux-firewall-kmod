//! 字节流 → 行：每源独立的 partial 行缓冲。
//!
//! 旧实现把 partial 行缓冲挂在 `Jail` 上（`jail.partial_line_buffer`），于是**同一 jail
//! 的多个日志源共用一个缓冲**——A 文件的半行会被追加上 B 文件的半行，且随 jail 重载
//! 被整体清空（`config_reloader::cleanup_partial_line_buffer`）。这里把缓冲挂在
//! **源**上（调用方按 `SourceId` 持有一个 [`LineSplitter`]），语义变成「每个文件各自的
//! 半行只与自己的后续字节拼接」，这是行为修正而非等价迁移。
//!
//! 缓冲是**长驻**的：`feed` 把新字节追加进来、把完整行交给回调、把不成行的尾部原地
//! 前移保留，容量跨轮复用，不产生每批分配。

/// 单行硬上限。与之相符的解析期上限见 [`super::rules::MAX_PARSE_LINE_BYTES`]。
///
/// 用 `>=` 判超长（与旧 `process_lines_in_buffer` 一致），因此恰好 8192 字节的行
/// 视为超长被跳过。
pub const MAX_LINE_BYTES: usize = 8192;

/// 一轮分割的计数结果。调用方据此更新自己的统计（本模块不碰任何全局计数器）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SplitStats {
    /// 交给回调的行数（含空行与 `\r\n` 行——空行过滤属调用方的语义）。
    pub emitted: u64,
    /// 被判为超长而丢弃的片段数。
    pub oversized: u64,
}

/// 单个日志源的行分割器：持有该源尚未成行的尾部字节。
#[derive(Debug)]
pub struct LineSplitter {
    /// 尚未成行的尾部。`feed` 之后长度恒 `< MAX_LINE_BYTES`。
    partial: Vec<u8>,
}

impl Default for LineSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl LineSplitter {
    /// 新建分割器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            partial: Vec::with_capacity(MAX_LINE_BYTES),
        }
    }

    /// 当前挂起的半行字节数。
    #[must_use]
    pub fn pending(&self) -> usize {
        self.partial.len()
    }

    /// 丢弃挂起的半行。
    ///
    /// 轮转 / 截断时调用：旧文件的半行不该与新文件的开头拼接。
    pub fn clear(&mut self) {
        self.partial.clear();
    }

    /// 喂入一批新字节，对每个**完整行**（不含 `\n`）调用一次 `on_line`。
    ///
    /// 行是借出的切片，借用期只在本次回调内——回调需要留存时必须自己 `to_vec()`。
    /// 完整行判据就是 `\n`：与旧实现一样按裸 `\n` 切分，`\r\n` 行的 `\r` 会保留在
    /// 行尾（调用方的正则/关键字匹配对此不敏感，故不额外归一化）。
    ///
    /// 超长行（`>= MAX_LINE_BYTES`）**丢弃并计数**，不交给回调：这种行在解析期也必定
    /// 被拒，提前丢弃可避免把 8 KB 垃圾搬进解析层。
    pub fn feed(&mut self, data: &[u8], stats: &mut SplitStats, mut on_line: impl FnMut(&[u8])) {
        if data.is_empty() {
            return;
        }
        self.partial.extend_from_slice(data);

        let mut line_start = 0usize;
        {
            let buf = &self.partial;
            let mut scan = 0usize;
            while scan < buf.len() {
                if buf[scan] == b'\n' {
                    let line = &buf[line_start..scan];
                    if line.len() >= MAX_LINE_BYTES {
                        stats.oversized += 1;
                    } else {
                        stats.emitted += 1;
                        on_line(line);
                    }
                    line_start = scan + 1;
                }
                scan += 1;
            }
        }

        // 把不成行的尾部前移到缓冲头部，容量保持不变。
        let tail_len = self.partial.len() - line_start;
        if line_start > 0 {
            self.partial.copy_within(line_start.., 0);
            self.partial.truncate(tail_len);
        }

        // 尾部自身已达上限：它既不可能再成行，也无法与后续字节拼成合法行，
        // 确定性丢弃（旧实现在此处存在「按读块边界决定是否把残段交给解析器」的
        // 不确定行为，本实现改为确定性丢弃并记入 oversized）。
        if self.partial.len() >= MAX_LINE_BYTES {
            self.partial.clear();
            stats.oversized += 1;
        }
    }

    /// 把挂起的尾部当作一行取出（不再等待换行）。
    ///
    /// 文件关闭 / 轮转 / 截断之前调用，避免丢掉最后一个不完整行——与旧
    /// `flush_partial_line` 的时机一致。取出后缓冲清空但保留容量。
    pub fn flush(&mut self, stats: &mut SplitStats, mut on_line: impl FnMut(&[u8])) {
        if self.partial.is_empty() {
            return;
        }
        let mut tail = std::mem::take(&mut self.partial);
        if tail.len() >= MAX_LINE_BYTES {
            stats.oversized += 1;
        } else {
            stats.emitted += 1;
            on_line(&tail);
        }
        tail.clear();
        // 返还缓冲以保容量（`mem::take` 会把容量一起换走）。
        self.partial = tail;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 跑一次 `feed`/`flush` 并把回调收到的行收集成 `Vec<Vec<u8>>`。
    fn collect(splitter: &mut LineSplitter, data: &[u8], stats: &mut SplitStats) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        splitter.feed(data, stats, |line| out.push(line.to_vec()));
        out
    }

    #[test]
    fn splits_complete_lines_and_keeps_tail() {
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        assert_eq!(
            collect(&mut s, b"a\nbb\nccc", &mut st),
            vec![b"a".to_vec(), b"bb".to_vec()],
            "只有完整行应被交出"
        );
        assert_eq!(st.emitted, 2);
        assert_eq!(s.pending(), 3, "不成行的尾部应挂起");
    }

    #[test]
    fn across_chunks_joins_the_partial() {
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        // 第一批只交出完整行 `abc`，残段 `d` 挂起。
        assert_eq!(collect(&mut s, b"abc\nd", &mut st), vec![b"abc".to_vec()]);
        assert_eq!(s.pending(), 1);
        // 下一批补全：残段 `d` 必须与 `ef` 拼成 `def`，而不是各自成行。
        assert_eq!(collect(&mut s, b"ef\n", &mut st), vec![b"def".to_vec()]);
        assert_eq!(st.emitted, 2);
        assert_eq!(s.pending(), 0);
    }

    #[test]
    fn empty_lines_are_emitted() {
        // 空行过滤是调用方的语义（旧实现里也由 `process_single_line` 早返回处理）。
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        assert_eq!(
            collect(&mut s, b"\n\n", &mut st),
            vec![Vec::<u8>::new(), Vec::new()]
        );
        assert_eq!(st.emitted, 2);
    }

    #[test]
    fn crlf_keeps_carriage_return() {
        // 记录保真度：只按 `\n` 切分，`\r` 留在行尾（与旧实现一致）。
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        assert_eq!(collect(&mut s, b"a\r\n", &mut st), vec![b"a\r".to_vec()]);
    }

    #[test]
    fn oversized_line_is_dropped_not_emitted() {
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        let mut line = vec![b'x'; MAX_LINE_BYTES];
        line.push(b'\n');
        assert!(collect(&mut s, &line, &mut st).is_empty());
        assert_eq!(st.oversized, 1);
        assert_eq!(st.emitted, 0);
        assert_eq!(s.pending(), 0);
    }

    #[test]
    fn oversized_unterminated_tail_is_dropped_deterministically() {
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        // 无换行且达到上限：确定性丢弃，不等待后续字节。
        assert!(collect(&mut s, &vec![b'y'; MAX_LINE_BYTES], &mut st).is_empty());
        assert_eq!(st.oversized, 1);
        assert_eq!(s.pending(), 0, "超长残段不得留在缓冲里");
    }

    #[test]
    fn flush_emits_tail_then_stays_empty() {
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        assert!(collect(&mut s, b"partial", &mut st).is_empty());

        let mut out = Vec::new();
        s.flush(&mut st, |line| out.push(line.to_vec()));
        assert_eq!(out, vec![b"partial".to_vec()]);
        assert_eq!(st.emitted, 1);

        // 再 flush 应为空操作，不得重复交出同一行。
        let mut again = Vec::new();
        s.flush(&mut st, |line| again.push(line.to_vec()));
        assert!(again.is_empty());
        assert_eq!(st.emitted, 1);
    }

    #[test]
    fn clear_drops_partial() {
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        assert!(collect(&mut s, b"stale-tail", &mut st).is_empty());
        s.clear();
        assert_eq!(s.pending(), 0);
    }

    #[test]
    fn buffer_is_reused_across_feeds() {
        let mut s = LineSplitter::new();
        let mut st = SplitStats::default();
        // 先用一大批把容量撑到工作集大小。
        let warm = vec![b'z'; 64 * 1024];
        let _ = collect(&mut s, &warm, &mut st);
        s.clear();
        let cap = s.partial.capacity();
        let ptr = s.partial.as_ptr();

        for _ in 0..8 {
            let _ = collect(&mut s, b"line-one\nline-two\n", &mut st);
        }
        assert_eq!(s.partial.capacity(), cap, "行缓冲不应每批重新分配");
        assert_eq!(s.partial.as_ptr(), ptr, "行缓冲地址应保持稳定");
    }

    /// 运行期对照：同一批字节在「整体喂入」与「逐字节喂入」下产出的行序列必须相同
    /// （分割结果不得依赖读块边界）；同时与旧 `process_lines_in_buffer` 的切分点一致。
    #[test]
    fn split_is_independent_of_chunk_boundaries() {
        let data = b"alpha\nbeta\ngamma";

        let mut whole = LineSplitter::new();
        let mut ws = SplitStats::default();
        let whole_lines = collect(&mut whole, data, &mut ws);

        let mut piecewise = LineSplitter::new();
        let mut ps = SplitStats::default();
        let mut piecewise_lines = Vec::new();
        for byte in data {
            piecewise.feed(&[*byte], &mut ps, |line| piecewise_lines.push(line.to_vec()));
        }

        assert_eq!(whole_lines, piecewise_lines, "切分不得依赖读块边界");
        assert_eq!(whole_lines, vec![b"alpha".to_vec(), b"beta".to_vec()]);
        assert_eq!(whole.pending(), piecewise.pending());
    }
}
