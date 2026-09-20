//! 单源日志读取：长驻 fd、长驻读缓冲、偏移与轮转检测。
//!
//! 旧实现每次事件都重走「打开 → `metadata` → `seek` → `vec![0u8; 256*1024]`」，
//! 256 KiB 的读缓冲**每批事件重新分配一次**（结构问题 B）。这里把 fd 与读缓冲都
//! 挂在源上长驻：事件到来时只在已有 fd 上 `read`，缓冲跨轮复用。
//!
//! 轮转仍须检测——长驻 fd 在轮转后指向旧 inode，只读它永远读不到新内容。检测方式
//! 改为一次 `symlink_metadata(path)`（廉价）与持有的 inode 比较，命中才重开 fd；
//! 事件里的 `MOVE_SELF` / `DELETE_SELF` 只作为提前触发，不作为唯一依据。

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// 单批读上限：平衡系统调用次数与内存占用（与旧实现一致）。
pub const BATCH_READ_MAX: usize = 256 * 1024;

/// 一轮读出的新字节。
///
/// `bytes` 借用源自己的读缓冲（零拷贝，跨轮复用同一个 `Vec`）；`rotated` 提示调用方
/// 该源的 partial 行缓冲已失效，必须清空——轮转/截断后残留的不完整行不属于新文件。
#[derive(Debug)]
pub struct Chunk<'a> {
    /// 本轮读出的新字节，可能为空（无新增或软失败）。
    pub bytes: &'a [u8],
    /// 本轮是否发生轮转或截断（inode 变化 / 文件缩小）。
    pub rotated: bool,
}

/// 单个日志源的读取状态，由采集线程独占（无需锁）。
#[derive(Debug)]
pub struct SourceReader {
    /// 长驻 fd。`None` 表示尚未打开或上次打开失败，下轮重试。
    fd: Option<File>,
    /// 长驻读缓冲，容量固定为 [`BATCH_READ_MAX`]，跨轮复用（修结构问题 B）。
    buffer: Vec<u8>,
    /// 已消费到的字节偏移。
    offset: u64,
    /// 持有的 fd 对应的 inode。`0` 表示尚未取得（未打开）。
    inode: u64,
}

impl Default for SourceReader {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceReader {
    /// 新建未打开的读取器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            fd: None,
            buffer: vec![0u8; BATCH_READ_MAX],
            offset: 0,
            inode: 0,
        }
    }

    /// 当前读取偏移。
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// 当前持有的 inode（未打开时为 0）。
    #[must_use]
    pub fn inode(&self) -> u64 {
        self.inode
    }

    /// 是否已打开 fd。
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.fd.is_some()
    }

    /// 启动期打开：定位到**文件末尾**，已有历史内容不回放。
    ///
    /// 与旧实现一致：新建 watch 时 `offset = metadata.len()`。文件不存在或撞到符号
    /// 链接时静默保持未打开，由后续 [`SourceReader::read_new`] 重试。
    pub fn open_at_end(&mut self, path: &Path) {
        match Self::open_no_follow(path) {
            Ok((file, inode, size)) => {
                self.fd = Some(file);
                self.inode = inode;
                self.offset = size;
            }
            Err(e) => {
                Self::log_open_failure(path, &e);
            }
        }
    }

    /// 丢弃当前 fd 与偏移，回到「未打开」状态（源被摘除时调用）。
    pub fn reset(&mut self) {
        self.fd = None;
        self.inode = 0;
        self.offset = 0;
    }

    /// 读出该源自上次读取以来的新增字节。
    ///
    /// 无新增时返回空 `bytes`；软失败（符号链接、文件暂不可读）同样返回空 `bytes`
    /// 且保留偏移，下轮重试——与旧实现「记录告警但不中断链路」的语义一致。
    ///
    /// # Errors
    /// 仅在 `seek` 失败（持有的 fd 意外失效）时返回错误；调用方按源重置处理。
    pub fn read_new(&mut self, path: &Path) -> io::Result<Chunk<'_>> {
        let mut rotated = false;

        // 轮转检测：路径现在指向的 inode 与持有 fd 的不一致，或文件比偏移还小
        // （同 inode 被 truncate / copytruncate）。两种情况都要重开并归零偏移。
        let observed = std::fs::symlink_metadata(path);
        match observed {
            Ok(meta) => {
                if !meta.is_file() {
                    // 被替换成目录 / 设备 / 符号链接：当作轮转，重开下一轮再说。
                    self.reset();
                    return Ok(Chunk {
                        bytes: &[],
                        rotated: true,
                    });
                }
                let current_inode = meta.ino();
                let truncation = self.inode != 0 && meta.len() < self.offset;
                let inode_change = self.inode != 0 && current_inode != self.inode;
                if inode_change || truncation {
                    self.fd = None;
                    self.inode = 0;
                    self.offset = 0;
                    rotated = true;
                }
            }
            Err(e) => {
                if self.fd.is_none() {
                    Self::log_open_failure(path, &e);
                    return Ok(Chunk {
                        bytes: &[],
                        rotated: false,
                    });
                }
                // 已持有 fd 而路径暂时不可见（轮转窗口内）：交给后续事件处理。
                return Ok(Chunk {
                    bytes: &[],
                    rotated: false,
                });
            }
        }

        if self.fd.is_none() {
            match Self::open_no_follow(path) {
                Ok((file, inode, size)) => {
                    self.fd = Some(file);
                    self.inode = inode;
                    // 轮转后新文件从头读；首次打开（无历史）也从 0 读。
                    self.offset = if rotated { 0 } else { size.min(self.offset) };
                }
                Err(e) => {
                    Self::log_open_failure(path, &e);
                    return Ok(Chunk {
                        bytes: &[],
                        rotated,
                    });
                }
            }
        }

        let Some(file) = self.fd.as_mut() else {
            return Ok(Chunk {
                bytes: &[],
                rotated,
            });
        };

        if self.offset > 0 {
            file.seek(SeekFrom::Start(self.offset))?;
        }

        let mut total = 0;
        loop {
            match file.read(&mut self.buffer[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    // 与旧实现一致：读满上限前留 1 字节余量即收工，下一轮继续。
                    if total >= BATCH_READ_MAX - 1 {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    crate::logger::debug!(
                        crate::logger::get(),
                        "读取日志文件失败";
                        "path" => path.display().to_string(),
                        "error" => %e
                    );
                    break;
                }
            }
        }

        self.offset += total as u64;
        Ok(Chunk {
            bytes: &self.buffer[..total],
            rotated,
        })
    }

    /// 以 `O_NOFOLLOW` 打开并返回 `(fd, inode, size)`。
    fn open_no_follow(path: &Path) -> io::Result<(File, u64, u64)> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let meta = file.metadata()?;
        Ok((file, meta.ino(), meta.len()))
    }

    /// 打开失败的统一日志：`ELOOP` 是「启动后文件被换成符号链接」，要告警且**不**
    /// 设永久标志（下轮仍重试）；其余按 debug 记录，避免日志刷屏。
    fn log_open_failure(path: &Path, err: &io::Error) {
        if err.raw_os_error() == Some(libc::ELOOP) {
            crate::logger::warn!(
                crate::logger::get(),
                "检测到符号链接，本次跳过文件（下次读取周期将重试）";
                "path" => path.display().to_string()
            );
        } else {
            crate::logger::debug!(
                crate::logger::get(),
                "打开日志文件失败";
                "path" => path.display().to_string(),
                "error" => %err
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 系统临时目录下的唯一子目录，避免污染仓库。
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fw-reader-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("建临时目录失败");
        dir
    }

    fn append(path: &Path, data: &[u8]) {
        let mut f = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("追加打开失败");
        f.write_all(data).expect("追加失败");
        f.sync_all().expect("sync 失败");
    }

    #[test]
    fn open_at_end_skips_existing_history() {
        let dir = tempdir();
        let path = dir.join("a.log");
        std::fs::write(&path, b"history-1\nhistory-2\n").expect("写文件失败");

        let mut r = SourceReader::new();
        r.open_at_end(&path);
        assert!(r.is_open(), "启动期应成功打开");
        assert_eq!(r.offset(), 20, "启动偏移必须是文件末尾");

        assert!(
            r.read_new(&path).expect("读失败").bytes.is_empty(),
            "启动后未追加时不应读出历史内容"
        );

        append(&path, b"new-line\n");
        let chunk = r.read_new(&path).expect("读失败");
        assert_eq!(chunk.bytes, b"new-line\n", "只应读出追加部分");
        assert!(!chunk.rotated, "追加不构成轮转");
        assert_eq!(r.offset(), 29);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_buffer_is_reused_across_reads() {
        let dir = tempdir();
        let path = dir.join("a.log");
        std::fs::write(&path, b"").expect("写文件失败");

        let mut r = SourceReader::new();
        r.open_at_end(&path);
        // 首次读取后才可能真正触碰缓冲；记下地址与容量，多轮后必须不变。
        append(&path, b"x\n");
        let _ = r.read_new(&path).expect("读失败");
        let cap = r.buffer.capacity();
        let ptr = r.buffer.as_ptr();

        for i in 0..8 {
            append(&path, format!("line-{i}\n").as_bytes());
            let _ = r.read_new(&path).expect("读失败");
        }

        assert_eq!(r.buffer.capacity(), cap, "读缓冲不应每轮重新分配（修 B）");
        assert_eq!(r.buffer.as_ptr(), ptr, "读缓冲地址应保持稳定");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn truncation_resets_offset_and_flags_rotation() {
        let dir = tempdir();
        let path = dir.join("a.log");
        std::fs::write(&path, b"aaaa\nbbbb\n").expect("写文件失败");

        let mut r = SourceReader::new();
        r.open_at_end(&path);
        append(&path, b"more\n");
        let first = r.read_new(&path).expect("读失败");
        assert_eq!(first.bytes, b"more\n");

        // copytruncate 风格：原地清空后写新内容。
        std::fs::write(&path, b"fresh\n").expect("截断写失败");
        let chunk = r.read_new(&path).expect("读失败");
        assert!(chunk.rotated, "截断必须置 rotated，调用方据此清 partial");
        assert_eq!(chunk.bytes, b"fresh\n", "截断后应从 0 重读");
        assert_eq!(r.offset(), 6);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn inode_change_is_detected_as_rotation() {
        let dir = tempdir();
        let path = dir.join("a.log");
        std::fs::write(&path, b"old\n").expect("写文件失败");

        let mut r = SourceReader::new();
        r.open_at_end(&path);
        let old_inode = r.inode();

        // logrotate 风格：改名后新建同名文件（新 inode）。
        let rotated = dir.join("a.log.1");
        std::fs::rename(&path, &rotated).expect("改名失败");
        std::fs::write(&path, b"brand-new\n").expect("建新文件失败");

        let chunk = r.read_new(&path).expect("读失败");
        assert!(chunk.rotated, "inode 变化必须置 rotated");
        assert_eq!(chunk.bytes, b"brand-new\n");
        assert_ne!(r.inode(), old_inode, "应换用新 inode 的 fd");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlink_after_startup_is_soft_skip() {
        let dir = tempdir();
        let path = dir.join("a.log");
        let target = dir.join("secret");
        std::fs::write(&path, b"real\n").expect("写文件失败");
        std::fs::write(&target, b"secret\n").expect("写文件失败");

        let mut r = SourceReader::new();
        r.open_at_end(&path);

        // 启动后文件被换成符号链接：O_NOFOLLOW 应拒绝，且不当作错误冒出。
        std::fs::remove_file(&path).expect("删除失败");
        std::os::unix::fs::symlink(&target, &path).expect("建符号链接失败");

        let chunk = r.read_new(&path).expect("符号链接不应是硬错误");
        assert!(chunk.bytes.is_empty(), "不应读出符号链接目标内容");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_soft_skip() {
        let dir = tempdir();
        let path = dir.join("nope.log");

        let mut r = SourceReader::new();
        let chunk = r.read_new(&path).expect("缺文件不应是硬错误");
        assert!(chunk.bytes.is_empty());
        assert!(!r.is_open(), "打不开时应保持未打开，下轮重试");
        std::fs::remove_dir_all(&dir).ok();
    }
}
