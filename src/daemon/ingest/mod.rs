//! 采集层：inotify 监视、源身份注册、按源增量读取。
//!
//! 本层由**单个采集执行体**独占运行（见设计文档「运行时模型」），因此内部状态一律
//! 不加锁：`SourceRegistry`、`SourceReader` 表、以及上层的 partial 行缓冲都只被该
//! 执行体触碰。跨执行体只传「已脱离本层的不可变消息」。
//!
//! 三个子模块各担一件事，且替换掉旧实现的三个结构问题：
//!
//! | 子模块 | 独占状态 | 消除的问题 |
//! |--------|---------|-----------|
//! | [`watcher`] | inotify fd + 读缓冲 | fd 与 `raw_fd` 两处记账的隐式契约 |
//! | [`registry`] | `SourceId ↔ (path, wd, inode)` | 用 `Vec` 下标当身份（C） |
//! | [`reader`] | 每源 fd、offset、复用缓冲 | 每事件重开、重分配 256 KiB（B） |

pub mod reader;
pub mod registry;
pub mod watcher;

pub use reader::{Chunk, SourceReader, BATCH_READ_MAX};
pub use registry::{SourceEntry, SourceId, SourceOwner, SourceRegistry};
pub use watcher::{log_file_watch_mask, WatchEvent, Watcher};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// 系统临时目录下的唯一子目录，避免污染仓库。
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fw-ingest-it-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("建临时目录失败");
        dir
    }

    fn append(path: &std::path::Path, data: &[u8]) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("追加打开失败");
        f.write_all(data).expect("追加失败");
        f.sync_all().expect("sync 失败");
    }

    /// 采集层闭环：事件 → `wd` → 稳定身份 → 该源的新字节。
    #[test]
    fn event_routes_to_stable_identity_and_reader_picks_up_bytes() {
        let dir = tempdir();
        let path = dir.join("sshd.log");
        std::fs::write(&path, b"old-history\n").expect("写文件失败");

        let mut watcher = Watcher::new().expect("inotify 初始化失败");
        let wd = watcher
            .add(&path, log_file_watch_mask())
            .expect("添加 watch 失败");

        let mut reg = SourceRegistry::new();
        let id = reg.register(
            SourceOwner::Log {
                jail: Arc::from("sshd"),
            },
            &path,
            wd,
            0,
        );

        // 启动语义：定位到末尾，不回放历史。
        let mut reader = SourceReader::new();
        reader.open_at_end(&path);
        assert_eq!(reader.offset(), 12, "启动偏移应为文件末尾");

        append(
            &path,
            b"Failed password for root from 1.2.3.4 port 22 ssh2\n",
        );

        // 事件驱动：轮询真实可读状态，等事件到达后按 wd 路由。
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut routed = None;
        while Instant::now() < deadline {
            if !watcher
                .wait_readable(Duration::from_millis(50))
                .unwrap_or(false)
            {
                continue;
            }
            for ev in watcher.read_events().expect("读事件失败") {
                if let Some(sid) = reg.resolve(&ev.wd) {
                    routed = Some(sid);
                    break;
                }
            }
            if routed.is_some() {
                break;
            }
        }
        assert_eq!(routed, Some(id), "事件应按 wd 路由回稳定身份");

        // 路由到身份后，从对应读取器取出新增字节（不再重开 fd、不再重分配缓冲）。
        let chunk = reader.read_new(&path).expect("读失败");
        assert_eq!(
            chunk.bytes, b"Failed password for root from 1.2.3.4 port 22 ssh2\n",
            "应正好读出追加的那一行"
        );
        assert!(!chunk.rotated);

        // 身份稳定性：轮转重挂后同一路径仍是同一身份，旧 wd 不再路由。
        let rotated = dir.join("sshd.log.1");
        std::fs::rename(&path, &rotated).expect("改名失败");
        std::fs::write(&path, b"new-file\n").expect("建新文件失败");
        let new_wd = watcher.add(&path, log_file_watch_mask()).expect("重挂失败");
        let again = reg.register(
            SourceOwner::Log {
                jail: Arc::from("sshd"),
            },
            &path,
            new_wd,
            1,
        );
        assert_eq!(again, id, "轮转重挂不得改变身份（结构问题 C）");
        assert_eq!(reg.len(), 1, "轮转不得产生第二个登记项");

        std::fs::remove_dir_all(&dir).ok();
    }
}
