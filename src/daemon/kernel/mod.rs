//! 内核 netlink 层：线格式编解码、传输、接收路由、类型化客户端与注册租约。
//!
//! 分层与职责：
//!
//! - [`codec`]：**唯一**的线格式转义层。把契约生成物定义的字节布局翻译成
//!   本机字节序的语义类型，或反向编码。
//! - [`transport`]：netlink socket 的唯一所有者（单写者）。
//! - [`reactor`]：接收 + 按 `type + seq` 路由。
//! - [`client`]：`Arc<Transport>` 上的类型化请求 API。
//! - [`lease`]：单守护进程注册租约，失联是显式可见状态。
//! - [`global`]：**过渡物**——全局 [`client::Client`] 定位器，供不在构造链上的旧
//!   调用点在 2.H-3 切换期取用；与 2.H-4 同批删除。
//!
//! 本层取代旧的 `crate::netlink`（含 `mod.rs` / `protocol.rs` / `responses.rs` /
//! `commands.rs` / `handlers.rs` / `decision.rs` / `config_sync.rs`）。

use std::time::Duration;

pub mod client;
pub mod codec;
pub mod global;
pub mod lease;
pub mod reactor;
pub mod transport;

/// 「已确认」请求的默认等待上限。
///
/// 内核在同一台机器上、软中断上下文里回一条报文，正常耗时是微秒级；这里给三个数量
/// 级余量。取值不能太长——周期任务的每个节拍都串行等待，超时上限直接决定「内核不回
/// 应时」轮询节奏能退化成多慢。
pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(500);

/// 分页拉取整表时**每页**的等待上限。
///
/// 比 [`REQUEST_TIMEOUT`] 宽：`List*` 要遍历内核侧的整张表（封禁/白名单/速率表容量
/// 上限是 65535），大表一次页遍历比「读几个计数器」慢得多。续页次数由
/// [`client::Client::drain`] 按契约页上限决定，故这里只是单页上限。
pub const PAGE_TIMEOUT: Duration = Duration::from_secs(2);
