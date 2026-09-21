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

pub mod client;
pub mod codec;
pub mod global;
pub mod lease;
pub mod reactor;
pub mod transport;
