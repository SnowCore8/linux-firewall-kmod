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
//!
//! 本层取代旧的 `crate::netlink`（含 `mod.rs` / `protocol.rs` / `responses.rs` /
//! `commands.rs` / `handlers.rs` / `decision.rs` / `config_sync.rs`）。

pub mod codec;
