//! 契约生成物的接入点：把 `contract/generated/netlink_contract.rs` 作为本 crate 的
//! 一个模块引入。
//!
//! 生成物本身是「独立 crate 根」（`contract/verify_layout.py` 会用 `rustc
//! --crate-type lib` 单独自检），这里用 `#[path]` 把它挂进 daemon crate，好处是
//! 线格式布局只有**一份**定义：实现侧读的是契约里的字段名与偏移，编译器负责
//! 保证两边一致，杜绝「手抄结构体」。
//!
//! 注意：一旦成为 crate 模块，`cargo fmt --check` 就会沿 mod 树进入该文件，故
//! 生成器对每个 `impl` 块都加了 `#[rustfmt::skip]`，避免 rustfmt 重排布局表。

#[path = "../../contract/generated/netlink_contract.rs"]
mod generated;

pub use generated::*;

/// HTTP 契约生成物：路由路径常量、业务码、认证与 SSE 上限。
///
/// 与 netlink 生成物同样以 `#[path]` 挂入，使**路由字面量**只有一份定义。
/// 它单独成模块（而不是 `pub use` 展开）是因为其中的 `path` / `code` / `auth` /
/// `sse` 子模块名与 netlink 侧同名的概念并列时更易读：`contract::http_contract::path::…`。
#[path = "../../contract/generated/http_contract.rs"]
pub mod http_contract;
