//! 解析层：字节流 → 行 → 来源 IP。
//!
//! 三个子模块职责单一，全部与全局状态解耦（除 `rules` 为对照测试而只在测试中引用旧
//! `log_parser`）：
//!
//! | 子模块 | 职责 | 状态 |
//! |--------|------|------|
//! | [`splitter`] | 字节流按 `\n` 切行，每源独立 partial 缓冲 | 每源一个（调用方持有） |
//! | [`extract`] | 从任意文本认出合法 IP | 无（纯函数） |
//! | [`rules`] | 每 jail 的编译正则集 + 关键字回退 | 构造后不可变，`Arc` 共享 |
//!
//! 旧实现把这三件事分别散在 `line_processor.rs`（切行 + 缓冲 + 统计）、
//! `log_parser/{parser,ip_extract}.rs`（匹配 + 提取）与 `types/jail.rs`
//! （缓冲与正则挂在 `Jail` 上），共享锁不可避免。这里按「谁拥有状态」重新切分：
//! 只有 `splitter` 有状态，且状态归**源**不归 jail。

pub mod extract;
pub mod rules;
pub mod splitter;

pub use extract::{extract_ip, is_reserved, validate_candidate};
pub use rules::{MatchVia, Parsed, Rule, RuleSet, MAX_PARSE_LINE_BYTES};
pub use splitter::{LineSplitter, SplitStats, MAX_LINE_BYTES};
