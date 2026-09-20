//! 每 jail 的解析规则集：**编译期一次性**编译正则，热路径只读。
//!
//! 旧实现把 `Option<Regex>` 塞在 `Jail` 里，与失败计数、partial 缓冲等运行时状态
//! 同居一个结构（`types/jail.rs`），于是「只读的正则」和「可变的计数窗口」被迫共享
//! 同一把锁。这里把规则拆出来：编译成功后不可变，重载产出**新的** [`RuleSet`] 整体
//! 替换，绝不在热路径上重编译或加锁。
//!
//! 匹配语义与旧 `log_parser::parser` 一致：按规则顺序尝试，命中后**从后往前**扫描捕获
//! 组，取最右侧通过校验的 IP——倒序是为了拿到最具体的那个（整体匹配组常在组 0，
//! 用户名组可能含数字，最右的才是来源地址）。

use std::net::IpAddr;
use std::sync::Arc;

use regex::Regex;

use super::extract::{extract_ip, validate_candidate};

/// 行长度硬上限：超过则视为异常行，直接不解析。
///
/// 与旧 `parse_log_line` 的 `> 8192 → None` 一致；链路上另有一道
/// [`super::splitter::MAX_LINE_BYTES`] 的分割期上限，两者不冲突（分割期用的是
/// `>= 8192`，更严），这里保留是为了本模块单独使用时语义仍然自洽。
pub const MAX_PARSE_LINE_BYTES: usize = 8192;

/// 命中方式，供调用方累加正确的计数器（`regex_matches` 只统计正则命中）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchVia {
    /// 由该 jail 的正则捕获组命中。
    Regex,
    /// 由关键字回退（`Failed password for` / `authentication failure`）命中。
    Fallback,
}

/// 一次成功的解析结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    /// 提取出的来源 IP。
    pub ip: IpAddr,
    /// 命中方式。
    pub via: MatchVia,
}

/// 单条规则：名称 + 已编译正则（不可变）。
#[derive(Debug, Clone)]
pub struct Rule {
    name: String,
    pattern: String,
    compiled: Regex,
}

impl Rule {
    /// 编译一条规则。正则非法时返回错误，由配置校验阶段处理。
    ///
    /// # Errors
    /// 正则语法非法时返回 [`regex::Error`]。
    pub fn new(name: impl Into<String>, pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            name: name.into(),
            pattern: pattern.to_string(),
            compiled: Regex::new(pattern)?,
        })
    }

    /// 规则名（诊断与配置回显用）。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 正则源码。
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// 用本规则尝试解析一行；命中返回 IP。
    ///
    /// 捕获组从后往前扫描：先过长度窗口与首字节 hex 检查（廉价），再做完整校验
    /// （昂贵），避免为明显的非 IP 片段付出解析代价。
    fn try_match(&self, line: &str) -> Option<IpAddr> {
        let captures = self.compiled.captures(line)?;
        for group in (1..captures.len()).rev() {
            let Some(m) = captures.get(group) else {
                continue;
            };
            let capture = m.as_str();
            if !(7..46).contains(&capture.len()) {
                continue;
            }
            if !capture.as_bytes()[0].is_ascii_hexdigit() {
                continue;
            }
            if let Some(ip) = validate_candidate(capture) {
                return Some(ip);
            }
        }
        None
    }
}

/// 一个 jail 的完整规则集，构造后不可变。
#[derive(Debug, Clone)]
pub struct RuleSet {
    jail: Arc<str>,
    rules: Vec<Rule>,
}

impl RuleSet {
    /// 用已编译的规则构造规则集。
    #[must_use]
    pub fn new(jail: Arc<str>, rules: Vec<Rule>) -> Self {
        Self { jail, rules }
    }

    /// 归属的 jail 名。
    #[must_use]
    pub fn jail(&self) -> &Arc<str> {
        &self.jail
    }

    /// 规则条数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// 是否没有规则（此时只走关键字回退）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 列出规则名（配置回显 / 诊断）。
    #[must_use]
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().map(Rule::name).collect()
    }

    /// 解析一行日志，返回来源 IP 与命中方式。
    ///
    /// 顺序与旧实现一致：**先正则、后关键字回退**；正则全部未命中（或压根没有正则）
    /// 时才走回退，因此回退不是「兜底猜 IP」，而是受关键字白名单约束的窄路径。
    #[must_use]
    pub fn parse(&self, line: &str) -> Option<Parsed> {
        if line.len() > MAX_PARSE_LINE_BYTES {
            return None;
        }

        for rule in &self.rules {
            if let Some(ip) = rule.try_match(line) {
                return Some(Parsed {
                    ip,
                    via: MatchVia::Regex,
                });
            }
        }

        fallback_match(line).map(|ip| Parsed {
            ip,
            via: MatchVia::Fallback,
        })
    }
}

/// 关键字回退：命中 sshd 的 `Failed password for` 或 PAM/dovecot 的
/// `authentication failure` 后，才在行内扫描 IP。
#[must_use]
fn fallback_match(line: &str) -> Option<IpAddr> {
    if line.contains("Failed password for") || line.contains("authentication failure") {
        extract_ip(line)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Jail, RegexInfo};

    const SSH_PATTERN: &str = r"Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";

    fn rules_one() -> RuleSet {
        RuleSet::new(
            Arc::from("sshd"),
            vec![Rule::new("default", SSH_PATTERN).expect("正则应可编译")],
        )
    }

    fn rules_empty() -> RuleSet {
        RuleSet::new(Arc::from("sshd"), Vec::new())
    }

    #[test]
    fn regex_hit_reports_regex_via() {
        let line = "Jun 11 15:30:00 host sshd[1]: Failed password for root from 192.168.1.100 port 22";
        let parsed = rules_one().parse(line).expect("应命中");
        assert_eq!(parsed.ip.to_string(), "192.168.1.100");
        assert_eq!(parsed.via, MatchVia::Regex);
    }

    #[test]
    fn invalid_user_variant_matches() {
        let line = "Failed password for invalid user admin from 10.0.0.99 port 22";
        let parsed = rules_one().parse(line).expect("应命中");
        assert_eq!(parsed.ip.to_string(), "10.0.0.99");
    }

    #[test]
    fn no_rules_falls_back_to_keyword() {
        let line = "sshd: Failed password for root from 172.16.0.1 port 22";
        let parsed = rules_empty().parse(line).expect("回退应命中");
        assert_eq!(parsed.ip.to_string(), "172.16.0.1");
        assert_eq!(parsed.via, MatchVia::Fallback);
    }

    #[test]
    fn keyword_absent_is_no_match() {
        assert!(rules_empty().parse("Accepted password for root").is_none());
        assert!(rules_one().parse("Accepted password for root").is_none());
    }

    #[test]
    fn oversize_line_is_not_parsed() {
        let line = "x".repeat(MAX_PARSE_LINE_BYTES + 1);
        assert!(rules_one().parse(&line).is_none());
    }

    #[test]
    fn invalid_regex_is_reported_at_construction() {
        assert!(Rule::new("bad", "([0-9").is_err());
    }

    /// 运行期对照：新 `RuleSet::parse` 与旧 `log_parser::parse_log_line` 在同一语料
    /// 上必须逐行一致。旧模块在 2.C 收尾时删除，本测试同时退役。
    #[test]
    fn parity_with_legacy_parse_log_line_on_corpus() {
        // 旧实现需要一份带 `Option<Regex>` 的 `Jail`，用同一 pattern 构造，保证两侧
        // 吃的是同一份正则。
        let mut legacy_jail = Jail::new("sshd".to_string());
        legacy_jail.regexes.push(RegexInfo {
            name: "default".to_string(),
            pattern: SSH_PATTERN.to_string(),
            compiled: Some(Regex::new(SSH_PATTERN).expect("正则应可编译")),
        });

        let new_rules = rules_one();
        let corpus: &[&str] = &[
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            "Failed password for invalid user admin from 10.0.0.99 port 22",
            "Failed password for root from 2001:db8::1 port 22",
            "Failed password for root from ::1 port 22",
            "authentication failure; rhost=8.8.8.8",
            "Accepted password for root from 1.1.1.1",
            "unrelated line with 9.9.9.9 inside",
            "Failed password for root from 1.2.3",
            "",
            "Failed password for root from 0.0.0.0 port 22",
        ];

        for line in corpus {
            let legacy = crate::log_parser::parse_log_line(&legacy_jail, line);
            let new = new_rules.parse(line).map(|p| p.ip.to_string());
            assert_eq!(new, legacy, "与旧实现不一致: {line:?}");
        }
    }

    /// 无正则时两侧都必须走关键字回退。
    #[test]
    fn parity_fallback_path_with_legacy() {
        let legacy_jail = Jail::new("sshd".to_string());
        let new_rules = rules_empty();
        for line in [
            "Failed password for root from 172.16.0.1 port 22",
            "authentication failure rhost=1.2.3.4",
            "nothing here",
        ] {
            let legacy = crate::log_parser::parse_log_line(&legacy_jail, line);
            let new = new_rules.parse(line).map(|p| p.ip.to_string());
            assert_eq!(new, legacy, "回退路径不一致: {line:?}");
        }
    }
}
