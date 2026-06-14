//! 正则表达式安全验证 + 编译 + 初始化/释放
//!
//! ReDoS 防护:编译前校验正则模式,拒绝嵌套量词/占有量词/量化交替组

use crate::types::{Jail, RegexInfo};

/// - `jail`: 目标 jail (可变引用)
pub(crate) fn free_jail_regex(jail: &mut Jail) {
    for regex_info in &mut jail.regexes {
        regex_info.compiled = None;
    }
}

/// 完全清空 jail 的正则列表 (模式串 + 编译对象)。`destroy_jail` 时调。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
pub fn free_jail_regex_full(jail: &mut Jail) {
    jail.regexes.clear();
}

/// `ReDoS` 防护: 拒绝易触发指数/多项式级回溯的模式。
///
/// 检查项:
/// 1. 嵌套量词 `(a+)+` / `(a*)*`
/// 2. 占有量词 `a++` / `a*+` (Rust regex 实际不支持, 仍校验防御性)
/// 3. 量化的交替组 `(a|aa)+`
/// 4. 模式 > 1024 字节 / 分支数 > 50
///
/// # Arguments
/// - `jail`: 目标 jail (用于错误信息)
/// - `pattern`: 待校验的正则模式串
///
/// # Returns
/// - `Ok(())`: 安全
/// - `Err(String)`: 拒绝原因
pub(crate) fn validate_regex_safety(jail: &Jail, pattern: &str) -> Result<(), String> {
    let pattern_len = pattern.len();

    if pattern_len > 1024 {
        return Err(format!(
            "Rejected unsafe regex for jail '{}': pattern too long ({} bytes, max 1024)",
            jail.name, pattern_len
        ));
    }

    for (i, c) in pattern.chars().enumerate() {
        if c == ')' {
            let next = pattern.chars().nth(i + 1);
            if next == Some('+') || next == Some('*') {
                return Err(format!(
                    "Rejected unsafe regex for jail '{}': nested quantifiers detected at offset {}",
                    jail.name, i
                ));
            }
        }
    }

    if pattern.contains("++") || pattern.contains("*+") {
        return Err(format!(
            "Rejected unsafe regex for jail '{}': possessive quantifiers detected",
            jail.name
        ));
    }

    // 检查 (? 结构：只拒绝 (?+  (?*  (?{ 等非法组合
    // 合法的 (?...) 包括：(?:非捕获组) (?=前瞻) (?!负向前瞻) (?<命名组) 等
    let chars: Vec<char> = pattern.chars().collect();
    for i in 0..chars.len() {
        if chars[i] == '(' && i + 1 < chars.len() && chars[i + 1] == '?' {
            // 检查 (? 后面的第三个字符
            if i + 2 < chars.len() {
                let third = chars[i + 2];
                // (?+  (?*  (?{  是非法的（量词直接跟在 (? 后）
                if third == '+' || third == '*' || third == '{' {
                    return Err(format!(
                        "Rejected unsafe regex for jail '{}': invalid quantifier after '(?' at offset {}",
                        jail.name, i
                    ));
                }
            }
        }
    }

    let pipe_count = pattern.chars().filter(|&c| c == '|').count();
    if pipe_count > 50 {
        return Err(format!(
            "Rejected unsafe regex for jail '{}': too many alternations ({} , max 50)",
            jail.name, pipe_count
        ));
    }

    let mut paren_depth: usize = 0;
    let mut has_alternation_in_group = false;
    for (i, c) in pattern.chars().enumerate() {
        match c {
            '(' => {
                let next = pattern.chars().nth(i + 1);
                if next != Some('?') {
                    paren_depth += 1;
                    has_alternation_in_group = false;
                }
            }
            ')' => {
                if has_alternation_in_group {
                    let next = pattern.chars().nth(i + 1);
                    if next == Some('+')
                        || next == Some('*')
                        || next == Some('{')
                        || next == Some('?')
                    {
                        return Err(format!(
                            "Rejected unsafe regex for jail '{}': alternation inside quantified group at offset {}",
                            jail.name, i
                        ));
                    }
                }
                paren_depth = paren_depth.saturating_sub(1);
            }
            '|' if paren_depth > 0 => {
                has_alternation_in_group = true;
            }
            _ => {}
        }
    }

    Ok(())
}

/// 编译 jail 内所有正则。空时自动套用内置默认 sshd 失败模式。
///
/// 失败模式 (`ReDoS 拒绝` / `regex 编译错误`) 不中断其他正则的尝试,
/// 全部失败时返回 `Err`,至少 1 条成功时返回 `Ok`。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
///
/// # Returns
/// - `Ok(())`: 至少 1 条编译成功
/// - `Err(String)`: 所有正则都失败
///
/// # Errors
/// `validate_regex_safety` 拒绝(嵌套量词等)或 `regex::Regex::new` 解析失败的模式
/// 累积到最后,只有当全部正则都失败时才返回
pub fn compile_jail_regex(jail: &mut Jail) -> Result<(), String> {
    free_jail_regex(jail);

    if jail.regexes.is_empty() {
        let default_pattern = r"Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";
        jail.regexes.push(RegexInfo {
            name: "default".to_string(),
            pattern: default_pattern.to_string(),
            compiled: None,
        });
    }

    let mut compiled_count = 0;
    for i in 0..jail.regexes.len() {
        let pattern = jail.regexes[i].pattern.clone();
        if pattern.is_empty() {
            continue;
        }

        if let Err(e) = validate_regex_safety(jail, &pattern) {
            crate::logger::warn!(
                crate::logger::get(),
                "正则安全检查失败，跳过编译";
                "jail" => &jail.name,
                "error" => &e
            );
            continue;
        }

        match regex::Regex::new(&pattern) {
            Ok(re) => {
                jail.regexes[i].compiled = Some(re);
                compiled_count += 1;
            }
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "正则编译失败";
                    "jail" => &jail.name,
                    "error" => %e
                );
            }
        }
    }

    if compiled_count > 0 {
        Ok(())
    } else {
        Err(format!(
            "No regex patterns compiled for jail '{}'",
            jail.name
        ))
    }
}
