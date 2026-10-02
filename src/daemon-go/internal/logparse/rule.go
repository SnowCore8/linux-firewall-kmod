package logparse

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// MaxParseLineBytes 是解析期的行长硬上限：超过则整行不解析。
const MaxParseLineBytes = 8192

// DefaultSSHDPattern 是 jail 未配置任何可用正则时套用的内置 sshd 失败模式。
const DefaultSSHDPattern = `Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`

// fallbackKeywordPrimary / fallbackKeywordSecondary 是关键字回退的窄路径判据：
// 命中 sshd 的 `Failed password for` 或 PAM/dovecot 的 `authentication failure`
// 后，才在行内扫描 IP。
const (
	fallbackKeywordPrimary   = "Failed password for"
	fallbackKeywordSecondary = "authentication failure"
)

// MatchVia 是命中方式，供调用方累加正确的计数器。
type MatchVia uint8

// 命中方式取值。
const (
	// MatchViaRegex 由该 jail 的正则捕获组命中。
	MatchViaRegex MatchVia = iota
	// MatchViaFallback 由关键字回退命中。
	MatchViaFallback
)

// Rule 是一条命名正则规则，编译成功后不可变。
type Rule struct {
	name     string
	pattern  string
	compiled *regexp.Regexp
}

// NewRule 编译一条规则。正则非法时返回错误，由配置校验阶段处理。
func NewRule(name, pattern string) (*Rule, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &Rule{name: name, pattern: pattern, compiled: re}, nil
}

// Name 返回规则名（诊断与配置回显用）。
func (r *Rule) Name() string { return r.name }

// Pattern 返回正则源码。
func (r *Rule) Pattern() string { return r.pattern }

// tryMatch 用本规则尝试解析一行；命中返回 IP。
//
// 捕获组从后往前扫描：先过长度窗口与首字节 hex 检查（廉价），再做完整校验（昂贵）。
// 倒序是为了拿到最具体的那个（整体匹配组常在组 0，用户名组可能含数字，最右的才是
// 来源地址）。
func (r *Rule) tryMatch(line string) (netip.Addr, bool) {
	groups := r.compiled.FindStringSubmatchIndex(line)
	if groups == nil {
		return netip.Addr{}, false
	}
	for g := len(groups)/2 - 1; g >= 1; g-- {
		start, end := groups[2*g], groups[2*g+1]
		if start < 0 || end < 0 {
			continue
		}
		capture := line[start:end]
		if len(capture) < minCandidateLen || len(capture) >= maxCandidateLen {
			continue
		}
		if !isHexDigit(capture[0]) {
			continue
		}
		if addr, ok := validateCandidate(capture); ok {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// RuleSet 是一个 jail 的完整规则集，构造后不可变。
type RuleSet struct {
	jail  string
	rules []*Rule
}

// NewRuleSet 用已编译的规则构造规则集。
func NewRuleSet(jail string, rules []*Rule) *RuleSet {
	return &RuleSet{jail: jail, rules: rules}
}

// Jail 返回归属的 jail 名。
func (rs *RuleSet) Jail() string { return rs.jail }

// Len 返回规则条数。
func (rs *RuleSet) Len() int { return len(rs.rules) }

// IsEmpty 报告是否没有规则（此时只走关键字回退）。
func (rs *RuleSet) IsEmpty() bool { return len(rs.rules) == 0 }

// RuleNames 列出规则名（配置回显 / 诊断）。
func (rs *RuleSet) RuleNames() []string {
	names := make([]string, len(rs.rules))
	for i, r := range rs.rules {
		names[i] = r.name
	}
	return names
}

// Parse 解析一行日志，返回来源 IP 与命中方式。
//
// 顺序与 Rust 版一致：先正则、后关键字回退；正则全部未命中（或压根没有正则）时才走
// 回退，因此回退不是「兜底猜 IP」，而是受关键字白名单约束的窄路径。
func (rs *RuleSet) Parse(line string) (netip.Addr, MatchVia, bool) {
	if len(line) > MaxParseLineBytes {
		return netip.Addr{}, 0, false
	}
	for _, rule := range rs.rules {
		if addr, ok := rule.tryMatch(line); ok {
			return addr, MatchViaRegex, true
		}
	}
	if fallbackMatch(line) {
		if addr, ok := ExtractIP(line); ok {
			return addr, MatchViaFallback, true
		}
	}
	return netip.Addr{}, 0, false
}

// fallbackMatch 报告该行是否命中关键字白名单。
func fallbackMatch(line string) bool {
	return strings.Contains(line, fallbackKeywordPrimary) ||
		strings.Contains(line, fallbackKeywordSecondary)
}

// 正则安全校验的阈值。与 Rust 版一致。
const (
	maxRegexPatternBytes = 1024
	maxAlternations      = 50
)

// ValidateRegexSafety 拒绝易触发指数级/多项式级回溯的正则模式（ReDoS 防护）。
//
// 检查项：
//  1. 嵌套量词 `(a+)+` / `(a*)*`（组内有量词，组外再量化）
//  2. 占有量词 `++` / `*+`
//  3. 量化的交替组 `(a|aa)+`
//  4. `(?+` / `(?*` / `(?{` 这类非法量词
//  5. 模式超过 1024 字节 / 分支数超过 50
//
// 与 Rust 版一致按**字符**（而非字节）遍历与报告偏移。
func ValidateRegexSafety(jailName, pattern string) error {
	if len(pattern) > maxRegexPatternBytes {
		return fmt.Errorf(
			"jail '%s' 的正则过长（%d 字节，上限 %d）",
			jailName, len(pattern), maxRegexPatternBytes,
		)
	}

	// 第一检查：嵌套量词。用栈跟踪每层组内是否出现过量词；仅拒绝「组内有量词 +
	// 组外再量化」的危险组合，允许 `(error)+` 等安全模式。
	if err := rejectNestedQuantifiers(jailName, pattern); err != nil {
		return err
	}

	if strings.Contains(pattern, "++") || strings.Contains(pattern, "*+") {
		return fmt.Errorf("jail '%s' 的正则含占有量词（++ / *+）", jailName)
	}

	// 第二检查：`(?` 后直接跟量词属非法组合。合法的 `(?...)` 包括非捕获组 `(?:`、
	// 前瞻 `(?=` / `(?!`、命名组 `(?<` 等。
	runes := []rune(pattern)
	for i := 0; i+2 < len(runes); i++ {
		if runes[i] == '(' && runes[i+1] == '?' {
			switch runes[i+2] {
			case '+', '*', '{':
				return fmt.Errorf(
					"jail '%s' 的正则中 `(?` 后跟量词（偏移 %d）", jailName, i,
				)
			}
		}
	}

	pipes := strings.Count(pattern, "|")
	if pipes > maxAlternations {
		return fmt.Errorf(
			"jail '%s' 的正则分支数过多（%d，上限 %d）", jailName, pipes, maxAlternations,
		)
	}

	return rejectQuantifiedAlternation(jailName, pattern)
}

// rejectNestedQuantifiers 扫描模式，拒绝「组内出现量词后整组再量化」的组合。
func rejectNestedQuantifiers(jailName, pattern string) error {
	runes := []rune(pattern)
	var innerHasQuantifier []bool
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			i++ // 跳过转义字符
		case '(':
			innerHasQuantifier = append(innerHasQuantifier, false)
		case ')':
			had := false
			if n := len(innerHasQuantifier); n > 0 {
				had = innerHasQuantifier[n-1]
				innerHasQuantifier = innerHasQuantifier[:n-1]
			}
			if had && i+1 < len(runes) {
				switch runes[i+1] {
				case '+', '*', '{':
					return fmt.Errorf(
						"jail '%s' 的正则含嵌套量词（偏移 %d）", jailName, i,
					)
				}
			}
		case '+', '*':
			if n := len(innerHasQuantifier); n > 0 {
				innerHasQuantifier[n-1] = true
			}
		case '{':
			if n := len(innerHasQuantifier); n > 0 && i+1 < len(runes) && isASCIIDigit(runes[i+1]) {
				innerHasQuantifier[n-1] = true
			}
		}
	}
	return nil
}

// rejectQuantifiedAlternation 扫描模式，拒绝「组内含 alternation 后整组再量化」的组合。
func rejectQuantifiedAlternation(jailName, pattern string) error {
	runes := []rune(pattern)
	var innerHasAlternation []bool
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			i++
		case '(':
			innerHasAlternation = append(innerHasAlternation, false)
		case ')':
			had := false
			if n := len(innerHasAlternation); n > 0 {
				had = innerHasAlternation[n-1]
				innerHasAlternation = innerHasAlternation[:n-1]
			}
			if had && i+1 < len(runes) {
				switch runes[i+1] {
				case '+', '*', '{', '?':
					return fmt.Errorf(
						"jail '%s' 的正则中含被量化的交替组（偏移 %d）", jailName, i,
					)
				}
			}
		case '|':
			if n := len(innerHasAlternation); n > 0 {
				innerHasAlternation[n-1] = true
			}
		}
	}
	return nil
}

// isASCIIDigit 判定 ASCII 数字（不接受 Unicode 数字）。
func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }
