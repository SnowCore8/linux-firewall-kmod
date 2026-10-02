package jail

import (
	"fmt"
	"regexp"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// DefaultPatternName 是内置模式在配置里的名字。
const DefaultPatternName = "default"

// CompileRegexes 编译所有 enabled jail 的正则，把编译结果写回 `jail.Regexes[i].Compiled`。
//
// 尽力而为 + 汇总失败：单个 jail 编译失败不连带其他 jail 一起放弃，但整体结果
// 必须如实返回失败（调用方据此告警），不得吞掉。
//
// 两条与直觉相反但必须保留的语义：
//
//  1. 内置 sshd 模式**只在正则列表为空时注入**。配置里写了 `regexes:` 却给空串，
//     列表非空，内置模式不会被补上。
//  2. 空模式被跳过；若因此一条都没编译成功，返回错误——但**不影响匹配**：
//     解析层的关键字回退（见 logparse.RuleSet.Parse）仍会命中 sshd 的
//     `Failed password for` 行。Rust 版如此，Go 版对齐，否则同一份配置在两侧
//     行为不同。
func CompileRegexes(cfg *config.Config) error {
	errs := make([]string, 0, len(cfg.Jails))
	for i := range cfg.Jails {
		j := &cfg.Jails[i]
		if !j.Enabled {
			continue
		}
		if err := CompileJailRegexes(j); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return JoinErrors(errs)
}

// CompileJailRegexes 编译单个 jail 的正则。
//
// 校验失败与编译失败都只跳过**该条**模式，不影响同一 jail 的其他模式：一条写错的
// 正则不该让整个 jail 失去防护。全部失败时返回错误，由调用方决定是告警还是拒绝启动。
func CompileJailRegexes(j *config.Jail) error {
	clearCompiled(j)

	if len(j.Regexes) == 0 {
		j.Regexes = append(j.Regexes, config.RegexInfo{
			Name:    DefaultPatternName,
			Pattern: logparse.DefaultSSHDPattern,
		})
	}

	compiled := 0
	for i := range j.Regexes {
		pattern := j.Regexes[i].Pattern
		if pattern == "" {
			continue
		}
		if err := logparse.ValidateRegexSafety(j.Name, pattern); err != nil {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		j.Regexes[i].Compiled = re
		compiled++
	}

	if compiled == 0 {
		return fmt.Errorf("No regex patterns compiled for jail '%s'", j.Name)
	}
	return nil
}

// clearCompiled 丢弃既有的编译结果。
//
// 必须在编译前调用：重复编译时若不清空，上一轮编译失败的条目会残留一个不再
// 对应任何配置的旧编译对象，`BuildRuleSet` 就会把它当成本轮的有效规则搬进去。
func clearCompiled(j *config.Jail) {
	for i := range j.Regexes {
		j.Regexes[i].Compiled = nil
	}
}

// ResetRegexes 清空正则列表（模式串 + 编译结果）。
func ResetRegexes(j *config.Jail) {
	j.Regexes = j.Regexes[:0]
}

// BuildRuleSet 由 jail 的已编译正则构建不可变规则集。
//
// **只搬 `Compiled != nil` 的条目**：正则的安全校验（ReDoS 启发式）发生在
// [`CompileJailRegexes`]，未通过的条目 `Compiled == nil`，若在这里按模式串重新
// 编译就会被「救活」，等于绕过安全闸门。
//
// 因此「配置里给了空模式」会得到一个零规则的规则集，此时只剩关键字回退——这是
// 有意的行为，不是遗漏。
func BuildRuleSet(j *config.Jail) *logparse.RuleSet {
	rules := make([]*logparse.Rule, 0, len(j.Regexes))
	for i := range j.Regexes {
		info := &j.Regexes[i]
		if info.Compiled == nil {
			continue
		}
		rule, err := logparse.NewRule(info.Name, info.Pattern)
		if err != nil {
			continue
		}
		rules = append(rules, rule)
	}
	return logparse.NewRuleSet(j.Name, rules)
}

// BuildRuleSets 为所有 enabled jail 构建规则集，顺序与 `cfg.Jails` 一致。
//
// 保持顺序而不是返回 map：调用方常按索引与 jail 一一对应地消费，顺序一致可以
// 免掉一次按名字查找，也避免同一份配置每次构建出不同顺序的集合。
func BuildRuleSets(cfg *config.Config) []*logparse.RuleSet {
	sets := make([]*logparse.RuleSet, 0, len(cfg.Jails))
	for i := range cfg.Jails {
		j := &cfg.Jails[i]
		if !j.Enabled {
			continue
		}
		sets = append(sets, BuildRuleSet(j))
	}
	return sets
}
