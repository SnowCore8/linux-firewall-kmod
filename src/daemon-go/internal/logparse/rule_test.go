package logparse

import (
	"strings"
	"testing"
)

func rulesOne(t *testing.T) *RuleSet {
	t.Helper()
	r, err := NewRule("default", DefaultSSHDPattern)
	if err != nil {
		t.Fatalf("内置 sshd 正则应可编译: %v", err)
	}
	return NewRuleSet("sshd", []*Rule{r})
}

func TestRegexHitReportsRegexVia(t *testing.T) {
	line := "Jun 11 15:30:00 host sshd[1]: Failed password for root from 192.168.1.100 port 22"
	addr, via, ok := rulesOne(t).Parse(line)
	if !ok || via != MatchViaRegex {
		t.Fatalf("应由正则命中: ok=%v via=%v", ok, via)
	}
	if addr != mustAddr(t, "192.168.1.100") {
		t.Fatalf("IP 不符: %v", addr)
	}
}

func TestInvalidUserVariantMatches(t *testing.T) {
	addr, _, ok := rulesOne(t).Parse("Failed password for invalid user admin from 10.0.0.99 port 22")
	if !ok || addr != mustAddr(t, "10.0.0.99") {
		t.Fatalf("invalid user 变体应命中: ok=%v addr=%v", ok, addr)
	}
}

// 捕获组从右往左扫描：最右侧通过校验的那个才是来源地址。
func TestRightmostValidCaptureGroupWins(t *testing.T) {
	r, err := NewRule("two", `from ([0-9.]+) via ([0-9.]+)`)
	if err != nil {
		t.Fatalf("正则应可编译: %v", err)
	}
	rs := NewRuleSet("x", []*Rule{r})
	addr, _, ok := rs.Parse("from 10.0.0.1 via 192.168.1.1")
	if !ok || addr != mustAddr(t, "192.168.1.1") {
		t.Fatalf("应取最右侧的合法捕获: ok=%v addr=%v", ok, addr)
	}
}

// 右侧捕获不是合法 IP 时，回退到左侧那个合法捕获，而不是放弃整行。
func TestSkipsInvalidRightmostCapture(t *testing.T) {
	r, err := NewRule("mixed", `from ([0-9.]+) port ([0-9]+)`)
	if err != nil {
		t.Fatalf("正则应可编译: %v", err)
	}
	rs := NewRuleSet("x", []*Rule{r})
	addr, _, ok := rs.Parse("from 10.0.0.1 port 22")
	if !ok || addr != mustAddr(t, "10.0.0.1") {
		t.Fatalf("应跳过过短的右侧捕获: ok=%v addr=%v", ok, addr)
	}
}

func TestFallbackKeywordPath(t *testing.T) {
	rs := NewRuleSet("sshd", nil)
	addr, via, ok := rs.Parse("Failed password for root from 172.16.0.1 port 22")
	if !ok || via != MatchViaFallback || addr != mustAddr(t, "172.16.0.1") {
		t.Fatalf("关键字回退应命中: ok=%v via=%v addr=%v", ok, via, addr)
	}

	if _, _, ok := rs.Parse("some line with no keyword from 10.0.0.1"); ok {
		t.Fatalf("无关键字白名单的行不应命中回退")
	}
}

func TestParseRejectsOversizeLine(t *testing.T) {
	if _, _, ok := rulesOne(t).Parse(strings.Repeat("x", MaxParseLineBytes+1)); ok {
		t.Fatalf("超长行应被拒")
	}
}

func TestValidateRegexSafetyAcceptsServePatterns(t *testing.T) {
	ok := []string{
		DefaultSSHDPattern,
		`(error)+`,
		`.*get a user connection \[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):\d+\]`,
		`FAIL LOGIN: Client \"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\"`,
	}
	for _, p := range ok {
		if err := ValidateRegexSafety("x", p); err != nil {
			t.Errorf("合法模式被拒 %q: %v", p, err)
		}
	}
}

func TestValidateRegexSafetyRejectsReDoS(t *testing.T) {
	bad := map[string]string{
		"嵌套量词":    `(a+)+`,
		"占有量词":    `a++`,
		"量化交替组":   `(a|aa)+`,
		"非法 (?量词": `(?+`,
		"过多分支":    strings.Repeat("a|", 51),
		"过长模式":    strings.Repeat("a", maxRegexPatternBytes+1),
	}
	for name, p := range bad {
		if err := ValidateRegexSafety("x", p); err == nil {
			t.Errorf("%s 应被拒: %q", name, p)
		}
	}
}

func TestRuleSetReportsNamesAndEmptiness(t *testing.T) {
	rs := rulesOne(t)
	if rs.IsEmpty() || rs.Len() != 1 {
		t.Fatalf("Len=%d IsEmpty=%v", rs.Len(), rs.IsEmpty())
	}
	if names := rs.RuleNames(); len(names) != 1 || names[0] != "default" {
		t.Fatalf("RuleNames=%v", names)
	}
	if rs.Jail() != "sshd" {
		t.Fatalf("Jail=%q", rs.Jail())
	}
	if empty := NewRuleSet("e", nil); !empty.IsEmpty() {
		t.Fatalf("空规则集 IsEmpty 应为 true")
	}
}
