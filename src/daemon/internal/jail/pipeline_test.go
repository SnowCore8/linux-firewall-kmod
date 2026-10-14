package jail

import (
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// TestFinalizeDowngradesEmptyRegexToWarning 覆盖「配置只给了空模式」的降级语义：
// Finalize 不返回错误，只给一条含 jail 名的告警——该 jail 退化为解析层的关键字回退，
// 不构成拒绝启动/拒绝重载的理由（compile.go 顶部语义②）。
func TestFinalizeDowngradesEmptyRegexToWarning(t *testing.T) {
	cfg := config.Default()
	j := jailWith("sshd")
	j.Regexes = []config.RegexInfo{{Name: DefaultPatternName, Pattern: ""}}
	cfg.Jails = []config.Jail{j}

	warnings, err := Finalize(&cfg)
	if err != nil {
		t.Fatalf("空模式应降级为告警而非致命错误，实得 %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("应有 1 条告警，实得 %d 条：%v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "sshd") {
		t.Fatalf("告警文案应点明 jail 名，实得 %q", warnings[0])
	}
}

// TestFinalizeStillRejectsInvalidConfig 覆盖降级不扩大到校验层：
// Validate 会拒的配置（max_retries=0）仍然是致命错误，且不返回告警。
func TestFinalizeStillRejectsInvalidConfig(t *testing.T) {
	cfg := config.Default()
	j := jailWith("sshd")
	j.MaxRetries = 0
	j.MaxRetriesSet = true
	cfg.Jails = []config.Jail{j}

	warnings, err := Finalize(&cfg)
	if err == nil {
		t.Fatal("max_retries=0 应仍被 Validate 拒绝")
	}
	if warnings != nil {
		t.Fatalf("致命错误时不应携带告警，实得 %v", warnings)
	}
}

// TestFinalizeWarningsScopedToBadJail 覆盖边界：多个 jail 里只有一个坏正则时，
// 告警只含那一个，其余 jail 的编译结果照常可用。
func TestFinalizeWarningsScopedToBadJail(t *testing.T) {
	cfg := config.Default()
	bad := jailWith("sshd")
	bad.Regexes = []config.RegexInfo{{Name: DefaultPatternName, Pattern: ""}}
	good := jailWith("nginx")
	good.Regexes = []config.RegexInfo{
		{Name: "default", Pattern: logparse.DefaultSSHDPattern},
	}
	cfg.Jails = []config.Jail{bad, good}

	warnings, err := Finalize(&cfg)
	if err != nil {
		t.Fatalf("单个 jail 编译失败不应致命，实得 %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "sshd") {
		t.Fatalf("告警应只含坏正则的 jail，实得 %v", warnings)
	}
	if strings.Contains(warnings[0], "nginx") {
		t.Fatalf("正常 jail 不应出现在告警里，实得 %q", warnings[0])
	}
	if cfg.Jails[1].Regexes[0].Compiled == nil {
		t.Fatal("nginx 的正则应编译成功")
	}
	if rs := BuildRuleSet(&cfg.Jails[1]); rs.IsEmpty() {
		t.Fatal("nginx 的规则集应可用")
	}
}
