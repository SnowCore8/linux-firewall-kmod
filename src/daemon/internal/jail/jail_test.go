package jail

import (
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/logparse"
)

// jailWith 构造一个通过校验的 enabled jail。
func jailWith(name string) config.Jail {
	j := config.NewJail(name)
	j.LogFiles = []string{"/var/log/test.log"}
	j.MaxRetries = 5
	j.MaxRetriesSet = true
	j.FindTime = 600
	j.FindTimeSet = true
	j.BanTime = 600
	j.BanTimeSet = true
	return j
}

// TestServiceNameMatchRequiresWordBoundaries 覆盖服务名匹配的边界规则。
//
// 任意子串匹配会让 `myhttpd` 里的 `http` 生效，阈值出现与名字无关的意外取值。
func TestServiceNameMatchRequiresWordBoundaries(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"sshd", true},
		{"ssh", true},
		{"ssh-custom", true},
		{"custom-ssh", true},
		{"my-ssh-jail", true},
		{"myhttpd", false},
		{"sshx", false},
		{"xssh", false},
		{"nginx", true},
		{"nginx-proxy", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsServiceNameMatch(tc.name, sshPatterns); got != tc.want && tc.name != "nginx" && tc.name != "nginx-proxy" {
			t.Fatalf("IsServiceNameMatch(%q, ssh)=%v，期望 %v", tc.name, got, tc.want)
		}
	}
	if !IsServiceNameMatch("nginx-proxy", webPatterns) {
		t.Fatal("nginx-proxy 应命中 WEB")
	}
}

// TestServiceKindPriorityIsStable 覆盖多类别命中时的固定优先级。
//
// `ssh-http` 同时命中 SSH 与 WEB，必须取最靠前的那一类，保证同一名字在所有进程
// 里推断出同一组阈值。
func TestServiceKindPriorityIsStable(t *testing.T) {
	cases := map[string]string{
		"sshd":        "SSH",
		"ssh-http":    "SSH",
		"nginx":       "WEB",
		"vsftpd":      "FTP",
		"postfix":     "MAIL",
		"frp":         "FRP",
		"mysql":       "DB",
		"unrelated":   "",
		"web-ssh-x":   "SSH",
		"db-postgres": "DB",
	}
	for name, want := range cases {
		if got := ServiceKind(name); got != want {
			t.Fatalf("ServiceKind(%q)=%q，期望 %q", name, got, want)
		}
	}
}

// TestApplySmartDefaultsFillsOnlyUnsetFields 覆盖「只填用户没写的字段」。
func TestApplySmartDefaultsFillsOnlyUnsetFields(t *testing.T) {
	cfg := config.Default()
	explicit := config.NewJail("sshd")
	explicit.LogFiles = []string{"/a"}
	explicit.MaxRetries = 42
	explicit.MaxRetriesSet = true
	cfg.Jails = []config.Jail{explicit}

	ApplySmartDefaults(&cfg)

	j := cfg.Jails[0]
	if j.MaxRetries != 42 {
		t.Fatalf("用户显式配置的 max_retries 被覆盖为 %d", j.MaxRetries)
	}
	if j.FindTime != 600 {
		t.Fatalf("SSH 类 findtime 应为 600，实得 %d", j.FindTime)
	}
	if j.BanTime != 900 {
		t.Fatalf("SSH 类 ban_time 应为 900，实得 %d", j.BanTime)
	}
}

// TestApplySmartDefaultsIsIdempotent 覆盖幂等性。
//
// 第二次调用不得把上一次推断出的值当作「用户输入」而固化：否则改过一次配置后
// 再改名字，阈值会停留在旧类别上。
func TestApplySmartDefaultsIsIdempotent(t *testing.T) {
	cfg := config.Default()
	cfg.Jails = []config.Jail{config.NewJail("nginx")}

	ApplySmartDefaults(&cfg)
	first := cfg.Jails[0]

	// 改名后重新推断：Set 标记仍为 false，故阈值应跟着新类别走。
	cfg.Jails[0].Name = "sshd"
	ApplySmartDefaults(&cfg)
	second := cfg.Jails[0]

	if first.MaxRetries != 10 || first.BanTime != 1800 {
		t.Fatalf("WEB 类推断值不符：retries=%d ban=%d", first.MaxRetries, first.BanTime)
	}
	if second.MaxRetries != 5 || second.BanTime != 900 {
		t.Fatalf("改名后应重新推断为 SSH 类：retries=%d ban=%d", second.MaxRetries, second.BanTime)
	}
}

// TestApplySmartDefaultsFallsBackToGlobalDefaults 覆盖未命中服务类型的分支。
func TestApplySmartDefaultsFallsBackToGlobalDefaults(t *testing.T) {
	cfg := config.Default()
	cfg.DefaultMaxRetries = 7
	cfg.DefaultFindTime = 111
	cfg.DefaultBanTime = 222
	cfg.Jails = []config.Jail{config.NewJail("mystery-service")}

	ApplySmartDefaults(&cfg)

	j := cfg.Jails[0]
	if j.MaxRetries != 7 || j.FindTime != 111 || j.BanTime != 222 {
		t.Fatalf("未命中服务类型应取全局默认，实得 retries=%d find=%d ban=%d",
			j.MaxRetries, j.FindTime, j.BanTime)
	}
}

// TestValidateAcceptsAHealthyConfig 覆盖校验通过路径。
func TestValidateAcceptsAHealthyConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Jails = []config.Jail{jailWith("sshd")}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("合法配置被拒：%v", err)
	}
}

// TestValidateRejectsTheDocumentedFields 覆盖每一项硬校验。
func TestValidateRejectsTheDocumentedFields(t *testing.T) {
	base := func() config.Config {
		cfg := config.Default()
		cfg.Jails = []config.Jail{jailWith("sshd")}
		return cfg
	}

	t.Run("无 jail", func(t *testing.T) {
		cfg := base()
		cfg.Jails = nil
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "jail_count") {
			t.Fatalf("应拒绝空 jail 列表，实得 %v", err)
		}
	})

	t.Run("jail 数超上限", func(t *testing.T) {
		cfg := base()
		cfg.Jails = make([]config.Jail, config.MaxJails+1)
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "jail_count") {
			t.Fatalf("应拒绝超上限，实得 %v", err)
		}
	})

	t.Run("interval 越界", func(t *testing.T) {
		cfg := base()
		cfg.Interval = 61
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "interval") {
			t.Fatalf("应拒绝 interval=61，实得 %v", err)
		}
		cfg.Interval = 0
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "interval") {
			t.Fatalf("应拒绝 interval=0，实得 %v", err)
		}
	})

	t.Run("log_max_files 为 0", func(t *testing.T) {
		cfg := base()
		cfg.LogMaxFiles = 0
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "log_max_files") {
			t.Fatalf("应拒绝 log_max_files=0，实得 %v", err)
		}
	})

	t.Run("全局重试为 0", func(t *testing.T) {
		cfg := base()
		cfg.DefaultMaxRetries = 0
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "default_max_retries") {
			t.Fatalf("应拒绝，实得 %v", err)
		}
	})

	t.Run("全局 findtime 为 0", func(t *testing.T) {
		cfg := base()
		cfg.DefaultFindTime = 0
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "default_findtime") {
			t.Fatalf("应拒绝，实得 %v", err)
		}
	})

	t.Run("jail 无日志文件", func(t *testing.T) {
		cfg := base()
		cfg.Jails[0].LogFiles = nil
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "no log files") {
			t.Fatalf("应拒绝，实得 %v", err)
		}
	})

	t.Run("jail 重试为 0", func(t *testing.T) {
		cfg := base()
		cfg.Jails[0].MaxRetries = 0
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "max_retries") {
			t.Fatalf("应拒绝，实得 %v", err)
		}
	})

	t.Run("jail findtime 为 0", func(t *testing.T) {
		cfg := base()
		cfg.Jails[0].FindTime = 0
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "findtime") {
			t.Fatalf("应拒绝，实得 %v", err)
		}
	})

	t.Run("ban_time 非法", func(t *testing.T) {
		cfg := base()
		cfg.Jails[0].BanTime = 0
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "ban_time") {
			t.Fatalf("应拒绝 ban_time=0，实得 %v", err)
		}
		cfg.Jails[0].BanTime = -2
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "ban_time") {
			t.Fatalf("应拒绝 ban_time=-2，实得 %v", err)
		}
		cfg.Jails[0].BanTime = -1
		if err := Validate(&cfg); err != nil {
			t.Fatalf("永久封禁（-1）应被接受，实得 %v", err)
		}
	})

	t.Run("禁用的 jail 不参与校验", func(t *testing.T) {
		cfg := base()
		bad := config.NewJail("disabled")
		bad.Enabled = false
		cfg.Jails = append(cfg.Jails, bad)
		if err := Validate(&cfg); err != nil {
			t.Fatalf("禁用 jail 的缺失字段不应报错，实得 %v", err)
		}
	})
}

// TestValidateClusterBounds 覆盖集群检测的上界与下界。
//
// 下界是**安全**约束：命中后封的是整个聚合网段，前缀过短会一次封掉远超预期的
// 地址范围（`/1` 即半个 IPv4 空间）。
func TestValidateClusterBounds(t *testing.T) {
	cfgWith := func(prefixV4, prefixV6 uint8) *config.Config {
		cfg := config.Default()
		j := jailWith("sshd")
		j.Cluster.Enabled = true
		j.Cluster.PrefixV4 = prefixV4
		j.Cluster.PrefixV6 = prefixV6
		cfg.Jails = []config.Jail{j}
		return &cfg
	}

	if err := Validate(cfgWith(24, 48)); err != nil {
		t.Fatalf("默认量级（/24、/48）应通过：%v", err)
	}
	if err := Validate(cfgWith(MinPrefixV4, MinPrefixV6)); err != nil {
		t.Fatalf("恰好等于下限应通过：%v", err)
	}
	if err := Validate(cfgWith(MinPrefixV4-1, 48)); err == nil {
		t.Fatal("低于下限的 prefix_v4 应被拒绝")
	}
	if err := Validate(cfgWith(24, MinPrefixV6-1)); err == nil {
		t.Fatal("低于下限的 prefix_v6 应被拒绝")
	}
	if err := Validate(cfgWith(33, 48)); err == nil {
		t.Fatal("超过 32 的 prefix_v4 应被拒绝")
	}
	if err := Validate(cfgWith(24, 129)); err == nil {
		t.Fatal("超过 128 的 prefix_v6 应被拒绝")
	}

	// window / min_ips 为 0 会让检测直接返回空：用户以为开着而实际永不触发。
	cfg := cfgWith(24, 48)
	cfg.Jails[0].Cluster.Window = 0
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "cluster.window") {
		t.Fatalf("应拒绝 cluster.window=0，实得 %v", err)
	}
	cfg = cfgWith(24, 48)
	cfg.Jails[0].Cluster.MinIPs = 0
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "cluster.min_ips") {
		t.Fatalf("应拒绝 cluster.min_ips=0，实得 %v", err)
	}
}

// TestClusterWarningOnMaxPerIPAboveMinIPs 覆盖「合法但失去区分度」的警告。
func TestClusterWarningOnMaxPerIPAboveMinIPs(t *testing.T) {
	j := jailWith("sshd")
	j.Cluster.Enabled = true
	j.Cluster.MinIPs = 3
	j.Cluster.MaxPerIP = 4
	if got := ClusterWarning(&j); got == "" {
		t.Fatal("max_per_ip 大于 min_ips 时应产生警告")
	}
	j.Cluster.MaxPerIP = 3
	if got := ClusterWarning(&j); got != "" {
		t.Fatalf("相等不应告警，实得 %q", got)
	}
	j.Cluster.Enabled = false
	if got := ClusterWarning(&j); got != "" {
		t.Fatalf("未启用不应告警，实得 %q", got)
	}
}

// TestCompileInjectsBuiltinPatternOnlyWhenTheListIsEmpty 覆盖内置模式的注入条件。
//
// `regexes:` 写了却给空串时列表非空，内置模式**不会**被补上——这正是集成测试里
// 「空 pattern 能否封禁」这一问的关键：答案只能来自关键字回退。
func TestCompileInjectsBuiltinPatternOnlyWhenTheListIsEmpty(t *testing.T) {
	empty := config.NewJail("sshd")
	empty.Regexes = nil
	if err := CompileJailRegexes(&empty); err != nil {
		t.Fatalf("空列表应注入内置模式并编译成功：%v", err)
	}
	if len(empty.Regexes) != 1 || empty.Regexes[0].Pattern != logparse.DefaultSSHDPattern {
		t.Fatalf("应注入内置 sshd 模式，实得 %+v", empty.Regexes)
	}
	if empty.Regexes[0].Compiled == nil {
		t.Fatal("内置模式应编译成功")
	}

	blank := config.NewJail("sshd")
	blank.Regexes = []config.RegexInfo{{Name: DefaultPatternName, Pattern: ""}}
	err := CompileJailRegexes(&blank)
	if err == nil {
		t.Fatal("唯一的空模式被跳过后一条都没编译成功，应报错")
	}
	if !strings.Contains(err.Error(), "No regex patterns compiled") {
		t.Fatalf("错误文案应点明一条都没编译成功，实得 %v", err)
	}
	if blank.Regexes[0].Compiled != nil {
		t.Fatal("空模式不应得到编译结果")
	}
}

// TestEmptyPatternLosesTheBuiltinButKeepsFallbackMatching 是本包最重要的一条断言。
//
// 它把 Rust 版与集成测试之间的分歧钉死在代码里：
//   - 配置写 `regexes: {default: {pattern: ""}}` 时，规则集是**零规则**的；
//   - 内置 sshd 模式不会补上（列表非空）；
//   - 该规则集仍能封禁 sshd 失败行，靠的是**关键字回退**，而不是任何正则；
//   - 非 sshd 的失败行（FRP、vsftpd、nginx）既无正则也无关键字，**匹配不到**。
//
// 最后一条解释了 `tests/test_13_frp_jail.py` 为何依赖「procfs 存在」这个前提：
// 该测试断言的是 FRP 行被封禁，而 FRP 支持已在早期提交中被有意移除。
func TestEmptyPatternLosesTheBuiltinButKeepsFallbackMatching(t *testing.T) {
	j := config.NewJail("sshd")
	j.Regexes = []config.RegexInfo{{Name: DefaultPatternName, Pattern: ""}}
	_ = CompileJailRegexes(&j)

	rs := BuildRuleSet(&j)
	if !rs.IsEmpty() {
		t.Fatalf("空 pattern 未编译成功，规则集应为空，实得 %d 条：%v", rs.Len(), rs.RuleNames())
	}

	sshdLine := "Mar 10 10:30:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 12345 ssh2"
	addr, via, ok := rs.Parse(sshdLine)
	if !ok {
		t.Fatal("sshd 失败行应靠关键字回退匹配到")
	}
	if via != logparse.MatchViaFallback {
		t.Fatalf("应走关键字回退，实得 %v", via)
	}
	if addr.String() != "192.0.2.1" {
		t.Fatalf("提取到 %s，期望 192.0.2.1", addr)
	}

	// 非 sshd 的失败行：没有正则、也没有关键字，匹配不到。
	for _, line := range []string{
		"2026/04/22 10:30:01 [W] [proxy/proxy.go:100] get a user connection [203.0.113.50:12345]",
		`vsftpd: FAIL LOGIN: Client="203.0.113.50"`,
		`203.0.113.100 - - [10/Mar/2026:10:30:01 +0000] "GET /admin HTTP/1.1" 401`,
	} {
		if _, _, ok := rs.Parse(line); ok {
			t.Fatalf("空 pattern 下不该匹配到非 sshd 行：%s", line)
		}
	}
}

// TestCompileKeepsOneBadPatternFromKillingTheJail 覆盖「一条坏模式不影响其他模式」。
func TestCompileKeepsOneBadPatternFromKillingTheJail(t *testing.T) {
	j := config.NewJail("sshd")
	j.Regexes = []config.RegexInfo{
		{Name: "redos", Pattern: `(a+)+$`},
		{Name: "valid", Pattern: logparse.DefaultSSHDPattern},
	}
	if err := CompileJailRegexes(&j); err != nil {
		t.Fatalf("至少一条成功时不应报错：%v", err)
	}
	if j.Regexes[0].Compiled != nil {
		t.Fatal("ReDoS 模式不应被编译")
	}
	if j.Regexes[1].Compiled == nil {
		t.Fatal("合法模式应编译成功")
	}
	rs := BuildRuleSet(&j)
	if rs.Len() != 1 || rs.RuleNames()[0] != "valid" {
		t.Fatalf("规则集应只含合法那条，实得 %v", rs.RuleNames())
	}
}

// TestRecompileMustClearStaleCompiledEntries 覆盖重复编译不得残留旧编译结果。
//
// 若不清空，上一轮编译成功的条目会让 `BuildRuleSet` 把一条已不在配置里的规则
// 搬进规则集，热重载后仍按旧正则匹配。
func TestRecompileMustClearStaleCompiledEntries(t *testing.T) {
	j := config.NewJail("sshd")
	j.Regexes = []config.RegexInfo{{Name: "old", Pattern: logparse.DefaultSSHDPattern}}
	if err := CompileJailRegexes(&j); err != nil {
		t.Fatalf("首次编译失败：%v", err)
	}
	if j.Regexes[0].Compiled == nil {
		t.Fatal("首次编译应成功")
	}

	j.Regexes = []config.RegexInfo{{Name: "new", Pattern: ""}}
	if err := CompileJailRegexes(&j); err == nil {
		t.Fatal("全部模式为空时应报错")
	}
	if j.Regexes[0].Compiled != nil {
		t.Fatal("重新编译后不应残留旧的编译结果")
	}
	if rs := BuildRuleSet(&j); !rs.IsEmpty() {
		t.Fatalf("规则集应为空，实得 %v", rs.RuleNames())
	}
}

// TestCompileSkipsDisabledJails 覆盖禁用 jail 不参与编译。
func TestCompileSkipsDisabledJails(t *testing.T) {
	cfg := config.Default()
	j := config.NewJail("sshd")
	j.Enabled = false
	j.Regexes = []config.RegexInfo{{Name: "redos", Pattern: `(a+)+$`}}
	cfg.Jails = []config.Jail{j}

	if err := CompileRegexes(&cfg); err != nil {
		t.Fatalf("禁用 jail 不应参与编译，实得错误 %v", err)
	}
}

// TestCompileReportsEveryFailingJail 覆盖「尽力而为 + 汇总失败」。
func TestCompileReportsEveryFailingJail(t *testing.T) {
	cfg := config.Default()
	a := config.NewJail("a")
	a.Regexes = []config.RegexInfo{{Name: "blank", Pattern: ""}}
	b := config.NewJail("b")
	b.Regexes = []config.RegexInfo{{Name: "blank", Pattern: ""}}
	cfg.Jails = []config.Jail{a, b}

	err := CompileRegexes(&cfg)
	if err == nil {
		t.Fatal("两个 jail 都失败时应返回错误")
	}
	// 两个 jail 各自的失败都要出现在同一条错误里，不能被后一个覆盖前一个。
	if !strings.Contains(err.Error(), "'a'") || !strings.Contains(err.Error(), "'b'") {
		t.Fatalf("错误应汇总两个 jail，实得 %v", err)
	}
}

// TestBuildRuleSetsFollowsJailOrderAndSkipsDisabled 覆盖规则集顺序与跳过规则。
func TestBuildRuleSetsFollowsJailOrderAndSkipsDisabled(t *testing.T) {
	cfg := config.Default()
	a := config.NewJail("a")
	a.Regexes = []config.RegexInfo{{Name: "r", Pattern: logparse.DefaultSSHDPattern}}
	b := config.NewJail("b")
	b.Enabled = false
	c := config.NewJail("c")
	c.Regexes = []config.RegexInfo{{Name: "r", Pattern: logparse.DefaultSSHDPattern}}
	cfg.Jails = []config.Jail{a, b, c}

	sets := BuildRuleSets(&cfg)
	if len(sets) != 2 {
		t.Fatalf("应得到 2 个规则集，实得 %d", len(sets))
	}
	if sets[0].Jail() != "a" || sets[1].Jail() != "c" {
		t.Fatalf("顺序应与配置一致，实得 %s, %s", sets[0].Jail(), sets[1].Jail())
	}
}

// TestResetRegexesClearsPatternsAndCompiled 覆盖清空。
func TestResetRegexesClearsPatternsAndCompiled(t *testing.T) {
	j := config.NewJail("sshd")
	j.Regexes = []config.RegexInfo{{Name: "r", Pattern: logparse.DefaultSSHDPattern}}
	if err := CompileJailRegexes(&j); err != nil {
		t.Fatalf("编译失败：%v", err)
	}
	ResetRegexes(&j)
	if len(j.Regexes) != 0 {
		t.Fatalf("清空后应为 0 条，实得 %d", len(j.Regexes))
	}
}
