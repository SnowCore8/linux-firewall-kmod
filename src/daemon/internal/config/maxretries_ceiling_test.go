// max_retries 上限的边界用例：用运行期真源算边界，而不是写死 95/96。
//
// 放在外部测试包里，是因为要同时 import decision 与 detect：decision 反向依赖本包，
// 包内测试引它会成环。
package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/detect"
)

// retriesCeiling 是还能触发的最大阈值：窗口只保留 detect.MaxTimestampsPerIP 条时间戳，
// 有效阈值再叠加 decision 的两个加数（高峰 +2、内网 +3）。
func retriesCeiling() uint32 {
	return uint32(detect.MaxTimestampsPerIP) - decision.PeakHoursAddend - decision.InternalSourceAddend
}

// jailYAML 拼一份带单个 jail 的配置；retries 为 nil 时不写 max_retries。
func jailYAML(defaultsRetries, jailRetries *uint32) string {
	var b strings.Builder
	if defaultsRetries != nil {
		fmt.Fprintf(&b, "defaults:\n  max_retries: %d\n", *defaultsRetries)
	}
	b.WriteString("jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n")
	if jailRetries != nil {
		fmt.Fprintf(&b, "    max_retries: %d\n", *jailRetries)
	}
	return b.String()
}

func parse(t *testing.T, content string) (config.Config, error) {
	t.Helper()
	cfg := config.Default()
	return cfg, config.ParseConfig(content, &cfg)
}

// TestMaxRetriesCeilingBoundaryAccepted 核对边界值本身可用：阈值恰好等于「保留条数 - 两个加数」，
// 内网地址在高峰期的窗口计数仍能顶到阈值。
func TestMaxRetriesCeilingBoundaryAccepted(t *testing.T) {
	ceiling := retriesCeiling()
	three := uint32(3)

	cfg, err := parse(t, jailYAML(&three, &ceiling))
	if err != nil {
		t.Fatalf("max_retries=%d（上限）应被接受，却报错: %v", ceiling, err)
	}
	if got := cfg.Jails[0].MaxRetries; got != ceiling {
		t.Errorf("jail max_retries = %d，期望原值 %d", got, ceiling)
	}

	// 全局默认同样按上限放行。
	cfg, err = parse(t, jailYAML(&ceiling, nil))
	if err != nil {
		t.Fatalf("defaults.max_retries=%d（上限）应被接受，却报错: %v", ceiling, err)
	}
	if got := cfg.DefaultMaxRetries; got != ceiling {
		t.Errorf("defaults.max_retries = %d，期望原值 %d", got, ceiling)
	}
}

// TestMaxRetriesCeilingBoundaryRejected 核对越界一格即拒绝，且错误里写明上限与算法由来。
func TestMaxRetriesCeilingBoundaryRejected(t *testing.T) {
	ceiling := retriesCeiling()
	over := ceiling + 1
	three := uint32(3)

	_, err := parse(t, jailYAML(&three, &over))
	if err == nil {
		t.Fatalf("max_retries=%d（超过上限 %d）应被拒绝", over, ceiling)
	}
	for _, want := range []string{"max_retries", "超过上限", fmt.Sprint(ceiling)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误 %q 未包含 %q", err, want)
		}
	}

	// 全局默认走同一条校验：jail 没写 max_retries 时取的就是它。
	_, err = parse(t, jailYAML(&over, nil))
	if err == nil {
		t.Fatalf("defaults.max_retries=%d 应被拒绝", over)
	}
	if !strings.Contains(err.Error(), "defaults.max_retries") {
		t.Errorf("错误 %q 未指明是 defaults.max_retries", err)
	}
}

// TestMaxRetriesZeroMeansDefault 固定 0 的语义没被上限校验改掉：0 取全局默认。
func TestMaxRetriesZeroMeansDefault(t *testing.T) {
	zero := uint32(0)
	five := uint32(5)

	cfg, err := parse(t, jailYAML(nil, &zero))
	if err != nil {
		t.Fatalf("max_retries=0 应被接受（表示取默认）: %v", err)
	}
	if got := cfg.Jails[0].MaxRetries; got != config.Default().DefaultMaxRetries {
		t.Errorf("jail max_retries = %d，期望全局默认 %d", got, config.Default().DefaultMaxRetries)
	}

	cfg, err = parse(t, jailYAML(&five, &zero))
	if err != nil {
		t.Fatalf("max_retries=0 应被接受（表示取默认）: %v", err)
	}
	if got := cfg.Jails[0].MaxRetries; got != five {
		t.Errorf("jail max_retries = %d，期望取全局默认 %d", got, five)
	}
}
