package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/config"
)

// repoRoot 从本测试文件位置向上回溯到仓库根，避免硬编码绝对路径。
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("无法定位测试文件位置")
	}
	// .../src/daemon-go/cmd/firewall-daemon/main_test.go -> 上溯五层到仓库根。
	return filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file)))))
}

func TestRunHelpReturnsNil(t *testing.T) {
	if err := run([]string{"firewall-daemon", "--help"}); err != nil {
		t.Fatalf("--help 应成功退出，实得: %v", err)
	}
}

func TestRunUnknownArgFails(t *testing.T) {
	if err := run([]string{"firewall-daemon", "--nope"}); err == nil {
		t.Fatal("未知参数应报错")
	}
}

func TestLoadConfigMissingPathFails(t *testing.T) {
	parsed := &config.ConfigArgs{ConfigPath: filepath.Join(repoRoot(t), "does-not-exist.yml"), Strict: true}
	cfg := config.Default()
	if err := loadConfig(parsed, &cfg); err == nil {
		t.Fatal("不存在的配置路径应报错")
	}
}

func TestLoadConfigFileSucceeds(t *testing.T) {
	// 复用仓库内现成的示例配置，验证单文件加载路径可用。
	path := filepath.Join(repoRoot(t), "config", "default.yaml")
	parsed := &config.ConfigArgs{ConfigPath: path, Strict: true}
	cfg := config.Default()
	if err := loadConfig(parsed, &cfg); err != nil {
		t.Fatalf("加载示例配置失败: %v", err)
	}
}
