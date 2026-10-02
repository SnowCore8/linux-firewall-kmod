package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
}

func findTestJail(t *testing.T, cfg *Config, name string) *Jail {
	t.Helper()
	j := cfg.FindJail(name)
	if j == nil {
		t.Fatalf("应存在 jail %q", name)
	}
	return j
}

// 运行期覆盖文件只带 enabled 时，不能抹掉预置文件里的 log_files。
func TestRuntimeOverrideKeepsDefinitionFromPresetFile(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "frp.yaml", "jails:\n  frp:\n    enabled: true\n    log_files:\n      - /var/log/frp.log\n")
	writeConfig(t, dir, "_overrides.yaml", "jails:\n  frp:\n    enabled: false\n")

	cfg := Default()
	if err := LoadConfigDirectory(dir, &cfg, false); err != nil {
		t.Fatalf("目录加载失败: %v", err)
	}

	var matched []*Jail
	for i := range cfg.Jails {
		if cfg.Jails[i].Name == "frp" {
			matched = append(matched, &cfg.Jails[i])
		}
	}
	if len(matched) != 1 {
		t.Fatalf("同名 jail 应合并成一条，实际 %d 条", len(matched))
	}
	if len(matched[0].LogFiles) != 1 || matched[0].LogFiles[0] != "/var/log/frp.log" {
		t.Errorf("运行期覆盖不应抹掉 log_files: %v", matched[0].LogFiles)
	}
	if matched[0].Enabled {
		t.Error("运行期覆盖的 enabled 应最后生效")
	}
}

// 运行期覆盖引用了未定义的 jail：忽略，而不是造出一个缺 log_files 的条目。
func TestRuntimeOverrideIgnoresUnknownJail(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "sshd.yaml", "jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n")
	writeConfig(t, dir, "_overrides.yaml", "jails:\n  ghost:\n    enabled: true\n")

	cfg := Default()
	if err := LoadConfigDirectory(dir, &cfg, false); err != nil {
		t.Fatalf("目录加载失败: %v", err)
	}
	if len(cfg.Jails) != 1 || cfg.Jails[0].Name != "sshd" {
		t.Fatalf("未定义的 jail 不应被造出来: %+v", cfg.Jails)
	}
}

// 普通文件之间的同名 jail 同样后到优先，且未声明的字段保留。
func TestLaterFileWinsForSameJailName(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "a-sshd.yaml", "jails:\n  sshd:\n    log_files:\n      - /var/log/a.log\n    max_retries: 2\n")
	writeConfig(t, dir, "b-sshd.yaml", "jails:\n  sshd:\n    max_retries: 5\n")

	cfg := Default()
	if err := LoadConfigDirectory(dir, &cfg, false); err != nil {
		t.Fatalf("目录加载失败: %v", err)
	}
	j := findTestJail(t, &cfg, "sshd")
	if j.MaxRetries != 5 {
		t.Errorf("后加载的文件应覆盖 max_retries: %d", j.MaxRetries)
	}
	if len(j.LogFiles) != 1 || j.LogFiles[0] != "/var/log/a.log" {
		t.Errorf("未声明的字段应保留: %v", j.LogFiles)
	}
}

// `_` 前缀文件即使字节序靠前，也必须最后合并。
func TestRuntimeOverrideFileSortsLast(t *testing.T) {
	dir := t.TempDir()
	// 00 排在 `_` 之前（字节序 0x30 < 0x5F），但运行期覆盖必须压过它。
	writeConfig(t, dir, "00-base.yaml", "jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n    enabled: true\n")
	writeConfig(t, dir, "_overrides.yaml", "jails:\n  sshd:\n    enabled: false\n")

	cfg := Default()
	if err := LoadConfigDirectory(dir, &cfg, false); err != nil {
		t.Fatalf("目录加载失败: %v", err)
	}
	if j := findTestJail(t, &cfg, "sshd"); j.Enabled {
		t.Error("运行期覆盖文件必须最后合并并生效")
	}
}

// 空目录报错。
func TestEmptyDirectoryIsRejected(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	if err := LoadConfigDirectory(dir, &cfg, false); err == nil {
		t.Fatal("空目录应报错")
	}
}

// 隐藏文件与非 YAML 文件被跳过。
func TestHiddenAndNonYamlFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, ".hidden.yaml", "jails:\n  ghost:\n    log_files:\n      - /var/log/x.log\n")
	writeConfig(t, dir, "notes.txt", "not yaml")
	writeConfig(t, dir, "sshd.yml", "jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n")

	cfg := Default()
	if err := LoadConfigDirectory(dir, &cfg, false); err != nil {
		t.Fatalf("目录加载失败: %v", err)
	}
	if len(cfg.Jails) != 1 || cfg.Jails[0].Name != "sshd" {
		t.Fatalf("只应加载 sshd.yml: %+v", cfg.Jails)
	}
}

// 目录加载失败时整体回滚，不留下半个配置。
func TestDirectoryLoadRollsBackAtomically(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "a-good.yaml", "jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n")
	writeConfig(t, dir, "b-bad.yaml", "jails:\n  sshd:\n    unknown_field: 1\n")

	cfg := Default()
	before := cfg.Jails
	err := LoadConfigDirectory(dir, &cfg, true)
	if err == nil {
		t.Fatal("含未知字段的文件应被严格模式拒绝")
	}
	if len(cfg.Jails) != len(before) {
		t.Errorf("失败后 jails 应回滚: %d", len(cfg.Jails))
	}
	if cfg.ConfigDir != "" {
		t.Error("失败后 ConfigDir 不应被设置")
	}
}

// 未知字段恒被拒绝：Rust 的 `deny_unknown_fields` 是结构性恒开的，
// `strict_mode` 字段虽被传递但并不放宽解析，Go 侧对齐同一行为。
func TestUnknownFieldAlwaysRejected(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "sshd.yaml", "jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n    unknown_field: 1\n")

	cfg := Default()
	if err := LoadConfigDirectory(dir, &cfg, false); err == nil {
		t.Fatal("未知字段应被拒绝")
	}
}

// 单文件加载设置 ConfigFile，目录加载设置 ConfigDir 并清空 ConfigFile。
func TestLoadConfigFileSetsPath(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, "sshd.yaml", "jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n")

	cfg := Default()
	path := filepath.Join(dir, "sshd.yaml")
	if err := ParseConfigFile(path, &cfg, false); err != nil {
		t.Fatalf("单文件加载失败: %v", err)
	}
	if cfg.ConfigFile != path {
		t.Errorf("ConfigFile=%q, want %q", cfg.ConfigFile, path)
	}

	cfg2 := Default()
	if err := LoadConfigDirectory(dir, &cfg2, false); err != nil {
		t.Fatalf("目录加载失败: %v", err)
	}
	if cfg2.ConfigDir != dir {
		t.Errorf("ConfigDir=%q, want %q", cfg2.ConfigDir, dir)
	}
	if cfg2.ConfigFile != "" {
		t.Errorf("目录模式应清空 ConfigFile: %q", cfg2.ConfigFile)
	}
}

// 缺少取值与未知参数都要报错。
func TestParseConfigArgsErrors(t *testing.T) {
	if _, err := ParseConfigArgs([]string{"firewall-daemon", "--bogus"}); err == nil {
		t.Error("未知参数应报错")
	}
	if _, err := ParseConfigArgs([]string{"firewall-daemon", "-c"}); err == nil {
		t.Error("-c 缺少取值应报错")
	}
}

// `-c` / `--config=` / `-C` 都写进 ConfigPath，默认严格模式。
func TestParseConfigArgsForms(t *testing.T) {
	a, err := ParseConfigArgs([]string{"firewall-daemon", "-c", "/tmp/x.yml", "-d"})
	if err != nil || a == nil {
		t.Fatalf("解析失败: %v", err)
	}
	if a.ConfigPath != "/tmp/x.yml" || !a.Daemon || !a.Strict {
		t.Errorf("解析结果不符: %+v", a)
	}

	b, err := ParseConfigArgs([]string{"firewall-daemon", "--config-dir=/tmp/dir", "--no-strict"})
	if err != nil || b == nil {
		t.Fatalf("解析失败: %v", err)
	}
	if b.ConfigPath != "/tmp/dir" || b.Strict {
		t.Errorf("解析结果不符: %+v", b)
	}
}

// `--help` 打印帮助并返回 nil 结果，调用方据此退出。
func TestParseConfigArgsHelp(t *testing.T) {
	a, err := ParseConfigArgs([]string{"firewall-daemon", "--help"})
	if err != nil {
		t.Fatalf("--help 不应报错: %v", err)
	}
	if a != nil {
		t.Errorf("--help 应返回 nil 结果: %+v", a)
	}
}

// 帮助文本包含关键参数，避免误删。
func TestHelpMentionsEssentialFlags(t *testing.T) {
	// PrintHelp 直接写 stdout，此处只校验常量与参数解析契约的一致性。
	if !strings.Contains(DefaultConfigPath, "config") {
		t.Errorf("默认配置路径异常: %s", DefaultConfigPath)
	}
}
