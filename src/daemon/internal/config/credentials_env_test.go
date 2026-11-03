package config

import (
	"os"
	"testing"
)

const credentialYAML = "defaults:\n  metrics_username: yaml-user\n  metrics_password: yaml-pass\n"

// clearCredentialEnv 把两项凭据变量清空，并在用例结束后恢复进程原值。
// 不直接用 t.Setenv 是因为还需要表达「变量未设置」这一状态。
func clearCredentialEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{EnvMetricsUsername, EnvMetricsPassword} {
		old, ok := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("清除 %s 失败: %v", key, err)
		}
		t.Cleanup(func() {
			if ok {
				_ = os.Setenv(key, old)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
}

func TestEnvCredentialsOverrideYAML(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv(EnvMetricsUsername, "env-user")
	t.Setenv(EnvMetricsPassword, "env-pass")

	cfg := Default()
	if err := ParseConfig(credentialYAML, &cfg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if cfg.MetricsUsername != "env-user" || cfg.MetricsPassword != "env-pass" {
		t.Fatalf("凭据 = (%q, %q)，期望环境变量的值", cfg.MetricsUsername, cfg.MetricsPassword)
	}
	if !cfg.AuthEnabled() {
		t.Error("两项都非空却报告未启用认证")
	}
}

func TestEnvCredentialsExplicitEmptyDisablesAuth(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv(EnvMetricsUsername, "")
	t.Setenv(EnvMetricsPassword, "")

	cfg := Default()
	if err := ParseConfig(credentialYAML, &cfg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if cfg.MetricsUsername != "" || cfg.MetricsPassword != "" {
		t.Fatalf("显式空串没有覆盖 YAML: (%q, %q)", cfg.MetricsUsername, cfg.MetricsPassword)
	}
	if cfg.AuthEnabled() {
		t.Error("两项都空却报告启用了认证")
	}
}

func TestEnvCredentialsCanSupplyOneField(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv(EnvMetricsUsername, "env-user")

	cfg := Default()
	if err := ParseConfig(credentialYAML, &cfg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if cfg.MetricsUsername != "env-user" || cfg.MetricsPassword != "yaml-pass" {
		t.Fatalf("混合来源结果 = (%q, %q)，期望 env-user / yaml-pass", cfg.MetricsUsername, cfg.MetricsPassword)
	}
}

func TestCredentialSourcesDistinguishExplicitEmpty(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv(EnvMetricsUsername, "")
	t.Setenv(EnvMetricsPassword, "env-pass")

	cfg := Default()
	if err := ParseConfig(credentialYAML, &cfg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	user, pass := cfg.CredentialSources()
	if user != CredentialFromEnv {
		t.Errorf("显式设空的用户名来源 = %q，期望 %q", user, CredentialFromEnv)
	}
	if pass != CredentialFromEnv {
		t.Errorf("环境变量口令来源 = %q，期望 %q", pass, CredentialFromEnv)
	}
}

func TestCredentialSourcesFallBackToYAML(t *testing.T) {
	clearCredentialEnv(t)

	cfg := Default()
	if err := ParseConfig(credentialYAML, &cfg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	user, pass := cfg.CredentialSources()
	if user != CredentialFromYAML || pass != CredentialFromYAML {
		t.Fatalf("来源 = (%q, %q)，期望都来自配置文件", user, pass)
	}
}

func TestEnvCredentialsDoNotTouchConfigOnParseFailure(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv(EnvMetricsUsername, "env-user")
	t.Setenv(EnvMetricsPassword, "env-pass")

	cfg := Default()
	cfg.MetricsUsername = "keep-user"
	cfg.MetricsPassword = "keep-pass"
	if err := ParseConfig("defaults: [", &cfg); err == nil {
		t.Fatal("非法 YAML 应返回错误")
	}
	if cfg.MetricsUsername != "keep-user" || cfg.MetricsPassword != "keep-pass" {
		t.Fatalf("解析失败后凭据被改写: (%q, %q)", cfg.MetricsUsername, cfg.MetricsPassword)
	}
}
