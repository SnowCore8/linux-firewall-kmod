// 面板认证凭据的第二条来源：环境变量。
//
// 为什么要它：`config/default.yaml` 是被 git 跟踪的，把可用凭据写在那里等于把钥匙和锁一起
// 发出去——公开仓库里尤其如此。随包 systemd 单元以
// `EnvironmentFile=-/etc/firewall/credentials.env` 读取（可选；`make install` 会准备一个
// 空的 0600 文件），填好两项即可把凭据从被跟踪的 YAML 里移出去。
//
// 语义照契约（`contract/http.fwidl` 的 `auth` 段）：两项**都空**才是「未配置认证并放行」，
// 只填一项判为非法、整组端点一律拒绝。所以环境变量把某项设成空串是「显式关掉认证」的一部分，
// 不是「没设置」——用 LookupEnv 而不是 Getenv 就是为了保住这个区别。
package config

import "os"

// 认证凭据的环境变量名。命名前缀与守护进程其余运维入口一致（`FIREWALL_`）。
const (
	EnvMetricsUsername = "FIREWALL_METRICS_USERNAME"
	EnvMetricsPassword = "FIREWALL_METRICS_PASSWORD"
)

// applyEnvCredentials 把环境变量里的凭据盖在 YAML 之上。
//
// 只有真正设置了的项才覆盖；覆盖发生在 YAML 应用成功之后，所以「解析失败不改 cfg」的原子性
// 仍然成立。这一步不落盘：PUT /config 写回的是 webui 段的补丁，不会把这里的值抄进配置文件。
func applyEnvCredentials(cfg *Config) {
	if v, ok := os.LookupEnv(EnvMetricsUsername); ok {
		cfg.MetricsUsername = v
	}
	if v, ok := os.LookupEnv(EnvMetricsPassword); ok {
		cfg.MetricsPassword = v
	}
}

// CredentialSource 是「这一项凭据从哪来」的答案，只用于日志，永远不带值。
type CredentialSource string

const (
	// CredentialFromEnv：来自环境变量（含显式设空）。
	CredentialFromEnv CredentialSource = "环境变量"
	// CredentialFromYAML：来自配置文件里的 defaults 段。
	CredentialFromYAML CredentialSource = "配置文件"
	// CredentialUnset：两处都没给，按契约即「未配置认证」。
	CredentialUnset CredentialSource = "未配置"
)

// CredentialSources 报告用户名与口令各自的来源，供启动日志说明认证是怎么配起来的。
//
// 判据只看「有没有非空值」与「环境变量是否设置过」，不读回值本身，所以日志里不会出现凭据。
func (c *Config) CredentialSources() (username, password CredentialSource) {
	return credentialSource(c.MetricsUsername, EnvMetricsUsername),
		credentialSource(c.MetricsPassword, EnvMetricsPassword)
}

func credentialSource(value, envName string) CredentialSource {
	// 先看环境变量是否设置过：显式设空也是「来自环境变量」的一种，它是有意关闭
	// 认证或覆盖 YAML 的决定，不能报成「未配置」。
	if _, ok := os.LookupEnv(envName); ok {
		return CredentialFromEnv
	}
	if value == "" {
		return CredentialUnset
	}
	return CredentialFromYAML
}

// AuthEnabled 报告面板是否真的要求认证：两项都有值才算。
//
// 与 `internal/http` 的判定同一口径（两项都空即放行，只填一项判为非法并一律拒绝），
// 组合根用它决定要不要在「绑定到非回环地址」时告警。
func (c *Config) AuthEnabled() bool {
	return c.MetricsUsername != "" && c.MetricsPassword != ""
}
