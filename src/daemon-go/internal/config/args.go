package config

import (
	"fmt"
	"strings"
)

// DefaultConfigPath 是未指定 `-c` / `-C` 时使用的默认单文件配置路径。
const DefaultConfigPath = "/etc/firewall-daemon/config.yml"

// Version 在构建期由链接器注入（-ldflags -X）。默认 dev 仅用于本地运行。
var Version = "dev"

// ConfigArgs 是命令行参数的解析结果。
type ConfigArgs struct {
	// ConfigPath 是 `-c` / `--config` 给出的文件路径，或 `-C` / `--config-dir` 给出的目录。
	ConfigPath string
	Daemon     bool
	Strict     bool
	Rollback   bool
}

// PrintHelp 打印帮助信息。
func PrintHelp() {
	fmt.Printf(`firewall-daemon - 日志监控 + 自动封禁守护进程

USAGE:
    firewall-daemon [OPTIONS]

OPTIONS:
    -c, --config <FILE>     配置文件路径 (默认: %s)
    -C, --config-dir <DIR>  配置目录路径 (加载目录下所有 .yaml 文件)
    -d, --daemon            以守护进程模式运行 (后台化 + PID 文件)
        --no-strict         宽松模式: 忽略未知配置 key (默认: 严格模式)
        --rollback          回滚到上一个配置版本 (需守护进程运行中)
    -h, --help              显示帮助信息

EXAMPLES:
    firewall-daemon -c /etc/firewall-daemon/config.yml
    firewall-daemon -C /etc/firewall -d
    firewall-daemon --config-dir /etc/firewall --daemon
    firewall-daemon --rollback

CONFIGURATION:
    配置文件为 YAML 格式, 必须包含 'jails' 列表。
    每个 jail 至少需要 'name' 和 'log_file' 字段。

    目录模式下, 加载目录下所有 .yml/.yaml 文件 (按名字母序合并)。
    后加载的文件可覆盖先加载的配置。

EXIT CODES:
    0   正常退出 (含 --help / --rollback 成功)
    1   启动失败 (配置错误 / 内核模块未加载 / procfs 不可用)
    2   运行时错误 (日志文件不可读 / 权限不足)

VERSION:
    %s
`, DefaultConfigPath, Version)
}

// ParseConfigArgs 解析命令行参数。
//
// args 需包含程序名（args[0]），与 Rust 侧一致地从下标 1 开始解析。
//
// 返回 nil, nil 表示 `--help` 已打印帮助，调用方应直接以成功状态退出。
// 未知参数或缺失取值返回错误。
func ParseConfigArgs(args []string) (*ConfigArgs, error) {
	out := &ConfigArgs{
		ConfigPath: DefaultConfigPath,
		Strict:     true,
	}

	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-h", "--help":
			PrintHelp()
			return nil, nil
		case "-c", "--config":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s 缺少取值", arg)
			}
			out.ConfigPath = args[i]
		case "-C", "--config-dir":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("%s 缺少取值", arg)
			}
			out.ConfigPath = args[i]
		case "-d", "--daemon":
			out.Daemon = true
		case "--no-strict":
			out.Strict = false
		case "--rollback":
			out.Rollback = true
		default:
			switch {
			case strings.HasPrefix(arg, "--config="):
				out.ConfigPath = strings.TrimPrefix(arg, "--config=")
			case strings.HasPrefix(arg, "--config-dir="):
				out.ConfigPath = strings.TrimPrefix(arg, "--config-dir=")
			default:
				return nil, fmt.Errorf("未知参数: %s", arg)
			}
		}
	}

	return out, nil
}
