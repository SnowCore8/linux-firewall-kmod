//! CLI 参数解析 (`--config`, `--daemon`, `--strict`, `--rollback`, `--help`)

use anyhow::Result;

// ============================================================================
// 帮助信息
// ============================================================================

fn print_help() {
    println!(
        "firewall-daemon - 日志监控 + 自动封禁守护进程

USAGE:
    firewall-daemon [OPTIONS]

OPTIONS:
    -c, --config <FILE>     配置文件路径 (默认: /etc/firewall-daemon/config.yml)
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
    {}
",
        env!("CARGO_PKG_VERSION")
    );
}

// ============================================================================
// 参数解析
// ============================================================================

/// 解析命令行参数, 返回 `(config_path, daemon_mode, strict_mode, rollback)`。
///
/// # 支持的参数形式
///
/// | 参数 | 等价形式 | 默认值 |
/// |------|----------|--------|
/// | `-c FILE` | `--config=FILE`, `--config FILE` | `/etc/firewall-daemon/config.yml` |
/// | `-d` | `--daemon` | `false` |
/// | `--no-strict` | - | `false` (默认严格模式) |
/// | `--rollback` | - | `false` |
/// | `-h` | `--help` | - |
///
/// # Returns
/// - `Some((path, daemon, strict, rollback))`: 正常解析结果
/// - `None`: `--help` 已打印帮助, 调用方应直接 `Ok(())` 退出
///
/// # Errors
/// - 未知参数
/// - `-c` / `--config` 缺少值
pub fn parse_config_args(args: &[String]) -> Result<Option<(String, bool, bool, bool)>> {
    let mut config_path = "/etc/firewall-daemon/config.yml".to_string();
    let mut daemon_mode = false;
    let mut strict_mode = true;
    let mut rollback = false;
    let mut i = 1; // 跳过 args[0] (程序名)

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--config requires a value");
                }
                config_path = args[i].clone();
            }
            "-C" | "--config-dir" => {
                i += 1;
                if i >= args.len() {
                    anyhow::bail!("--config-dir requires a value");
                }
                config_path = args[i].clone();
            }
            s if s.starts_with("--config=") => {
                // 支持 --config=FILE 形式
                config_path = s["--config=".len()..].to_string();
            }
            s if s.starts_with("--config-dir=") => {
                // 支持 --config-dir=DIR 形式
                config_path = s["--config-dir=".len()..].to_string();
            }
            "-d" | "--daemon" => {
                daemon_mode = true;
            }
            "--no-strict" => {
                strict_mode = false;
            }
            "--rollback" => {
                rollback = true;
            }
            other => {
                anyhow::bail!("Unknown argument: {}", other);
            }
        }
        i += 1;
    }

    Ok(Some((config_path, daemon_mode, strict_mode, rollback)))
}
