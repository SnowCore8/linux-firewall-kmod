# 安装

本文档介绍如何安装 Linux Firewall 内核模块及其用户态守护进程。

## 系统要求

| 项目 | 最低要求 | 推荐配置 |
|------|----------|----------|
| 内核版本 | Linux 5.x | Linux 6.x LTS |
| CPU 架构 | x86_64 | x86_64 |
| 内存 | 256 MB | 512 MB+ |
| 磁盘空间 | 50 MB | 100 MB+ |
| 编译器 | GCC 10+ | GCC 12+ |

### 支持的发行版

| 发行版 | 状态 |
|--------|------|
| Ubuntu 20.04+ | 完全支持 |
| Debian 11+ | 完全支持 |
| CentOS 8+ | 完全支持 |
| RHEL 8+ | 完全支持 |
| Arch Linux | 社区支持 |
| Fedora 35+ | 社区支持 |

## 安装依赖

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    linux-headers-$(uname -r) \
    pkg-config
```

### CentOS / RHEL

```bash
sudo dnf install -y \
    gcc gcc-c++ make \
    kernel-devel-$(uname -r) \
    kernel-headers-$(uname -r) \
    pkg-config
```

### Arch Linux

```bash
sudo pacman -S --needed \
    base-devel \
    linux-headers \
    pkg-config
```

## 编译安装

### 1. 克隆仓库

```bash
git clone https://github.com/SnowCore8/linux-firewall-kmod.git
cd linux-firewall-kmod
```

### 2. 编译

编译完整项目（内核模块 + 守护进程）：

```bash
make
```

仅编译内核模块：

```bash
make kernel-module
```

仅编译守护进程：

```bash
make daemon
```

### 从源码构建 .deb 包

推荐使用 `make deb` 一步构建可分发的 .deb 安装包(适用于 Debian/Ubuntu 系发行版)。

```bash
# 编译产物
make                    # 编译内核模块 + Rust 守护进程
                        # 内核模块: build/kernel-module/firewall.ko
                        # 守护进程: build/daemon/firewall-daemon (6.2MB stripped)

# 构建 .deb
make deb                # 输出: build/deb/linux-firewall-kmod-2.2.0.deb (1.5MB)

# 安装
sudo dpkg -i build/deb/linux-firewall-kmod-2.2.0.deb
# 等同于:
#   1. dkms add + build + install firewall/2.2.0
#   2. modprobe firewall
#   3. systemctl enable --now firewall-daemon
#   4. cp /etc/firewall/*.yaml (从 /usr/share/firewall/ 复制)

# 验证
systemctl status firewall-daemon
lsmod | grep firewall
ls /proc/firewall/
```

> 如果 `make deb` 报 `make: cargo: 没有那个文件或目录`,说明 PATH 里没有 cargo。可以 `source ~/.cargo/env` 后重试,或安装 rustup (https://rustup.rs)。

### 3. 安装

#### 方式一：一键安装（推荐）

```bash
sudo env "PATH=$PATH" make install
```

此命令会自动：
1. 构建内核模块和守护进程（如果尚未构建）
2. 安装所有组件到系统目录
3. 验证安装完整性
4. 加载内核模块
5. 启动 systemd 服务

> 💡 **提示**：使用 `sudo env "PATH=$PATH"` 确保 cargo 在 PATH 中。如果不加，sudo 环境下可能找不到 cargo。

#### 方式二：先构建后安装

```bash
# 先构建
make build

# 再安装
sudo env "PATH=$PATH" make install
```

#### 安装流程说明

`make install` 按以下顺序执行：
1. **build** - 构建内核模块和守护进程
2. **install-kernel-module** - 安装内核模块到 `/lib/modules/$(uname -r)/extra/`
3. **install-daemon** - 安装守护进程到 `/usr/local/sbin/`
4. **install-config** - 安装配置文件到 `/etc/firewall/`
5. **install-state** - 创建状态目录 `/var/lib/firewall/`
6. **install-systemd** - 安装 systemd 服务单元
7. **install-start** - 加载内核模块并启动守护进程
8. **install-verify** - 验证所有组件安装成功

安装完成后：

- 内核模块 `firewall.ko` 安装到 `/lib/modules/$(uname -r)/extra/`
- 守护进程 `firewall-daemon` 安装到 `/usr/local/sbin/`
- 配置文件安装到 `/etc/firewall/`（包含 12 个 jail 配置）
- 状态数据目录 `/var/lib/firewall/`
- systemd 服务文件安装到 `/etc/systemd/system/`

### 4. 验证安装

安装完成后，验证服务状态：

```bash
# 检查服务状态
sudo systemctl status firewall-daemon

# 检查内核模块
lsmod | grep firewall

# 查看 procfs 接口
ls /proc/firewall/

# 查看日志
journalctl -u firewall-daemon.service -f
```

### 5. 手动加载内核模块（可选）

如果服务未自动加载内核模块：

```bash
sudo modprobe firewall
```

验证模块已加载：

```bash
lsmod | grep firewall
```

## 验证安装

### 检查内核模块

```bash
cat /proc/firewall/config
```

应输出类似：

```
Firewall Module Status
======================
Module: loaded
Version: 1.0.0
Banned IPs: 0
Whitelisted IPs: 0
Hash table capacity: 4096
Whitelist capacity: 64
```

### 检查守护进程

```bash
cat /proc/firewall/config
```

### 检查 Prometheus 指标

```bash
curl http://localhost:9119/metrics
```

## 安装后行为

无论是 `sudo make install` 还是 `sudo dpkg -i *.deb` 安装完成,系统会自动执行以下动作:

1. **systemd 启动 `firewall-daemon.service`**
   - 单元文件位于 `/etc/systemd/system/firewall-daemon.service`
   - `enable --now` 后立即启动并设为开机自启
   - 单元配置已启用安全沙箱:`ProtectSystem=strict`、`ReadOnlyPaths=/etc/firewall`、`ReadWritePaths=/var/lib/firewall`

2. **加载内核模块 `firewall.ko`**
   - 通过 `modprobe firewall` 或 `install-systemd` 钩子加载
   - 模块在 `/proc/firewall/` 下导出 config / stats / bans / whitelist / log_level 等 procfs 文件

3. **守护进程启动流程**
   - 读取 `/etc/firewall/*.yaml` 下的所有配置文件(按字典序加载,后加载的覆盖前加载的)
   - 编译各 jail 的正则表达式(`regex::Regex::new`)
   - 启动 Prometheus HTTP exporter 监听 `:9119/metrics`
   - 启动 inotify 监听 `log_path` 配置的日志文件
   - 进入主监控循环:正则匹配 → 失败计数 → 阈值判定 → 调用 procfs 触发封禁

4. **首次启动观察**
   ```bash
   journalctl -u firewall-daemon -f
   # 正常输出:
   #   Loaded config: /etc/firewall/default.yaml
   #   Compiled regex for jail 'sshd' (12 patterns)
   #   Prometheus exporter listening on 0.0.0.0:9119
   #   inotify watching /var/log/auth.log
   #   Daemon ready
   ```

> 注意:守护进程启动后若 `log_file: /var/log/firewall.log` 打开失败,会以 warning 级别记录 "Failed to open log file ... (falling back to syslog-only)"。这是 systemd 单元 `ProtectSystem=strict` 故意让 `/var/log` 不可写的设计 — 详见 [故障排查 - 守护进程无法打开 /var/log/firewall.log](../operations/troubleshooting.md#守护进程无法打开-varlogfirewalllog)。

## 卸载

```bash
sudo systemctl stop firewall-daemon
sudo systemctl disable firewall-daemon
sudo make uninstall
```

卸载将移除：

- 内核模块（自动卸载）
- 守护进程二进制文件
- 配置文件（可选，保留用户配置）
- systemd 服务文件

## 常见问题

### 内核头文件找不到

```bash
# Ubuntu/Debian
sudo apt install linux-headers-$(uname -r)

# CentOS/RHEL
sudo dnf install kernel-devel-$(uname -r) kernel-headers-$(uname -r)
```

### Secure Boot 问题

如果启用了 Secure Boot，需要签名内核模块或使用 MOK (Machine Owner Key)：

```bash
sudo mokutil --import /path/to/signing_key.der
```

### 权限不足

确保使用 `sudo` 或 root 用户执行安装命令。