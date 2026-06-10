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
    libyaml-dev \
    libsqlite3-dev \
    libmicrohttpd-dev \
    libpcre2-dev \
    pkg-config
```

### CentOS / RHEL

```bash
sudo dnf install -y \
    gcc gcc-c++ make \
    kernel-devel-$(uname -r) \
    kernel-headers-$(uname -r) \
    libyaml-devel \
    sqlite-devel \
    libmicrohttpd-devel \
    pcre2-devel \
    pkg-config
```

### Arch Linux

```bash
sudo pacman -S --needed \
    base-devel \
    linux-headers \
    libyaml \
    sqlite \
    libmicrohttpd \
    pcre2 \
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

### 3. 安装

```bash
sudo make install
```

安装完成后：

- 内核模块 `fw_fire.ko` 安装到 `/lib/modules/$(uname -r)/extra/`
- 守护进程 `fwctl` 安装到 `/usr/local/sbin/`
- 配置文件安装到 `/etc/fw_fire/fw_fire.yaml`
- systemd 服务文件安装到 `/etc/systemd/system/`

### 4. 加载内核模块

```bash
sudo modprobe fw_fire
```

验证模块已加载：

```bash
lsmod | grep fw_fire
```

### 5. 启动守护进程

```bash
sudo systemctl enable fw_fire
sudo systemctl start fw_fire
```

检查服务状态：

```bash
sudo systemctl status fw_fire
```

## 验证安装

### 检查内核模块

```bash
cat /proc/fw_fire/status
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
fwctl status
```

### 检查 Prometheus 指标

```bash
curl http://localhost:9119/metrics
```

## 卸载

```bash
sudo systemctl stop fw_fire
sudo systemctl disable fw_fire
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