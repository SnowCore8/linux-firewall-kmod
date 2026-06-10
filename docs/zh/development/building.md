# 构建

本文档介绍 Linux Firewall 内核模块的构建系统和编译选项。

## Makefile 目标

### 主要目标

| 目标 | 说明 |
|------|------|
| `make` | 编译全部（内核模块 + 守护进程） |
| `make kernel-module` | 仅编译内核模块 |
| `make daemon` | 仅编译守护进程 |
| `make install` | 安装到系统 |
| `make uninstall` | 从系统卸载 |
| `make clean` | 清理编译产物 |

### 调试目标

| 目标 | 说明 |
|------|------|
| `make debug` | 编译调试版本 |
| `make debug DL=2` | 编译调试版本（级别 2） |
| `make asan` | 编译 AddressSanitizer 版本 |

### 测试目标

| 目标 | 说明 |
|------|------|
| `make test` | 运行所有测试 |
| `make test-unit` | 运行单元测试 |
| `make test-integration` | 运行集成测试 |

## 构建内核模块

### 标准编译

```bash
make kernel-module
```

输出：

```
make -C /lib/modules/$(uname -r)/build M=$(PWD) modules
make[1]: Entering directory '/usr/src/linux-headers-...'
  CC [M]  /path/to/src/kernel/firewall.o
  LD [M]  /path/to/firewall.ko
  MODPOST /path/to/Module.symvers
make[1]: Leaving directory '/usr/src/linux-headers-...'
```

### 调试编译

```bash
make debug DL=2
```

调试级别说明：

| DL 值 | 输出内容 |
|-------|----------|
| 0 | 无调试输出 |
| 1 | 关键事件（模块加载/卸载） |
| 2 | 详细事件（封禁/解封操作） |
| 3 | 全部事件（包含数据包处理） |

## 构建守护进程

### 标准编译

```bash
make daemon
```

输出：

```
gcc -Wall -Wextra -O2 -o fwctl \
    src/daemon/main.c \
    src/daemon/config.c \
    src/daemon/jail.c \
    src/daemon/monitor.c \
    src/daemon/regex.c \
    src/daemon/database.c \
    src/daemon/metrics.c \
    src/daemon/procfs.c \
    -lyaml -lsqlite3 -lmicrohttpd -lpcre2-8
```

### AddressSanitizer 编译

```bash
make asan
```

用于检测内存错误：

- 缓冲区溢出
- 释放后使用
- 内存泄漏

使用：

```bash
sudo ./fwctl asan
# 运行一段时间后检查输出
```

## 完整构建

```bash
# 清理之前的构建
make clean

# 编译全部
make

# 安装
sudo make install
```

## 交叉编译

### 为目标架构编译

```bash
export ARCH=x86_64
export CROSS_COMPILE=x86_64-linux-gnu-

make kernel-module
```

### 指定内核源码路径

```bash
make kernel-module KDIR=/path/to/kernel/source
```

## 编译标志

### 内核模块标志

| 标志 | 说明 |
|------|------|
| `-Wall` | 启用所有警告 |
| `-Wextra` | 启用额外警告 |
| `-Werror` | 将警告视为错误 |
| `-O2` | 优化级别 2 |
| `-DLINUX_VERSION_CODE` | 内核版本检测 |

### 守护进程标志

| 标志 | 说明 |
|------|------|
| `-Wall -Wextra` | 启用警告 |
| `-O2` | 发布模式优化 |
| `-O0 -g` | 调试模式 |
| `-fsanitize=address` | AddressSanitizer |
| `-DDEBUG` | 启用调试代码 |

## 依赖检查

### 自动检查

构建系统自动检查依赖：

```bash
make
```

如果缺少依赖：

```
Checking dependencies...
  linux-headers: OK
  libyaml:       NOT FOUND
  libsqlite3:    OK
  libmicrohttpd: OK
  libpcre2:      OK

Error: Missing dependencies. Install:
  sudo apt install libyaml-dev
```

### 手动检查

```bash
# 检查内核头文件
ls /lib/modules/$(uname -r)/build

# 检查库
pkg-config --libs libyaml
pkg-config --libs sqlite3
pkg-config --libs libmicrohttpd
pkg-config --libs libpcre2
```

## 构建产物

### 内核模块

| 文件 | 说明 |
|------|------|
| `firewall.ko` | 内核模块 |
| `firewall.mod.c` | 模块元数据 |
| `Module.symvers` | 符号版本 |
| `modules.order` | 模块顺序 |

### 守护进程

| 文件 | 说明 |
|------|------|
| `fwctl` | 守护进程二进制 |

### 安装位置

| 文件 | 安装路径 |
|------|----------|
| `firewall.ko` | `/lib/modules/$(uname -r)/extra/` |
| `fwctl` | `/usr/local/sbin/` |
| `default.yaml` | `/etc/firewall/` |
| `firewall-daemon.service` | `/etc/systemd/system/` |

## 构建问题排查

### 内核头文件不匹配

```
ERROR: Kernel configuration is invalid.
```

解决方案：

```bash
sudo apt install --reinstall linux-headers-$(uname -r)
```

### 库版本不兼容

```
undefined reference to `pcre2_compile_8'
```

解决方案：

```bash
sudo apt install --reinstall libpcre2-dev
```

### 权限不足

```
make install: Permission denied
```

解决方案：

```bash
sudo make install
```