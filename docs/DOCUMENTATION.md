# Firewall 项目文档

## 项目概述

Firewall 是一个 Linux 内核模块版本的 fail2ban，用于实时 IP 封禁防护。它将 fail2ban 的核心功能从用户空间移动到内核空间，使用 netfilter 框架在数据包级别进行封禁，具有更低的延迟和更高的性能。

**当前版本**: v1.6（Jail 系统 + 安全加固）

## 项目架构

项目由两部分组成：

1. **内核模块** (`firewall.ko`)
   - Netfilter Hook 拦截所有传入数据包
   - 哈希表存储封禁 IP（1024 容量，O(1) 查找）
   - 自动过期清理机制
   - IP 白名单保护（自动发现系统 IP + 手动添加，64 容量）
   - 通过 procfs 提供用户接口
   - RCU 并发安全 + spinlock 保护
   - 统一分级日志系统

2. **用户态守护进程** (`firewall-daemon`)
   - C 语言实现（无 Python 依赖）
   - **Jail 系统** - 类似 fail2ban 的多服务隔离配置
   - 每个 Jail 独立监控日志文件
   - 每个 Jail 有独立的失败计数器和封禁阈值
   - 使用 POSIX 正则表达式解析日志
   - 自动管理封禁（通过 procfs 接口）
   - SQLite 永久封禁持久化支持
   - Prometheus metrics 导出（HTTP exporter）
   - 配置热重载（SIGHUP 信号）

## 主要特性

- ✅ 内核态 IP 封禁（netfilter hooks，比 iptables 用户态规则更高效）
- ✅ **Jail 系统** - 类似 fail2ban 的多服务隔离配置
- ✅ 哈希表存储封禁 IP（1024 容量，O(1) 查找）
- ✅ 自动过期清理机制
- ✅ IP 白名单保护（自动发现系统 IP + 手动添加，64 容量）
- ✅ 通过 procfs 的用户接口
- ✅ 可配置的封禁持续时间
- ✅ 纯 IPv4 支持
- ✅ C 语言用户态守护进程（无 Python 依赖）
  - Jail 级别独立配置（max_retries / findtime / ban_time）
- ✅ POSIX 正则表达式日志解析（减少误判 90%+）
- ✅ 统一分级日志系统（fw_pr_err/warn/info/debug）
- ✅ RCU 并发安全 + spinlock 保护
- ✅ 状态持久化（保存/恢复封禁和白名单）
- ✅ 输入验证和边界检查
- ✅ 安全编译选项（-fstack-protector-strong, -D_FORTIFY_SOURCE=2, PIE）
- ✅ systemd 安全加固（NoNewPrivileges, ProtectSystem=strict 等 14 项）
- ✅ 配置热重载（SIGHUP 信号触发完整配置重载）
- ✅ SQLite 永久封禁持久化
- ✅ Prometheus metrics 导出
- ✅ 零编译警告

## 安全性改进

### 安全编译选项

项目在编译时启用多项安全加固选项：

```makefile
# 安全聚焦的编译器标志
SECURITY_CFLAGS = -Wall -Wextra -Werror=format-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
SECURITY_LDFLAGS = -pie -Wl,-z,relro,-z,now
```

| 选项 | 说明 |
|------|------|
| `-fstack-protector-strong` | 栈溢出保护，检测缓冲区溢出攻击 |
| `-D_FORTIFY_SOURCE=2` | 编译时和运行时检查常见缓冲区溢出 |
| `-fPIE` + `-pie` | 位置无关可执行文件，配合 ASLR 提供地址随机化 |
| `-Wl,-z,relro,-z,now` | 重定位只读，防止 GOT 覆写攻击 |
| `-Werror=format-security` | 防止格式化字符串漏洞 |

### systemd 服务安全加固

服务文件 (`firewall-daemon.service`) 包含 14 项安全限制：

```ini
# 安全加固
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/firewall /etc/firewall
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
```

| 限制 | 说明 |
|------|------|
| `NoNewPrivileges=yes` | 禁止进程获取新权限 |
| `ProtectSystem=strict` | 将 `/usr` 和 `/boot` 设为只读 |
| `PrivateTmp=yes` | 提供隔离的 `/tmp` 命名空间 |
| `ProtectHome=yes` | 禁止访问 `/home`、`/root`、`/run/user` |
| `ProtectKernelTunables=yes` | 禁止修改内核参数 |
| `ProtectKernelModules=yes` | 禁止加载内核模块 |
| `MemoryDenyWriteExecute=yes` | 禁止映射同时可写可执行的内存 |
| `SystemCallFilter=@system-service` | 限制系统调用白名单 |

### 内核态 TOCTOU 竞态修复

**问题**: `save_state_to_file()` 函数中存在 Time-of-Check to Time-of-Use (TOCTOU) 竞态条件，攻击者可在检查后替换文件为符号链接，导致写入到非预期位置。

**修复方案**:
- 使用 `O_NOFOLLOW` 标志打开文件，拒绝跟随符号链接
- 添加 inode 一致性检查：打开文件后验证 `st_dev` 和 `st_ino` 与检查时一致
- 修复变量遮蔽问题（`saved_dev`/`saved_ino` 作用域错误）

```c
// 安全文件打开示例
int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC, 0644);
if (fd < 0) {
    fw_pr_err("Failed to open file: %s", path);
    return -1;
}

// inode 一致性检查
struct stat st;
if (fstat(fd, &st) < 0) {
    close(fd);
    return -1;
}
if (st.st_dev != saved_dev || st.st_ino != saved_ino) {
    fw_pr_err("File inode changed, possible symlink attack");
    close(fd);
    return -1;
}
```

### 正则匹配边界检查

**问题**: 正则表达式匹配时可能存在越界读取，特别是 IP 地址提取时可能匹配到类似 `1.2.3.4.5` 的非法格式。

**修复方案**:
- `extract_ipv4()` 添加单词边界检查
- 正则捕获组动态检测（支持自定义正则，不再硬编码索引）
- 防止误匹配和缓冲区越界读取

### 其他安全特性

- 使用 RCU 机制提高并发安全性
- 防止整数溢出和下溢（inotify 事件处理）
- 强化的输入验证（IP 地址、日志数据、procfs 接口）
- 自动白名单保护防止自锁
- 洪泛保护机制防止滥用
- 数据包完整性验证
- 内存操作边界检查
- 永久 ban 容量检查（防止拒绝服务）
- 全局变量 `fw_info` 改为 `static`，通过 `get_fw_info()` 导出受控访问

## 性能优化

### 优化成果
1. **内核模块性能优化**
   - 优化了 `nf_hook_func` 函数，实现了快速路径
   - 改进了哈希表查找性能
   - 优化了白名单查找效率

2. **守护进程性能优化**
   - 优化了链表操作算法
   - 改进了日志文件监控的 I/O 效率
   - 增强了正则表达式处理

### 基准测试结果
- 封禁操作: ~840 ops/ms
- 查询操作: ~885 ops/ms
- 解封操作: ~1235 ops/ms
- 白名单添加: ~1220 ops/ms
- 白名单查询: ~1227 ops/ms

## Jail 系统详解

Jail 系统是 v1.6 的核心特性，提供类似 fail2ban 的多服务隔离配置能力。

### 架构设计

```
┌─────────────────────────────────────────────┐
│           firewall-daemon                   │
├─────────────────────────────────────────────┤
│  defaults:                                  │
│    max_retries: 5                           │
│    findtime: 600                            │
│    ban_time: 900                            │
├─────────────────────────────────────────────┤
│  jails:                                     │
│  ┌─────────────┐  ┌─────────────┐          │
│  │   sshd      │  │   custom    │          │
│  │ log_files:  │  │ log_files:  │          │
│  │  - auth.log │  │  - app.log  │          │
│  │ max_retries:│  │ max_retries:│          │
│  │     5       │  │     3       │          │
│  └──────┬──────┘  └──────┬──────┘          │
│         │                │                 │
│         ▼                ▼                 │
│    ┌─────────────────────────┐             │
│    │   独立失败计数器        │             │
│    │   独立封禁阈值          │             │
│    │   独立 inotify 监控     │             │
│    └─────────────────────────┘             │
└─────────────────────────────────────────────┘
```

### 关键特性

1. **独立监控**: 每个 Jail 独立监控自己配置的日志文件
2. **独立计数器**: 每个 Jail 维护独立的失败计数器和时间窗口
3. **独立阈值**: 每个 Jail 可配置不同的 `max_retries`、`findtime`、`ban_time`
4. **资源隔离**: Jail 之间互不干扰，单个 Jail 配置错误不影响其他 Jail
5. **配置合并**: 支持多配置文件，按字母顺序加载，后加载的覆盖前面的

### 配置示例

```yaml
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
      - /var/log/secure
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""  # 空字符串使用内置 sshd 模式
```

### Jail 限制

| 限制项 | 值 | 说明 |
|--------|-----|------|
| 最大 Jail 数量 | 16 | 防止资源耗尽 |
| 每个 Jail 最大日志文件数 | 10 | 防止 inotify 资源耗尽 |
| 配置文件数量 | 50 | 配置目录加载限制 |

### 配置解析改进

- 使用 `strsep` 替代 `sscanf`（更健壮的参数解析）
- 配置目录加载使用 `qsort` 替代冒泡排序（O(n log n) + 50 文件限制）
- 正则捕获组动态检测（支持自定义正则，不再硬编码索引）
- `extract_ipv4()` 添加单词边界检查（防止误匹配如 1.2.3.4.5）

## 配置热重载

守护进程支持运行时配置热重载，无需重启服务：

```bash
# 发送 SIGHUP 信号触发配置重载
sudo kill -HUP $MAINPID

# 或使用 systemd
sudo systemctl reload firewall-daemon
```

### 热重载流程

1. 接收 SIGHUP 信号
2. 清理旧 Jail 资源（关闭日志文件句柄、释放 inotify 监控）
3. 重新解析 YAML 配置文件
4. 重新设置 inotify 监控
5. 重新注册所有 Jail 的日志文件

### 注意事项

- 热重载会完整重新加载配置，包括新增/删除的 Jail
- 已封禁的 IP 不会因热重载而解封
- 如果配置文件有语法错误，热重载会失败并记录错误日志
- 配置重载时添加了 `cleanup_all_jails()` 释放旧资源，防止内存泄漏

## 构建和安装

### 构建

```bash
# 编译两者（内核模块 + 守护进程）
make all-with-daemon

# 仅编译内核模块
make kernel-module

# 仅编译守护进程
make daemon

# 清理构建产物
make clean
```

**安全编译选项**（自动启用）：
- `-fstack-protector-strong` - 栈溢出保护
- `-D_FORTIFY_SOURCE=2` - 缓冲区溢出检测
- `-fPIE` + `-pie` - 地址空间布局随机化
- `-Wl,-z,relro,-z,now` - GOT 保护

### 安装

```bash
# 一键安装（内核模块 + 守护进程 + 配置 + systemd 服务）
sudo make install

# 或手动安装
# 安装内核模块
sudo cp build/kernel-module/firewall.ko /lib/modules/$(uname -r)/kernel/net/
sudo depmod -a

# 安装守护进程
sudo cp build/daemon/firewall-daemon /usr/local/bin/

# 安装配置文件
sudo install -d -m 755 /etc/firewall/config
sudo install -m 644 config/*.yaml /etc/firewall/config/

# 安装 systemd 服务
sudo install -D -m 644 firewall-daemon.service /etc/systemd/system/firewall-daemon.service
sudo systemctl daemon-reload
```

## 使用方法

### 基本操作

```bash
# 加载内核模块（带参数）
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600

# 查看配置
cat /proc/firewall/config

# 卸载模块
sudo rmmod firewall
```

### 启动守护进程

```bash
# 使用配置文件启动（推荐）
sudo ./build/daemon/firewall-daemon

# 指定配置目录
sudo ./build/daemon/firewall-daemon -C /etc/firewall/config/

# 指定单个配置文件
sudo ./build/daemon/firewall-daemon -c config/default.yaml

# 查看帮助
sudo ./build/daemon/firewall-daemon --help
```

### systemd 服务管理

```bash
# 启动服务
sudo systemctl start firewall-daemon

# 停止服务
sudo systemctl stop firewall-daemon

# 启用开机自启
sudo systemctl enable firewall-daemon

# 重载配置（热重载）
sudo systemctl reload firewall-daemon

# 查看状态
sudo systemctl status firewall-daemon
```

### 模块参数
| 参数 | 说明 | 默认值 |
|------|------|--------|
| `fw_ban_time` | 封禁持续时间（秒） | 600 (10分钟) |

**注意**：`max_retries`（触发封禁的失败次数）、`findtime`（失败记录时间窗口）、`ban_time`（封禁持续时间）、`interval`（检查间隔）和 `metrics_port`（Prometheus 端口）是**守护进程配置参数**，必须通过 YAML 配置文件设置，不支持命令行参数。

### 守护进程参数

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml --daemonize
```

| 参数 | 说明 | 默认值 | 状态 |
|------|------|--------|------|
| `-c` | 配置文件路径 | - | ✅ 推荐使用 |
| `-C` | 配置目录路径 | ./config/ 或 /etc/firewall/config/ | ✅ 推荐使用 |
| `-d`, `--daemonize` | 后台运行模式 | false | ✅ 生产环境推荐 |
| `-h`, `--help` | 显示帮助信息 | - | - |

**注意**：所有封禁策略参数（`max_retries`、`findtime`、`ban_time`、`interval`、`metrics_port`）必须通过 YAML 配置文件设置。

### Procfs 接口

| 路径 | 功能 | 访问模式 |
|------|------|----------|
| `/proc/firewall/bans` | 查看封禁列表；临时/自定义时长/永久封禁 IP；解封 IP | 读写 |
| `/proc/firewall/whitelist` | 查看白名单；添加/移除白名单 | 读写 |
| `/proc/firewall/config` | 查看/修改运行时配置（目前仅支持 ban_time） | 读写 |
| `/proc/firewall/stats` | 查看统计信息（供 HTTP exporter 使用） | 只读 |

```bash
# 查看封禁列表
cat /proc/firewall/bans

# 临时封禁 IP（使用默认 ban_time）
echo "1.2.3.4" | sudo tee /proc/firewall/bans

# 自定义时长封禁
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans    # 封禁 1 小时
echo "1.2.3.4 86400" | sudo tee /proc/firewall/bans   # 封禁 1 天

# 永久封禁（0 表示永久）
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans

# 解封 IP
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# 查看白名单
cat /proc/firewall/whitelist

# 添加白名单（支持 IP 和子网）
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist
echo "add 192.168.1.0/24" | sudo tee /proc/firewall/whitelist

# 移除白名单
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist

# 运行时修改配置（目前仅支持 ban_time）
echo "ban_time 1200" | sudo tee /proc/firewall/config

# 查看统计信息
cat /proc/firewall/stats
```

## 测试

项目采用模块化测试框架，共 94+ 项测试：

```bash
# 运行所有测试（推荐）
make test

# 或手动运行
sudo ./tests/run_tests.sh

# 运行单个测试套件
sudo ./tests/run_tests.sh --suite 03       # 封禁/解封测试
sudo ./tests/run_tests.sh --suite 09       # 配置测试

# 按类别运行
sudo ./tests/run_tests.sh --category security   # 安全测试
sudo ./tests/run_tests.sh --category daemon     # 守护进程测试

# 生成测试报告
sudo ./tests/run_tests.sh --report

# 运行旧测试脚本（向后兼容）
make test-legacy
```

**测试结果**: 94 项测试全部通过

### 测试覆盖

- ✅ 模块加载/卸载
- ✅ Procfs 接口功能
- ✅ 封禁/解封功能
- ✅ 白名单保护（IP 和子网）
- ✅ 输入验证和边界检查
- ✅ 安全测试（注入防护、权限检查）
- ✅ 并发访问安全
- ✅ 压力/性能测试
- ✅ Jail 配置加载和目录加载
- ✅ 日志解析功能
- ✅ 资源管理和内存安全
- ✅ 配置热重载
- ✅ 永久封禁持久化（SQLite）

### 测试框架特性

- 统一测试入口 `run_tests.sh`
- 测试框架核心 `test_framework.sh`
- 11 个独立测试套件
- 支持按类别运行测试
- 支持生成测试报告

## 适用场景

### 适合
- 个人 VPS 防护
- 开发/测试环境
- 小规模 SSH 暴力破解防护
- 需要低延迟 IP 封禁的场景

### 不推荐
- 生产环境 DDoS 防护
- 需要审计合规的场景
- 大规模分布式部署
- 需要 IPv6 支持的环境

## 已知限制

- **仅支持 IPv4**（纯 IPv4 实现）
- **封禁上限 1024 IP**
- **无持久化存储**（模块重启后状态丢失，但有状态文件保存/恢复机制）
- **procfs 通信**（不支持批量操作）
- **永久封禁依赖 SQLite**（可选功能，需要 libsqlite3）

## 项目结构

```
firewall/
├── src/
│   ├── kernel-module/
│   │   ├── firewall.c          # 内核模块主源码（~2300 行）
│   │   └── firewall.h          # 头文件（含统一日志系统）
│   └── daemon/
│       ├── firewall-daemon.c   # 守护进程主源码（~3000 行，Jail 系统）
│       ├── http-exporter.c     # Prometheus 指标导出器
│       └── sqlite-persistent.c # SQLite 永久封禁持久化
├── tests/
│   ├── run_tests.sh            # 统一测试入口（94 项测试）
│   ├── test_framework.sh       # 测试框架核心
│   ├── test_config.sh          # 测试配置
│   ├── suites/                 # 11 个测试套件
│   └── reports/                # 测试报告
├── config/                     # YAML 配置文件目录
│   └── default.yaml            # 默认配置（sshd jail）
├── docs/
│   ├── DOCUMENTATION.md        # 详细技术文档（本文件）
│   └── PERMANENT_BAN_GUIDE.md  # 永久封禁指南
├── scripts/
│   ├── build.sh                # 构建脚本
│   └── verify_project.sh       # 项目验证脚本
├── build/                      # 构建产物目录
│   ├── kernel-module/
│   │   └── firewall.ko
│   └── daemon/
│       └── firewall-daemon
├── Makefile                    # 构建配置
├── firewall-daemon.service     # systemd 服务文件
├── CHANGELOG.md                # 变更日志
├── LICENSE                     # GPL v2 许可证
├── README.md                   # 项目主文档
└── .gitignore                  # Git 忽略配置
```

## 代码质量改进

### 全局变量管理

- 全局变量 `fw_info` 改为 `static`，防止外部直接访问
- 通过 `get_fw_info()` 函数导出受控访问
- 提高封装性和安全性

### 服务支持调整

- **移除 vsftpd/nginx/frp 服务支持**（仅保留 sshd）
- 移除旧格式配置兼容，要求显式 `jails:` 配置
- 简化代码库，专注于核心功能

### 编译质量

- **零编译警告**（启用 `-Wall -Wextra -Werror=format-security`）
- 配置解析使用 `strsep` 替代 `sscanf`（更健壮的参数解析）
- 配置目录加载使用 `qsort` 替代冒泡排序（O(n log n) + 50 文件限制）
- `process_new_lines()` 加锁保护 Jail 配置访问（防止并发竞态）

## 许可证

GPL v2