# 贡献指南

## 欢迎贡献

感谢你关注 **linux-firewall-kmod** 项目！无论是修复 Bug、添加新功能、改进文档，还是提出建议，每一份贡献都让项目变得更好。

## 开始之前

- 阅读 [README.md](README.md) 了解项目目标和核心特性
- 浏览 [文档目录](docs/zh/) 熟悉项目文档
- 查看现有 [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues) 避免重复

## 开发环境设置

### 系统要求

- **操作系统**：Linux（Debian/Ubuntu 或 RHEL/CentOS/Fedora）
- **内核版本**：4.19+（推荐 5.10+）
- **架构**：x86_64

### 安装依赖

```bash
# Debian/Ubuntu
sudo apt install build-essential linux-headers-$(uname -r) \
  pkg-config git

# RHEL/CentOS/Fedora
sudo dnf install gcc make kernel-devel kernel-headers \
  pkg-config git
```

### 克隆与编译

```bash
git clone https://github.com/SnowCore8/linux-firewall-kmod.git
cd linux-firewall-kmod

# 编译内核模块 + 守护进程
make

# 仅编译内核模块
make kernel-module

# 仅编译守护进程
make daemon
```

### 运行测试

```bash
# 运行全部测试（19 套件集成测试）
make test

# 仅运行 Rust 单元测试 (88 项)
cargo test --release

# 仅运行集成测试
./tests/run_tests.sh

# 现场 crash 调试 (32MB 带 DWARF + 符号表)
cargo build --release --profile dev-with-debug
```

## 贡献方式

### 1. 报告 Bug

使用 [Bug 报告模板](.github/ISSUE_TEMPLATE/bug_report.md) 提交 Issue，包含：
- 环境信息（内核版本、发行版、项目版本）
- 问题描述和复现步骤
- 预期行为与实际行为
- 相关日志输出（kernel log、daemon log）

### 2. 提出新功能

使用 [功能请求模板](.github/ISSUE_TEMPLATE/feature_request.md) 提交 Issue，说明：
- 功能描述和使用场景
- 替代方案（如有）
- 参考实现或设计思路

### 3. 提交代码修复

1. 在 Issue 中说明你打算修复的问题
2. Fork 仓库并创建功能分支
3. 编写代码并添加测试
4. 确保所有测试通过
5. 提交 Pull Request

### 4. 改进文档

- 修正拼写错误或表述不清
- 补充缺失的配置说明
- 添加使用示例和最佳实践
- 翻译文档为其他语言

### 5. 添加测试用例

- 为未覆盖的代码路径添加单元测试
- 为边界条件添加回归测试
- 完善集成测试场景

## 代码规范

### 内核模块 C 语言编码规范

| 规则 | 说明 |
|------|------|
| 命名 | 函数/变量使用 `snake_case`，宏使用 `UPPER_CASE` |
| 缩进 | 4 个空格，禁止使用 Tab |
| 行宽 | 最大 100 字符 |
| 括号 | K&R 风格，左括号不换行 |
| 函数长度 | 单个函数不超过 50 行，复杂逻辑拆分为子函数 |

### 守护进程 Rust 编码规范

守护进程使用 Rust 编写,遵循:
- `cargo fmt` 格式化代码
- `cargo clippy` 通过 lint 检查
- 使用 `anyhow::Result` 进行错误处理
- 模块注释使用中文

> **提交前必须 `cargo fmt` + `cargo clippy -- -D warnings` 通过 (CI 卡口)**。任何 warning 都会被 CI 拒绝合并,合入前请先本地跑通这两个命令。

### 注释规范

- **统一使用中文注释**
- 注释解释"为什么"而非"做什么"
- 公共函数必须包含文档字符串（功能、参数、返回值）
- 复杂算法必须包含思路说明

```c
/**
 * 检查 IP 是否在白名单中
 * @param ip 待检查的 IPv4 地址（网络字节序）
 * @return 1 表示在白名单中，0 表示不在
 * 
 * 注意：使用 RCU 读端临界区，调用方无需额外加锁
 */
int whitelist_check(__be32 ip);
```

### 测试 / Tests

| 测试类型 | 命令 | 规模 / 说明 |
|----------|------|------------|
| Rust 单元测试 | `cargo test` | 88 项 `#[test]` 单元 + 6 项 doctest。doctest 全部真跑,不写 `no_run` / `ignore` |
| 集成测试 | `make test` | 19 套件用例,19 个套件 (`tests/suites/01_*.sh` 到 `21_*.sh`,5/6 合并) |
| 行为审计 | `c-to-rust-behavioral-audit` skill | C 守护进程已退役,审计按需触发,确保 Rust 版零回归 |

**修改下列内容时必跑 `make test` 集成测试**:

- YAML 配置 schema / 字段含义(例如新增 `defaults:` 块下的字段)
- procfs 命令接口(增减 `/proc/firewall/*` 节点)
- 守护进程与内核模块的交互协议(`/proc/firewall/ban` 写入格式等)

跑测试时 `tests/run_tests.sh` 会自动 `source ~/.cargo/env` 把 `cargo` 加进 PATH,但 Rust 单元测试推荐直接在仓库根目录跑 `cargo test`。

### 内存安全 (Rust unsafe 块)

当前代码库共有 **46 个 `unsafe` 块**,分布在:

| 文件 | 数量 | 用途 |
|------|------|------|
| `src/daemon/netlink/responses.rs` | 15 | `ptr::read` / `from_raw_parts` 反序列化 `#[repr(C, packed)]` 结构体 |
| `src/daemon/netlink/mod.rs` | 13 | `socket` / `bind` / `poll` / `recv` / `sendto` / `close` 等 netlink socket 操作 |
| `src/daemon/netlink/protocol.rs` | 7 | netlink 协议类型定义与序列化 |
| `src/daemon/daemonizer.rs` | 7 | `libc::fork` 守护进程化 / `libc::flock` / `from_raw_fd` 接管 fd |
| `src/daemon/file_monitor/monitor_loop.rs` | 1 | `libc::poll` 包装 inotify fd 等待事件 |
| `src/daemon/ip_utils.rs` | 1 | 原始 IP 地址操作 |
| `src/daemon/logger.rs` | 1 | `libc::openlog` / `libc::syslog` / `libc::closelog` 接入 syslog(3) |
| `src/daemon/signals.rs` | 1 | `libc::sigaction` 信号处理器注册 |

**每个 `unsafe` 块都必须紧跟 `// SAFETY:` 注释**,说明:

1. **前置条件**:为什么这个操作是必要的、什么不变式已经确保它安全
2. **后置不变量**:操作完成后,程序状态依旧保持的强约束(例如:fd 所有权不泄露、`O_NOFOLLOW` 已设防 symlink 攻击、调用方拿到的 `RawFd` 唯一)
3. **错误路径**:出错时 fd / 内存 / 全局状态如何回滚

例:

```rust
// SAFETY: 调用方已持有 path 的所有权(From<CString>),
// O_NOFOLLOW 阻止 symlink 攻击,O_WRONLY 不会读文件。
// 失败时返回 -1,本调用方立即检查并走 cleanup 分支。
let new_fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NOFOLLOW) };
```

> **PR 审查硬性要求**:提交新 `unsafe` 块或修改现有 `unsafe` 块的 PR,必须在描述中包含 `// SAFETY:` 注释,**没有 SAFETY 注释的 unsafe 代码一律不合并**。如果一个 unsafe 块的安全论证超过 5 行,改写为封装函数并把 SAFETY 注释写在该函数顶端。

### Cargo release profile

`Cargo.toml` 定义了 3 套 release profile,按用途选用:

| Profile | 命令 | 体积 | 用途 |
|---------|------|------|------|
| `release` (默认) | `cargo build --release` | **6.2 MB** stripped | 生产 / 发行版,启用 `lto = "fat"` + `strip = "symbols"` + `codegen-units = 1` |
| `dev-with-debug` | `cargo build --release --profile dev-with-debug` | **~32 MB** 带 DWARF + 完整符号表 | 现场 crash 复盘,用 `coredumpctl` / `gdb` 拿回精确行号 |
| `asan` | `cargo +nightly build --profile asan` | 较大,需 nightly | 内存检测,需 `cargo +nightly` + opt-in `.cargo/config.toml` 重编 std |

**选型建议**:

- 日常开发:`cargo build`(默认 dev profile,带调试信息但未优化)
- 性能基准 / 发版前:`cargo build --release`(6.2 MB,LTO 后的最终优化)
- 现场 crash:`cargo build --release --profile dev-with-debug`,把 binary 拷到现场跑,crash 后用 gdb attach core 还原栈
- ASAN 内存体检:仅在 nightly 工具链上跑,平时不开

**不要做的事**:

- 不要在 release profile 上加 debug 符号(会让 binary 涨到 30MB+)
- 不要在 dev profile 上做性能基准(LTO 缺失,数据偏差 20%+)
- 不要把 `dev-with-debug` 的 binary 发到生产环境

### 提交信息规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<type>(<scope>): <subject>

<body>

<footer>
```

| Type | 说明 | 示例 |
|------|------|------|
| `feat` | 新功能 | `feat(rules): add CIDR range matching support` |
| `fix` | Bug 修复 | `fix(kernel): resolve RCU grace period deadlock` |
| `docs` | 文档更新 | `docs(readme): add quick start guide` |
| `style` | 代码格式 | `style: fix indentation in rule_parser.c` |
| `refactor` | 代码重构 | `refactor(hash): simplify resize logic` |
| `perf` | 性能优化 | `perf(lookup): reduce lock contention in hot path` |
| `test` | 测试相关 | `test(rules): add edge case for empty rule file` |
| `chore` | 构建/工具 | `chore(ci): add kernel 6.1 to test matrix` |

## Pull Request 流程

### 1. Fork 仓库

在 GitHub 上点击 "Fork" 将仓库复制到你的账号。

### 2. 创建功能分支

```bash
git clone https://github.com/<your-username>/linux-firewall-kmod.git
cd linux-firewall-kmod
git checkout main
git checkout -b feature/your-feature-name
```

### 3. 开发与提交

```bash
# 编写代码...

# 确保测试通过
make test

# 提交变更
git add <files>
git commit -m "feat(scope): your commit message"
```

### 4. 推送并创建 PR

```bash
git push origin feature/your-feature-name
```

在 GitHub 上向本仓库的 `main` 分支发起 Pull Request。

### 5. 代码审查

维护者会在 48 小时内响应。审查通过后即可合并。

### 6. 合并

PR 合并后，功能分支可安全删除。

## PR 检查清单

发起 PR 前请确认：

- [ ] 代码通过所有测试（`make test`）
- [ ] 遵循 Conventional Commits 提交规范
- [ ] 新功能已添加对应测试用例
- [ ] 文档已同步更新
- [ ] PR 描述清晰，说明变更内容和原因
- [ ] 无敏感信息泄露（密钥、配置等）

## 审查标准

| 维度 | 要求 |
|------|------|
| 正确性 | 逻辑正确，无已知 Bug |
| 性能 | 内核态代码避免阻塞操作 |
| 安全 | 输入严格验证，无内存泄漏 |
| 可读性 | 命名清晰，注释充分 |
| 测试 | 覆盖正常路径和边界情况 |

## 行为准则

- 尊重每一位贡献者，使用友好、包容的语言
- 接受建设性批评，专注于问题而非个人
- 维护社区和谐，禁止人身攻击或歧视性言论
- 发现不当行为请联系项目维护者

## 许可证

本项目采用 [MIT License](LICENSE) 开源协议。提交代码即表示你同意将代码以 MIT License 发布。

## 联系方式

- **GitHub**: [@SnowCore8](https://github.com/SnowCore8)
- **邮箱**: snowcore8@gmail.com
- **Issues**: [提交问题或建议](https://github.com/SnowCore8/linux-firewall-kmod/issues)
