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
  git

# RHEL/CentOS/Fedora
sudo dnf install gcc make kernel-devel kernel-headers \
  git
```

守护进程为 Go 1.26+（`make` 会在缺失时尝试用 `golangc` 引导），前端构建需要
Node.js 22 + npm。二者均无需额外的系统开发库（Go 依赖全为纯 Go）。

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
# 运行全部测试（集成测试套件）
make test

# 仅运行守护进程 Go 单元测试
cd src/daemon && go test ./...

# 仅运行集成测试
sudo python3 -m pytest tests/ -v

# 现场 crash 调试（带 DWARF + 符号表，即不加 -s -w 的默认构建）
cd src/daemon && go build -o firewall-daemon-debug ./cmd/firewall-daemon
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
| 缩进 | 2 个空格，禁止使用 Tab（以 `.clang-format` 的 `IndentWidth` 为准） |
| 行宽 | 最大 80 字符（以 `.clang-format` 的 `ColumnLimit` 为准） |
| 括号 | K&R 风格，左括号不换行 |
| 函数长度 | 单个函数不超过 50 行，复杂逻辑拆分为子函数 |

### 守护进程 Go 编码规范

守护进程使用 Go 编写，遵循：

- `gofmt` 格式化代码（CI 卡口是 `cd src/daemon && gofmt -l ./cmd ./internal` 输出为空）
- `go vet` 通过 lint 检查（CI 卡口是 `go vet ./cmd/... ./internal/...`）
- 错误链路用 `fmt.Errorf("...: %w", err)` 包装，保留可判定性
- 模块与导出符号注释使用中文

> **提交前必须 `gofmt` 干净 + `go vet` 通过（CI 卡口）**。任何问题都会被 CI 拒绝合并，合入前请先本地跑通这两条命令。

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
| Go 单元测试 | `cd src/daemon && go test ./...` | Go 包内 `_test.go` 用例（含契约往返与算式边界）；用例数随开发变动，以命令实时输出为准 |
| 集成测试 | `make test` | 集成测试套件（`tests/test_*_*.py`）；套件数与用例数随开发变动，以命令实时输出为准 |
| 浏览器端到端 | `npx playwright test` | `tests/e2e/*.spec.ts`；内核模块不可加载的环境会显式跳过 |

**修改下列内容时必跑 `make test` 集成测试**:

- YAML 配置 schema / 字段含义(例如新增 `defaults:` 块下的字段)
- procfs 命令接口(增减 `/proc/firewall/*` 节点)
- 守护进程与内核模块的交互协议（netlink 消息与契约，见 `contract/`）

跑测试时 `make test` 会用 `sudo python3 -m pytest tests/ -v` 运行集成测试，Go 单元测试推荐直接在 `src/daemon` 下跑 `go test ./...`。

### 代码检查（Go）

守护进程为纯 Go 模块（`modernc.org/sqlite` 等依赖均为纯 Go，无 cgo），不再使用
Rust 风格的 `unsafe { ... } // SAFETY:` 论证。仓库要求的检查是：

- `cd src/daemon && gofmt -l ./cmd ./internal` 输出为空
- `cd src/daemon && go vet ./cmd/... ./internal/...` 通过

违反时先修代码，再重新跑这两条命令；CI 的 lint 作业按同样两条卡口。

### 守护进程构建

构建由 Makefile 统一驱动，不需要手工推导 Go 构建参数：

| 目标 | 命令 | 产物 / 说明 |
|------|------|-------------|
| `daemon` | `make daemon` | 先 `npm run build` 产出面板，再 `go build -ldflags "-s -w=1"`；产物 `build/daemon/firewall-daemon`（stripped） |
| `all` | `make all` | 内核模块 + 守护进程（含前端） |
| 调试构建 | `cd src/daemon && go build -o firewall-daemon-debug ./cmd/firewall-daemon` | 不加 `-s -w`，保留 DWARF 与符号表，供 `gdb` / core 复盘 |

**不要做的事**：

- 不要绕过 Makefile 手工 `go build` 后直接发版：缺 `-ldflags "-s -w=1"` 会显著增大二进制
- 不要把未 strip 的调试构建二进制发到生产环境
- 不要引入需要 cgo 的依赖，那会打破「单一静态二进制」的交付形态

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
