# 贡献指南

感谢你关注本项目！无论是修复 Bug、添加功能、改进文档，还是提出建议，每一份贡献都弥足珍贵。

## 快速开始

### 环境准备

**系统要求**：Linux 内核 4.19+（推荐 5.10+），x86_64 架构

**安装依赖**：

```bash
# Debian/Ubuntu
sudo apt install build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev \
  pkg-config git

# RHEL/CentOS/Fedora
sudo dnf install gcc make kernel-devel kernel-headers \
  libyaml-devel sqlite-devel libmicrohttpd-devel pcre2-devel \
  pkg-config git
```

### 编译项目

```bash
git clone https://github.com/SnowCore8/firewall.git
cd firewall

# 编译内核模块
make modules

# 编译用户态守护进程
make userland

# 完整编译（内核模块 + 用户态）
make all
```

### 运行测试

```bash
# 运行全部测试
make test

# 运行单元测试
make unit-test

# 运行集成测试
make integration-test
```

## Git 工作流

本项目采用 **Fork + Pull Request** 协作模式。

### 分支命名规范

| 分支类型 | 命名格式 | 示例 |
|----------|----------|------|
| 新功能 | `feature/<简短描述>` | `feature/ipv6-support` |
| Bug 修复 | `fix/<简短描述>` | `fix/race-condition-in-lookup` |
| 紧急修复 | `hotfix/<简短描述>` | `hotfix/critical-memory-leak` |
| 文档更新 | `docs/<简短描述>` | `docs/update-api-reference` |
| 重构 | `refactor/<简短描述>` | `refactor/extract-rule-parser` |
| 性能优化 | `perf/<简短描述>` | `perf/optimize-hash-resize` |

**命名要求**：
- 使用小写字母和连字符（kebab-case）
- 描述简洁明确，不超过 5 个单词
- 避免使用缩写（除非是广泛认可的，如 `api`、`ip`）

### PR 提交流程

1. Fork 本仓库到你的 GitHub 账号
2. 从 `main` 分支创建功能分支
3. 在功能分支上进行开发
4. 提交变更（遵循[提交规范](#提交规范)）
5. 推送功能分支到你的 Fork
6. 向本仓库的 `main` 分支发起 Pull Request

## 提交规范

本项目遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范。

### 提交格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Type 类型

| Type | 说明 | 示例 |
|------|------|------|
| `feat` | 新功能 | `feat(rules): add CIDR range matching support` |
| `fix` | Bug 修复 | `fix(kernel): resolve RCU grace period deadlock` |
| `docs` | 文档更新 | `docs(readme): add quick start guide` |
| `style` | 代码格式（不影响功能） | `style: fix indentation in rule_parser.c` |
| `refactor` | 代码重构 | `refactor(hash): simplify resize logic` |
| `perf` | 性能优化 | `perf(lookup): reduce lock contention in hot path` |
| `test` | 测试相关 | `test(rules): add edge case for empty rule file` |
| `chore` | 构建/工具链变更 | `chore(ci): add kernel 6.1 to test matrix` |

### 提交示例

```bash
# 简单提交
git commit -m "feat(rules): add port range matching support"

# 完整提交（含 body 和 footer）
git commit -m "fix(kernel): resolve RCU grace period deadlock

The lookup function was accessing freed memory during hash resize.
This patch adds proper RCU read-side critical section to prevent
use-after-free.

Fixes #42"
```

### Subject 书写要求

- 使用祈使句（"add" 而非 "added"）
- 首字母小写
- 结尾不加句号
- 长度不超过 72 个字符

## 开发流程

### 完整流程图

```
克隆仓库 → 创建分支 → 开发实现 → 运行测试 → 提交变更 → 发起 PR → 代码审查 → 合并
```

### 详细步骤

**1. 克隆仓库**

```bash
git clone https://github.com/SnowCore8/firewall.git
cd firewall
```

**2. 创建功能分支**

```bash
git checkout main
git pull origin main
git checkout -b feature/your-feature-name
```

**3. 开发实现**

- 遵循项目[代码风格](#代码风格)
- 保持函数职责单一
- 添加必要的注释和日志

**4. 运行测试**

```bash
# 确保所有测试通过
make test

# 检查代码格式
make lint

# 检查内存泄漏（需要 valgrind）
make valgrind
```

**5. 提交变更**

```bash
git add <files>
git commit -m "feat(scope): your commit message"
```

**6. 推送并发起 PR**

```bash
git push origin feature/your-feature-name
```

然后在 GitHub 上创建 Pull Request。

## 测试要求

### 测试层级

| 层级 | 说明 | 命令 |
|------|------|------|
| 单元测试 | 测试单个函数/模块 | `make unit-test` |
| 集成测试 | 测试模块间交互 | `make integration-test` |
| 端到端测试 | 完整场景验证 | `make e2e-test` |

### 覆盖率要求

- **新功能**：必须附带单元测试，行覆盖率 ≥ 80%
- **Bug 修复**：必须添加回归测试
- **核心模块**（内核态规则匹配、用户态配置解析）：行覆盖率 ≥ 90%

### 编写测试

```c
// tests/test_rule_parser.c
void test_parse_cidr_rule(void) {
    const char *yaml = "rule:\n  ip: 192.168.1.0/24\n  action: drop";
    rule_t *rule = rule_parse(yaml);

    assert(rule != NULL);
    assert(rule->type == RULE_TYPE_CIDR);
    assert(rule->ip.addr == 0xC0A80100);
    assert(rule->ip.prefix == 24);

    rule_free(rule);
}
```

## 代码审查

### PR 要求

发起 PR 时请确保：

- [ ] 代码通过所有测试（`make test`）
- [ ] 遵循 Conventional Commits 提交规范
- [ ] 新功能已添加对应测试
- [ ] 文档已同步更新
- [ ] PR 描述清晰，说明变更内容和原因

### 审查标准

| 维度 | 要求 |
|------|------|
| 正确性 | 逻辑正确，无已知 Bug |
| 性能 | 内核态代码避免阻塞操作 |
| 安全 | 输入严格验证，无内存泄漏 |
| 可读性 | 命名清晰，注释充分 |
| 测试 | 覆盖正常路径和边界情况 |

### 审查流程

1. 维护者收到 PR 后 48 小时内响应
2. 审查者提出修改建议或批准合并
3. 贡献者根据反馈修改代码
4. 审查通过后由维护者合并到 `main` 分支

## 文档更新

**代码变更时，必须同步更新相关文档**：

| 变更类型 | 需要更新的文档 |
|----------|----------------|
| 新增配置项 | `docs/configuration.md` |
| 新增 API | `docs/api/` 目录 |
| 架构变更 | `docs/architecture.md` |
| 部署变更 | `docs/deployment.md` |
| 用户可见变更 | `CHANGELOG.md` |

文档编写要求：
- 使用中文
- 代码示例可运行
- 参数说明完整
- 标注版本信息（如适用）

## 问题报告

### 提交 Issue

在 [Issues](https://github.com/SnowCore8/firewall/issues) 页面创建新问题。

### Bug 报告模板

```markdown
## 环境信息
- 内核版本：`uname -r`
- 发行版：如 Ubuntu 22.04
- 项目版本：`git describe --tags`

## 问题描述
清晰简洁地描述你遇到的问题。

## 复现步骤
1. 执行 '...'
2. 配置 '...'
3. 触发 '...'

## 预期行为
描述你期望发生什么。

## 实际行为
描述实际发生了什么。

## 日志输出
```
# 粘贴相关日志（kernel log、daemon log）
```

## 附加信息
其他有助于排查的信息（配置文件、网络拓扑等）。
```

### 功能请求模板

```markdown
## 功能描述
清晰简洁地描述你想要的功能。

## 使用场景
说明这个功能能解决什么问题。

## 替代方案
描述你考虑过的替代解决方案。

## 附加信息
其他相关信息或参考实现。
```

---

## 项目理念

- **简洁优先** — 每个模块职责单一，代码易读
- **安全第一** — 内核态防护，输入严格验证
- **性能导向** — O(1) 查找，RCU 无锁读取
- **文档完整** — 代码即文档，注释解释"为什么"

## 技术栈

- **语言**: C (C99/C11)
- **内核框架**: Netfilter + RCU + procfs
- **外部库**: libyaml, libsqlite3, libmicrohttpd, libpcre2-8
- **第三方库**: khash.h (MIT)

## 开发工具链

| 工具 | 用途 |
|------|------|
| [OpenCode](https://opencode.ai) | AI 编程助手（代码编写、审查、重构） |
| GCC | C 编译器 |
| Kbuild | 内核模块构建系统 |
| GNU Make | 项目构建 |
| GitHub Actions | CI/CD 自动化 |

## 许可证

本项目采用 MIT License — 详见 [LICENSE](LICENSE)

## 联系方式

- **GitHub**: [@SnowCore8](https://github.com/SnowCore8)
- **邮箱**: snowcore8@gmail.com
