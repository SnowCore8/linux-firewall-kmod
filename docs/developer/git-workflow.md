# Git 工作流规范

> 本文档定义项目的 Git 分支策略、提交规范、开发流程和版本发布流程，所有贡献者必须遵守。

## 目录

- [1. 概述](#1-概述)
- [2. 分支策略](#2-分支策略)
- [3. 分支命名规范](#3-分支命名规范)
- [4. 提交规范](#4-提交规范)
- [5. 开发流程](#5-开发流程)
- [6. PR 规范](#6-pr-规范)
- [7. 版本发布与紧急修复](#7-版本发布与紧急修复)
- [8. 注意事项](#8-注意事项)

---

## 1. 概述

建立统一的 Git 协作规范，确保代码变更可追溯、分支管理清晰、提交信息结构化（便于生成 CHANGELOG）。适用于所有贡献者。

本项目为 Linux 内核模块版 fail2ban，含内核模块（C/Netfilter）、守护进程（C/PCRE2/SQLite3）、Bash 测试套件和 GitHub Actions CI/CD。

---

## 2. 分支策略

采用 **Git Flow 变体**：

```
main (生产) ── develop (开发)
                    ├── feature/* ──→ develop
                    ├── fix/* ──→ develop
                    ├── release/* ──→ main + develop
                    └── hotfix/* (从 main) ──→ main + develop
```

| 分支 | 来源 | 合并目标 | 保护 |
|------|------|----------|------|
| `main` | — | — | 🔒 |
| `develop` | `main` | `main` | 🔒 |
| `feature/*` | `develop` | `develop` | 完成后删除 |
| `fix/*` | `develop` | `develop` | 完成后删除 |
| `release/*` | `develop` | `main` + `develop` | 发布后删除 |
| `hotfix/*` | `main` | `main` + `develop` | 修复后删除 |

---

## 3. 分支命名

使用 **kebab-case**（小写 + 短横线），≤40 字符。

| 类型 | 格式 | 示例 |
|------|------|------|
| 功能 | `feature/<描述>` | `feature/jail-system` |
| Bug 修复 | `fix/<描述>` | `fix/rcu-concurrency-bug` |
| 发布 | `release/<版本>` | `release/v2.1` |
| 紧急修复 | `hotfix/<描述>` | `hotfix/integer-overflow` |
| 文档 | `docs/<描述>` | `docs/api-reference` |
| 重构 | `refactor/<描述>` | `refactor/extract-ban-functions` |
| 性能 | `perf/<描述>` | `perf/hash-lookup-optimization` |
| 测试 | `test/<描述>` | `test/add-yaml-parser-tests` |

| ✅ | ❌ | 原因 |
|---|---|---|
| `feature/yaml-config` | `feature/YAML_Config` | 禁止大写/下划线 |
| `fix/procfs-read-crash` | `fix/crash` | 描述过模糊 |
| `release/v2.1` | `release/2.1` | 需 `v` 前缀 |

---

## 4. 提交规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/v1.0.0/)。

### 4.1 格式

```
<type>(<scope>): <subject>
[空行]
[body]
[空行]
[footer]
```

| 部分 | 必填 | 说明 |
|------|------|------|
| `type` | ✅ | 变更类型 |
| `scope` | 可选 | 影响模块 |
| `subject` | ✅ | ≤72 字符，中文，动词开头，不以句号结尾 |
| `body` | 可选 | 详细描述 |
| `footer` | 可选 | `BREAKING CHANGE:` 或 `Closes #N` |

### 4.2 type

| type | 说明 | CHANGELOG |
|------|------|-----------|
| `feat` | 新功能 | 新增 |
| `fix` | Bug 修复 | 修复 |
| `docs` | 文档 | 文档 |
| `refactor` | 重构 | — |
| `perf` | 性能优化 | 性能 |
| `test` | 测试 | 测试 |
| `chore` | 构建/工具 | — |
| `ci` | CI/CD | — |
| `style` | 代码格式 | — |
| `build` | 构建系统 | — |

### 4.3 scope

| scope | 说明 | 示例 |
|-------|------|------|
| `kernel-module` | 内核模块 | `fix(kernel-module): 修复 RCU 读取竞态` |
| `daemon` | 守护进程 | `feat(daemon): 新增 YAML 配置解析` |
| `config` | 配置文件 | `fix(config): 修复 max_retries 校验` |
| `tests` | 测试 | `test(tests): 新增整数溢出测试` |
| `docs` | 文档 | `docs(docs): 添加 API 参考` |
| `ci` | CI/CD | `ci(ci): 添加 Debian 包构建` |

### 4.4 示例

```
feat(daemon): 新增 Jail 系统支持多服务隔离

fix(kernel-module): 修复 __do_ban_ip 中 whitelist 的 RCU 读取竞态

perf(daemon): 优化哈希表查找性能

将线性查找替换为 khash，查找时间从 O(n) 降至 O(1)。

feat(daemon)!: 配置文件从 INI 迁移到 YAML

BREAKING CHANGE: 旧 firewall.conf 不再支持，请运行 migrate-config.sh。

fix(daemon): 修复 SQLite 并发 use-after-free

Closes #42
```

### 4.5 禁止

| ❌ | ✅ |
|---|---|
| `update` | `fix(daemon): 修复配置重载内存泄漏` |
| `fix bug` | `fix(kernel-module): 修复分片包日志未限流` |
| `修改代码` | `refactor(daemon): 简化路径验证逻辑` |

---

## 5. 开发流程

```bash
# 1. 创建分支
git checkout develop && git pull origin develop
git checkout -b feature/your-feature-name

# 2. 开发提交
git add -A
git commit -m "feat(daemon): 新增 YAML 配置解析器"
# 修改最近提交（未 push）：git commit --amend

# 3. 同步（推荐 rebase）
git fetch origin && git rebase origin/develop
# 如已 push：git push --force-with-lease

# 4. 推送
git push -u origin feature/your-feature-name  # 首次
git push                                       # 后续
```

---

## 6. PR 规范

合入 `main`/`develop` **必须** 通过 PR，禁止直接 push。

### 6.1 标题与描述

标题遵循 Conventional Commits。描述使用 [PR 模板](../.github/PULL_REQUEST_TEMPLATE.md)：

```markdown
## 描述
简要说明 PR 目的。

## 相关 Issue
Closes #123

## 测试
- [x] 本地测试通过：`make && sudo ./tests/run_tests.sh`
```

### 6.2 审查与合并

| 要求 | 说明 |
|------|------|
| 审查 | ≥ 1 人批准 |
| CI | 全部通过 |
| 合并 | **Squash Merge**（压缩为单提交，信息需为 Conventional Commits 格式） |

---

## 7. 版本发布与紧急修复

### 7.1 版本号

遵循 [SemVer](https://semver.org/lang/zh-CN/)：`主版本.次版本.修订号`

| 变更 | 规则 | 示例 |
|------|------|------|
| 不兼容 API | 主版本 +1 | `v1.9` → `v2.0` |
| 新功能 | 次版本 +1 | `v2.0` → `v2.1` |
| Bug 修复 | 修订号 +1 | `v2.1.0` → `v2.1.1` |

### 7.2 发布流程

```bash
git checkout develop && git checkout -b release/v2.1
# 更新 CHANGELOG.md（[Unreleased] → 新版本号，新增 [Unreleased] 空段落）和版本号
make clean && make && sudo ./tests/run_tests.sh
git add -A && git commit -m "chore: 准备发布 v2.1"

git checkout main && git merge --no-ff release/v2.1
git tag -a v2.1 -m "发布 v2.1" && git push origin main --tags

git checkout develop && git merge --no-ff release/v2.1 && git push origin develop

gh release create v2.1 --title "v2.1" --notes-file CHANGELOG.md
git branch -d release/v2.1 && git push origin --delete release/v2.1
```

### 7.3 CHANGELOG

```markdown
## [v2.1] - 2026-XX-XX
### 新增 / 修复 / 安全 / 废弃
- 描述
```

### 7.4 Hotfix

**适用**：安全漏洞、服务崩溃、数据丢失。

```bash
git checkout main && git pull origin main
git checkout -b hotfix/integer-overflow
# 修复...
git add -A && git commit -m "fix(kernel-module): 修复 ban 时间整数溢出"
git push -u origin hotfix/integer-overflow

git checkout main && git merge --no-ff hotfix/integer-overflow
git tag -a v1.7.1 -m "紧急修复" && git push origin main --tags

git checkout develop && git merge --no-ff hotfix/integer-overflow && git push origin develop
git branch -d hotfix/integer-overflow && git push origin --delete hotfix/integer-overflow
```

---

## 8. 注意事项

### 8.1 安全红线

- 🚫 禁止提交密钥、密码、Token
- 🚫 禁止直接 push 到 `main`/`develop`
- 🚫 禁止未审查合并 PR / 跳过 CI
- 🚫 禁止提交 >100MB 文件

### 8.2 常见错误

| 错误 | 避免 |
|------|------|
| 在 main 上开发 | 始终从 develop 创建分支 |
| 提交信息模糊 | 遵循 Conventional Commits |
| 大文件提交 | `.gitignore` 排除编译产物 |
| 不同步 develop | 每天至少同步一次 |
| 未测试提交 | `make && sudo ./tests/run_tests.sh` |

### 8.3 内核模块注意

| 事项 | 说明 |
|------|------|
| 内核版本 | 确认目标内核，使用对应头文件 |
| RCU | 读取必须 `rcu_read_lock()` / `rcu_read_unlock()` |
| 内存 | 无 Valgrind，手动检查分配/释放 |
| 并发 | 考虑并发，加锁或原子操作 |
| procfs | 写入必须验证输入 |

### 8.4 常用命令

```bash
make                          # 编译
make clean                    # 清理
sudo ./tests/run_tests.sh     # 全部测试
./build-deb.sh                # 构建 Debian 包
```

---

## 附录

| 资源 | 链接 |
|------|------|
| Conventional Commits | https://www.conventionalcommits.org/zh-hans/v1.0.0/ |
| SemVer | https://semver.org/lang/zh-CN/ |
| PR 模板 | [.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md) |
