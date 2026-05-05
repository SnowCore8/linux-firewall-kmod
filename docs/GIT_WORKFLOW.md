# Git 工作流规范

> 本文档定义了本项目的 Git 分支策略、提交规范、开发流程和版本发布流程，所有贡献者必须遵守。

## 目录

- [1. 概述](#1-概述)
- [2. 分支策略](#2-分支策略)
- [3. 分支命名规范](#3-分支命名规范)
- [4. 提交规范](#4-提交规范)
- [5. 开发流程](#5-开发流程)
- [6. PR 规范](#6-pr-规范)
- [7. 版本发布流程](#7-版本发布流程)
- [8. 紧急修复流程](#8-紧急修复流程)
- [9. 常用命令速查](#9-常用命令速查)
- [10. 注意事项](#10-注意事项)

---

## 1. 概述

### 1.1 文档目的

本文档旨在建立统一的 Git 协作规范，确保：

- 代码变更可追溯、可回滚
- 分支管理清晰，避免冲突
- 提交信息结构化，便于生成 CHANGELOG
- 代码审查流程标准化
- 版本发布可重复、可验证

### 1.2 适用范围

本文档适用于本项目的所有代码贡献者，包括核心维护者和外部贡献者。

### 1.3 技术栈上下文

本项目是 Linux 内核模块版本的 fail2ban，包含：

| 组件 | 技术 | 说明 |
|------|------|------|
| 内核模块 | C (C99/C11) | Netfilter 框架 + RCU 并发 |
| 用户态守护进程 | C (C99/C11) | PCRE2 + libyaml + SQLite3 + libmicrohttpd |
| 测试套件 | Bash | 12 个测试套件，106+ 项测试 |
| CI/CD | GitHub Actions | 自动化构建、测试、发布 |

---

## 2. 分支策略

本项目采用 **Git Flow 变体** 的分支模型，适配内核模块项目的特点。

### 2.1 分支类型总览

```
main (生产分支)
  └── develop (开发集成分支)
        ├── feature/* (新功能)
        ├── fix/* (Bug 修复)
        ├── release/* (发布准备)
        └── hotfix/* (紧急修复)
```

### 2.2 分支说明

| 分支 | 来源 | 合并目标 | 说明 | 保护级别 |
|------|------|----------|------|----------|
| `main` | — | — | 生产环境代码，每个 commit 对应一个已发布版本 | 🔒 严格保护 |
| `develop` | `main` | `main` | 日常开发集成分支，包含最新已测试功能 | 🔒 严格保护 |
| `feature/*` | `develop` | `develop` | 新功能开发分支 | 开发完成后删除 |
| `fix/*` | `develop` | `develop` | 非紧急 Bug 修复分支 | 开发完成后删除 |
| `release/*` | `develop` | `main` + `develop` | 发布准备分支，用于最终测试和文档整理 | 发布完成后删除 |
| `hotfix/*` | `main` | `main` + `develop` | 生产环境紧急修复分支 | 修复完成后删除 |

### 2.3 分支生命周期

```
创建 feature/new-jail-system
    ↓
开发 + 提交 (feat: 新增 Jail 系统)
    ↓
创建 PR → develop (代码审查)
    ↓
Squash Merge → develop
    ↓
删除 feature 分支
```

---

## 3. 分支命名规范

### 3.1 命名规则

所有分支名称使用 **小写英文 + 短横线分隔**（kebab-case），禁止使用下划线、大写字母或特殊字符。

### 3.2 命名格式

| 分支类型 | 格式 | 示例 |
|----------|------|------|
| 功能开发 | `feature/<简短描述>` | `feature/jail-system` |
| Bug 修复 | `fix/<简短描述>` | `fix/rcu-concurrency-bug` |
| 发布准备 | `release/<版本号>` | `release/v2.1` |
| 紧急修复 | `hotfix/<简短描述>` | `hotfix/integer-overflow` |
| 文档更新 | `docs/<简短描述>` | `docs/git-workflow-guide` |
| 重构 | `refactor/<简短描述>` | `refactor/extract-ban-functions` |
| 性能优化 | `perf/<简短描述>` | `perf/hash-lookup-optimization` |
| 测试相关 | `test/<简短描述>` | `test/add-yaml-parser-tests` |

### 3.3 命名示例对照

| ✅ 正确 | ❌ 错误 | 原因 |
|---------|---------|------|
| `feature/yaml-config` | `feature/YAML_Config` | 禁止大写和下划线 |
| `fix/procfs-read-crash` | `fix/crash` | 描述过于模糊 |
| `release/v2.1` | `release/2.1` | 版本号需带 `v` 前缀 |
| `hotfix/sqlite-use-after-free` | `hotfix/fix-sqlite-bug` | 避免冗余的 "fix" 前缀 |

### 3.4 分支长度限制

- 分支名称（不含前缀）不超过 **40 个字符**
- 描述应简洁但足够明确，能一眼看出用途

---

## 4. 提交规范

本项目遵循 **[Conventional Commits](https://www.conventionalcommits.org/zh-hans/v1.0.0/)** 规范。

### 4.1 提交格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

| 部分 | 必填 | 说明 |
|------|------|------|
| `type` | ✅ | 变更类型（见下表） |
| `scope` | 可选 | 变更影响的模块范围 |
| `subject` | ✅ | 简要描述（不超过 72 字符） |
| `body` | 可选 | 详细描述变更动机和行为 |
| `footer` | 可选 | Breaking Change 说明或关联 Issue |

### 4.2 类型（type）

| 类型 | 说明 | CHANGELOG 分类 |
|------|------|----------------|
| `feat` | 新功能 | 新增 |
| `fix` | Bug 修复 | 修复 |
| `docs` | 文档更新 | 文档 |
| `style` | 代码格式（不影响逻辑） | — |
| `refactor` | 代码重构（非新功能、非修复） | — |
| `perf` | 性能优化 | 性能 |
| `test` | 测试相关 | 测试 |
| `chore` | 构建/工具/依赖变更 | — |
| `ci` | CI/CD 配置变更 | — |
| `build` | 构建系统变更 | — |

### 4.3 作用域（scope）

| 作用域 | 说明 | 示例 |
|--------|------|------|
| `kernel-module` | 内核模块代码 | `fix(kernel-module): 修复 RCU 读取竞态` |
| `daemon` | 用户态守护进程 | `feat(daemon): 新增 YAML 配置解析` |
| `config` | 配置文件 | `fix(config): 修复 max_retries 范围校验` |
| `tests` | 测试套件 | `test(tests): 新增整数溢出测试` |
| `docs` | 项目文档 | `docs(docs): 添加 API 参考文档` |
| `ci` | CI/CD 工作流 | `ci(ci): 添加 Debian 包构建` |

### 4.4 subject 规范

- 使用 **中文** 描述（与项目文档语言一致）
- 使用 **祈使句**，以动词开头（如"新增"、"修复"、"移除"）
- **不超过 72 个字符**
- **不以句号结尾**
- **首字母不需要大写**（中文无大小写概念）

### 4.5 格式示例

#### 简单提交

```
feat(daemon): 新增 Jail 系统支持多服务隔离
```

```
fix(kernel-module): 修复 __do_ban_ip 中 whitelist 的 RCU 读取竞态
```

#### 含 Body 的提交

```
perf(daemon): 优化哈希表查找性能

将线性查找替换为 khash 哈希表，IP 封禁查找时间
从 O(n) 降低到 O(1)，在 1024 容量下性能提升约 10 倍。
```

#### 含 Breaking Change 的提交

```
feat(daemon)!: 配置文件格式从 INI 迁移到 YAML

BREAKING CHANGE: 旧的 firewall.conf 格式不再支持，
请使用 config/default.yaml 格式。运行 migrate-config.sh
可自动转换旧配置文件。
```

#### 含 Footer 关联 Issue 的提交

```
fix(daemon): 修复 SQLite 并发访问导致的 use-after-free

所有 SQLITE_STATIC 替换为 SQLITE_TRANSIENT，确保
字符串数据在 SQLite 内部正确复制。

Closes #42
```

### 4.6 多作用域提交

当变更涉及多个模块时，选择 **最主要的影响模块** 作为 scope，或在 body 中说明影响范围：

```
refactor: 统一内核模块 Ban 函数族

影响范围：
- kernel-module: 提取 __do_ban_ip() 统一 ban 函数
- kernel-module: 提取 __do_unban_ip() 统一 unban 函数
- kernel-module: 提取 __find_ban_entry_rcu() 统一查询
```

### 4.7 禁止的提交信息

| ❌ 错误示例 | 原因 | ✅ 正确写法 |
|-------------|------|-------------|
| `update` | 过于模糊 | `fix(daemon): 修复配置重载时的内存泄漏` |
| `fix bug` | 未说明修复了什么 | `fix(kernel-module): 修复分片包日志未限流问题` |
| `修改代码` | 未使用 Conventional Commits | `refactor(daemon): 简化路径验证逻辑` |
| `完成功能开发` | 未说明是什么功能 | `feat(daemon): 新增 Prometheus metrics 导出` |

---

## 5. 开发流程

### 5.1 克隆和初始设置

```bash
# 克隆仓库
git clone git@github.com:SnowCore8/firewall.git
cd firewall

# 配置用户信息（如未全局配置）
git config user.name "Your Name"
git config user.email "your.email@example.com"

# 安装 pre-commit hook（如项目提供）
# 配置 Conventional Commits 校验
```

### 5.2 创建开发分支

```bash
# 确保 develop 分支是最新的
git checkout develop
git pull origin develop

# 创建并切换到新分支
git checkout -b feature/your-feature-name
```

### 5.3 开发和提交

```bash
# 编写代码...

# 查看变更
git status
git diff

# 暂存变更
git add <file>
# 或暂存所有变更
git add -A

# 提交（遵循 Conventional Commits 规范）
git commit -m "feat(daemon): 新增 YAML 配置解析器"

# 如需修改最近一次提交（未 push 前）
git commit --amend -m "feat(daemon): 新增 YAML 配置解析器

支持嵌套配置结构，包括 log_files 数组和 regex_patterns 映射。"
```

### 5.4 同步上游代码

在开发过程中，定期同步 `develop` 分支以获取最新变更：

```bash
# 方式一：rebase（推荐，保持线性历史）
git fetch origin
git rebase origin/develop

# 方式二：merge（如团队协作需要保留合并记录）
git fetch origin
git merge origin/develop
```

> **注意**：如果已经 push 到远程分支，使用 `rebase` 后需要 `git push --force-with-lease`。

### 5.5 推送分支

```bash
# 首次推送（设置上游分支）
git push -u origin feature/your-feature-name

# 后续推送
git push
```

### 5.6 完整工作流示例

```bash
# 1. 从 develop 创建功能分支
git checkout develop
git pull origin develop
git checkout -b feature/jail-system

# 2. 开发并提交
# ... 编写代码 ...
git add src/config_parser.c src/config_parser.h
git commit -m "feat(daemon): 新增 Jail 配置解析器

支持 YAML 格式的 jails 配置段，每个 Jail 可独立配置
日志文件、正则模式和封禁阈值。"

# ... 继续开发 ...
git add tests/test_jail.sh
git commit -m "test(tests): 新增 Jail 系统测试用例"

# 3. 同步 develop（如有冲突则解决）
git fetch origin
git rebase origin/develop

# 4. 推送
git push -u origin feature/jail-system

# 5. 在 GitHub 创建 Pull Request
```

---

## 6. PR 规范

### 6.1 创建 Pull Request

所有合入 `main` 和 `develop` 的变更 **必须** 通过 Pull Request（PR），禁止直接 push。

### 6.2 PR 标题

PR 标题应遵循 Conventional Commits 格式，与提交信息保持一致：

```
feat(daemon): 新增 Jail 系统支持多服务隔离
```

### 6.3 PR 描述

PR 描述应包含以下内容（使用项目提供的 [PR 模板](../.github/PULL_REQUEST_TEMPLATE.md)）：

```markdown
## 描述

简要说明此 PR 的目的和变更内容。

## 相关 Issue

Closes #123

## 变更类型

- [x] 新功能（非破坏性变更）

## 测试

- [x] 已通过本地测试
- [x] 已添加/更新测试用例
- [x] 所有现有测试通过

### 测试命令

```bash
# 编译
make

# 运行测试
sudo ./tests/run_tests.sh
```

## 检查清单

- [x] 代码遵循项目编码规范
- [x] 已添加必要的注释
- [x] 已更新相关文档
- [x] 无硬编码敏感信息
- [x] 提交信息遵循 Conventional Commits 规范
```

### 6.4 代码审查流程

```
创建 PR
    ↓
CI 自动检查（构建 + 测试）
    ↓
代码审查者审查
    ↓
├── 通过 → 合并
├── 需要修改 → 提交修改 → 重新审查
└── 拒绝 → 关闭 PR 或大幅修改后重新提交
```

### 6.5 审查要求

| 要求 | 说明 |
|------|------|
| 最少审查人数 | 至少 **1 人** 批准（核心维护者） |
| CI 状态 | 所有 CI 检查必须通过 |
| 冲突解决 | PR 必须无合并冲突 |
| 提交整理 | 合并前整理提交，确保逻辑清晰 |

### 6.6 合并策略

本项目使用 **Squash Merge** 策略：

| 策略 | 是否使用 | 说明 |
|------|----------|------|
| Squash Merge | ✅ | 将 PR 的所有提交压缩为单个提交，保持主分支历史整洁 |
| Merge Commit | ❌ | 会产生额外的合并提交，历史不够清晰 |
| Rebase and Merge | ❌ | 保留所有中间提交，可能包含调试提交 |

> **Squash Merge 注意事项**：合并时的提交信息应使用 Conventional Commits 格式，便于自动生成 CHANGELOG。

---

## 7. 版本发布流程

### 7.1 版本号规范

本项目遵循 **[Semantic Versioning (SemVer)](https://semver.org/lang/zh-CN/)** 规范：

```
主版本号.次版本号.修订号
  ↑         ↑        ↑
不兼容的   向下兼容  Bug 修复
API 变更    新功能
```

| 变更类型 | 版本号变更 | 示例 |
|----------|------------|------|
| 不兼容的 API 变更 | 主版本号 +1 | `v1.9` → `v2.0` |
| 向下兼容的新功能 | 次版本号 +1 | `v2.0` → `v2.1` |
| Bug 修复 | 修订号 +1 | `v2.1.0` → `v2.1.1` |

> **注意**：本项目当前版本号为 `vX.Y` 格式（无修订号），后续稳定后可采用完整 `vX.Y.Z` 格式。

### 7.2 发布步骤

#### 步骤 1：创建 release 分支

```bash
# 从 develop 创建 release 分支
git checkout develop
git checkout -b release/v2.1
```

#### 步骤 2：更新版本号和 CHANGELOG

```bash
# 更新 CHANGELOG.md
# 1. 将 [Unreleased] 段落改为新版本号
# 2. 添加版本发布日期
# 3. 新增 [Unreleased] 空段落

# 如有版本号常量文件，同步更新
# 例如：src/version.h 或 Makefile 中的 VERSION
```

#### 步骤 3：最终测试

```bash
# 完整编译
make clean && make

# 运行全部测试
sudo ./tests/run_tests.sh

# 检查编译警告（应为零）
make CFLAGS="-Wall -Wextra -Werror"
```

#### 步骤 4：提交 release 分支变更

```bash
git add CHANGELOG.md
git commit -m "chore: 准备发布 v2.1"
```

#### 步骤 5：合并到 main 和 develop

```bash
# 合并到 main
git checkout main
git merge --no-ff release/v2.1

# 打标签
git tag -a v2.1 -m "发布 v2.1：新增 XX 功能，修复 XX 问题"

# 合并回 develop
git checkout develop
git merge --no-ff release/v2.1

# 推送
git push origin main --tags
git push origin develop
```

#### 步骤 6：创建 GitHub Release

```bash
# 使用 GitHub CLI 创建 Release
gh release create v2.1 \
  --title "v2.1" \
  --notes-file CHANGELOG.md \
  --generate-notes
```

#### 步骤 7：删除 release 分支

```bash
git branch -d release/v2.1
git push origin --delete release/v2.1
```

### 7.3 CHANGELOG 更新规范

CHANGELOG.md 应遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式：

```markdown
## [v2.1] - 2026-XX-XX

### 新增
- 功能描述

### 变更
- 变更描述

### 修复
- 修复描述

### 安全
- 安全相关变更

### 废弃
- 即将移除的功能
```

---

## 8. 紧急修复流程

### 8.1 何时使用 Hotfix

| 场景 | 是否使用 Hotfix |
|------|-----------------|
| 生产环境安全漏洞 | ✅ |
| 导致服务崩溃的 Bug | ✅ |
| 数据丢失风险 | ✅ |
| 普通功能 Bug | ❌（走正常 fix 流程） |
| 新功能开发 | ❌ |

### 8.2 Hotfix 流程

```
发现生产问题
    ↓
从 main 创建 hotfix 分支
    ↓
修复问题 + 测试
    ↓
提交（遵循 Conventional Commits）
    ↓
创建 PR → main（紧急审查）
    ↓
合并到 main → 打标签 → 发布
    ↓
同时合并到 develop（保持同步）
```

### 8.3 Hotfix 操作示例

```bash
# 1. 从 main 创建 hotfix 分支
git checkout main
git pull origin main
git checkout -b hotfix/integer-overflow

# 2. 修复问题
# ... 编写修复代码 ...

# 3. 提交
git add src/firewall.c
git commit -m "fix(kernel-module): 修复 ban 时间计算的整数溢出

添加 check_mul_overflow() 检查所有 seconds * HZ 运算，
防止大数值导致溢出。"

# 4. 推送并创建紧急 PR
git push -u origin hotfix/integer-overflow

# 5. 审查通过后合并到 main
git checkout main
git merge --no-ff hotfix/integer-overflow
git tag -a v1.7.1 -m "紧急修复：ban 时间整数溢出"
git push origin main --tags

# 6. 合并回 develop
git checkout develop
git merge --no-ff hotfix/integer-overflow
git push origin develop

# 7. 删除 hotfix 分支
git branch -d hotfix/integer-overflow
git push origin --delete hotfix/integer-overflow
```

---

## 9. 常用命令速查

### 9.1 分支操作

| 命令 | 说明 |
|------|------|
| `git branch` | 列出本地分支 |
| `git branch -r` | 列出远程分支 |
| `git branch -a` | 列出所有分支 |
| `git checkout -b <branch>` | 创建并切换分支 |
| `git checkout <branch>` | 切换分支 |
| `git branch -d <branch>` | 删除本地分支（已合并） |
| `git branch -D <branch>` | 强制删除本地分支 |
| `git push origin --delete <branch>` | 删除远程分支 |

### 9.2 提交操作

| 命令 | 说明 |
|------|------|
| `git status` | 查看工作区状态 |
| `git diff` | 查看未暂存的变更 |
| `git diff --cached` | 查看已暂存的变更 |
| `git add <file>` | 暂存指定文件 |
| `git add -A` | 暂存所有变更 |
| `git commit -m "msg"` | 提交变更 |
| `git commit --amend` | 修改最近一次提交 |
| `git log --oneline -10` | 查看最近 10 条提交 |
| `git log --oneline --graph` | 图形化查看提交历史 |

### 9.3 同步操作

| 命令 | 说明 |
|------|------|
| `git fetch origin` | 获取远程更新（不合并） |
| `git pull origin develop` | 拉取并合并 develop |
| `git rebase origin/develop` | 变基到 develop |
| `git push` | 推送到远程 |
| `git push -u origin <branch>` | 推送并设置上游分支 |
| `git push --force-with-lease` | 安全强制推送 |

### 9.4 标签操作

| 命令 | 说明 |
|------|------|
| `git tag` | 列出所有标签 |
| `git tag -a v1.0 -m "msg"` | 创建带注释的标签 |
| `git push origin --tags` | 推送所有标签 |
| `git tag -d v1.0` | 删除本地标签 |

### 9.5 撤销操作

| 命令 | 说明 | 安全性 |
|------|------|--------|
| `git reset HEAD <file>` | 取消暂存 | ✅ 安全 |
| `git checkout -- <file>` | 丢弃工作区修改 | ⚠️ 不可恢复 |
| `git reset --soft HEAD~1` | 撤销提交，保留变更 | ✅ 安全 |
| `git reset --hard HEAD~1` | 撤销提交，丢弃变更 | ⚠️ 不可恢复 |
| `git revert <commit>` | 创建反向提交 | ✅ 安全（已 push 时用这个） |

### 9.6 项目常用命令

```bash
# 编译项目
make

# 运行全部测试
sudo ./tests/run_tests.sh

# 运行指定测试套件
sudo ./tests/run_tests.sh -c <category>

# 生成测试报告
sudo ./tests/run_tests.sh --report

# 清理构建产物
make clean

# 构建 Debian 包
./build-deb.sh
```

---

## 10. 注意事项

### 10.1 常见错误

| 错误 | 原因 | 避免方法 |
|------|------|----------|
| 直接在 main 上开发 | 污染生产分支 | **始终**从 develop 创建功能分支 |
| 提交信息模糊 | 无法追溯变更目的 | 遵循 Conventional Commits 规范 |
| 大文件提交 | 仓库膨胀 | 使用 `.gitignore` 排除编译产物 |
| 提交敏感信息 | 安全风险 | 使用环境变量或配置文件，不硬编码 |
| 长期不同步 develop | 合并冲突严重 | **每天**至少同步一次 |
| 未测试就提交 | 引入回归 | 提交前运行 `make && sudo ./tests/run_tests.sh` |
| 强制 push 到共享分支 | 覆盖他人提交 | 仅在个人分支使用 `--force-with-lease` |

### 10.2 安全红线

- 🚫 **禁止** 提交密钥、密码、Token 等敏感信息
- 🚫 **禁止** 直接 push 到 `main` 或 `develop`
- 🚫 **禁止** 在未审查的情况下合并 PR
- 🚫 **禁止** 跳过 CI 检查强制合并
- 🚫 **禁止** 提交超过 100MB 的文件

### 10.3 内核模块开发特别注意

| 注意事项 | 说明 |
|----------|------|
| 内核版本兼容 | 提交前确认目标内核版本，使用对应版本的头文件 |
| RCU 安全 | 所有 RCU 读取路径必须使用 `rcu_read_lock()` / `rcu_read_unlock()` |
| 内存安全 | 内核态无 Valgrind，需手动检查所有内存分配/释放路径 |
| 并发安全 | 新增代码需考虑并发场景，必要时加锁或使用原子操作 |
| procfs 安全 | 所有 procfs 写入操作必须验证输入，防止注入攻击 |

### 10.4 Git 配置建议

```bash
# 推荐的全局配置
git config --global core.autocrlf input          # Linux 项目统一使用 LF
git config --global core.editor "vim"            # 设置默认编辑器
git config --global pull.rebase true             # pull 默认使用 rebase
git config --global push.default current         # push 默认推当前分支
git config --global rerere.enabled true          # 自动记录冲突解决方案
git config --global fetch.prune true             # fetch 时自动清理已删除的远程分支
```

### 10.5 .gitignore 关键规则

本项目已配置 `.gitignore`，确保以下文件不被提交：

```
# 编译产物
*.o
*.ko
*.mod.c
*.mod
*.order
*.symvers
firewall-daemon

# 编辑器
*.swp
*~
.vscode/
.idea/

# 系统文件
.DS_Store
Thumbs.db

# 测试临时文件
test_output/
*.log
```

---

## 附录

### A. 相关资源

| 资源 | 链接 |
|------|------|
| Conventional Commits 规范 | https://www.conventionalcommits.org/zh-hans/v1.0.0/ |
| Semantic Versioning | https://semver.org/lang/zh-CN/ |
| Keep a Changelog | https://keepachangelog.com/zh-CN/1.1.0/ |
| Git Flow 工作流 | https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow |
| GitHub Flow | https://docs.github.com/zh/get-started/quickstart/github-flow |
| 项目 PR 模板 | [.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md) |

### B. 文档版本

| 版本 | 日期 | 说明 |
|------|------|------|
| v1.0 | 2026-05-05 | 初始版本 |
