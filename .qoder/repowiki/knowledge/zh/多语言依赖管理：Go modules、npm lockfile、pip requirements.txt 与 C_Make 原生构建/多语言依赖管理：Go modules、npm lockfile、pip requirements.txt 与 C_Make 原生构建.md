---
kind: dependency_management
name: 多语言依赖管理：Go modules、npm lockfile、pip requirements.txt 与 C/Make 原生构建
category: dependency_management
scope:
    - '**'
source_files:
    - src/daemon/go.mod
    - src/daemon/go.sum
    - frontend/package.json
    - frontend/package-lock.json
    - package.json
    - package-lock.json
    - docs/package.json
    - docs/package-lock.json
    - tests/requirements.txt
    - Makefile
    - Makefile.dkms
    - dkms.conf
---

## 1. 使用的工具与方案

仓库是一个多语言项目，每个子模块各自使用其生态的标准依赖管理工具：

- **Go（firewall-daemon）**：`src/daemon/go.mod` + `go.sum`，使用 Go Modules；模块路径为 `github.com/snowcore8/linux-firewall-kmod/daemon`，要求 Go 1.26.0。
- **前端 React 应用**：`frontend/package.json` + `frontend/package-lock.json`，使用 npm 包管理器，锁定版本到精确的 `package-lock.json`。
- **E2E 测试（Playwright）**：根级 `package.json` + `package-lock.json`，仅声明 `@playwright/test` 作为 devDependency。
- **文档站点（HonKit）**：`docs/package.json` + `docs/package-lock.json`，额外通过 `overrides` 字段覆盖下游依赖中的安全漏洞依赖（`tmp`、`qs`、`undici`、`brace-expansion`、`moment`）。
- **Python 集成测试**：`tests/requirements.txt`，使用 pip 安装 pytest、pyyaml、pytest-html、pytest-cov。
- **C 内核模块 / Make 构建**：无第三方库依赖声明文件，直接通过 `Makefile`、`Makefile.dkms`、`dkms.conf` 调用系统内核头与 gcc 编译，不引入用户态包管理器。

## 2. 关键文件

- `src/daemon/go.mod` — Go 模块定义与 require 列表
- `src/daemon/go.sum` — Go 依赖校验和锁文件
- `frontend/package.json` + `frontend/package-lock.json` — 前端运行时与开发依赖
- `package.json` + `package-lock.json`（根目录）— Playwright E2E 测试依赖
- `docs/package.json` + `docs/package-lock.json` — HonKit 文档站依赖，含 `overrides`
- `tests/requirements.txt` — Python 测试依赖
- `Makefile`、`Makefile.dkms`、`dkms.conf` — C 内核模块构建入口

## 3. 架构与约定

- **按子系统隔离依赖**：Go、前端、文档、E2E 测试各自维护独立的 manifest 与 lockfile，不存在跨子系统的共享依赖。Go 代码只引用自身模块路径下的内部包，外部依赖极少（仅 `golang.org/x/sys`、`gopkg.in/yaml.v3` 以及 modernc/sqlite 等 indirect 依赖）。
- **Lockfile 强制可重复构建**：前端与文档均提交对应的 `package-lock.json`；Go 提交 `go.sum`。这保证 CI 与本地安装得到相同版本的依赖树。
- **语义化版本范围**：前端依赖使用 `^` 前缀（如 `antd ^6.6.8`、`react ^19.2.0`），允许小版本升级但由 lockfile 固定实际安装版本；Go 依赖在 `go.mod` 中写死具体版本（如 `golang.org/x/sys v0.48.0`）。
- **Go 间接依赖显式列出**：`go.mod` 同时包含 `require` 与 `require (...)` 两个块，间接依赖（如 `modernc.org/sqlite`、`fsnotify/fsnotify`）被显式写入而非隐式存在，便于审计。
- **Go 不使用 GOPRIVATE / 私有代理**：仓库内未出现 `GOPRIVATE`、`GONOSUMDB`、`GONOPROXY`、`goproxy` 等环境变量或配置，所有 Go 模块均来自公共 Go 代理 / 源码仓库。
- **C 内核模块零用户态依赖**：内核模块通过 `Makefile` 直接调用系统提供的内核头与编译器，不引入任何 C/C++ 包管理器；DKMS 打包通过 `dkms.conf` 与 `Makefile.dkms` 完成。

## 4. 约定与约束

- **Go 模块版本锁定**：`go.mod` 指定 `go 1.26.0`，CI 与本地构建需匹配该版本；`go.sum` 提供每个依赖的哈希校验，`go mod verify` 会拒绝篡改的依赖。
- **npm 依赖通过 lockfile 锁定**：`frontend/package-lock.json` 与 `docs/package-lock.json` 提交至仓库，安装时优先读取 lockfile 以复现依赖树。
- **文档站安全修复通过 overrides 注入**：`docs/package.json` 中的 `overrides` 字段强制将 `tmp >= 0.2.6`、`qs >= 6.16.1`、`undici ^6.29.1`、`brace-expansion ^1.1.21`、`moment ^2.31.0` 升级到安全版本，这是针对 HonKit 下游依赖的安全补丁策略。
- **Python 测试依赖使用最低版本约束**：`tests/requirements.txt` 使用 `>=` 语法（如 `pytest>=7.0`），允许安装更高版本，但未使用 `requirements.txt.lock` 类工具做严格锁定。
- **Node.js 引擎约束**：根 `package.json` 通过 `engines.node >= 20` 限制运行环境，Playwright E2E 测试需 Node ≥ 20。
- **无 vendoring**：仓库未发现 `vendor/` 目录或 Go `go mod vendor` 产物，也未见 `.npmrc`、`.yarnrc`、`Pipfile.lock` 等私有源配置；依赖全部从公共注册表拉取。
- **Go 模块路径遵循组织命名**：模块名 `github.com/snowcore8/linux-firewall-kmod/daemon` 表明该仓库托管于 GitHub 且采用子模块路径风格。