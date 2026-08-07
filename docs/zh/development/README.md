# 开发指南

本章节介绍如何开发、构建和测试 Linux Firewall 内核模块。

## 开发环境

### 推荐配置

| 项目 | 要求 |
|------|------|
| OS | Ubuntu 22.04+ / Debian 12+ |
| GCC | 12+ |
| Make | 4.0+ |
| Git | 2.30+ |

### 安装开发依赖

```bash
# Ubuntu/Debian
sudo apt install -y \
    build-essential \
    linux-headers-$(uname -r) \
    pkg-config \
    clang \
    cmake
```

## 项目结构

```mermaid
graph LR
    ROOT["linux-firewall-kmod/"]
    KERNEL["src/kernel-module/<br/>C 内核模块"]
    DAEMON["src/daemon/<br/>Rust 守护进程"]
    FRONTEND["frontend/<br/>Leptos WASM 前端"]
    STATIC["src/daemon/web_ui/static/<br/>编译后静态资源"]
    SUPPORT["config/ · tests/ · docs/<br/>scripts/ · debian/ · grafana/"]

    ROOT --> KERNEL
    ROOT --> DAEMON
    ROOT --> FRONTEND
    ROOT --> SUPPORT
    FRONTEND -->|"trunk build"| STATIC
    STATIC -->|"rust-embed"| DAEMON
    DAEMON <-->|"netlink"| KERNEL
```

### 三个运行组件

| 组件 | 入口 | 职责 |
|------|------|------|
| 内核模块 | `src/kernel-module/firewall-main.c` | 注册 netfilter hook，维护封禁/白名单并在数据包路径执行判定 |
| 守护进程 | `src/daemon/main.rs`、`src/daemon/lib.rs` | 解析配置与日志、执行封禁策略、持久化状态，并提供 HTTP 服务 |
| Web 前端 | `frontend/src/main.rs` | Leptos 管理界面；构建后嵌入守护进程二进制，不单独部署 |

### 构建链路

`make daemon` 会先执行 `make frontend`。Trunk 根据
`frontend/Trunk.toml` 将前端输出到 `src/daemon/web_ui/static/`，
随后 `rust-embed` 把这些资源编译进 `firewall-daemon`。

其他目录分别保存 YAML 配置（`config/`）、集成测试（`tests/`）、
正式文档（`docs/`）、辅助脚本（`scripts/`）、Debian 打包元数据
（`debian/`）和 Grafana 资源（`grafana/`）。

## 代码规范

### C 语言规范

- 使用 C99 标准
- 4 空格缩进
- 函数名使用 `snake_case`
- 常量使用 `UPPER_CASE`
- 结构体使用 `snake_case` 并以 `_t` 结尾

### 内核模块规范

- 遵循 Linux 内核编码风格
- 使用 `pr_*` 宏进行日志输出
- 使用 `__init` 和 `__exit` 标记初始化和退出函数
- 避免在原子上下文中睡眠

### 提交规范

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

| Type | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档更新 |
| `style` | 代码格式 |
| `refactor` | 重构 |
| `perf` | 性能优化 |
| `test` | 测试相关 |
| `chore` | 构建/工具链 |

## 贡献流程

1. Fork 仓库
2. 创建特性分支 (`git checkout -b feat/amazing-feature`)
3. 提交更改 (`git commit -m 'feat: add amazing feature'`)
4. 运行测试 (`make test`)
5. 推送分支 (`git push origin feat/amazing-feature`)
6. 创建 Pull Request