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
    libyaml-dev \
    libsqlite3-dev \
    libmicrohttpd-dev \
    libpcre2-dev \
    pkg-config \
    valgrind \
    clang \
    cmake
```

## 项目结构

```
linux-firewall-kmod/
├── Makefile              # 主 Makefile
├── src/
│   ├── kernel/           # 内核模块源码
│   │   ├── fw_fire.c
│   │   └── fw_fire.h
│   ├── daemon/           # 守护进程源码
│   │   ├── main.c
│   │   ├── config.c      # YAML 配置解析
│   │   ├── jail.c        # Jail 管理
│   │   ├── monitor.c     # 日志监控 (inotify)
│   │   ├── regex.c       # PCRE2 匹配
│   │   ├── database.c    # SQLite 持久化
│   │   ├── metrics.c     # Prometheus 指标
│   │   └── procfs.c      # ProcFS 通信
│   └── include/          # 公共头文件
│       └── common.h
├── tests/                # 测试文件
│   ├── unit/             # 单元测试
│   └── integration/      # 集成测试
├── docs/                 # 文档
├── config/
│   └── fw_fire.yaml      # 示例配置
└── scripts/              # 辅助脚本
```

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

---

[English Version](../../en/development/README.md)
