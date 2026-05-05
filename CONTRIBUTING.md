# 关于本项目

## 开发模式

本项目由 **SnowCore8** 独立开发，全程使用 [OpenCode](https://opencode.ai) AI 编程助手辅助完成。

## 开发工具链

| 工具 | 用途 |
|------|------|
| [OpenCode](https://opencode.ai) | AI 编程助手（代码编写、审查、重构） |
| GCC | C 编译器 |
| Kbuild | 内核模块构建系统 |
| GNU Make | 项目构建 |
| GitHub Actions | CI/CD 自动化 |

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

## 许可证

MIT License — 详见 [LICENSE](LICENSE)

## 联系方式

- **GitHub**: [@SnowCore8](https://github.com/SnowCore8)
- **邮箱**: snowcore8@gmail.com
