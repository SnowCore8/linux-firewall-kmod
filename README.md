# Firewall

**Linux 内核模块版 fail2ban — 实时 IP 封禁防护**

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.2.0-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Language](https://img.shields.io/badge/Language-Go%20%7C%20C-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%205.x%20%7C%206.x-orange.svg)]()

## 概述

Firewall 是 Linux 内核模块版的 fail2ban：**把「封哪个 IP」的判定留在用户态，把「丢掉这个包」搬进内核**。
Go 守护进程读日志、算失败窗口、做判定，经 netlink 把结果下发给内核模块；内核模块挂在 netfilter
钩子上，在包路径上用哈希表查封禁表，命中即丢。封禁因此不再受用户态进程调度与规则遍历拖累。

### 项目目标

目标不是「做一个防火墙」，而是把 fail2ban 的三类痛点做实。三条判据都可验证，也都有对应的验收方：

| 判据 | 说的是什么 | 由谁验收 |
|------|------------|----------|
| **防护真的在跑** | 守护进程与内核模块必须处于工作状态。任一 jail 的配置劣化不得让整个进程拒绝启动——那等于把所有 jail 的防护一起下线 | [`STANDARDS.md`](STANDARDS.md) 把「核心功能完全不可用（封禁失效、日志解析完全错误）」定为 Critical；`tests/` 集成套件是行为规格 |
| **装得进普通 Linux** | 目标用户的那台发行版上，`.ko` 要编得出来、载得进去、`/proc/firewall` 要出现。编译通过不等于加载得了 | [`tests/test_01_module_lifecycle.py`](tests/test_01_module_lifecycle.py) 等内核套件；见下方「内核版本口径」 |
| **分得开扫描器和正常访客** | 判据方向必须对：扫描的形态是「同一网段内 IP 多、每个 IP 少」，单 IP 计数器恰好把这类流量漏掉 | [`docs/zh/development/cluster-detection-design.md`](docs/zh/development/cluster-detection-design.md) 与 `config/frp.yaml` 的停用说明（这条教训的出处） |

一句话口径：**宁可少封，也不能不封、不能乱封，也不能在用户的机器上起不来。**

### 非目标

- 不是通用防火墙：不表达 allow 规则、不做 NAT / 端口映射 / QoS，也不替代 iptables 的规则表达能力。
- 不是转发设备：包路径上只做「命中封禁表就丢」，不追求吞吐性能本身。性能口径是「不拖垮宿主」
  （`STANDARDS.md` 以 10Gbps 目标场景下 30% 的性能下降为 High 级红线），不是「拿它当路由器」。
- 不做应用层防护：不解析 HTTP 语义、不识别 payload、不管 WAF 那一类问题。
- 不追求无配置：需要 jail 的日志路径与正则；正则写坏时降级为告警 + 关键字回退，而不是假装能识别。

### 交付形态

| 部件 | 形态 | 位置 |
|------|------|------|
| 内核模块 | 单个 `firewall.ko`，C 语言，netfilter + RCU + 哈希表 | `src/kernel-module/` |
| 守护进程 | 单文件 Go 二进制，移动端优先的 React 面板经 `//go:embed` 一并嵌入 | `src/daemon/`（组合根 `cmd/firewall-daemon`） |
| 操作接口 | procfs 条目（`/proc/firewall/*`）、HTTP/JSON API、SSE 实时推送、Prometheus 指标 | 契约单一真相源：`contract/` |

### 内核版本口径

顶部徽章写的 `Linux 5.x | 6.x` 目前是**意图而非实测结论**。已验证的是 6.8.0-146（Ubuntu 24.04 GA
内核）：可编译、可 `insmod`、`/proc/firewall` 条目齐全；7.0.0-38 亦可编译。**5.x 未做过任何验证**，
而 6.x 内部也存在真实的 API 断层（例：`timer_container_of` 与 `from_timer` 的改名、
单次 per-CPU 分配的 32KiB 上限），这两处都已在 `src/kernel-module/` 里显式适配。
新版本内核上的验证记录应随 CHANGELOG 补充，不要仅凭徽章宣称兼容范围。

## 为什么选择本项目

| 对比项 | fail2ban（用户态） | Firewall（内核态） |
|--------|-------------------|-------------------|
| 封禁位置 | iptables/nftables 用户态 | netfilter 内核钩子 |
| 响应延迟 | 秒级 | 毫秒级 |
| 资源占用 | Python 解释器 + 完整依赖链 | 单文件 Go binary（前端产物一并嵌入，无运行时库体积） |
| 查找性能 | 线性遍历规则 | 哈希表 O(1) 查找 |
| 永久封禁 | 配置文件 | 内存缓存，重启后失效 |

## 核心特性

- ✅ **内核态 IP 封禁** — netfilter hooks，比 iptables 用户态更高效
- ✅ **Jail 系统** — 类似 fail2ban 的多服务隔离配置
- ✅ **哈希表存储** — O(1) 查找性能
- ✅ **自动过期清理** — 定时清理过期封禁记录
- ✅ **IP 白名单保护** — 自动发现系统 IP + 手动添加
- ✅ **procfs 用户接口** — 封禁/解封/白名单/配置操作
- ✅ **Go 守护进程（`src/daemon` Go module）** — `go build -ldflags "-s -w=1"`，输出即为带符号剥离的单文件二进制；前端由 `src/daemon/web_ui/static/assets.go` 的 `//go:embed *` 携带进包
- ✅ **React 移动端前端** — React 19 + TypeScript + Vite + antd-mobile 5 构建，移动优先，hash 路由，手写 SVG 图表，支持 PWA
- ✅ **正则解析** — 支持命名捕获组提取 IP
- ✅ **RCU 并发安全** — spinlock 保护，高并发安全
- ✅ **严格配置校验** — 未知参数或无效值直接报错拒绝加载
- ✅ **Prometheus 指标** — 端口 9119 导出监控指标
- ✅ **独立日志文件** — `cfg.log_file` 默认 `/var/log/firewall.log`，失败回退 syslog-only
- ✅ **安全加固** — 整数溢出防护、Use-After-Free 修复、RCU 一致性增强、所有 unsafe 块均带 `// SAFETY:` 注释
- ✅ **性能优化** — 哈希表与白名单两阶段匹配、LTO 编译优化
- ✅ **代码质量** — Go 守护进程 `go test ./...` / `go vet ./cmd/... ./internal/...` / `gofmt -l ./cmd ./internal` 通过；
集成测试套件是行为规格，由 CI（GitHub Actions）在 Python/Playwright 环境下执行

## 快速开始

### 编译

```bash
make                    # 编译内核模块 + Go 守护进程 + React 前端
make kernel-module      # 仅内核模块
make daemon             # 仅 Go 守护进程：先 npm run build:only（产出去面板）再 go build
make frontend           # 仅前端 (npm ci + vite build)，产物写入 src/daemon/web_ui/static/
make build-quick        # 快速编译（跳过格式检查）
make clean              # 清理
```

### 安装

```bash
# 方式一：一键安装（自动构建 + 验证）
sudo env "PATH=$PATH" make install

# 方式二：先构建后安装
make build
sudo env "PATH=$PATH" make install

# 卸载
sudo make uninstall
```

> 💡 **提示**：`make install` 会自动构建、安装、验证，并启动 systemd 服务。使用
> `sudo env "PATH=$PATH"` 确保 Go（Go 1.23+）与 GCC 都在 PATH 中。

### 加载模块（手动方式）

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
cat /proc/firewall/config
sudo rmmod firewall
```

### 基本操作

```bash
# 封禁（默认 / 自定义时长 / 永久）
echo "1.2.3.4"       | sudo tee /proc/firewall/bans
echo "1.2.3.4 3600"  | sudo tee /proc/firewall/bans
echo "1.2.3.4 0"     | sudo tee /proc/firewall/bans

# 解封 / 白名单
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
echo "10.0.0.0/8"    | sudo tee /proc/firewall/whitelist
```

### 启动守护进程

```bash
sudo ./build/daemon/firewall-daemon                         # 默认配置
sudo ./build/daemon/firewall-daemon -c config/default.yaml  # 指定配置
sudo ./build/daemon/firewall-daemon --help                  # 帮助
```

### 构建 .deb 包

```bash
make deb                 # 调用 ./build-deb.sh
                         # 产物: build/deb/linux-firewall-kmod-2.2.0.deb
sudo dpkg -i build/deb/linux-firewall-kmod-2.2.0.deb  # 安装（DKMS 自动编译 + systemd 启动）
```

> 📖 文档: [中文](docs/zh/) | [在线浏览](https://snowcore8.github.io/linux-firewall-kmod/)

## 📚 文档导航

完整文档请通过侧边栏浏览，章节速查：

- [快速开始](docs/zh/getting-started/README.md) - 安装、编译、首次使用
- [配置指南](docs/zh/configuration/README.md) - YAML Jail 格式、参数详解
- [架构设计](docs/zh/architecture/README.md) - 内核模块与守护进程设计
- [运维手册](docs/zh/operations/README.md) - 管理命令、监控
  - [故障排查](docs/zh/operations/troubleshooting.md)
- [开发指南](docs/zh/development/README.md) - 构建、贡献流程
  - [测试](docs/zh/development/testing.md)
- [迁移指南](docs/zh/migration/from-fail2ban.md) - 从 fail2ban 迁移
- [CHANGELOG.md](CHANGELOG.md) - v1.0 至 v2.2 变更记录

## 适用场景

| ✅ 适合 | ❌ 不推荐 |
|---------|-----------|
| 个人 VPS 防护 | 生产环境 DDoS 防护 |
| 开发/测试环境 | 需要审计合规的场景 |
| 小规模 SSH 暴力破解防护 | 大规模分布式部署 |

## 许可证与贡献

- **许可证**: [MIT License](LICENSE)
- **贡献**: [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues) | [PRs](https://github.com/SnowCore8/linux-firewall-kmod/pulls)
- **作者**: [SnowCore8](https://github.com/SnowCore8) — 使用 [Code CLI](https://github.com/github/code-cli) 辅助开发
