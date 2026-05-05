---
name: "🐛 Bug 报告"
about: "报告一个 bug 帮助我们改进"
title: "[BUG] "
labels: bug
assignees: ""
---

## 紧急程度

<!-- 请选择此 Bug 的严重程度 -->

- [ ] **阻塞** - 系统完全不可用，无法启动或崩溃
- [ ] **严重** - 核心功能失效，但有临时绕过方案
- [ ] **一般** - 部分功能异常，不影响主要使用
- [ ] **轻微** - UI/体验问题或边界情况

## Bug 描述

<!-- 用一两句话清晰简洁地描述 bug 是什么 -->

## 环境信息

| 项目 | 值 |
|------|-----|
| **操作系统** | [e.g. Ubuntu 22.04, CentOS Stream 9] |
| **内核版本** | [e.g. 5.15.0-91-generic，运行 `uname -r` 获取] |
| **Firewall 版本** | [e.g. v2.0.1，运行 `git describe --tags` 获取] |
| **GCC 版本** | [e.g. gcc 11.4.0，运行 `gcc --version` 获取] |
| **硬件架构** | [e.g. x86_64, aarch64] |

## 版本确认

- [ ] 我已确认使用的是**最新版本**（或 main 分支最新提交）
- [ ] 我已搜索过现有 Issue，未找到相同问题

## 复现步骤

<!-- 请提供完整、可复现的操作步骤，尽量精简到最小步骤 -->

1. 加载内核模块（如有自定义参数请提供）：
   ```bash
   sudo insmod build/kernel-module/firewall.ko [参数=值]
   ```
2. 启动守护进程：
   ```bash
   sudo ./build/daemon/firewall-daemon -c config/default.yaml
   ```
3. [描述你的具体操作，例如：发送特定类型的网络请求]
4. [描述观察到的错误现象]

## 最小复现配置

<!-- 请提供能够复现此 bug 的最小配置文件，移除无关规则 -->

```yaml
# 最小可复现配置
rules:
  - name: example
    # ...
```

## 内核模块参数

<!-- 如果加载时传入了模块参数，请在此列出 -->

| 参数名 | 值 | 说明 |
|--------|-----|------|
| [e.g. debug] | [e.g. 1] | [e.g. 开启调试模式] |
| | | |

<!-- 可通过 `sudo cat /sys/module/firewall/parameters/*` 查看当前参数值 -->

## 预期行为

<!-- 清晰描述你期望发生的结果 -->

## 实际行为

<!-- 清晰描述实际发生的结果，如有错误截图或输出请附上 -->

## 日志输出

<!-- 请收集并提供以下日志，帮助定位问题 -->

<details>
<summary>日志收集命令（点击展开）</summary>

```bash
# 1. 内核环形缓冲区日志（最近 100 条 firewall 相关日志）
dmesg -T | grep -i firewall | tail -n 100

# 2. 守护进程日志（最近 200 条）
sudo journalctl -u firewall-daemon -n 200 --no-pager

# 3. 内核模块统计信息
sudo cat /proc/firewall/stats

# 4. 内核模块当前规则列表
sudo cat /proc/firewall/rules

# 5. 被 ban 的 IP 列表
sudo cat /proc/firewall/banned_ips
```

</details>

```
# 请粘贴上述命令的输出（如内容过长可使用 Gist 或附件）
```

## 配置文件

<!-- 提供完整的配置文件，或脱敏后的关键部分 -->

```yaml
# 你的 firewall 配置（注意脱敏，不要包含真实 IP 或密钥）
```

## 其他信息

<!-- 添加任何其他有助于解决问题的信息，例如：
- 网络拓扑或部署架构
- 触发频率（必现 / 偶现 / 特定条件下触发）
- 是否尝试过回退到旧版本
- 相关的系统配置（iptables/nftables 规则等）
-->
