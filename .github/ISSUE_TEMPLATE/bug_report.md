---
name: "Bug 报告"
about: "报告一个可复现的问题"
title: "[BUG] "
labels: bug
assignees: ""
---

## 一句话现象

<!-- 说清哪里坏了。例：解封后这个 IP 还在丢包。 -->

## 严重程度

按 `STANDARDS.md` 的定级选一项。

- [ ] Critical：崩溃、封禁失效、日志解析完全错误
- [ ] High：功能异常但有绕过办法，或性能掉得明显
- [ ] Medium：影响局部功能，暂时无害
- [ ] Low：表述、样式、命名

## 环境

| 项 | 值 |
|----|-----|
| 发行版 | 例：Ubuntu 24.04 |
| 内核 | `uname -r` 的输出 |
| 架构 | `uname -m` 的输出 |
| 本项目版本 | `git describe --tags` 的输出 |
| 内核模块版本 | `sudo cat /sys/module/firewall/version` |
| 模块是否已加载 | `sudo lsmod` 的输出里有没有 `firewall` |

## 版本确认

- [ ] 用的是最新版或 main 分支最新提交
- [ ] 搜过现有 Issue，没有重复

## 复现步骤

写最小步骤。每步能照做。

1. 编模块与守护进程：`make build-quick`
2. 加载模块，带上自定义参数（没有就删掉方括号）：
   ```bash
   sudo insmod build/kernel-module/firewall.ko [参数=值]
   ```
3. 起守护进程：
   ```bash
   sudo ./build/daemon/firewall-daemon -c config/default.yaml
   ```
4. 具体操作：<!-- 例：从另一台机器对 22 端口做 10 次失败登录 -->
5. 观察到的现象：<!-- 例：30 秒后 /proc/firewall/bans 仍没有这个 IP -->

## 最小复现配置

贴一份能复现问题的 YAML。删掉无关 jail。

```yaml
defaults:
  # ...
jails:
  # ...
```

## 模块参数

加载时传了参数就列出来。没传就留空。

| 参数名 | 值 |
|--------|-----|
| 例：fw_ban_time | 600 |

当前实际值：`sudo cat /sys/module/firewall/parameters/*`

## 预期行为

<!-- 你本来看到什么。 -->

## 实际行为

<!-- 真正看到什么。有截图或原始输出就附上。 -->

## 日志

按顺序贴，缺哪条说明为什么缺。

<details>
<summary>收集命令</summary>

```bash
# 1. 内核侧
dmesg -T | grep -i firewall | tail -n 100

# 2. 守护进程侧（用 systemd 时）
sudo journalctl -u firewall-daemon -n 200 --no-pager

# 3. 内核统计，13 个计数器
sudo cat /proc/firewall/stats

# 4. 当前封禁列表
sudo cat /proc/firewall/bans

# 5. 当前白名单
sudo cat /proc/firewall/whitelist

# 6. 运行时配置与条目计数
sudo cat /proc/firewall/config
```

</details>

```text
# 粘贴输出。太长就用附件或 Gist。
```

## 其他信息

- 必现还是偶现？概率大概多少？
- 什么时候开始的？改过什么？
- 装过别的封禁类软件或自定义 iptables、nftables 规则吗？
- 回退到旧版本还复现吗？
