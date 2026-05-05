---
name: "🐛 Bug 报告"
about: "报告一个 bug 帮助我们改进"
title: "[BUG] "
labels: bug
assignees: ""
---

## Bug 描述

<!-- 清晰简洁地描述 bug 是什么 -->

## 复现步骤

<!-- 如何复现此 bug -->

1. 加载内核模块 `sudo insmod build/kernel-module/firewall.ko`
2. 启动守护进程 `sudo ./build/daemon/firewall-daemon -c config/default.yaml`
3. 执行操作 '...'
4. 看到错误

## 预期行为

<!-- 清晰简洁地描述你期望发生的事情 -->

## 实际行为

<!-- 描述实际发生的事情 -->

## 环境信息

- **操作系统**: [e.g. Ubuntu 22.04, CentOS 8]
- **内核版本**: [e.g. 5.15.0-91-generic]
- **Firewall 版本**: [e.g. v2.0]
- **GCC 版本**: [e.g. gcc 11.4.0]

## 日志输出

<!-- 如果适用，添加相关日志输出 -->

```bash
# 内核日志
dmesg | grep firewall

# 守护进程日志
sudo journalctl -u firewall-daemon -n 50
```

## 配置文件

<!-- 如果适用，添加相关配置 -->

```yaml
# 你的 firewall 配置
```

## 其他信息

<!-- 添加任何其他有助于解决问题的信息 -->
