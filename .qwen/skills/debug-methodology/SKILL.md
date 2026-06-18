---
name: debug-methodology
description: 系统化的 bug 排查方法论，包含通用调试流程和防火墙项目专项排查指南。当遇到网络不通、服务异常、性能问题或需要诊断复杂问题时使用。
---

# Debug 方法论

## 核心原则

1. **假设驱动**：每次修改必须有假设支撑，验证假设后再修复
2. **数据驱动**：用证据说话，禁止猜测
3. **最小变更**：一次只改一个变量，便于归因
4. **可复现**：修复后必须写复现测试，防止回归

## 五步法

```
复现 → 定位 → 修复 → 验证 → 记录
```

### 1. 复现

- 明确现象：什么操作触发了问题？
- 收集证据：日志、错误信息、系统状态
- 建立基线：正常状态是什么样的？

### 2. 定位

- **二分排查**：逐步缩小范围（git bisect / 注释一半代码 / 断点逐行）
- **结构化调试**：日志/断点优先于 print
- **检查常见嫌疑点**：见下方"防火墙项目专项排查"

### 3. 修复

- 一次只修一个问题
- 修复必须有明确的因果链
- 禁止"碰运气"式修改

### 4. 验证

- 运行相关测试套件
- 确认修复未引入新问题
- 性能敏感场景需基准测试

### 5. 记录

- 记录排查过程：现象 → 假设 → 验证 → 根因 → 修复
- 更新文档或添加注释说明"为什么"

## 防火墙项目专项排查

### 网络不通

**第一反应：检查防火墙状态，不要假设服务崩溃**

```bash
# 1. 确认网络层是否通
ping <目标IP>

# 2. 检查防火墙封禁表
cat /proc/firewall/bans

# 3. 检查白名单
cat /proc/firewall/whitelist

# 4. 检查统计信息（看 dropped 计数）
cat /proc/firewall/stats

# 5. 检查内核日志
dmesg | grep firewall

# 6. 检查守护进程日志
journalctl -u firewall-daemon -n 50
```

**常见原因**：
- 分片包被丢弃（MTU 问题）
- DDoS 速率检测误封正常流量
- 白名单未包含关键 IP（网关、API 服务器）
- 日志解析器批量封禁历史攻击 IP

### 虚拟机不可达

**用短封禁时间区分是封禁还是内核 panic**

```bash
# 先用短 ban_time 部署
sudo insmod build/kernel-module/firewall.ko fw_ban_time=30

# 观察：
# - 30 秒后网络恢复 → 是封禁问题
# - 30 秒后仍不可达 → 可能是内核 panic
```

### 性能问题

```bash
# 1. 检查 per-CPU 统计
cat /proc/firewall/stats

# 2. 检查速率检测表大小
cat /proc/firewall/stats | grep rate_count

# 3. 检查封禁表大小
cat /proc/firewall/stats | grep ban_count

# 4. 使用 perf 分析热点
sudo perf record -g -p <守护进程PID>
sudo perf report
```

### 守护进程崩溃

```bash
# 1. 检查 systemd 日志
journalctl -u firewall-daemon -n 100 --no-pager

# 2. 检查 core dump
ls -lh /var/lib/systemd/coredump/

# 3. 用 gdb 分析 core
gdb /usr/local/sbin/firewall-daemon <core-file>
(gdb) bt

# 4. 检查 procfs 接口权限
ls -l /proc/firewall/
```

## 调试工具速查

| 场景 | 工具 | 命令 |
|------|------|------|
| 内核模块日志 | dmesg | `dmesg \| grep firewall` |
| 守护进程日志 | journalctl | `journalctl -u firewall-daemon -f` |
| 封禁表状态 | procfs | `cat /proc/firewall/bans` |
| 白名单状态 | procfs | `cat /proc/firewall/whitelist` |
| 统计信息 | procfs | `cat /proc/firewall/stats` |
| 网络抓包 | tcpdump | `tcpdump -i any host <IP>` |
| 系统调用追踪 | strace | `strace -p <PID>` |
| 性能分析 | perf | `perf record -g -p <PID>` |
| 内存泄漏 | kmemleak | `echo scan > /sys/kernel/debug/kmemleak` |

## 反模式

- ❌ 盲目改代码碰运气
- ❌ 同时修改多个变量
- ❌ 忽视日志直接猜测
- ❌ 修复后不写复现测试
- ❌ 假设服务崩溃而不检查防火墙
