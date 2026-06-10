# 运维管理

本章节介绍 Linux Firewall 内核模块的日常运维操作。

## 运维概览

### 日常检查清单

| 检查项 | 频率 | 命令 |
|--------|------|------|
| 服务状态 | 每日 | `systemctl status firewall` |
| 封禁数量 | 每日 | `cat /proc/firewall/stats` |
| 日志大小 | 每周 | `ls -lh /var/log/firewall.log` |
| 数据库大小 | 每周 | `ls -lh /var/lib/firewall/bans.db` |
| 磁盘空间 | 每周 | `df -h /var` |

### 关键指标阈值

| 指标 | 警告阈值 | 严重阈值 |
|------|----------|----------|
| 封禁 IP 数 | > 1000 | > 3000 |
| 哈希表使用率 | > 50% | > 80% |
| 日志文件大小 | > 100MB | > 500MB |
| 数据库大小 | > 50MB | > 200MB |

### 自动化运维脚本

```bash
#!/bin/bash
# firewall-health-check.sh

echo "=== firewall Health Check ==="
echo ""

# 检查服务状态
if systemctl is-active --quiet firewall; then
    echo "[OK] Service is running"
else
    echo "[FAIL] Service is not running"
    exit 1
fi

# 检查封禁数量
banned=$(cat /proc/firewall/stats | grep "Current banned" | awk '{print $NF}')
echo "Banned IPs: $banned"
if [ "$banned" -gt 3000 ]; then
    echo "[WARN] High number of banned IPs!"
fi

# 检查磁盘空间
log_size=$(du -m /var/log/firewall.log | cut -f1)
echo "Log size: ${log_size}MB"
if [ "$log_size" -gt 500 ]; then
    echo "[WARN] Log file is too large!"
fi

echo ""
echo "=== Check Complete ==="
```