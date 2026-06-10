# Operations

This section covers daily operations for the Linux Firewall Kernel Module.

## Operations Overview

### Daily Checklist

| Check Item | Frequency | Command |
|------------|-----------|---------|
| Service status | Daily | `systemctl status firewall` |
| Ban count | Daily | `cat /proc/firewall/stats` |
| Log size | Weekly | `ls -lh /var/log/firewall.log` |
| Database size | Weekly | `ls -lh /var/lib/firewall/bans.db` |
| Disk space | Weekly | `df -h /var` |

### Key Metric Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Banned IPs | > 1000 | > 3000 |
| Hash table usage | > 50% | > 80% |
| Log file size | > 100MB | > 500MB |
| Database size | > 50MB | > 200MB |

### Automated Health Check Script

```bash
#!/bin/bash
# firewall-health-check.sh

echo "=== firewall Health Check ==="
echo ""

# Check service status
if systemctl is-active --quiet firewall; then
    echo "[OK] Service is running"
else
    echo "[FAIL] Service is not running"
    exit 1
fi

# Check ban count
banned=$(cat /proc/firewall/stats | grep "Current banned" | awk '{print $NF}')
echo "Banned IPs: $banned"
if [ "$banned" -gt 3000 ]; then
    echo "[WARN] High number of banned IPs!"
fi

# Check disk space
log_size=$(du -m /var/log/firewall.log | cut -f1)
echo "Log size: ${log_size}MB"
if [ "$log_size" -gt 500 ]; then
    echo "[WARN] Log file is too large!"
fi

echo ""
echo "=== Check Complete ==="
```