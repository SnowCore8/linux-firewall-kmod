#!/bin/bash
# deploy.sh - Deploy firewall to remote server (with remote compilation)
# Usage: ./deploy.sh <remote_host> [remote_user]

if [[ -z "$1" ]]; then
    echo "Usage: ./deploy.sh <remote_host> [remote_user]"
    echo "  remote_host: Target server IP or hostname (required)"
    echo "  remote_user: SSH user (default: root)"
    exit 1
fi

REMOTE_HOST="$1"
REMOTE_USER="${2:-root}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "========================================="
echo "Firewall Deployment Script"
echo "Target server: $REMOTE_USER@$REMOTE_HOST"
echo "========================================="

read -p "Confirm deployment to $REMOTE_HOST? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Deployment cancelled."
    exit 0
fi

# 1. Check remote server dependencies
echo ""
echo "[1/7] Checking remote server dependencies..."
ssh -o StrictHostKeyChecking=accept-new "$REMOTE_USER@$REMOTE_HOST" << 'EOF'
# Detect package manager
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    YAML_PKG="libyaml-dev"
    SQLITE_PKG="libsqlite3-dev"
    MHD_PKG="libmicrohttpd-dev"
    PCRE2_PKG="libpcre2-dev"
    KERNEL_HEADERS_PKG="linux-headers-$(uname -r)"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    YAML_PKG="libyaml-devel"
    SQLITE_PKG="sqlite-devel"
    MHD_PKG="libmicrohttpd-devel"
    PCRE2_PKG="pcre2-devel"
    KERNEL_HEADERS_PKG="kernel-devel-$(uname -r)"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    YAML_PKG="libyaml-devel"
    SQLITE_PKG="sqlite-devel"
    MHD_PKG="libmicrohttpd-devel"
    PCRE2_PKG="pcre2-devel"
    KERNEL_HEADERS_PKG="kernel-devel-$(uname -r)"
else
    echo "❌ Unsupported package manager"
    exit 1
fi

echo "  检测到包管理器: $PKG_MANAGER"

echo "  检查 gcc..."
which gcc >/dev/null 2>&1 || { echo "❌ 缺少 gcc"; exit 1; }
echo "  检查 make..."
which make >/dev/null 2>&1 || { echo "❌ 缺少 make"; exit 1; }
echo "  检查内核头文件..."
ls /lib/modules/$(uname -r)/build/Makefile >/dev/null 2>&1 || {
    echo "❌ 缺少内核头文件"
    if [ "$PKG_MANAGER" = "apt" ]; then
        echo "   安装命令: apt install linux-headers-$(uname -r)"
    else
        echo "   安装命令: $PKG_MANAGER install kernel-devel-$(uname -r)"
    fi
    exit 1;
}
echo "  检查 $YAML_PKG..."
if [ "$PKG_MANAGER" = "apt" ]; then
    dpkg -l | grep $YAML_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $YAML_PKG"; exit 1; }
else
    rpm -q $YAML_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $YAML_PKG"; exit 1; }
fi
echo "  检查 $SQLITE_PKG..."
if [ "$PKG_MANAGER" = "apt" ]; then
    dpkg -l | grep $SQLITE_PKG >/dev/null 2>&1 || { echo "❌ Missing $SQLITE_PKG"; exit 1; }
else
    rpm -q $SQLITE_PKG >/dev/null 2>&1 || { echo "❌ Missing $SQLITE_PKG"; exit 1; }
fi
echo "  检查 $MHD_PKG..."
if [ "$PKG_MANAGER" = "apt" ]; then
    dpkg -l | grep $MHD_PKG >/dev/null 2>&1 || { echo "❌ Missing $MHD_PKG"; exit 1; }
else
    rpm -q $MHD_PKG >/dev/null 2>&1 || { echo "❌ Missing $MHD_PKG"; exit 1; }
fi
echo "  检查 $PCRE2_PKG..."
if [ "$PKG_MANAGER" = "apt" ]; then
    dpkg -l | grep $PCRE2_PKG >/dev/null 2>&1 || { echo "❌ Missing $PCRE2_PKG"; exit 1; }
else
    rpm -q $PCRE2_PKG >/dev/null 2>&1 || { echo "❌ Missing $PCRE2_PKG"; exit 1; }
fi
echo "✅ Dependencies check passed"
EOF

if [[ $? -ne 0 ]]; then
    echo "❌ 依赖检查失败"
    exit 1
fi

# 2. Package source code (excluding build directory)
echo ""
echo "[2/7] Packaging source code..."
cd "$PROJECT_DIR"
tar czf /tmp/firewall-src.tar.gz \
    src/ \
    config/ \
    tests/ \
    Makefile \
    firewall-daemon.service \
    scripts/
echo "✅ Packaging complete"

# 3. Upload to remote server
echo ""
echo "[3/7] Uploading to remote server..."
scp /tmp/firewall-src.tar.gz "$REMOTE_USER@$REMOTE_HOST":/tmp/
if [[ $? -ne 0 ]]; then
    echo "❌ Upload failed"
    exit 1
fi
echo "✅ Upload complete"

# 4. Remote compilation and installation
echo ""
echo "[4/7] Remote compilation and installation..."
ssh -o StrictHostKeyChecking=accept-new "$REMOTE_USER@$REMOTE_HOST" << 'REMOTE_SCRIPT'
set -e

echo "  [4.1] Extracting source..."
REMOTE_WORK_DIR=$(mktemp -d)
cd "$REMOTE_WORK_DIR"
tar xzf /tmp/firewall-src.tar.gz

echo "  [4.2] Creating required directories..."
mkdir -p /var/log/frp
mkdir -p /var/lib/firewall

echo "  [4.3] Compiling project..."
make clean
make all-with-daemon
if [[ $? -ne 0 ]]; then
    echo "  ❌ Compilation failed"
    exit 1
fi
echo "  ✅ Compilation successful"

echo "  [4.4] Installing to system..."
make install

echo "  [4.5] Loading kernel module..."
rmmod firewall 2>/dev/null || true
sleep 1
modprobe firewall 2>/dev/null || insmod /lib/modules/$(uname -r)/extra/firewall.ko fw_ban_time=600
echo "  ✅ Kernel module loaded"
lsmod | grep firewall

echo "  [4.6] Configuring daemon..."
pkill -9 firewall-daemon 2>/dev/null || true
sleep 1
systemctl daemon-reload
systemctl enable firewall-daemon
systemctl start firewall-daemon
sleep 3
echo "  ✅ 守护进程已启动"
systemctl status firewall-daemon --no-pager | head -12

echo "  [4.7] 验证部署..."
echo "  内核版本: $(uname -r)"
echo "  内核模块: $(lsmod | grep firewall | awk '{print $1, $2, $3}')"
echo "  守护进程: $(ps aux | grep firewall-daemon | grep -v grep | wc -l) 个实例"
echo "  PID file: $(cat /run/firewall-daemon.pid 2>/dev/null || echo 'not found')"
echo "  封禁统计: $(cat /proc/firewall/stats | grep -E 'current_bans|current_whitelist')"
echo "  Prometheus: $(curl -s http://localhost:9119/metrics 2>/dev/null | head -3 || echo '不可用')"

# 清理
rm -f /tmp/firewall-src.tar.gz

echo ""
echo "✅ 远程安装完成"
REMOTE_SCRIPT

if [[ $? -ne 0 ]]; then
    echo "❌ 远程安装失败"
    exit 1
fi

# 5. Verify remote service
echo ""
echo "[5/7] Verifying remote service..."
ssh -o StrictHostKeyChecking=accept-new "$REMOTE_USER@$REMOTE_HOST" "curl -s http://localhost:9119/metrics | head -10"
if [[ $? -eq 0 ]]; then
    echo "✅ Prometheus 指标导出正常"
else
    echo "⚠️  Prometheus 指标导出异常"
fi

# 6. Test SSH Jail
echo ""
echo "[6/7] Testing SSH Jail..."
ssh -o StrictHostKeyChecking=accept-new "$REMOTE_USER@$REMOTE_HOST" << 'EOF'
TEST_IP="203.0.113.99"
    echo "  模拟 6 次 SSH 失败登录..."
    for i in $(seq 1 6); do
        echo "$(date '+%b %d %H:%M:%S') server sshd[$$]: Failed password for root from $TEST_IP port 12345 ssh2" | sudo tee -a /var/log/auth.log > /dev/null
    done
    sleep 5

    if cat /proc/firewall/bans | grep -q "$TEST_IP"; then
        echo "  ✅ SSH Jail working: $TEST_IP has been banned"
    else
        echo "  ⚠️  SSH Jail did not trigger"
    fi

    # Clean up test IP
    echo "unban $TEST_IP" | sudo tee /proc/firewall/bans >/dev/null 2>&1
EOF

# 7. Clean up local temporary files
echo ""
echo "[7/7] Cleaning up local temporary files..."
rm -f /tmp/firewall-src.tar.gz
echo "✅ Cleanup complete"

echo ""
echo "========================================="
echo "🎉 Deployment complete!"
echo "========================================="
echo ""
echo "Remote management commands:"
echo "  Status: ssh $REMOTE_USER@$REMOTE_HOST 'systemctl status firewall-daemon'"
echo "  Logs:   ssh $REMOTE_USER@$REMOTE_HOST 'journalctl -u firewall-daemon -f'"
echo "  Bans:   ssh $REMOTE_USER@$REMOTE_HOST 'cat /proc/firewall/bans'"
echo "  Reload: ssh $REMOTE_USER@$REMOTE_HOST 'systemctl reload firewall-daemon'"
echo "  Metrics: ssh $REMOTE_USER@$REMOTE_HOST 'curl http://localhost:9119/metrics'"
echo ""
