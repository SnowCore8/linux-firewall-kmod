#!/bin/bash
# deploy.sh - 部署防火墙到远程服务器（远程编译）
# 用法: ./deploy.sh <远程主机> [远程用户]

if [[ -z "$1" ]]; then
    echo "用法：./deploy.sh <远程主机> [远程用户]"
    echo "  remote_host: 目标服务器 IP 或主机名（必需）"
    echo "  remote_user: SSH 用户（默认：root）"
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
    echo "部署已取消。"
    exit 0
fi

# 回滚函数（在部署失败时清理所有更改）
rollback() {
    echo "⚠️  检测到部署失败，正在回滚..."
    ssh "$REMOTE_USER@$REMOTE_HOST" << 'ROLLBACK_SCRIPT'
    rmmod firewall 2>/dev/null || true
    systemctl stop firewall-daemon 2>/dev/null || true
    systemctl disable firewall-daemon 2>/dev/null || true
    rm -f /etc/systemd/system/firewall-daemon.service
    systemctl daemon-reload 2>/dev/null || true
    rm -f /tmp/firewall-src.tar.gz
    ROLLBACK_SCRIPT
    echo "✅ 回滚完成"
    exit 1
}
trap 'rollback' EXIT INT TERM

# 1. 检查远程服务器依赖
echo ""
echo "[1/7] Checking remote server dependencies..."
ssh -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    "$REMOTE_USER@$REMOTE_HOST" << 'EOF'
# 检测远程服务器的包管理器
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
        echo "   安装命令：apt install linux-headers-$(uname -r)"
    else
        echo "   安装命令：$PKG_MANAGER install kernel-devel-$(uname -r)"
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
    dpkg -l | grep $SQLITE_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $SQLITE_PKG"; exit 1; }
else
    rpm -q $SQLITE_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $SQLITE_PKG"; exit 1; }
fi
echo "  检查 $MHD_PKG..."
if [ "$PKG_MANAGER" = "apt" ]; then
    dpkg -l | grep $MHD_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $MHD_PKG"; exit 1; }
else
    rpm -q $MHD_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $MHD_PKG"; exit 1; }
fi
echo "  检查 $PCRE2_PKG..."
if [ "$PKG_MANAGER" = "apt" ]; then
    dpkg -l | grep $PCRE2_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $PCRE2_PKG"; exit 1; }
else
    rpm -q $PCRE2_PKG >/dev/null 2>&1 || { echo "❌ 缺少 $PCRE2_PKG"; exit 1; }
fi

echo "  检查 curl（用于监控指标）..."
which curl >/dev/null 2>&1 || { echo "❌ 缺少 curl"; exit 1; }
echo "  ✅ curl 已安装"

echo "✅ 依赖检查通过"
EOF

if [[ $? -ne 0 ]]; then
    echo "❌ 依赖检查失败"
    exit 1
fi

# 2. 打包源代码（排除构建目录）
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
echo "✅ 打包完成"

# 生成 MD5 校验文件
echo ""
echo "  生成 MD5 校验文件..."
cd "$PROJECT_DIR"
md5sum firewall-src.tar.gz > firewall-src.tar.gz.md5
echo "✅ MD5 文件生成完成"

# 3. 上传到远程服务器
echo ""
echo "[3/7] Uploading to remote server..."
scp /tmp/firewall-src.tar.gz "$REMOTE_USER@$REMOTE_HOST":/tmp/
if [[ $? -ne 0 ]]; then
    echo "❌ Upload failed"
    exit 1
fi
echo "✅ 上传完成"

# 验证上传文件完整性
echo "  验证上传文件完整性..."
ssh "$REMOTE_USER@$REMOTE_HOST" << 'VERIFY_SCRIPT'
cd /tmp
md5sum -c firewall-src.tar.gz.md5 >/dev/null 2>&1 || {
    echo "❌ 上传文件验证失败"
    exit 1
}
VERIFY_SCRIPT
if [[ $? -ne 0 ]]; then
    echo "❌ 文件完整性验证失败"
    exit 1
fi

# 4. 远程编译和安装
echo ""
echo "[4/7] Remote compilation and installation..."
ssh -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    "$REMOTE_USER@$REMOTE_HOST" << 'REMOTE_SCRIPT'
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
make
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
echo "  Prometheus: $(curl -s http://localhost:9119/metrics 2>/dev/null | head -3 || echo '无法访问')"

# 清理
rm -f /tmp/firewall-src.tar.gz
echo "✅ 清理完成"

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
