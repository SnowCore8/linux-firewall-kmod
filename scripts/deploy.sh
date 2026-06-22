#!/bin/bash
# deploy.sh - 部署防火墙到远程服务器（本地预编译 + 产物上传）
# 用法: ./deploy.sh <远程主机> [远程用户]
#
# 与旧版区别: 不再传源码到远端编译, 而是本地编译后仅上传二进制产物。
# 远端不再需要 gcc / make / Rust / 内核头, 只需 systemd + curl。

set -euo pipefail

if [[ -z "${1:-}" ]]; then
    echo "用法：./deploy.sh <远程主机> [远程用户]"
    echo "  remote_host: 目标服务器 IP 或主机名（必需）"
    echo "  remote_user: SSH 用户（默认：root）"
    exit 1
fi

REMOTE_HOST="$1"
REMOTE_USER="${2:-root}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=~/.ssh/known_hosts -o IdentitiesOnly=yes"

echo "========================================="
echo "Firewall Deployment Script (local-build mode)"
echo "Target server: $REMOTE_USER@$REMOTE_HOST"
echo "========================================="

read -rp "Confirm deployment to $REMOTE_HOST? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "部署已取消。"
    exit 0
fi

# ----------------------------------------------------------------------------
# 回滚函数（在部署失败时清理所有更改）
# ----------------------------------------------------------------------------
rollback() {
    echo "⚠️  检测到部署失败，正在回滚..."
    ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" << 'ROLLBACK_SCRIPT'
rmmod firewall 2>/dev/null || true
systemctl stop firewall-daemon 2>/dev/null || true
systemctl disable firewall-daemon 2>/dev/null || true
rm -f /etc/systemd/system/firewall-daemon.service
systemctl daemon-reload 2>/dev/null || true
rm -rf /tmp/firewall-deploy.*
ROLLBACK_SCRIPT
    echo "✅ 回滚完成"
    exit 1
}
trap 'rollback' ERR INT TERM

# ----------------------------------------------------------------------------
# 0. 本地构建产物检查
# ----------------------------------------------------------------------------
echo ""
echo "[0/5] 检查本地构建产物..."
KERNEL_MODULE="$PROJECT_DIR/build/kernel-module/firewall.ko"
DAEMON_BIN="$PROJECT_DIR/build/daemon/firewall-daemon"

if [[ ! -f "$KERNEL_MODULE" ]]; then
    echo "  ✗ 内核模块不存在: $KERNEL_MODULE"
    echo "  → 请先运行 'make kernel-module'"
    exit 1
fi
if [[ ! -x "$DAEMON_BIN" ]]; then
    echo "  ✗ 守护进程二进制不存在或不可执行: $DAEMON_BIN"
    echo "  → 请先运行 'make daemon'"
    exit 1
fi
echo "  ✓ 内核模块: $KERNEL_MODULE ($(du -h "$KERNEL_MODULE" | cut -f1))"
echo "  ✓ 守护进程: $DAEMON_BIN ($(du -h "$DAEMON_BIN" | cut -f1))"

# ----------------------------------------------------------------------------
# 1. 内核版本对齐 + 远端最小依赖
# ----------------------------------------------------------------------------
echo ""
echo "[1/5] 检查远端环境..."

LOCAL_KERNEL=$(uname -r)
REMOTE_KERNEL=$(ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" 'uname -r')

echo "  本地内核: $LOCAL_KERNEL"
echo "  远端内核: $REMOTE_KERNEL"

if [[ "$LOCAL_KERNEL" != "$REMOTE_KERNEL" ]]; then
    echo ""
    echo "❌ 内核版本不匹配 —— 无法部署预编译的内核模块"
    echo "   内核模块 (.ko) 包含 vermagic 校验, 跨内核版本加载会被拒绝。"
    echo "   解决方案 (任选其一):"
    echo "     1) 在远端安装与本机一致的内核并重启"
    echo "     2) 在本机用目标内核重新编译 (设置 KDIR / 切内核)"
    echo "     3) 改用 build-deb.sh 在远端本地编译 (DKMS 模式)"
    exit 1
fi
echo "  ✓ 内核版本一致"

# 远端最小依赖 (只需 systemd + curl)
ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" << 'EOF'
set -e
echo "  检查 systemd..."
command -v systemctl >/dev/null 2>&1 || { echo "❌ 缺少 systemd"; exit 1; }
echo "  检查 curl..."
command -v curl >/dev/null 2>&1 || { echo "❌ 缺少 curl"; exit 1; }
echo "  ✓ 远端最小依赖就绪"
EOF

# ----------------------------------------------------------------------------
# 2. 打包产物 (仅二进制 + 配置 + systemd 单元)
# ----------------------------------------------------------------------------
echo ""
echo "[2/5] 打包部署产物..."
STAGE_DIR=$(mktemp -d /tmp/firewall-deploy-stage.XXXXX)
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$STAGE_DIR/root"
cp "$KERNEL_MODULE" "$STAGE_DIR/root/firewall.ko"
cp "$DAEMON_BIN"    "$STAGE_DIR/root/firewall-daemon"
chmod 755 "$STAGE_DIR/root/firewall-daemon"

# systemd 单元需要替换 __SBINDIR__ 占位符
SBINDIR="/usr/local/sbin"
sed "s|__SBINDIR__|$SBINDIR|g" "$PROJECT_DIR/firewall-daemon.service" \
    > "$STAGE_DIR/root/firewall-daemon.service"

# 配置 + 模块自动加载配置
mkdir -p "$STAGE_DIR/config"
cp "$PROJECT_DIR"/config/*.yaml "$STAGE_DIR/config/"
mkdir -p "$STAGE_DIR/modules-load"
cp "$PROJECT_DIR/config/modules-load.d/firewall.conf" "$STAGE_DIR/modules-load/" 2>/dev/null \
    || echo "# firewall kernel module autoload" > "$STAGE_DIR/modules-load/firewall.conf"

# 打包
tar -C "$STAGE_DIR" -czf /tmp/firewall-deploy.tar.gz .
echo "  ✓ 打包完成: $(du -h /tmp/firewall-deploy.tar.gz | cut -f1)"

# ----------------------------------------------------------------------------
# 3. 上传
# ----------------------------------------------------------------------------
echo ""
echo "[3/5] 上传到远端..."
scp /tmp/firewall-deploy.tar.gz "$REMOTE_USER@$REMOTE_HOST":/tmp/
echo "  ✓ 上传完成"

# ----------------------------------------------------------------------------
# 4. 远端安装
# ----------------------------------------------------------------------------
echo ""
echo "[4/5] 远端安装..."
ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" sudo bash << 'REMOTE_SCRIPT'
set -euo pipefail

WORK_DIR=$(mktemp -d /tmp/firewall-deploy.XXXXX)
cd "$WORK_DIR"
tar xzf /tmp/firewall-deploy.tar.gz

echo "  [4.1] 安装内核模块..."
install -D -m 644 root/firewall.ko \
    "/lib/modules/$(uname -r)/extra/firewall.ko"
depmod -a

echo "  [4.2] 安装守护进程..."
install -D -m 755 root/firewall-daemon /usr/local/sbin/firewall-daemon

echo "  [4.3] 安装配置..."
install -d -m 700 /etc/firewall
install -m 600 config/*.yaml /etc/firewall/
chown -R root:root /etc/firewall

echo "  [4.4] 创建状态目录..."
install -d -m 700 /var/lib/firewall
install -d -m 755 /var/log/frp
chown root:root /var/lib/firewall /var/log/frp

echo "  [4.5] 安装 systemd 单元..."
install -D -m 644 root/firewall-daemon.service \
    /etc/systemd/system/firewall-daemon.service
if [ -f modules-load/firewall.conf ]; then
    install -D -m 644 modules-load/firewall.conf \
        /etc/modules-load.d/firewall.conf
fi
systemctl daemon-reload

echo "  [4.6] 加载内核模块..."
rmmod firewall 2>/dev/null || true
sleep 1
modprobe firewall 2>/dev/null \
    || insmod "/lib/modules/$(uname -r)/extra/firewall.ko" fw_ban_time=600
lsmod | grep firewall || { echo "❌ 内核模块加载失败"; exit 1; }

echo "  [4.7] 启动守护进程..."
pkill -9 firewall-daemon 2>/dev/null || true
sleep 1
systemctl enable firewall-daemon
systemctl restart firewall-daemon
sleep 3

if systemctl is-active --quiet firewall-daemon; then
    echo "  ✓ 守护进程已启动"
else
    echo "  ✗ 守护进程启动失败"
    systemctl status firewall-daemon --no-pager | head -20
    journalctl -u firewall-daemon -n 30 --no-pager
    exit 1
fi

# 清理
rm -f /tmp/firewall-deploy.tar.gz
rm -rf "$WORK_DIR"
REMOTE_SCRIPT

# ----------------------------------------------------------------------------
# 5. 验证
# ----------------------------------------------------------------------------
echo ""
echo "[5/5] 验证部署..."
ssh $SSH_OPTS "$REMOTE_USER@$REMOTE_HOST" bash << 'VERIFY_SCRIPT'
set -e
echo "  内核版本: $(uname -r)"
echo "  内核模块: $(lsmod | grep '^firewall ' || echo '未加载')"
echo "  守护进程: $(systemctl is-active firewall-daemon)"
echo "  封禁统计: $(cat /proc/firewall/stats 2>/dev/null | tr '\n' ' ' || echo 'N/A')"
echo "  Prometheus:"
curl -sf http://127.0.0.1:9119/metrics 2>/dev/null | head -3 || echo "  ✗ metrics 不可达"
VERIFY_SCRIPT

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
