#!/bin/bash
# deploy-deb.sh - 打包并部署 deb 到远程主机（DKMS 模式）
# 用法: ./deploy-deb.sh <远程主机> [远程用户]
#
# 与 deploy.sh 的区别：不预编译 .ko。deb 内含 DKMS 源码，在远端对目标内核编译，
# 因此本地内核与目标内核不一致（跨版本 / HWE）也能装。
#
# 环境变量:
#   SKIP_BUILD=1  跳过打包，直接部署 build/deb/ 下最新的 deb
#   CLEAN=1       打包前全量清理（见 build-deb.sh）

set -euo pipefail

if [[ -z "${1:-}" ]]; then
    echo "用法：./deploy-deb.sh <远程主机> [远程用户]"
    echo "  remote_host: 目标服务器 IP 或主机名（必需）"
    echo "  remote_user: SSH 用户（默认：root）"
    exit 1
fi

REMOTE_HOST="$1"
REMOTE_USER="${2:-root}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=~/.ssh/known_hosts -o IdentitiesOnly=yes)

echo "========================================="
echo "Firewall Deployment (deb/DKMS mode)"
echo "Target server: $REMOTE_USER@$REMOTE_HOST"
echo "========================================="

read -rp "Confirm deployment to $REMOTE_HOST? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "部署已取消。"
    exit 0
fi

find_deb() {
    find "$PROJECT_DIR/build/deb" -maxdepth 1 -name 'linux-firewall-kmod-*.deb' \
        -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true
}

# ----------------------------------------------------------------------------
# 1. 打包
# ----------------------------------------------------------------------------
DEB_FILE="$(find_deb)"
if [[ "${SKIP_BUILD:-0}" == "1" && -n "$DEB_FILE" ]]; then
    echo ""
    echo "[1/4] 跳过打包，使用现有 deb"
else
    echo ""
    echo "[1/4] 打包 deb..."
    (cd "$PROJECT_DIR" && ./build-deb.sh)
    DEB_FILE="$(find_deb)"
fi
if [[ -z "$DEB_FILE" || ! -f "$DEB_FILE" ]]; then
    echo "❌ 找不到 deb 产物（build/deb/linux-firewall-kmod-*.deb）"
    exit 1
fi
echo "  ✓ $(basename "$DEB_FILE") ($(du -h "$DEB_FILE" | cut -f1))"

# ----------------------------------------------------------------------------
# 2. 远端环境准备：清理脚本模式残留 + 安装 DKMS 依赖
# ----------------------------------------------------------------------------
echo ""
echo "[2/4] 准备远端环境..."
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" sudo bash <<'REMOTE_PREP'
set -euo pipefail
KVER=$(uname -r)

# 脚本模式（deploy.sh）残留会遮蔽包管理的单元与 DKMS 模块，先清掉
if [ -f /etc/systemd/system/firewall-daemon.service ] && \
   [ ! -L /etc/systemd/system/firewall-daemon.service ]; then
    echo "  清理脚本模式残留: /etc/systemd/system/firewall-daemon.service"
    systemctl stop firewall-daemon 2>/dev/null || true
    rm -f /etc/systemd/system/firewall-daemon.service
fi
if [ -f "/lib/modules/$KVER/extra/firewall.ko" ]; then
    echo "  清理脚本模式残留: /lib/modules/$KVER/extra/firewall.ko"
    lsmod | grep -q '^firewall ' && rmmod firewall 2>/dev/null || true
    rm -f "/lib/modules/$KVER/extra/firewall.ko"
    depmod -a
fi

# DKMS 构建依赖：apt 负责解析，缺什么补什么
if ! command -v dkms >/dev/null 2>&1 || \
   ! dpkg -s "linux-headers-$KVER" >/dev/null 2>&1; then
    echo "  安装依赖: dkms build-essential linux-headers-$KVER"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        dkms build-essential "linux-headers-$KVER"
fi
systemctl daemon-reload
echo "  远端依赖就绪"
REMOTE_PREP

# ----------------------------------------------------------------------------
# 3. 上传并安装（apt 解析依赖，失败清理半配置状态）
# ----------------------------------------------------------------------------
echo ""
echo "[3/4] 上传并安装..."
scp "${SSH_OPTS[@]}" "$DEB_FILE" "$REMOTE_USER@$REMOTE_HOST:/tmp/linux-firewall-kmod.deb"
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" sudo bash <<'REMOTE_INSTALL'
set -euo pipefail
NEW_VER="$(dpkg-deb -f /tmp/linux-firewall-kmod.deb Version)"
OLD_VER="$(dpkg-query -W -f='${Version}' linux-firewall-kmod 2>/dev/null || true)"
if [ "$OLD_VER" = "$NEW_VER" ]; then
    # 同版本重部署必须 --reinstall，否则 apt 认为「已是最新版」直接跳过，
    # 改了代码也不会真正更新（版本号来自 CHANGELOG，迭代期通常不变）。
    REINSTALL_FLAG="--reinstall"
else
    REINSTALL_FLAG=""
fi
if ! DEBIAN_FRONTEND=noninteractive apt-get install -y $REINSTALL_FLAG /tmp/linux-firewall-kmod.deb; then
    echo "❌ 安装失败，清理半配置状态..."
    dpkg --remove --force-remove-reinstreq linux-firewall-kmod 2>/dev/null || true
    exit 1
fi
rm -f /tmp/linux-firewall-kmod.deb
REMOTE_INSTALL

# ----------------------------------------------------------------------------
# 4. 验证
# ----------------------------------------------------------------------------
echo ""
echo "[4/4] 验证..."
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" bash <<'VERIFY'
set -e
# 服务刚启动，给它最多 10 秒进入 active
for _ in $(seq 1 10); do
    systemctl is-active --quiet firewall-daemon && break
    sleep 1
done
echo "  内核版本: $(uname -r)"
echo "  内核模块: $(lsmod | grep '^firewall ' || echo '未加载')"
echo "  守护进程: $(systemctl is-active firewall-daemon)"
echo "  DKMS: $(dkms status -m linux-firewall-kmod 2>/dev/null | head -1 || echo '无')"
echo "  单元文件: $(systemctl show -p FragmentPath --value firewall-daemon)"
# metrics 走 Basic 认证，401 也说明服务在监听；只有连不上才是不可达
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9119/dashboard || true)"
if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ]; then
    echo "  面板: 可达 (HTTP $HTTP_CODE)"
else
    echo "  面板: 不可达"
fi
VERIFY

echo ""
echo "========================================="
echo "🎉 Deployment complete!"
echo "========================================="
