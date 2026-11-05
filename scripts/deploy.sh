#!/bin/bash
# deploy.sh - 部署防火墙到远程服务器
# 用法: ./deploy.sh <主机> [用户] [--mode deb|script]
#       ./deploy.sh <用户@主机> [--mode deb|script]
#
# MODE=deb（默认）: 打包 DKMS deb，远端对目标内核编译——跨内核版本 / HWE 也能装。
# MODE=script    : 上传本地预编译的 .ko + 二进制，要求 .ko vermagic 与远端一致。
#
# 环境变量: SKIP_BUILD=1 跳过打包（deb 模式，复用 build/deb/ 下最新的 deb）

set -euo pipefail

usage() {
    echo "用法：./deploy.sh <主机> [用户] [--mode deb|script]"
    echo "      ./deploy.sh <用户@主机> [--mode deb|script]"
    echo "  主机:   目标服务器 IP 或主机名（必需，放第一个）"
    echo "  用户:   SSH 用户（默认：root）"
    echo "  --mode: deb（默认，远端 DKMS 编译）/ script（预编译 .ko）"
    exit 1
}

REMOTE_HOST=""
REMOTE_USER=""
MODE="deb"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode=*) MODE="${1#*=}"; shift ;;
        --mode)   MODE="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) if [[ -z "$REMOTE_HOST" ]]; then REMOTE_HOST="$1"
           elif [[ -z "$REMOTE_USER" ]]; then REMOTE_USER="$1"
           else echo "❌ 多余参数: $1"; usage; fi
           shift ;;
    esac
done

[[ -n "$REMOTE_HOST" ]] || usage

# 支持 user@host 单参数写法
if [[ "$REMOTE_HOST" == *@* ]]; then
    if [[ -n "$REMOTE_USER" ]]; then
        echo "❌ 用户指定了两遍：$REMOTE_HOST 与 $REMOTE_USER"
        usage
    fi
    REMOTE_USER="${REMOTE_HOST%@*}"
    REMOTE_HOST="${REMOTE_HOST#*@}"
fi

REMOTE_USER="${REMOTE_USER:-root}"
[[ -n "$REMOTE_USER" && -n "$REMOTE_HOST" ]] || usage

# 位置参数写反（用户在前、主机在后）时提前报错，
# 否则会拼成 <IP>@<用户名>，ssh 只会报无解的 "Could not resolve hostname"
if [[ "$REMOTE_HOST" != *.* && "$REMOTE_HOST" != *:* && "$REMOTE_HOST" != "localhost" \
      && "$REMOTE_USER" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo "❌ 参数顺序写反了：第一个是主机，第二个是用户。"
    echo "   收到：主机=$REMOTE_HOST 用户=$REMOTE_USER"
    echo "   应写：./scripts/deploy.sh $REMOTE_USER $REMOTE_HOST"
    echo "   或写：./scripts/deploy.sh $REMOTE_HOST@$REMOTE_USER"
    exit 1
fi
case "$MODE" in deb|script) ;; *) echo "❌ 未知 MODE=$MODE（可选 deb / script）"; exit 1 ;; esac

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=~/.ssh/known_hosts -o IdentitiesOnly=yes)

echo "========================================="
echo "Firewall Deployment (mode: $MODE)"
echo "Target server: $REMOTE_USER@$REMOTE_HOST"
echo "========================================="

read -rp "Confirm deployment to $REMOTE_HOST? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "部署已取消。"
    exit 0
fi

# 两次部署会各自 rm -rf build/deb，先完成的那个会在打包末尾找不到产物
LOCK_FILE="${TMPDIR:-/tmp}/firewall-deploy-$(id -u).lock"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "❌ 已有部署在进行（锁: $LOCK_FILE），等它结束再试"
    exit 1
fi

# ----------------------------------------------------------------------------
# deb 模式：打包 → 远端装依赖/清残留 → apt 安装（同版本 --reinstall）→ 验证
# ----------------------------------------------------------------------------
deploy_deb() {
    local deb_file
    find_deb() {
        find "$PROJECT_DIR/build/deb" -maxdepth 1 -name 'linux-firewall-kmod-*.deb' \
            -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2- || true
    }

    deb_file="$(find_deb)"
    if [[ "${SKIP_BUILD:-0}" == "1" && -n "$deb_file" ]]; then
        echo ""
        echo "[1/4] 跳过打包，使用现有 deb"
    else
        echo ""
        echo "[1/4] 打包 deb..."
        (cd "$PROJECT_DIR" && ./build-deb.sh)
        deb_file="$(find_deb)"
    fi
    if [[ -z "$deb_file" || ! -f "$deb_file" ]]; then
        echo "❌ 找不到 deb 产物（build/deb/linux-firewall-kmod-*.deb）"
        exit 1
    fi
    echo "  ✓ $(basename "$deb_file") ($(du -h "$deb_file" | cut -f1))"

    echo ""
    echo "[2/4] 准备远端环境..."
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" sudo bash <<'REMOTE_PREP'
set -euo pipefail
KVER=$(uname -r)
# 脚本模式残留会遮蔽包管理的单元与 DKMS 模块，先清掉
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
if ! command -v dkms >/dev/null 2>&1 || ! dpkg -s "linux-headers-$KVER" >/dev/null 2>&1; then
    echo "  安装依赖: dkms build-essential linux-headers-$KVER"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dkms build-essential "linux-headers-$KVER"
fi
systemctl daemon-reload
echo "  远端依赖就绪"
REMOTE_PREP

    echo ""
    echo "[3/4] 上传并安装..."
    scp "${SSH_OPTS[@]}" "$deb_file" "$REMOTE_USER@$REMOTE_HOST:/tmp/linux-firewall-kmod.deb"
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" sudo bash <<'REMOTE_INSTALL'
set -euo pipefail
NEW_VER="$(dpkg-deb -f /tmp/linux-firewall-kmod.deb Version)"
OLD_VER="$(dpkg-query -W -f='${Version}' linux-firewall-kmod 2>/dev/null || true)"
# 同版本重部署必须 --reinstall，否则 apt 认为已是最新版直接跳过
REINSTALL_FLAG=""
[ "$OLD_VER" = "$NEW_VER" ] && REINSTALL_FLAG="--reinstall"
if ! DEBIAN_FRONTEND=noninteractive apt-get install -y $REINSTALL_FLAG /tmp/linux-firewall-kmod.deb; then
    echo "❌ 安装失败，清理半配置状态..."
    dpkg --remove --force-remove-reinstreq linux-firewall-kmod 2>/dev/null || true
    exit 1
fi
rm -f /tmp/linux-firewall-kmod.deb
REMOTE_INSTALL

    echo ""
    echo "[4/4] 验证..."
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" bash <<'VERIFY_DEB'
set -e
for _ in $(seq 1 10); do systemctl is-active --quiet firewall-daemon && break; sleep 1; done

HTTP_CODE=""
for _ in $(seq 1 10); do
    HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9119/dashboard || true)"
    [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ] && break
    sleep 1
done

SVC_STATE="$(systemctl is-active firewall-daemon 2>/dev/null || true)"
MOD_STATE="$(lsmod | grep '^firewall ' || true)"
DKMS_STATE="$(dkms status -m linux-firewall-kmod 2>/dev/null | head -1 || true)"

echo "  内核版本: $(uname -r)"
echo "  内核模块: ${MOD_STATE:-未加载}"
echo "  守护进程: ${SVC_STATE:-未知}"
echo "  DKMS: ${DKMS_STATE:-无}"
echo "  单元文件: $(systemctl show -p FragmentPath --value firewall-daemon 2>/dev/null || true)"
if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ]; then
    echo "  面板: 可达 (HTTP $HTTP_CODE)"
else
    echo "  面板: 不可达"
fi

# 只打印不断言会让死掉的守护进程照样走到 "Deployment complete!"，故此处硬性判定
FAIL=0
[ "$SVC_STATE" = "active" ] || { echo "❌ 守护进程不是 active（当前: ${SVC_STATE:-未知}）"; FAIL=1; }
[ -n "$MOD_STATE" ]         || { echo "❌ 内核模块未加载"; FAIL=1; }
if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ]; then :; else echo "❌ 面板 9119 不可达"; FAIL=1; fi

if [ "$FAIL" != 0 ]; then
    echo "--- 诊断 ---"
    systemctl status firewall-daemon --no-pager -l 2>&1 | head -20 || true
    journalctl -u firewall-daemon -n 30 --no-pager 2>&1 || true
    exit 1
fi
echo "  ✓ 验证通过"
VERIFY_DEB
}

# ----------------------------------------------------------------------------
# script 模式：本地预编译产物上传（要求 vermagic 与远端一致）
# ----------------------------------------------------------------------------
deploy_script() {
    # 远端已装 deb 时，脚本部署会遮蔽包管理内容
    if ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" \
        "dpkg -s linux-firewall-kmod 2>/dev/null | grep -q 'Status:.*installed'"; then
        echo ""
        echo "⚠️  远端已通过 deb 包安装 linux-firewall-kmod"
        echo "   脚本部署会遮蔽包管理的 systemd 单元和 DKMS 模块。"
        read -rp "   是否卸载 deb 并继续脚本部署？[y/N] " purge_confirm
        if [[ "$purge_confirm" == "y" || "$purge_confirm" == "Y" ]]; then
            # shellcheck disable=SC2029
            ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" "sudo dpkg --purge linux-firewall-kmod" 2>&1
        else
            echo "部署已取消。"
            exit 0
        fi
    fi

    rollback() {
        echo "⚠️  检测到部署失败，正在回滚..."
        # shellcheck disable=SC2029
        ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" << 'ROLLBACK_SCRIPT'
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

    echo ""
    echo "[0/5] 检查本地构建产物..."
    local kernel_module="$PROJECT_DIR/build/kernel-module/firewall.ko"
    local daemon_bin="$PROJECT_DIR/build/daemon/firewall-daemon"
    if [[ ! -f "$kernel_module" ]]; then
        echo "  ✗ 内核模块不存在: $kernel_module"
        echo "  → 请先运行 'make kmod-remote HOST=$REMOTE_HOST USER=$REMOTE_USER'"
        exit 1
    fi
    if [[ ! -x "$daemon_bin" ]]; then
        echo "  ✗ 守护进程二进制不存在: $daemon_bin"
        echo "  → 请先运行 'make daemon'"
        exit 1
    fi
    echo "  ✓ 内核模块: $kernel_module ($(du -h "$kernel_module" | cut -f1))"
    echo "  ✓ 守护进程: $daemon_bin ($(du -h "$daemon_bin" | cut -f1))"

    echo ""
    echo "[1/5] 检查远端环境..."
    local remote_kernel ko_vermagic
    remote_kernel=$(ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" 'uname -r')
    ko_vermagic=$(modinfo -F vermagic "$kernel_module" 2>/dev/null | awk '{print $1}')
    echo "  远端内核: $remote_kernel"
    echo "  .ko vermagic: ${ko_vermagic:-无法读取}"
    if [[ "$ko_vermagic" != "$remote_kernel" ]]; then
        echo ""
        echo "❌ .ko 的 vermagic ($ko_vermagic) 与远端内核 ($remote_kernel) 不匹配"
        echo "   改用 deb 模式让远端 DKMS 编译："
        echo "     ./scripts/deploy.sh $REMOTE_HOST $REMOTE_USER --mode deb"
        exit 1
    fi
    echo "  ✓ vermagic 与远端内核一致"
    # shellcheck disable=SC2029
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" << 'EOF'
set -e
command -v systemctl >/dev/null 2>&1 || { echo "❌ 缺少 systemd"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "❌ 缺少 curl"; exit 1; }
echo "  远端最小依赖就绪"
EOF

    echo ""
    echo "[2/5] 打包部署产物..."
    local stage_dir
    stage_dir=$(mktemp -d /tmp/firewall-deploy-stage.XXXXX)
    trap 'rm -rf "$stage_dir"' EXIT
    mkdir -p "$stage_dir/root"
    cp "$kernel_module" "$stage_dir/root/firewall.ko"
    cp "$daemon_bin"    "$stage_dir/root/firewall-daemon"
    chmod 755 "$stage_dir/root/firewall-daemon"
    sed "s|__SBINDIR__|/usr/sbin|g" "$PROJECT_DIR/firewall-daemon.service" \
        > "$stage_dir/root/firewall-daemon.service"
    mkdir -p "$stage_dir/config" "$stage_dir/modules-load"
    cp "$PROJECT_DIR"/config/*.yaml "$stage_dir/config/"
    cp "$PROJECT_DIR/config/modules-load.d/firewall.conf" "$stage_dir/modules-load/" 2>/dev/null \
        || echo "# firewall kernel module autoload" > "$stage_dir/modules-load/firewall.conf"
    tar -C "$stage_dir" -czf /tmp/firewall-deploy.tar.gz .
    echo "  ✓ 打包完成: $(du -h /tmp/firewall-deploy.tar.gz | cut -f1)"

    echo ""
    echo "[3/5] 上传到远端..."
    scp /tmp/firewall-deploy.tar.gz "$REMOTE_USER@$REMOTE_HOST":/tmp/
    echo "  ✓ 上传完成"

    echo ""
    echo "[4/5] 远端安装..."
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" sudo bash << 'REMOTE_SCRIPT'
set -euo pipefail
WORK_DIR=$(mktemp -d /tmp/firewall-deploy.XXXXX)
cd "$WORK_DIR"
tar xzf /tmp/firewall-deploy.tar.gz
echo "  [4.1] 安装内核模块..."
install -D -m 644 root/firewall.ko "/lib/modules/$(uname -r)/extra/firewall.ko"
depmod -a
echo "  [4.2] 安装守护进程..."
install -D -m 755 root/firewall-daemon /usr/sbin/firewall-daemon
echo "  [4.3] 安装配置..."
install -d -m 700 /etc/firewall
install -m 600 config/*.yaml /etc/firewall/
chown -R root:root /etc/firewall
echo "  [4.4] 创建状态目录..."
install -d -m 700 /var/lib/firewall
chown root:root /var/lib/firewall
echo "  [4.5] 安装 systemd 单元..."
install -D -m 644 root/firewall-daemon.service /etc/systemd/system/firewall-daemon.service
if [ -f modules-load/firewall.conf ]; then
    install -D -m 644 modules-load/firewall.conf /etc/modules-load.d/firewall.conf
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
    systemctl status firewall-daemon --no-pager | head -20
    journalctl -u firewall-daemon -n 30 --no-pager
    exit 1
fi
rm -f /tmp/firewall-deploy.tar.gz
rm -rf "$WORK_DIR"
REMOTE_SCRIPT

    echo ""
    echo "[5/5] 验证部署..."
    ssh "${SSH_OPTS[@]}" "$REMOTE_USER@$REMOTE_HOST" bash << 'VERIFY_SCRIPT'
set -e
for _ in $(seq 1 10); do systemctl is-active --quiet firewall-daemon && break; sleep 1; done

HTTP_CODE=""
for _ in $(seq 1 10); do
    HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9119/dashboard || true)"
    [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ] && break
    sleep 1
done

SVC_STATE="$(systemctl is-active firewall-daemon 2>/dev/null || true)"
MOD_STATE="$(lsmod | grep '^firewall ' || true)"

echo "  内核版本: $(uname -r)"
echo "  内核模块: ${MOD_STATE:-未加载}"
echo "  守护进程: ${SVC_STATE:-未知}"
echo "  封禁统计: $(cat /proc/firewall/stats 2>/dev/null | tr '\n' ' ' || echo 'N/A')"
if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ]; then
    echo "  面板: 可达 (HTTP $HTTP_CODE)"
else
    echo "  面板: 不可达"
fi

# 与 deb 模式一致：断言而非仅打印，失败让本地 ERR trap 走回滚
FAIL=0
[ "$SVC_STATE" = "active" ] || { echo "❌ 守护进程不是 active（当前: ${SVC_STATE:-未知}）"; FAIL=1; }
[ -n "$MOD_STATE" ]         || { echo "❌ 内核模块未加载"; FAIL=1; }
if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ]; then :; else echo "❌ 面板 9119 不可达"; FAIL=1; fi

if [ "$FAIL" != 0 ]; then
    echo "--- 诊断 ---"
    systemctl status firewall-daemon --no-pager -l 2>&1 | head -20 || true
    journalctl -u firewall-daemon -n 30 --no-pager 2>&1 || true
    exit 1
fi
echo "  ✓ 验证通过"
VERIFY_SCRIPT
}

case "$MODE" in
    deb) deploy_deb ;;
    script) deploy_script ;;
esac

echo ""
echo "========================================="
echo "🎉 Deployment complete!"
echo "========================================="
echo ""
echo "  Status:  ssh $REMOTE_USER@$REMOTE_HOST 'systemctl status firewall-daemon'"
echo "  Logs:    ssh $REMOTE_USER@$REMOTE_HOST 'journalctl -u firewall-daemon -f'"
echo "  Bans:    ssh $REMOTE_USER@$REMOTE_HOST 'cat /proc/firewall/bans'"
echo "  Reload:  ssh $REMOTE_USER@$REMOTE_HOST 'systemctl reload firewall-daemon'"
