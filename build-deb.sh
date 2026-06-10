#!/bin/bash
# build-deb.sh - 构建 Debian 软件包
# 用法: ./build-deb.sh [版本号]
#
# 内核模块通过 DKMS (Dynamic Kernel Module Support) 管理：
# - deb 包不包含预编译的 .ko 文件
# - 源码放置在 /usr/src/linux-firewall-kmod-{VERSION}/
# - 安装时 dkms 自动为当前内核编译模块
# - 内核升级时 dkms 自动重新编译

set -euo pipefail

# 从 CHANGELOG.md 自动提取最新已发布版本号（跳过 [Unreleased]）
auto_version() {
    local changelog
    changelog="$(dirname "${BASH_SOURCE[0]}")/CHANGELOG.md"
    if [[ -f "$changelog" ]]; then
        grep -m1 '^## v' "$changelog" | sed 's/^## v//;s/[^0-9.].*//'
    fi
}
DEFAULT_VERSION="$(auto_version)"
: "${DEFAULT_VERSION:=2.1.1}"
VERSION="${1:-$DEFAULT_VERSION}"
# 移除版本号前的 'v' 前缀（deb 版本必须以数字开头）
VERSION="${VERSION#v}"
BUILD_DIR="build/deb"
PACKAGE_NAME="linux-firewall-kmod"
DKMS_NAME="linux-firewall-kmod"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== 构建 Debian 软件包 (DKMS) ==="
echo "版本: $VERSION"

# 清理旧构建产物
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 仅编译守护进程（内核模块由 DKMS 在安装时编译）
echo "编译守护进程..."
make -C "$PROJECT_ROOT" clean
make -C "$PROJECT_ROOT" daemon

# P2-8: 使用 make install DESTDIR= 复用安装逻辑
TEMP_DIR="$BUILD_DIR/$PACKAGE_NAME-$VERSION"
echo "安装到暂存目录: $TEMP_DIR"
make -C "$PROJECT_ROOT" install-daemon install-config install-state install-systemd \
    DESTDIR="$TEMP_DIR" PREFIX=/usr

# 安装 DKMS 源码到标准位置 /usr/src/{dkms_name}-{version}/
echo "安装 DKMS 源码..."
DKMS_SRC_DIR="$TEMP_DIR/usr/src/$DKMS_NAME-$VERSION"
install -d "$DKMS_SRC_DIR/src/kernel-module"
cp -r "$PROJECT_ROOT/src/kernel-module/"* "$DKMS_SRC_DIR/src/kernel-module/"
cp "$PROJECT_ROOT/Makefile.dkms" "$DKMS_SRC_DIR/"
cp "$PROJECT_ROOT/dkms.conf" "$DKMS_SRC_DIR/"

# 更新 dkms.conf 中的版本占位符
sed -i "s|#MODULE_VERSION#|$VERSION|g" "$DKMS_SRC_DIR/dkms.conf"

# 安装文档
echo "安装文档..."
install -d "$TEMP_DIR/usr/share/doc/$PACKAGE_NAME"
install -m 644 "$PROJECT_ROOT/README.md" "$PROJECT_ROOT/CHANGELOG.md" "$PROJECT_ROOT/LICENSE" \
    "$TEMP_DIR/usr/share/doc/$PACKAGE_NAME/" 2>/dev/null || true

# 创建 DEBIAN 目录
echo "创建 DEBIAN 控制文件..."
install -d "$TEMP_DIR/DEBIAN"

# 创建 control 文件
cat > "$TEMP_DIR/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Depends: libyaml-0-2, libsqlite3-0, libmicrohttpd12, libpcre2-8-0, dkms, build-essential, linux-headers
Maintainer: SnowCore8 <snowcore8@gmail.com>
Description: Linux kernel module version of fail2ban
 Firewall is a high-performance real-time IP ban protection system.
 It moves fail2ban's core functionality from userspace to the kernel,
 using netfilter framework for packet-level banning with lower latency.
 .
 This package uses DKMS to build the kernel module for the running
 kernel during installation. The module will be automatically rebuilt
 when the kernel is upgraded.
 .
 Features:
  - Kernel-space IP banning via netfilter hooks
  - Jail system for multi-service isolation
  - Hash table for O(1) IP lookup (4096 capacity)
  - RCU concurrency safety + spinlock protection
  - PCRE2 regex log parsing with JIT acceleration
  - SQLite persistence for permanent bans
  - Prometheus metrics export
EOF

# 创建 postinst 脚本（DKMS 模式）
cat > "$TEMP_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

echo "=== 通过 DKMS 编译并安装内核模块 ==="

# 幂等性:检测 DKMS 树中是否已有同 module/version 残留,先清理后重装
# (修复:避免 "DKMS tree already contains" 报错导致重装失败)
if dkms status -m linux-firewall-kmod -v __VERSION__ 2>/dev/null | grep -q .; then
    echo "检测到 DKMS 树残留,清理后重新添加..."
    # 停服务 + 卸载模块(若已加载),否则 dkms remove 会因模块 active 警告
    if command -v systemctl &> /dev/null && [ -z "$DESTDIR" ]; then
        systemctl stop firewall-daemon 2>/dev/null || true
    fi
    if lsmod | grep -q "^firewall"; then
        rmmod firewall 2>/dev/null || true
    fi
    dkms remove -m linux-firewall-kmod -v __VERSION__ --all 2>/dev/null || true
    rm -rf /var/lib/dkms/linux-firewall-kmod-__VERSION__ 2>/dev/null || true
fi

# 添加模块到 DKMS 树
dkms add -m linux-firewall-kmod -v __VERSION__

# 为当前运行的内核编译并安装模块
CURRENT_KERNEL="$(uname -r)"
echo "为内核 $CURRENT_KERNEL 编译模块..."
dkms build -m linux-firewall-kmod -v __VERSION__ -k "$CURRENT_KERNEL"
dkms install -m linux-firewall-kmod -v __VERSION__ -k "$CURRENT_KERNEL" --force

# 加载内核模块
if ! lsmod | grep -q "^firewall"; then
    echo "加载内核模块..."
    modprobe firewall || {
        echo "ERROR: 无法加载 firewall 内核模块"
        echo "请检查 dmesg 获取详细信息"
        exit 1
    }
fi

# 启用并启动 systemd 服务
if command -v systemctl &> /dev/null; then
    systemctl daemon-reload
    systemctl enable firewall-daemon || true
    systemctl start firewall-daemon || true
fi

echo "linux-firewall-kmod installed successfully."
EOF

# 替换 postinst 中的版本占位符
sed -i "s|__VERSION__|$VERSION|g" "$TEMP_DIR/DEBIAN/postinst"
chmod 755 "$TEMP_DIR/DEBIAN/postinst"

# 创建 prerm 脚本（在删除 deb 包前运行）
cat > "$TEMP_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# 停止 systemd 服务
if command -v systemctl &> /dev/null && [ -z "$DESTDIR" ]; then
    systemctl stop firewall-daemon 2>/dev/null || true
    systemctl disable firewall-daemon 2>/dev/null || true
fi

# 卸载内核模块
if lsmod | grep -q "^firewall "; then
    rmmod firewall 2>/dev/null || true
fi
EOF
chmod 755 "$TEMP_DIR/DEBIAN/prerm"

# 创建 postrm 脚本
cat > "$TEMP_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/bash
# 注意：不要 set -e，因为 dkms remove 可能在某些情况下返回非零

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    # 从所有已安装的内核中卸载 DKMS 模块
    for kernel in $(ls /lib/modules/ 2>/dev/null); do
        dkms remove -m linux-firewall-kmod -v __VERSION__ -k "$kernel" 2>/dev/null || true
    done
    # 从 DKMS 树中彻底移除
    dkms remove -m linux-firewall-kmod -v __VERSION__ --all 2>/dev/null || true

    # 强制清理残留
    rm -rf /var/lib/dkms/linux-firewall-kmod-__VERSION__
    rm -rf /var/lib/dkms/linux-firewall-kmod
    rm -f /lib/modules/*/updates/dkms/firewall.ko*

    if command -v depmod &> /dev/null; then
        depmod -a 2>/dev/null || true
    fi

    # 删除运行时状态目录
    rm -rf /var/lib/firewall

    # dpkg 不会自动删除非空目录，强制清理文档目录
    rm -rf /usr/share/doc/linux-firewall-kmod
fi

# purge 时额外删除用户配置和 DKMS 源码
if [ "$1" = "purge" ]; then
    rm -rf /etc/firewall
    rm -rf /usr/src/linux-firewall-kmod-__VERSION__
fi
EOF

# 替换 postrm 中的版本占位符
sed -i "s|__VERSION__|$VERSION|g" "$TEMP_DIR/DEBIAN/postrm"
chmod 755 "$TEMP_DIR/DEBIAN/postrm"

# 构建 deb 包
echo "构建 deb 包..."
cd "$TEMP_DIR/.."
dpkg-deb --build --root-owner-group "$PACKAGE_NAME-$VERSION"

# 回到项目根目录
cd "$PROJECT_ROOT"

echo "=== 构建完成 ==="
echo "deb 包位置: $BUILD_DIR/$PACKAGE_NAME-$VERSION.deb"
ls -lh "$BUILD_DIR/$PACKAGE_NAME-$VERSION.deb"
