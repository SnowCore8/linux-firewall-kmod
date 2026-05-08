#!/bin/bash
# build-deb.sh - 构建 Debian 软件包
# 用法: ./build-deb.sh [版本号]

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
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== 构建 Debian 软件包 ==="
echo "版本: $VERSION"

# 清理旧构建产物
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# 编译项目
echo "编译项目..."
make -C "$PROJECT_ROOT" clean
make -C "$PROJECT_ROOT" all

# P2-8: 使用 make install DESTDIR= 复用安装逻辑，避免与 Makefile 重复
TEMP_DIR="$BUILD_DIR/$PACKAGE_NAME-$VERSION"
echo "安装到暂存目录: $TEMP_DIR"
make -C "$PROJECT_ROOT" install-kernel-module install-daemon install-config install-state install-systemd \
    DESTDIR="$TEMP_DIR" PREFIX=/usr

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
Depends: libyaml-0-2, libsqlite3-0, libmicrohttpd12, libpcre2-8-0
Maintainer: SnowCore8 <snowcore8@gmail.com>
Description: Linux kernel module version of fail2ban
 Firewall is a high-performance real-time IP ban protection system.
 It moves fail2ban's core functionality from userspace to the kernel,
 using netfilter framework for packet-level banning with lower latency.
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

# 创建 postinst 脚本
cat > "$TEMP_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# 更新模块依赖
if command -v depmod &> /dev/null; then
    depmod -a
fi

# 加载内核模块
if ! lsmod | grep -q "^firewall"; then
    echo "Loading firewall kernel module..."
    if ! modprobe firewall; then
        echo "ERROR: Failed to load firewall kernel module" >&2
        echo "Please check dmesg for details" >&2
        exit 1
    fi
fi

# 启用并启动 systemd 服务
if command -v systemctl &> /dev/null; then
    systemctl daemon-reload
    systemctl enable firewall-daemon || true
    systemctl start firewall-daemon || true
fi

echo "linux-firewall-kmod installed successfully."
EOF
chmod 755 "$TEMP_DIR/DEBIAN/postinst"

# 创建 postrm 脚本
cat > "$TEMP_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    # 停止并禁用 systemd 服务
    if command -v systemctl &> /dev/null; then
        systemctl stop firewall-daemon 2>/dev/null || true
        systemctl disable firewall-daemon 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi

    # 卸载内核模块
    if lsmod | grep -q "^firewall "; then
        echo "Unloading firewall kernel module..."
        rmmod firewall 2>/dev/null || true
    fi

    # 更新模块依赖
    if command -v depmod &> /dev/null; then
        depmod -a 2>/dev/null || true
    fi
fi
EOF
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
