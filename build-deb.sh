#!/bin/bash
# build-deb.sh - 构建 Debian 软件包
# 用法: ./build-deb.sh [版本号]

set -e

VERSION="${1:-2.0.0}"
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
make clean
make all

# 创建临时安装目录
TEMP_DIR="$BUILD_DIR/$PACKAGE_NAME-$VERSION"
mkdir -p "$TEMP_DIR"

# 安装内核模块
echo "安装内核模块..."
KERNEL_VERSION=$(uname -r)
install -d "$TEMP_DIR/lib/modules/$KERNEL_VERSION/extra"
install -m 644 build/kernel-module/firewall.ko "$TEMP_DIR/lib/modules/$KERNEL_VERSION/extra/"

# 安装守护进程
echo "安装守护进程..."
install -d "$TEMP_DIR/usr/local/sbin"
install -m 755 build/daemon/firewall-daemon "$TEMP_DIR/usr/local/sbin/"

# 安装配置文件
echo "安装配置文件..."
install -d "$TEMP_DIR/etc/firewall"
install -m 644 config/*.yaml "$TEMP_DIR/etc/firewall/"
install -d "$TEMP_DIR/etc/modules-load.d"
install -m 644 config/modules-load.d/firewall.conf "$TEMP_DIR/etc/modules-load.d/"

# 安装 systemd 服务
echo "安装 systemd 服务..."
install -d "$TEMP_DIR/etc/systemd/system"
install -m 644 firewall-daemon.service "$TEMP_DIR/etc/systemd/system/"

# 创建状态目录
install -d -m 700 "$TEMP_DIR/var/lib/firewall"

# 安装文档
echo "安装文档..."
install -d "$TEMP_DIR/usr/share/doc/$PACKAGE_NAME"
install -m 644 README.md CHANGELOG.md LICENSE "$TEMP_DIR/usr/share/doc/$PACKAGE_NAME/"

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
  - Hash table for O(1) IP lookup (1024 capacity)
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
    modprobe firewall || true
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
        systemctl stop firewall-daemon || true
        systemctl disable firewall-daemon || true
        systemctl daemon-reload
    fi

    # 卸载内核模块
    if lsmod | grep -q "^firewall"; then
        echo "Unloading firewall kernel module..."
        rmmod firewall || true
    fi

    # 更新模块依赖
    if command -v depmod &> /dev/null; then
        depmod -a
    fi
fi
EOF
chmod 755 "$TEMP_DIR/DEBIAN/postrm"

# 构建 deb 包
echo "构建 deb 包..."
cd "$BUILD_DIR"
dpkg-deb --build --root-owner-group "$PACKAGE_NAME-$VERSION"

# 回到项目根目录
cd "$PROJECT_ROOT"

echo "=== 构建完成 ==="
echo "deb 包位置: $BUILD_DIR/$PACKAGE_NAME-$VERSION.deb"
ls -lh "$BUILD_DIR/$PACKAGE_NAME-$VERSION.deb"
