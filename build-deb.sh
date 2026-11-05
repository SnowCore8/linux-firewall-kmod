#!/bin/bash
# build-deb.sh - 构建 Debian 软件包（debhelper / debian/rules）
# 用法: ./build-deb.sh [版本号]
#
# 内核模块由目标机的 DKMS 在安装时编译，本地只编守护进程（含前端）。
# 版本号只从 CHANGELOG.md 取，构建期生成 debian/changelog（生成物不入库）。

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# 从 CHANGELOG.md 自动提取最新已发布版本号（跳过 [Unreleased]）
auto_version() {
    local changelog
    changelog="$PROJECT_ROOT/CHANGELOG.md"
    if [[ -f "$changelog" ]]; then
        grep -E '^## (v|[0-9])' "$changelog" | head -1 | sed 's/^## v//;s/^## //;s/[^0-9.].*//'
    fi
}

VERSION="${VERSION_ENV:-${1:-$(auto_version)}}"
# 移除版本号前的 'v' 前缀（deb 版本必须以数字开头）
VERSION="${VERSION#v}"
if [[ ! "$VERSION" =~ ^[0-9] ]]; then
    echo "ERROR: 无法确定版本号（得到 '$VERSION'），请显式传入，例如 ./build-deb.sh 2.4.0" >&2
    exit 1
fi

echo "=== 构建 Debian 软件包 (debhelper / DKMS) ==="
echo "版本: $VERSION"

# 清理旧构建产物（默认增量构建；CLEAN=1 时全量清理）
if [[ "${CLEAN:-0}" == "1" ]]; then
    echo "全量清理后构建..."
    make -C "$PROJECT_ROOT" clean
fi

# debian/changelog 是 Debian 侧唯一的版本来源，由 CHANGELOG.md 派生。
cat > debian/changelog <<EOF
linux-firewall-kmod ($VERSION) unstable; urgency=medium

  * Release $VERSION

 -- SnowCore8 <snowcore8@gmail.com>  $(LC_ALL=C date -R)
EOF

rm -rf build/deb
mkdir -p build/deb

echo "调用 dpkg-buildpackage..."
dpkg-buildpackage -b -us -uc

# dpkg-buildpackage 固定写到项目根目录的上一级；搬到 build/deb 并恢复既有文件名契约
# （scripts/deploy.sh 与 release.yml 都按 linux-firewall-kmod-*.deb 查找）。
shopt -s nullglob
artifacts=()
for f in ../linux-firewall-kmod_"${VERSION}"_*.deb \
         ../linux-firewall-kmod_"${VERSION}"_*.buildinfo \
         ../linux-firewall-kmod_"${VERSION}"_*.changes; do
    artifacts+=("$f")
done
if (( ${#artifacts[@]} == 0 )); then
    echo "ERROR: dpkg-buildpackage 未产出预期的 .deb/.buildinfo/.changes" >&2
    exit 1
fi
mv "${artifacts[@]}" build/deb/

built=(build/deb/linux-firewall-kmod_"${VERSION}"_*.deb)
mv "${built[0]}" "build/deb/linux-firewall-kmod-${VERSION}.deb"

echo "=== 构建完成 ==="
echo "deb 包位置: build/deb/linux-firewall-kmod-${VERSION}.deb"
ls -lh "build/deb/linux-firewall-kmod-${VERSION}.deb"
