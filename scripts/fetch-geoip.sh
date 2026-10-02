#!/bin/bash
# fetch-geoip.sh - 下载 DB-IP City Lite 城市级地理库（本项目的 GeoIP 数据源）
#
# 做什么：按年月拼出 DB-IP 免费城市级数据库的下载地址，下载 .mmdb.gz、校验压缩包完整性、
#         解压出 .mmdb 落到目标目录，供守护进程的 `geoip_db_path` 配置项加载。
# 影响什么：只在目标目录写入 city.mmdb（默认 /var/lib/firewall/geoip/），不改任何配置文件——
#           数据库路径需要你自己写进 config/default.yaml（脚本末尾会打印该怎么写）。
#
# ⚠️ 必须是 City 级，不要下 Country 级：
#     dbip-country-lite-YYYY-MM.mmdb.gz 只有国家代码、**没有经纬度坐标**，本项目的地理分布
#     （GET /api/v1/stats/attack-geo）与 Web UI 的 3D 攻击地图都依赖坐标，用 Country 库会得到
#     「地理解析可用但没有任何点位」的结果——功能看起来是坏的，其实只是下错了库。
#
# 预期体积（实测）：压缩包约 58MB，解压后约 122MB。
#
# 许可与归属（DB-IP City Lite 采用 CC BY 4.0）：
#     数据来源 https://db-ip.com
#     许可协议 CC BY 4.0（https://creativecommons.org/licenses/by/4.0/）
#   CC BY 4.0 要求署名：把该数据随产品分发、或在界面上对外展示地理分布时，必须保留对
#   DB-IP 的署名（https://db-ip.com）与许可标识。本脚本的输出里始终保留这段声明。
#
# 用法：
#     sudo ./scripts/fetch-geoip.sh                    # 下载到默认目录
#     sudo ./scripts/fetch-geoip.sh /data/geoip        # 指定落盘目录
#     sudo ./scripts/fetch-geoip.sh --force            # 已存在也重新下载
#     sudo ./scripts/fetch-geoip.sh --month 2026-08    # 指定数据月份（默认当前年月）
#     DBIP_URL=<镜像地址> ./scripts/fetch-geoip.sh      # 官方源不可达时指到镜像/内网缓存

set -euo pipefail

# ---- 常量 -------------------------------------------------------------------

DEFAULT_DIR="/var/lib/firewall/geoip"
DB_FILENAME="city.mmdb"
OFFICIAL_BASE="https://download.db-ip.com/free"
# 解压后体积下限（字节）：实测约 122MB，低于 50MB 一律认为下载被截断
MIN_EXTRACTED_BYTES=$((50 * 1000 * 1000))

FORCE=0
MONTH=""
TARGET_DIR=""

# ---- 输出格式（与 scripts/build.sh 一致：非终端时不上色，便于重定向到日志） ----

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

info() { echo -e "${GREEN}INFO:${NC} $1"; }
warn() { echo -e "${YELLOW}WARN:${NC} $1"; }
error() { echo -e "${RED}ERROR:${NC} $1"; }

usage() {
    cat <<EOF
用法：$0 [目录] [选项]

  目录                 数据库落盘目录（默认 $DEFAULT_DIR）
  -m, --month YYYY-MM  指定数据月份（默认当前年月；当月文件尚未发布时自动回退上一月）
  -f, --force          目标文件已存在也重新下载
  -h, --help           显示本帮助

环境变量：
  DBIP_URL             自定义下载地址（官方源不可达时指到镜像或内网缓存上的同名 .mmdb.gz）
  https_proxy          标准代理变量，curl 会自动使用

数据来源 https://db-ip.com （DB-IP City Lite，CC BY 4.0），使用时必须保留署名。
EOF
}

# ---- 参数解析 ---------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--month)
            if [[ $# -lt 2 ]]; then error "--month 需要一个 YYYY-MM 参数"; exit 1; fi
            MONTH="$2"; shift 2 ;;
        -f|--force) FORCE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) error "未知参数：$1"; usage; exit 1 ;;
        *) TARGET_DIR="$1"; shift ;;
    esac
done

TARGET_DIR="${TARGET_DIR:-$DEFAULT_DIR}"

# ---- 前置检查 ---------------------------------------------------------------

command -v curl >/dev/null 2>&1 || { error "未找到 curl，请先安装（apt install curl / yum install curl）"; exit 1; }
command -v gzip >/dev/null 2>&1 || { error "未找到 gzip，请先安装（apt install gzip / yum install gzip）"; exit 1; }

if [[ -z "$MONTH" ]]; then
    MONTH="$(date +%Y-%m)"
fi
if [[ ! "$MONTH" =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]]; then
    error "--month 需要 YYYY-MM 形式（例：2026-09），收到：$MONTH"
    exit 1
fi

# 上一月：DB-IP 在月初几天才会发布当月文件，此时官方源对当月地址返回 404。
# 用 date 直接按月回退（跨年由 date 自己处理），不支持 -d 的环境跳过该兜底。
PREV_MONTH=""
if date -d "2000-01-01 -1 month" +%Y-%m >/dev/null 2>&1; then
    PREV_MONTH="$(date -d "${MONTH}-01 -1 month" +%Y-%m)"
fi

TARGET="$TARGET_DIR/$DB_FILENAME"

if ! mkdir -p "$TARGET_DIR" 2>/dev/null; then
    error "无法创建目录 $TARGET_DIR（默认路径需要 root：sudo $0 …）"
    exit 1
fi
if [[ ! -w "$TARGET_DIR" ]]; then
    error "目录不可写：$TARGET_DIR（改用 sudo，或换一个当前用户可写的目录）"
    exit 1
fi

# ---- 幂等：已存在就跳过（除非 --force） --------------------------------------

if [[ -f "$TARGET" && "$FORCE" -ne 1 ]]; then
    info "已存在，跳过下载：$TARGET（$(du -h "$TARGET" | cut -f1)）"
    info "如需重新下载，请加 --force。"
    echo "  下一步：确认 config/default.yaml 的 geoip_db_path 指向该文件，然后重启守护进程。"
    exit 0
fi

# ---- 下载（官方源优先，支持镜像兜底） ---------------------------------------

TMP_GZ="$(mktemp "${TMPDIR:-/tmp}/dbip-city-lite-XXXXXX.mmdb.gz")"
TMP_OUT="$(mktemp "${TMPDIR:-/tmp}/dbip-city-lite-XXXXXX.mmdb")"
# shellcheck disable=SC2064  # 变量在设置 trap 时已确定，此处就要立即展开
trap "rm -f '$TMP_GZ' '$TMP_OUT'" EXIT

# 候选地址顺序：官方当月 → 官方上一月（月初尚未发布） → DBIP_URL 指定的镜像/内网缓存。
# 这里**不内置**任何第三方镜像地址：未经核实的镜像会把用户引到一个不存在的下载点，
# 比明确报错更难排查。需要镜像时用 DBIP_URL 显式指过去。
CANDIDATES=("$OFFICIAL_BASE/dbip-city-lite-${MONTH}.mmdb.gz")
if [[ -n "$PREV_MONTH" && "$PREV_MONTH" != "$MONTH" ]]; then
    CANDIDATES+=("$OFFICIAL_BASE/dbip-city-lite-${PREV_MONTH}.mmdb.gz")
fi
if [[ -n "${DBIP_URL:-}" ]]; then
    CANDIDATES+=("$DBIP_URL")
fi

FETCHED=""
for url in "${CANDIDATES[@]}"; do
    info "尝试下载：$url"
    if curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --progress-bar -o "$TMP_GZ" "$url"; then
        FETCHED="$url"
        break
    fi
    warn "该地址下载失败，尝试下一个来源。"
done

if [[ -z "$FETCHED" ]]; then
    error "所有来源均下载失败，未写入任何文件。"
    cat <<EOF

可尝试的兜底方式：
  1) 走代理：            https_proxy=http://<proxy>:<port> $0 ${TARGET_DIR}
  2) 指到可达的镜像/内网缓存： DBIP_URL=<镜像上的 dbip-city-lite-YYYY-MM.mmdb.gz 地址> $0
  3) 手动下载后拷到：     $TARGET
官方源地址形如：$OFFICIAL_BASE/dbip-city-lite-YYYY-MM.mmdb.gz（按年月拼）
注意：必须下 city（含经纬度），不要下 country（只有国家代码，本项目用不了）。
EOF
    exit 1
fi

info "下载完成，来源：$FETCHED"

# ---- 完整性校验 -------------------------------------------------------------

# gzip -t 只做解压校验，不落盘：能挡住被网络中间层改写/截断的包
if ! gzip -t "$TMP_GZ" 2>/dev/null; then
    error "下载的文件不是有效的 gzip 包（可能被网络中间层改写或截断）：$TMP_GZ"
    exit 1
fi
info "gzip 完整性校验通过（压缩包 $(du -h "$TMP_GZ" | cut -f1)）"

gunzip -c "$TMP_GZ" > "$TMP_OUT"

EXTRACTED_BYTES="$(stat -c %s "$TMP_OUT" 2>/dev/null || echo 0)"
if [[ "$EXTRACTED_BYTES" -lt "$MIN_EXTRACTED_BYTES" ]]; then
    error "解压后体积异常（$EXTRACTED_BYTES 字节，预期约 122MB）：疑似下载不完整，已放弃写入。"
    exit 1
fi

mv -f "$TMP_OUT" "$TARGET"
chmod 0644 "$TARGET"

info "完成：$TARGET（$(du -h "$TARGET" | cut -f1)）"

# ---- 下一步与归属声明 -------------------------------------------------------

cat <<EOF

下一步：
  1) 在 config/default.yaml 里设置数据库路径（改为你的实际路径即可）：
       geoip_db_path: $TARGET
  2) 重启守护进程使其生效（例如 systemctl restart firewall-daemon）。
     之后 Web UI 的攻击地图与 GET /api/v1/stats/attack-geo 即可返回城市级坐标。

归属声明（许可要求，请勿删除）：
  地理数据来自 DB-IP —— https://db-ip.com
  DB-IP City Lite 采用 CC BY 4.0 许可 —— https://creativecommons.org/licenses/by/4.0/
  对外展示该数据（包括 Web UI 的地理分布图）时必须保留上述署名与许可标识。
EOF
