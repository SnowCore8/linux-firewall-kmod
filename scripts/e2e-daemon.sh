#!/bin/bash
# e2e-daemon.sh - 浏览器端到端测试（Playwright）的守护进程夹具
#
# 为什么需要本脚本：`tests/e2e/` 的用例要连一个真实守护进程，而守护进程在
# `/proc/firewall` 不存在时**直接退出**（src/daemon/cmd/firewall-daemon/main.go 的
# checkProcfs 前置检查），也就是说「有守护进程」蕴含「内核模块已加载」。因此起测试用
# daemon 必须先把模块插进去，还要收尾时拔出来——这套顺序写在 CI YAML 里就无法本地复现，
# 故独立成本脚本，CI 与本地共用同一份逻辑。
#
# 用法：
#   scripts/e2e-daemon.sh probe     # 环境探测：内核能否加载本模块（只读，不改状态）
#   scripts/e2e-daemon.sh start     # 载模块 + 起守护进程 + 事件驱动等待监听端口
#   scripts/e2e-daemon.sh stop      # 停守护进程 + 卸模块 + 清理临时目录
#   scripts/e2e-daemon.sh env       # 打印 BASE_URL / 凭据（供 eval "$(... env)" 使用）
#
# 需要 root（insmod/rmmod 与写 /var/lib/firewall）。
#
# 关键设计点：
#   1. 临时配置而非仓库 config/default.yaml：不碰系统日志路径、不碰系统状态文件，
#      端口与凭据都由本脚本决定，测试因此可复现且可并行于真实部署。
#   2. 模块用 state_file= 指向临时路径：避免 rmmod 时把测试期间的封禁写进
#      真实的 /var/lib/firewall/state。
#   3. 只等就绪条件，不等固定秒数：轮询 /health 直到返回 200（未就绪时是 503），
#      与服务端实际进度挂钩。

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---- 可覆盖参数 -----------------------------------------------------------
E2E_PORT="${E2E_PORT:-9119}"
E2E_BIND="${E2E_BIND:-0.0.0.0}"
E2E_METRICS_USER="${E2E_METRICS_USER:-e2e}"
E2E_METRICS_PASSWORD="${E2E_METRICS_PASSWORD:-e2e-password}"
E2E_STATE_DIR="${E2E_STATE_DIR:-/tmp/firewall-e2e}"
E2E_DAEMON_BIN="${E2E_DAEMON_BIN:-$PROJECT_DIR/build/daemon/firewall-daemon}"
E2E_KO="${E2E_KO:-$PROJECT_DIR/build/kernel-module/firewall.ko}"
E2E_WAIT_SECS="${E2E_WAIT_SECS:-30}"

PID_FILE="$E2E_STATE_DIR/daemon.pid"
CONFIG_FILE="$E2E_STATE_DIR/e2e-config.yaml"
DAEMON_LOG="$E2E_STATE_DIR/daemon.log"
JAIL_LOG="$E2E_STATE_DIR/auth.log"
STATE_FILE="$E2E_STATE_DIR/module-state"

log() { echo "[e2e-daemon] $*" >&2; }
die() { echo "[e2e-daemon] 错误：$*" >&2; exit 1; }

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "需要 root（insmod/rmmod 与写 /var/lib/firewall）：请用 sudo 执行"
    fi
}

# 模块是否已加载（按精确名字匹配，不用 grep 子串以防误判）
module_loaded() {
    lsmod | awk '{print $1}' | grep -qx 'firewall'
}

# ============================================================================
# probe：能否加载并卸载本模块
# ============================================================================
# 为什么单独做探测：GitHub Actions 的 Azure VM 使用自定义内核，其头文件常与
# 运行内核不匹配，编译出的 .ko 可能加载不了。这是**运行环境**限制而非代码缺陷，
# 仓库既有 test 作业对同一情况采用「显式跳过并说明原因」的策略，这里保持一致。
do_probe() {
    require_root
    [[ -f "$E2E_KO" ]] || die "内核模块不存在：$E2E_KO（先跑 make kernel-module）"

    if module_loaded; then
        log "模块已加载，探测通过"
        return 0
    fi
    if insmod "$E2E_KO" 2>&1; then
        rmmod firewall
        log "模块可加载，探测通过"
        return 0
    fi
    log "本机内核无法加载 $E2E_KO —— 环境限制，浏览器用例将跳过"
    return 1
}

# ============================================================================
# start：载模块 + 起守护进程 + 等 procfs 就绪
#
# 当前 Go 构建只有 procfs 接口，没有 HTTP 服务：/health、/metrics、/api/v1、
# /static/*path 都尚未移植到 Go 侧（见
# src/daemon/cmd/firewall-daemon/main.go 的「未装配」标注与文档
# docs/zh/architecture/daemon.md）。因此就绪条件按 procfs 接口判定，
# 不再轮询 HTTP 端口。
# ============================================================================
do_start() {
    require_root
    [[ -x "$E2E_DAEMON_BIN" ]] || die "守护进程二进制不存在或不可执行：$E2E_DAEMON_BIN（先跑 make daemon）"
    [[ -f "$E2E_KO" ]] || die "内核模块不存在：$E2E_KO（先跑 make kernel-module）"

    # 端口先探测再使用：被别的进程占着时应该在起 daemon 之前失败，
    # 而不是等守护进程绑定失败（那种失败只写进日志，表现是「等端口超时」）。
    if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 "http://127.0.0.1:$E2E_PORT/health" >/dev/null 2>&1; then
        die "端口 $E2E_PORT 上已有 HTTP 服务在响应，换 E2E_PORT 或先停掉它"
    fi

    # 幂等：重复 start 时先把上一轮残留清干净（含内核租约，见 stop 的说明）
    do_stop >/dev/null 2>&1 || true

    mkdir -p "$E2E_STATE_DIR" /var/lib/firewall
    : >"$JAIL_LOG"

    # ---- 临时配置 ----
    # 字段名必须与 Go module `src/daemon/internal/config` 的 `YamlConfig`（deny_unknown_fields）完全一致
    # （该结构体带 deny_unknown_fields，多一个键即启动失败）。
    # 凭据是必需的：绑定非回环地址时启动期守卫会拒绝无认证监听。
    cat >"$CONFIG_FILE" <<YAML
defaults:
  max_retries: 3
  findtime: 600
  ban_time: 300
  interval: 1
  metrics_port: $E2E_PORT
  metrics_bind_address: "$E2E_BIND"
  metrics_username: "$E2E_METRICS_USER"
  metrics_password: "$E2E_METRICS_PASSWORD"
  log_file: $DAEMON_LOG
  log_level: 3

jails:
  sshd:
    enabled: true
    log_files:
      - $JAIL_LOG
    max_retries: 2
    findtime: 600
    ban_time: 300
    regexes:
      failed_password:
        pattern: "Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3}\\\\.[0-9]{1,3})"

webui:
  sse_push_interval: 1

ddos:
  enabled: true
YAML

    # ---- 内核模块 ----
    if ! module_loaded; then
        log "加载内核模块（state_file=$STATE_FILE）"
        insmod "$E2E_KO" state_file="$STATE_FILE" || die "insmod 失败（见上一行内核输出）"
    fi

    # 等 procfs 接口就绪：insmod 返回并不意味着 /proc/firewall 已经可见，
    # 而守护进程启动期就会检查它，提前启动只会拿到一次「Procfs directory not found」。
    local i
    for ((i = 0; i < 50; i++)); do
        [[ -e /proc/firewall/bans ]] && break
        sleep 0.1
    done
    [[ -e /proc/firewall/bans ]] || die "模块已加载但 /proc/firewall/bans 未出现"

    # ---- 守护进程 ----
    # 前台模式（不加 -d）：守护进程化会 fork，PID 文件随之落到 /run/ 而不便追踪；
    # 前台模式让本脚本直接用自己拿到的 PID 管理生命周期。setsid 让它脱离本脚本的
    # 进程组与终端，脚本退出后 daemon 继续跑。
    log "启动守护进程：$E2E_DAEMON_BIN -c $CONFIG_FILE"
    setsid "$E2E_DAEMON_BIN" -c "$CONFIG_FILE" >>"$DAEMON_LOG" 2>&1 &
    echo $! >"$PID_FILE"

    # ---- 等就绪（事件驱动，不用固定 sleep）----
    # Go 构建启动期前置检查 /proc/firewall（见 main.go 的 checkProcfs），
    # 「/proc/firewall/bans 可见」即模块接口就绪、守护进程能起。
    local deadline=$((SECONDS + E2E_WAIT_SECS))
    while ((SECONDS < deadline)); do
        [[ -e /proc/firewall/bans ]] && break
        sleep 0.1
    done
    [[ -e /proc/firewall/bans ]] && {
        log "模块接口就绪：/proc/firewall/bans 可见"
        break
    }
    [[ -e /proc/firewall/bans ]] || {
        log "守护进程启动后 /proc/firewall/bans 未出现，日志末尾："
        tail -n 40 "$DAEMON_LOG" >&2 || true
        die "模块接口未就绪（当前 Go 构建只有 procfs，HTTP 服务尚未移植）"
    }
}

# ============================================================================
do_env() {
    # Playwright 侧据此覆盖 baseURL 与凭据；token 是 Basic 凭据的 base64
    # （与前端 api/auth.ts::encodeCredentials 的算法一致，均以 UTF-8 先编码）。
    echo "BASE_URL=http://127.0.0.1:$E2E_PORT"
    echo "E2E_METRICS_USER=$E2E_METRICS_USER"
    echo "E2E_METRICS_PASSWORD=$E2E_METRICS_PASSWORD"
    # 走到这里说明模块已加载、守护进程已就绪，写操作链路因此可用；
    # 写操作用例据此决定是执行还是跳过（跳过而非失败，见 write-flow.spec.ts）。
    echo "E2E_KERNEL_MODULE=1"
}

# ============================================================================
# stop：停守护进程 + 卸模块 + 清理
# ============================================================================
do_stop() {
    # 停守护进程：先 SIGTERM 让它走完清理路径（状态回写、关库），再兜底 SIGKILL。
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid="$(cat "$PID_FILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "停止守护进程 pid=$pid"
            kill -TERM "$pid" 2>/dev/null || true
            local i
            for ((i = 0; i < 50; i++)); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            kill -KILL "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi

    # 卸模块：这一步不只是卫生问题，而是**必须**。
    # 内核把「单守护进程」实现为 portid + 30 秒活动超时，且没有注销消息，
    # 所以 daemon 退出后租约仍被占住最多 30 秒，期间新 daemon 会收到 Refused
    # 并以非零码退出。重载模块是唯一可靠的立即释放手段
    # （与 tests/conftest.py::release_kernel_lease 同一处置）。
    if module_loaded; then
        log "卸载内核模块"
        rmmod firewall || log "警告：rmmod 失败，内核租约可能残留"
    fi

    # 临时目录：默认清理；排查失败时用 E2E_KEEP=1 保留（含 daemon.log）。
    if [[ "${E2E_KEEP:-0}" == "1" ]]; then
        log "保留临时目录：$E2E_STATE_DIR"
    else
        rm -rf "$E2E_STATE_DIR"
    fi
    log "已停止并清理"
}

case "${1:-}" in
probe) do_probe ;;
start) do_start ;;
stop) do_stop ;;
env) do_env ;;
*)
    echo "用法：$0 {probe|start|stop|env}" >&2
    exit 2
    ;;
esac
