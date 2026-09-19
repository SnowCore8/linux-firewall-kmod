#!/bin/bash
# 热路径每包成本对照测量。
#
# 五条路径（同一源地址，避免被内核自动白名单短路后测量退化）：
#   E) ddos关 + 白名单   —— 钩子最短路径（白名单命中 → 立即接受）
#   A) ddos关 + 非白名单 —— 白名单未命中 + 封禁表未命中
#   B) ddos开 + 非白名单 —— A 再加速率引擎（update_rate_stats + 三路 violation 检查）
#   C) ddos开 + 白名单   —— 与 E 同路径，用于估算开关噪声
#   D) 已封禁            —— 封禁表命中 → NF_DROP
#
# 每包成本 = softirq 增量 / 处理包数。
#   为什么看 softirq 而不看 total：total 含发送侧进程的系统调用开销
#   （~1 Mpps 时约占满多个核），会把钩子成本淹没；softirq 才是协议栈 +
#   netfilter + 钩子的落点。
#   B 组必须统计 accepted + dropped —— 速率引擎会在打流中途自动封禁源地址，
#   封禁后的包只进 dropped，若只数 accepted 会把每包成本高估几十倍。
#
# 前置：先跑 fwflow.sh 拿到 NS_PID；netns 内 SRC 已配置；procfs 可写。
# 用法: fwsweep.sh <NS_PID> [secs] [threads] [reps] [src]
set -u
NSPID=${1:?需要 fwflow.sh 打印的 NS_PID}
SECS=${2:-8}
THREADS=${3:-3}
REPS=${4:-3}
SRC=${5:-10.99.0.11}
DST=${6:-10.99.0.1}
PORT=${7:-9999}
PARAM=/sys/module/firewall/parameters
HZ=$(getconf CLK_TCK)
BINDIR=$(cd "$(dirname "$0")" && pwd)

snap() { awk '/^cpu /{t=0;for(i=2;i<=NF;i++)t+=$i; print t, $5, $8}' /proc/stat; }
counter() { grep -E "^$1 " /proc/firewall/stats | awk '{print $2}'; }

# 单次采样：$1=计数字段，$2=是否合计 dropped（B 组用），输出 "包数 softirq秒 每包µs"
once() {
  local key=$1 add_drop=${2:-no} a b a2 b2 s0 s1 t0 i0 q0 t1 i1 q1 n blank out
  if [ "$add_drop" = yes ]; then
    echo "unban $SRC" > /proc/firewall/bans 2>/dev/null
    sleep 0.2
    a2=$(counter packets_dropped)
  fi
  a=$(counter "$key"); s0=$(snap)
  out=$(nsenter -t "$NSPID" -n "$BINDIR/blast2" "$DST" "$PORT" "$SECS" 64 "$THREADS")
  s1=$(snap); sleep 3; b=$(counter "$key")
  read -r t0 i0 q0 <<<"$s0"; read -r t1 i1 q1 <<<"$s1"
  n=$((b - a))
  if [ "$add_drop" = yes ]; then
    b2=$(counter packets_dropped); n=$((n + b2 - a2))
  fi
  awk -v q=$((q1-q0)) -v hz="$HZ" -v n="$n" \
    'BEGIN{printf "%d %.3f %.3f\n", n, q/hz, (n>0)?(q/hz)*1e6/n:0}'
}

med() { sort -n | awk '{a[NR]=$1} END{if(NR)print a[int((NR+1)/2)]}'; }

suite() {   # $1=标签 $2=计数字段 $3=是否合计 dropped
  local label=$1 key=$2 add=${3:-no} i n s p
  local pk=() so=() pe=()
  for i in $(seq "$REPS"); do
    read -r n s p < <(once "$key" "$add")
    pk+=("$n"); so+=("$s"); pe+=("$p")
  done
  printf '%-36s 处理中位=%-9s softirq中位=%6.3fs  每包=%6.3f µs\n' \
    "$label" "$(printf '%s\n' "${pk[@]}" | med)" \
    "$(printf '%s\n' "${so[@]}" | med)" "$(printf '%s\n' "${pe[@]}" | med)"
}

echo "== NS_PID=$NSPID secs=$SECS threads=$THREADS reps=$REPS src=$SRC =="
echo "unban $SRC"  > /proc/firewall/bans 2>/dev/null
echo "remove $SRC" > /proc/firewall/whitelist 2>/dev/null
sleep 0.3

echo 0 > "$PARAM/fw_ddos_detection"
echo "add $SRC" > /proc/firewall/whitelist; sleep 0.5
suite "E) ddos关 + 白名单（钩子最短路径）" packets_accepted

echo "remove $SRC" > /proc/firewall/whitelist; sleep 0.5
suite "A) ddos关 + 非白名单（两表未命中）" packets_accepted

echo 1 > "$PARAM/fw_ddos_detection"; sleep 0.3
suite "B) ddos开 + 非白名单（+速率引擎）" packets_accepted yes

echo "add $SRC" > /proc/firewall/whitelist; sleep 0.5
suite "C) ddos开 + 白名单（对照 E）" packets_accepted

echo "remove $SRC" > /proc/firewall/whitelist 2>/dev/null; sleep 0.3
echo "$SRC 0" > /proc/firewall/bans; sleep 0.5
suite "D) 已封禁（命中 → NF_DROP）" packets_dropped

echo "unban $SRC" > /proc/firewall/bans 2>/dev/null
echo 1 > "$PARAM/fw_ddos_detection"
echo "== 结束（fw_ddos_detection 已恢复为 1）=="
