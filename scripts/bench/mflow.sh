#!/bin/bash
# 多通路并发每包成本：N 条独立 veth 通路同时打流，测跨核争用。
#
# 为什么要多通路：单通路（fwsweep.sh）每包成本里不含跨核共享写争用，
# 旧实现在 4 通路并发下从 2.46 µs 升到 4.6 µs —— 升幅即共享计数器
# （直方图 atomic64、速率桶锁、last_seen）的 cache line ping-pong 代价。
# 本脚本用同样的打流强度复测，升幅收敛即证明共享写已 per-CPU 化。
#
# 每条通路一组 veth：
#   打流侧（netns 内）10.99.<i>.11/24  →  收侧（init_net）10.99.<i>.1/32
#   一个 netns 持有全部 vns 设备；N 个 sink 各绑一个收侧地址。
#   每通路源地址不同 ⇒ 各自独立的封禁/速率表条目，互不干扰。
#
# 判定口径：ddos 关、非白名单（对应 fwsweep.sh 的 A 组路径），
#   每包成本 = softirq 增量 / 全部通路处理包数之和（取 packets_accepted 增量）。
#   单通路与多通路的绝对数不可混用比较，引用时必须注明通路数。
#
# 前置：模块已加载、procfs 可写、scripts/bench 已 make。
# 用法: mflow.sh [通路数=4] [secs=8] [每通路线程数=2] [reps=3]
set -u
PATHS=${1:-4}
SECS=${2:-8}
THREADS=${3:-2}
REPS=${4:-3}
BASE=10.99
PORT=9999
HOLDER=""
SINK_PIDS=()
HZ=$(getconf CLK_TCK)
BINDIR=$(cd "$(dirname "$0")" && pwd)
PARAM=/sys/module/firewall/parameters

cleanup() {
  for p in "${SINK_PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null
  done
  for i in $(seq 0 $((PATHS - 1))); do
    ip link del "fwmh$i" 2>/dev/null
  done
  [ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null
  return 0
}
trap cleanup EXIT
cleanup

[ -x "$BINDIR/sink" ] || { echo "缺少 $BINDIR/sink，先执行 make -C $BINDIR"; exit 1; }
[ -w "$PARAM/fw_ddos_detection" ] || { echo "模块未加载或参数不可写"; exit 1; }

snap() { awk '/^cpu /{t=0;for(i=2;i<=NF;i++)t+=$i; print t, $5, $8}' /proc/stat; }
counter() { grep -E "^$1 " /proc/firewall/stats | awk '{print $2}'; }

# 建 N 条通路：init_net 侧 /32（避免白名单 remove 的子网越界判定），
# netns 侧 /24（让 netns 内有直连路由，无需额外路由条目）。
unshare -n sleep 3600 &
HOLDER=$!
sleep 0.3

for i in $(seq 0 $((PATHS - 1))); do
  ip link add "fwmh$i" type veth peer name "fwmv$i" || { echo "veth$i 创建失败"; exit 1; }
  ip addr add "$BASE.$i.1/32" dev "fwmh$i"
  ip link set "fwmh$i" up
  ip link set "fwmv$i" netns "$HOLDER" || { echo "veth$i 移入 netns 失败"; exit 1; }
  nsenter -t "$HOLDER" -n ip addr add "$BASE.$i.11/24" dev "fwmv$i"
  nsenter -t "$HOLDER" -n ip link set "fwmv$i" up
done
nsenter -t "$HOLDER" -n ip link set lo up

for i in $(seq 0 $((PATHS - 1))); do
  "$BINDIR/sink" "$BASE.$i.1" "$PORT" >/dev/null &
  SINK_PIDS+=("$!")
done
sleep 0.5

# 单次采样：N 个通路同时起、同时停，输出 "包数 softirq秒 每包µs"
once() {
  local a b s0 s1 t0 i0 q0 t1 i1 q1 n pids=() pid

  a=$(counter packets_accepted); s0=$(snap)
  for i in $(seq 0 $((PATHS - 1))); do
    nsenter -t "$HOLDER" -n "$BINDIR/blast2" "$BASE.$i.1" "$PORT" \
      "$SECS" 64 "$THREADS" >/dev/null &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do wait "$pid"; done
  s1=$(snap); sleep 3; b=$(counter packets_accepted)

  read -r t0 i0 q0 <<<"$s0"; read -r t1 i1 q1 <<<"$s1"
  n=$((b - a))
  awk -v q=$((q1-q0)) -v hz="$HZ" -v n="$n" \
    'BEGIN{printf "%d %.3f %.3f\n", n, q/hz, (n>0)?(q/hz)*1e6/n:0}'
}

med() { sort -n | awk '{a[NR]=$1} END{if(NR)print a[int((NR+1)/2)]}'; }

echo "== 通路=$PATHS secs=$SECS 每通路线程=$THREADS reps=$REPS =="
echo 0 > "$PARAM/fw_ddos_detection"
for i in $(seq 0 $((PATHS - 1))); do
  echo "unban $BASE.$i.11"   > /proc/firewall/bans 2>/dev/null
  echo "remove $BASE.$i.11" > /proc/firewall/whitelist 2>/dev/null
done
sleep 0.3

for r in $(seq "$REPS"); do
  read -r n s p < <(once)
  printf 'M 第%s次: 处理=%s softirq=%6.3fs  每包=%6.3f µs\n' "$r" "$n" "$s" "$p"
done
echo "== 结束（fw_ddos_detection 已恢复为 1）=="
echo 1 > "$PARAM/fw_ddos_detection"
