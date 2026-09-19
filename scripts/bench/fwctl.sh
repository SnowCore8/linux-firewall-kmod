#!/bin/bash
# 无钩子对照组：在单个 netns 内部建一对 veth 互打。
#
# 这组流量的收发、路由、netfilter 框架、本地投递都与主测量一致，
# 唯一差别是它不出该 netns —— 于是不会经过注册在 init_net 上的防火墙钩子。
# 用「主测量 softirq − 本对照 softirq」即得钩子自身的净成本，
# 用来交叉验证 fwsweep.sh 里各路径之间的差值。
#
# 用法: fwctl.sh [secs] [threads]
# 自动清理 veth 与子进程。
set -u
SECS=${1:-8}
THREADS=${2:-3}
HZ=$(getconf CLK_TCK)
BINDIR=$(cd "$(dirname "$0")" && pwd)
ZH=""
ZS=""

cleanup() {
  [ -n "$ZS" ] && kill "$ZS" 2>/dev/null
  [ -n "$ZH" ] && kill "$ZH" 2>/dev/null
  return 0
}
trap cleanup EXIT
cleanup

[ -x "$BINDIR/sink" ] || { echo "缺少 $BINDIR/sink，先执行 make -C $BINDIR"; exit 1; }

snap() { awk '/^cpu /{t=0;for(i=2;i<=NF;i++)t+=$i; print t, $5, $8}' /proc/stat; }

unshare -n sleep 900 &
ZH=$!
sleep 0.3
ip link add fwzA type veth peer name fwzB
ip link set fwzA netns "$ZH"
ip link set fwzB netns "$ZH"
nsenter -t "$ZH" -n ip addr add 10.98.0.1/32 dev fwzA
nsenter -t "$ZH" -n ip addr add 10.98.0.2/24 dev fwzB
nsenter -t "$ZH" -n ip link set fwzA up
nsenter -t "$ZH" -n ip link set fwzB up
nsenter -t "$ZH" -n ip link set lo up
nsenter -t "$ZH" -n "$BINDIR/sink" 10.98.0.2 9998 &
ZS=$!
sleep 0.5

# 打流侧自报包数即视为处理量：netns 内部无防火墙计数，且 sink 不读数据，
# 发送成功的包必然已走完该 netns 的数据通路。
for i in 1 2 3; do
  s0=$(snap)
  out=$(nsenter -t "$ZH" -n "$BINDIR/blast2" 10.98.0.2 9998 "$SECS" 64 "$THREADS")
  s1=$(snap)
  read -r t0 i0 q0 <<<"$s0"; read -r t1 i1 q1 <<<"$s1"
  n=$(echo "$out" | grep -oE '发送 [0-9]+ 包' | grep -oE '[0-9]+')
  printf 'Z 第%d次: %s  softirq=%.3fs  每包=%.3f µs\n' "$i" "${out##*→ }" \
    "$(awk -v q=$((q1-q0)) -v hz="$HZ" 'BEGIN{print q/hz}')" \
    "$(awk -v q=$((q1-q0)) -v hz="$HZ" -v n="$n" 'BEGIN{print (n>0)?(q/hz)*1e6/n:0}')"
done
echo "== 对照完成（清理中）=="
