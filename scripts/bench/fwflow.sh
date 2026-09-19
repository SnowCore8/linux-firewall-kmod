#!/bin/bash
# 单条 IPv4 打流通路：netns（打流侧）→ veth → init_net（收侧 sink）。
#
# 为什么这样搭：本机 netfilter 钩子注册在 init_net（nf_register_net_hook(&init_net, ...)），
# 且 lo 与 netns 内部的流量不会到达 init_net 的 NF_INET_PRE_ROUTING，
# 因此必须在两个 netns 之间架一条 veth，让包跨命名空间边界进入 init_net。
# `ip netns add` 在本机报 Invalid argument（/var/run/netns 挂载方式不被支持），
# 所以用 `unshare -n` 起长驻进程持有 netns，再 `ip link set <dev> netns <pid>`。
#
# 为什么 init_net 侧与 netns 侧掩码不同：
#   收侧 /32 —— procfs 的白名单 remove 用「接口子网」判定本机 IP
#              （见 contract/procfs.fwidl 的 PROC_WHITELIST_REMOVE_SUBNET_OVERREACH），
#              若收侧配 /24，则该网段内任何白名单条目都无法删除，对照组会被锁死。
#   打流侧 /24 —— 让 netns 内有到收侧地址的直连路由，无需额外路由条目。
#
# 用法: fwflow.sh [源地址] [收侧地址] [端口]
# 前台运行，Ctrl-C 或 kill 时自动清理 veth 与全部子进程。
set -u
SRC=${1:-10.99.0.11}
DST=${2:-10.99.0.1}
PORT=${3:-9999}
VHOST=fwhost0
VNS=fwvns0
HOLDER=""
SINKPID=""
BINDIR=$(cd "$(dirname "$0")" && pwd)

cleanup() {
  [ -n "$SINKPID" ] && kill "$SINKPID" 2>/dev/null
  [ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null
  ip link del "$VHOST" 2>/dev/null
  return 0
}
trap cleanup EXIT
cleanup

[ -x "$BINDIR/sink" ] || { echo "缺少 $BINDIR/sink，先执行 make -C $BINDIR"; exit 1; }

unshare -n sleep 3600 &
HOLDER=$!
sleep 0.3

ip link add "$VHOST" type veth peer name "$VNS" || { echo "veth 创建失败"; exit 1; }
ip addr add "$DST/32" dev "$VHOST"
ip link set "$VHOST" up
ip link set "$VNS" netns "$HOLDER" || { echo "移入 netns 失败"; exit 1; }
nsenter -t "$HOLDER" -n ip addr add "$SRC/24" dev "$VNS"
nsenter -t "$HOLDER" -n ip link set "$VNS" up
nsenter -t "$HOLDER" -n ip link set lo up

"$BINDIR/sink" "$DST" "$PORT" &
SINKPID=$!
sleep 0.3

echo "NS_PID=$HOLDER SRC=$SRC DST=$DST PORT=$PORT"
wait "$SINKPID"
