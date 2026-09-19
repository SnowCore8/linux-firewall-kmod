#!/bin/bash
# check_contract.sh - 契约门禁：重新生成三端产物并校验一致性
#
# 做什么：
#   1. 从 contract/*.fwidl 重新生成 C/Rust/TS/JSON 产物（保证工作区产物是最新的）
#   2. 与内核手写结构体、daemon 手写结构体逐字段比对 sizeof/offset
#   3. 各自工具链编译生成物（rustc / tsc）
#
# 为什么：契约是内核与 daemon 的线格式真相源。产物一旦与任一侧手写代码不一致，
# 换用生成物就等于静默改变线协议——双方互相丢弃报文且不报错。故此处必须门禁。
#
# 用法: bash scripts/check_contract.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "生成契约产物..."
python3 contract/gen.py contract/netlink.fwidl --targets c,rust,ts,json

echo
echo "校验三端布局一致性..."
python3 contract/verify_layout.py

echo
echo "契约门禁通过。"
