#!/bin/bash
# check_contract.sh - 契约门禁：重新生成各契约产物并逐一校验
#
# 做什么：
#   1. 遍历 contract/*.fwidl，按契约各自的默认产物集重新生成（C/Rust/TS/JSON）
#      ——  不显式传 --targets，产物集由 gen.py 的 CONTRACTS 决定，避免脚本
#          与生成器各维护一份映射而漂移。
#   2. 按契约类型调用对应的第三方校验器：
#        binary    （首个有效行不是 textproto/httpproto）：verify_layout.py
#                     —— 生成物与内核/daemon 手写结构体逐字段比对 sizeof/offset，
#                        并各自工具链编译生成物（rustc / tsc）
#        textproto （首个有效行以 textproto 开头）：verify_procfs.py
#                     —— 到源码里核对 proc_create 条目与权限、stats 字段与格式符、
#                        写文法 token、容量数值与缺陷锚点
#        http      （首个有效行以 httpproto 开头）：verify_http.py
#                     —— 到 handler.rs / auth.rs / sse.rs 与前端 types.ts /
#                        endpoints.ts 核对路由、认证、SSE、信封、业务码、安全头、
#                        错误形状与跨层字段一致性
#
# 为什么：契约是三端接口的真相源。产物一旦与任一侧手写代码不一致，换用生成物
# 就等于静默改变线协议/文本协议——双方互相丢弃报文且不报错。故此处必须门禁。
#
# 用法: bash scripts/check_contract.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

shopt -s nullglob
contracts=(contract/*.fwidl)
shopt -u nullglob

if [ ${#contracts[@]} -eq 0 ]; then
  echo "错误: contract/ 下没有任何 .fwidl 契约文件" >&2
  exit 2
fi

# 判定契约类型：直接复用生成器的 detect_format，不在脚本里维护第二份口径。
# （不能靠 sed 去注释：引号内的 '#' 在 shell 侧无法与注释区分——procfs 契约的
#   where 锚点里就有 "### 封禁 IP 列表" 这类内容。）
# -B 抑制 __pycache__：否则每次跑门禁都会在 contract/ 下留下字节码目录。
contract_kind() {
  python3 -B -c 'import sys; sys.path.insert(0, "contract"); import gen; print(gen.detect_format(sys.argv[1]))' "$1"
}

for src in "${contracts[@]}"; do
  kind="$(contract_kind "$src")"
  echo "=== $src（$kind）==="
  echo "生成契约产物..."
  python3 contract/gen.py "$src"
  echo
  echo "校验契约与实现一致性..."
  case "$kind" in
    http)      python3 contract/verify_http.py ;;
    textproto) python3 contract/verify_procfs.py ;;
    *)         python3 contract/verify_layout.py ;;
  esac
  echo
done

echo "契约门禁通过。"
