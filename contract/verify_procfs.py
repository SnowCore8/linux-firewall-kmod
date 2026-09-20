#!/usr/bin/env python3
"""procfs 契约一致性校验：契约 vs 新内核实现（src/kernel-module/fw_*.c）。

为什么需要这一步
----------------
``gen.py`` 只保证**契约自身自洽**（枚举取值不重复、可写条目都有写文法、
machine 文件都有 key 声明……），完全没有核对契约是不是在描述真实实现。
文本协议不像字节布局那样有 ``sizeof`` 可以机械比对，所以更需要在源码里
逐一核对**锚点字符串**，否则契约很快就会变成一份善意但撒谎的文档。

重写后的口径变化
----------------
Phase 1 把实现从 ``procfs.c`` / ``whitelist.c`` / ``rate-detector.c`` 等旧文件
重组进 ``fw_procfs.c`` / ``fw_wl.c`` / ``fw_rate.c`` / ``fw_ban.c`` / ``fw_main.c``。
因此本校验器：

1. 只读新实现文件；权限、条目名、stats 字段、容量、写文法都按新文件名与
   新 API 核对。
2. **不再把每条 defect 的 where 都当作「必须存在」**。契约现在用 ``status``
   表达处置结论，校验器据此决定核对哪一侧：

   - ``open``     ：``where`` 指向缺陷现场，必须**仍存在**。
   - ``fixed``    ：``where`` 指向旧缺陷现场，必须**已消失**；``fix`` 指向
                    修复证据锚点，必须**存在**。旧文件在 Phase 1 末被删除，
                    删除即「消失」；仍存在的旧文件里若锚点还在，则报错。
   - ``retained`` ：``where`` 指向源码里「有意保留」的注释，必须存在。

   没有这一改动，契约一旦记录「已修」就永远是红的（旧文件迟早删掉），
   反过来又无法发现「契约说修了、代码其实没动」。

3. 对几条高价值 defect 追加**语义核对**（不只看锚点在不在）：计数器方向、
   flush 收进快照函数、泛洪闸门收敛到封禁模块。

用法::

    python3 contract/verify_procfs.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_DIR = os.path.join(ROOT, "contract", "generated")
LAYOUT_JSON = os.path.join(GEN_DIR, "procfs_layout.json")
UAPI_H = os.path.join(GEN_DIR, "procfs_uapi.h")
KERNEL_DIR = os.path.join(ROOT, "src", "kernel-module")
PROCFS_C = os.path.join(KERNEL_DIR, "fw_procfs.c")
TYPES_H = os.path.join(KERNEL_DIR, "fw_types.h")
MAIN_C = os.path.join(KERNEL_DIR, "fw_main.c")
BAN_C = os.path.join(KERNEL_DIR, "fw_ban.c")
WL_C = os.path.join(KERNEL_DIR, "fw_wl.c")
STATS_C = os.path.join(KERNEL_DIR, "fw_stats.c")
NETLINK_C = os.path.join(KERNEL_DIR, "fw_netlink.c")

# key 数值类型 -> 实现应使用的 printf 转换符（含长度修饰）
KEY_FORMAT = {
    "u8": "%u",
    "u16": "%u",
    "u32": "%u",
    "u64": "%llu",
    "i32": "%d",
    "i64": "%lld",
}

# 可写文件 -> 其解析代码所在文件；用于核对命令形式的字面 token
WRITE_SOURCE = {
    "bans": PROCFS_C,
    "whitelist": PROCFS_C,
    "config": PROCFS_C,
}

# limit -> (常量名, 所在文件)；值必须与契约 entries 逐项相同
LIMIT_CONST = {
    "bans": ("fw_max_ban_entries", MAIN_C),
    "whitelist": ("fw_max_whitelist_entries", MAIN_C),
    "rates": ("fw_max_rate_entries", MAIN_C),
    "udp_ports": ("MAX_UDP_PORT_ENTRIES", TYPES_H),
    "icmp_types": ("MAX_ICMP_TYPE_ENTRIES", TYPES_H),
    "port_scanners": ("PORT_SCAN_MAX_RESULTS", TYPES_H),
    "service_probes": ("SERVICE_PROBE_MAX_RESULTS", TYPES_H),
}


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def anchor_exists(where: str) -> bool:
    """where/fix 的锚点是否仍在仓库里。文件不存在视为「已消失」。"""
    rel, sep, anchor = where.partition(":")
    if not sep:
        return False
    path = os.path.join(ROOT, rel)
    if not os.path.isfile(path):
        return False
    return anchor in read(path)


def check_proc_create(contract: dict) -> list[str]:
    """proc_create 的条目名与权限必须与契约一致。

    权限位在实现里是生成头宏（``FW_PROCFS_<NAME>_MODE``），故两侧都核：
    生成头里该宏的取值必须等于契约，实现必须真的用这个宏（而不是自己写死
    一个八进制字面量）。只用宏名而不管取值、或只看实现字面量，都会漏掉
    「生成头与实现各自漂移」的情况。
    """
    problems: list[str] = []
    src = read(PROCFS_C)

    macro_mode: dict[str, str] = {}
    for m in re.finditer(r"#define\s+(FW_PROCFS_\w+_MODE)\s+(0[0-7]+)\b", read(UAPI_H)):
        macro_mode[m.group(1)] = m.group(2)

    found: dict[str, str] = {}
    for m in re.finditer(
        r'proc_create\(\s*"(\w+)"\s*,\s*(0[0-7]+|[A-Z][A-Z0-9_]*)\s*,', src
    ):
        found[m.group(1)] = m.group(2)

    declared = {
        name: f"0{int(meta['mode'], 8):03o}" for name, meta in contract["files"].items()
    }

    for name, mode in sorted(declared.items()):
        want_macro = f"FW_PROCFS_{name.upper()}_MODE"
        if name not in found:
            problems.append(f"proc_create 中缺少条目 {name}（契约声明 mode {mode}）")
            continue
        token = found[name]
        if token.startswith("0"):
            if token != mode:
                problems.append(f"{name}: proc_create 字面量 {token} != 契约 {mode}")
            else:
                print(f"  {name:16} 字面量 {token} == 契约")
            continue
        if token != want_macro:
            problems.append(
                f"{name}: proc_create 用的是 {token}，应为契约宏 {want_macro}"
            )
            continue
        got = macro_mode.get(want_macro)
        if got is None:
            problems.append(f"{name}: 生成头 {os.path.basename(UAPI_H)} 缺少 {want_macro}")
        elif got != mode:
            problems.append(f"{name}: 生成头 {want_macro}={got} != 契约 {mode}")
        else:
            print(f"  {name:16} {want_macro}={got} == 契约")

    for name in sorted(found):
        if name not in declared:
            problems.append(f"proc_create 中存在契约未声明的条目 {name}（{found[name]}）")
    print(f"  契约 {len(declared)} 个条目 / proc_create {len(found)} 个条目")
    return problems


def check_stats_keys(contract: dict) -> list[str]:
    """stats 的 seq_printf key 与格式符必须与契约逐项、按序一致。"""
    problems: list[str] = []
    keys: dict[str, str] = contract["keys"].get("stats")
    if keys is None:
        return ["契约缺少 key stats 块"]

    src = read(PROCFS_C)
    m = re.search(r"static int stats_show\(.*?\n\}", src, re.S)
    if not m:
        return ["未能在 fw_procfs.c 中定位 stats_show"]
    body = m.group(0)

    emitted: list[tuple[str, str]] = []
    for line in re.finditer(
        r'seq_printf\(\s*m\s*,\s*"([A-Za-z_]\w*)\s+([^"\\]*)\\n"', body
    ):
        emitted.append((line.group(1), line.group(2)))

    declared = list(keys.items())
    if len(emitted) != len(declared):
        problems.append(
            f"stats 字段数不符: 实现 {len(emitted)} 个，契约 {len(declared)} 个"
        )
    for i, (key, typ) in enumerate(declared):
        if i >= len(emitted):
            problems.append(f"stats 缺少字段 {key}")
            continue
        got_key, got_fmt = emitted[i]
        if got_key != key:
            problems.append(f"stats 第 {i + 1} 个字段: 实现 {got_key} != 契约 {key}")
            continue
        want = KEY_FORMAT[typ]
        if got_fmt != want:
            problems.append(
                f"stats.{key}: 格式符 '{got_fmt}' != 契约声明 {typ} 对应的 '{want}'"
            )
    print(f"  stats: 实现 {len(emitted)} 个字段 / 契约 {len(declared)} 个字段")
    return problems


def check_write_forms(contract: dict) -> list[str]:
    """可写文件的解析代码必须包含契约声明的每种命令形式的字面 token。

    这里只做「字面 token 是否出现」的机械核对——占位符（``<ip>`` 等）不是
    源码里的字符串，故只核对非占位符部分。
    """
    problems: list[str] = []
    for target, decl in contract["writes"].items():
        src_path = WRITE_SOURCE.get(target)
        if src_path is None:
            problems.append(f"{target}: 校验器不知道其解析代码在哪个文件")
            continue
        src = read(src_path)
        for form in decl["forms"]:
            fixed = re.sub(r"<[^>]*>", "\0", form["pattern"])
            tokens = [t for t in re.split(r"[\s\0]+", fixed) if t]
            if not tokens:
                print(
                    f"  {target}: '{form['pattern']}' 无固定 token（纯占位形式），"
                    f"跳过字面核对"
                )
                continue
            for tok in tokens:
                if tok not in src:
                    problems.append(
                        f"{target}: 命令形式 '{form['pattern']}' 的 token '{tok}' "
                        f"在 {os.path.relpath(src_path, ROOT)} 中找不到"
                    )
        print(f"  {target}: {len(decl['forms'])} 种形式的 token 已核对")
    return problems


def check_limits(contract: dict) -> list[str]:
    """limit 的数值必须与源码常量/参数一致。"""
    problems: list[str] = []
    for target, meta in contract["limits"].items():
        spec = LIMIT_CONST.get(target)
        if spec is None:
            problems.append(f"limit {target}: 校验器不知道其对应的源码常量")
            continue
        const, path = spec
        src = read(path)
        # 支持 #define NAME 512 与 NAME = 65536 两种写法
        m = re.search(rf"\b{const}\b[^\n]*?(\d{{2,}})", src)
        if not m:
            problems.append(
                f"limit {target}: 在 {os.path.relpath(path, ROOT)} 中找不到常量 {const}"
            )
            continue
        actual = int(m.group(1))
        if actual != meta["entries"]:
            problems.append(
                f"limit {target}: 契约 {meta['entries']} != 源码 {const}={actual}"
            )
        else:
            print(f"  limit {target}: {actual} == {const}")
    return problems


def check_anchors(contract: dict) -> list[str]:
    """按 status 核对 limit 与 defect 的 where / fix 锚点。

    形状校验：锚点必须是 ``<相对路径>:<非空锚点>``，且路径在仓库内。否则一条
    被截断/含换行的畸形 where 会被当成「文件名含换行」而报出难以理解的错误。
    """
    problems: list[str] = []
    n_ok = 0

    for target, meta in contract["limits"].items():
        if anchor_exists(meta["where"]):
            n_ok += 1
        else:
            problems.append(
                f"limit {target}: 锚点 '{meta['where']}' 已不存在（实现已变，契约需同步）"
            )

    for d in contract["defects"]:
        name, status = d["name"], d["status"]
        where = d["where"]
        if "\n" in where or "\r" in where:
            problems.append(f"defect {name}: where 含换行，契约被破坏: {where!r}")
            continue
        if not where.partition(":")[1]:
            problems.append(f"defect {name}: where 形状非法（应为 '<路径>:<锚点>'）: {where!r}")
            continue
        w_exists = anchor_exists(where)

        if status == "open":
            if w_exists:
                n_ok += 1
            else:
                problems.append(f"defect {name}: status=open 但 where 锚点已消失，契约需同步")
        elif status == "retained":
            if w_exists:
                n_ok += 1
            else:
                problems.append(
                    f"defect {name}: status=retained 但 where 注释锚点 '{where}' 不存在"
                )
        elif status == "fixed":
            if w_exists:
                rel = where.partition(":")[0]
                problems.append(
                    f"defect {name}: status=fixed 但旧现场 '{where}' 仍在 "
                    f"（{rel} 若属旧实现应删除；若实现已修则契约需改判）"
                )
            else:
                n_ok += 1
            fix = d.get("fix") or ""
            if not fix.partition(":")[1]:
                problems.append(f"defect {name}: status=fixed 但 fix 形状非法: {fix!r}")
            elif not anchor_exists(fix):
                problems.append(
                    f"defect {name}: status=fixed 但修复证据锚点 '{fix}' 不存在"
                )
            else:
                n_ok += 1

    print(f"  {n_ok} 个 where/fix 锚点核对通过")
    return problems


def check_semantics(contract: dict) -> list[str]:
    """对高价值 defect 追加语义核对（不只看锚点在不在）。

    只做能机械判定的部分，不做语义推断；其余 defect 由锚点存在性覆盖。
    """
    problems: list[str] = []
    by_name = {d["name"]: d for d in contract["defects"]}

    kernel_src = {
        f: read(os.path.join(KERNEL_DIR, f))
        for f in sorted(os.listdir(KERNEL_DIR))
        if f.endswith((".c", ".h"))
    }
    joined = "\n".join(kernel_src.values())

    def inc_sites(field: str) -> list[str]:
        hits = []
        for fname, src in kernel_src.items():
            for i, line in enumerate(src.splitlines(), 1):
                if field not in line:
                    continue
                if re.search(rf"atomic(64)?_(inc|add)\(\s*&?\w*\.?{field}\b", line):
                    hits.append(f"{fname}:{i}")
        return hits

    if "PROC_BAN_TABLE_FULL_NEVER_INC" in by_name:
        sites = inc_sites("ban_table_full_rejects")
        if sites:
            print(f"  PROC_BAN_TABLE_FULL_NEVER_INC(fixed): 递增点 {sites} 已存在（成立）")
        else:
            problems.append(
                "PROC_BAN_TABLE_FULL_NEVER_INC 声明已修，但 ban_table_full_rejects "
                "仍无递增点"
            )

    if "PROC_CLEANUP_CYCLES_DEAD" in by_name:
        sites = inc_sites("cleanup_cycles")
        if sites:
            problems.append(
                f"PROC_CLEANUP_CYCLES_DEAD 声明有意保留（恒为 0），但出现递增点 {sites}"
            )
        else:
            print("  PROC_CLEANUP_CYCLES_DEAD(retained): 递增点仍不存在（成立）")

    if "PROC_STATS_STALE_NO_FLUSH" in by_name:
        m = re.search(r"static int stats_show\(.*?\n\}", kernel_src["fw_procfs.c"], re.S)
        show = m.group(0) if m else ""
        snap = re.search(r"void fw_stats_snapshot\(.*?\n\}", kernel_src["fw_stats.c"], re.S)
        flush_in_snap = "fw_stats_flush_all()" in (snap.group(0) if snap else "")
        if "fw_stats_snapshot(" in show and flush_in_snap:
            print("  PROC_STATS_STALE_NO_FLUSH(fixed): stats_show→snapshot→flush_all（成立）")
        else:
            problems.append(
                "PROC_STATS_STALE_NO_FLUSH 声明已修，但 stats_show 未走 snapshot "
                f"或 snapshot 内不 flush（show={bool(show)}, flush={flush_in_snap}）"
            )

    if "STAB_FLOOD_GATE_PROCFS_ONLY" in by_name:
        gate = "fw_ban_flood_allow" in kernel_src.get("fw_ban.c", "")
        leaked = "check_flood_protection" in joined
        if gate and not leaked:
            print("  STAB_FLOOD_GATE_PROCFS_ONLY(fixed): 闸门在 fw_ban.c，旧函数已消失（成立）")
        else:
            problems.append(
                "STAB_FLOOD_GATE_PROCFS_ONLY 声明已修，但 "
                f"fw_ban_flood_allow={gate} / 旧 check_flood_protection 残留={leaked}"
            )

    if "KERNEL_NETLINK_STRUCTS_HANDWRITTEN" in by_name:
        inc = "#include" in kernel_src.get("fw_netlink.c", "") and (
            "generated/netlink_uapi.h" in kernel_src.get("fw_netlink.c", "")
        )
        if inc:
            print("  KERNEL_NETLINK_STRUCTS_HANDWRITTEN(fixed): fw_netlink.c 引用生成头（成立）")
        else:
            problems.append(
                "KERNEL_NETLINK_STRUCTS_HANDWRITTEN 声明已修，但 fw_netlink.c 未引用生成头"
            )

    return problems


def check_artifacts() -> list[str]:
    """确认 procfs 生成物本身可用：Rust 契约能编译。

    与 verify_layout.py 同一纪律——锚点/数值比对不覆盖生成器语法错误。
    """
    problems: list[str] = []
    print("=== 生成物自检 ===")
    rs_src = os.path.join(GEN_DIR, "procfs_contract.rs")
    with tempfile.TemporaryDirectory() as td:
        rlib = os.path.join(td, "p.rlib")
        proc = subprocess.run(
            ["rustc", "--edition", "2021", "--crate-type", "lib", "-o", rlib, rs_src],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            problems.append("procfs_contract.rs 编译失败:\n" + proc.stderr[-3000:])
            print("  失败  procfs_contract.rs 编译")
        else:
            print("  OK    procfs_contract.rs 编译")
    print()
    return problems


def main() -> int:
    if not os.path.isfile(LAYOUT_JSON):
        print("错误: 未找到生成物，请先运行 gen.py", file=sys.stderr)
        return 2
    with open(LAYOUT_JSON, encoding="utf-8") as fh:
        contract = json.load(fh)

    print("=== procfs 契约 vs 内核实现 ===")
    failures: list[str] = []
    failures += check_proc_create(contract)
    print()
    failures += check_stats_keys(contract)
    print()
    failures += check_write_forms(contract)
    print()
    failures += check_limits(contract)
    print()
    failures += check_anchors(contract)
    print()
    failures += check_semantics(contract)
    print()
    failures += check_artifacts()

    print()
    if failures:
        print("procfs 契约校验失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("procfs 契约校验通过：条目、权限、stats 字段、写文法、容量与缺陷处置均与实现一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
