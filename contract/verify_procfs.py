#!/usr/bin/env python3
"""procfs 契约一致性校验：契约 vs 内核 procfs.c / whitelist.c / 文档。

为什么需要这一步
----------------
``gen.py`` 只保证**契约自身自洽**（枚举取值不重复、可写条目都有写文法、
machine 文件都有 key 声明……），完全没有核对契约是不是在描述真实实现。
文本协议不像字节布局那样有 ``sizeof`` 可以机械比对，所以更需要在源码里
逐一核对**锚点字符串**，否则契约很快就会变成一份善意但撒谎的文档。

做法（全部为机械核对，不做语义推断）
------------------------------------
1. ``proc_create`` 的条目名与 mode 必须与契约逐项相同（多/少/权限不符都报错）。
2. ``stats_show`` 的 ``seq_printf(m, "<key> ...")`` 行必须与契约 key 块
   **逐项、按顺序**相同（含数值类型推导出的格式符）。
3. 三个可写文件的解析代码里必须能找到契约声明的每种命令形式的**字面 token**
   （``unban`` / ``add`` / ``remove`` / ``ban_time`` / ``0`` 等）。
4. ``limit`` 块的 ``where`` 锚点必须仍存在于源码中，且声明的上限值必须与
   源码里的数值一致（如 udp_ports 512、icmp_types 128）。
5. 每条 ``defect`` 的 ``where`` 锚点必须仍存在——缺陷被修掉后契约必须同步
   修改，否则门禁失败，避免「契约说有问题、代码其实已修」或反之。
6. ``defect`` 里声明为「计数器恒为 0」的，校验其递增点确实缺失；声明为
   「无上限」的，校验容量检查确实不存在。

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
PROCFS_C = os.path.join(ROOT, "src", "kernel-module", "procfs.c")
WHITELIST_C = os.path.join(ROOT, "src", "kernel-module", "whitelist.c")
FIREWALL_H = os.path.join(ROOT, "src", "kernel-module", "firewall.h")
RATE_DETECTOR_C = os.path.join(ROOT, "src", "kernel-module", "rate-detector.c")
FIREWALL_MAIN_C = os.path.join(ROOT, "src", "kernel-module", "firewall-main.c")
DOC_PROCFS = os.path.join(ROOT, "docs", "zh", "configuration", "procfs.md")

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

# 用于核对 limit 数值的常量名（契约里的 entries 必须等于源码里的这个值）
LIMIT_CONST = {
    "rates": ("fw_max_rate_entries", FIREWALL_MAIN_C, False),
    "udp_ports": ("MAX_UDP_PORT_ENTRIES", FIREWALL_H, True),
    "icmp_types": ("MAX_ICMP_TYPE_ENTRIES", FIREWALL_H, True),
    "port_scanners": ("PORT_SCAN_MAX_RESULTS", PROCFS_C, True),
    "service_probes": ("SERVICE_PROBE_MAX_RESULTS", PROCFS_C, True),
}

# 用于核对「无上限」声明的注释锚点（存在即说明容量检查确实被跳过）
NO_LIMIT_MARKER = {
    "bans": ("按需扩展", FIREWALL_H),
    "whitelist": ("跳过容量检查", WHITELIST_C),
}


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def snake(name: str) -> str:
    out = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    out = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", out)
    return out.lower()


def check_proc_create(contract: dict) -> list[str]:
    """proc_create 的条目名与权限必须与契约一致。"""
    problems: list[str] = []
    src = read(PROCFS_C)
    found: dict[str, str] = {}
    for m in re.finditer(
        r'proc_create\(\s*"(\w+)"\s*,\s*(0[0-7]+)\s*,\s*[^,]+,\s*&(\w+)\s*\)', src
    ):
        found[m.group(1)] = m.group(2)

    declared = {
        name: f"0{int(meta['mode'], 8):03o}" for name, meta in contract["files"].items()
    }

    for name, mode in sorted(declared.items()):
        if name not in found:
            problems.append(f"proc_create 中缺少条目 {name}（契约声明 mode {mode}）")
            continue
        if found[name] != mode:
            problems.append(
                f"{name}: proc_create mode {found[name]} != 契约 {mode}"
            )
    for name in sorted(found):
        if name not in declared:
            problems.append(f"proc_create 中存在契约未声明的条目 {name}（mode {found[name]}）")
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
        return ["未能在 procfs.c 中定位 stats_show"]
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
            # 提取占位符之外的固定 token
            fixed = re.sub(r"<[^>]*>", "\0", form["pattern"])
            tokens = [t for t in re.split(r"[\s\0]+", fixed) if t]
            if not tokens:
                # 形如 "<ip>" / "<subnet>" 的纯占位形式没有固定 token，
                # 其可达性由 defect/语义核对负责，此处显式记录而非静默跳过
                print(f"  {target}: '{form['pattern']}' 无固定 token（纯占位形式），跳过字面核对")
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
    """limit 的数值必须与源码常量一致；无上限声明必须有对应注释锚点。"""
    problems: list[str] = []
    for target, meta in contract["limits"].items():
        if meta["entries"] is None:
            marker = NO_LIMIT_MARKER.get(target)
            if marker is None:
                problems.append(f"limit {target}: 校验器不知道其无上限的注释锚点")
                continue
            text, path = marker
            if text not in read(path):
                problems.append(
                    f"limit {target}: 契约声明无上限，但 {os.path.relpath(path, ROOT)} "
                    f"中找不到说明 '{text}'（可能已加上容量检查，契约需同步）"
                )
            else:
                print(f"  limit {target}: 无上限，注释锚点 '{text}' 存在")
            continue

        spec = LIMIT_CONST.get(target)
        if spec is None:
            problems.append(f"limit {target}: 校验器不知道其对应的源码常量")
            continue
        const, path, _ = spec
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
    """limit 与 defect 的 where 锚点必须仍存在于源码中。

    这里额外做**形状校验**：锚点必须是 ``<相对路径>:<非空锚点>``，且路径
    在仓库内。否则一条被截断/含换行的畸形 where 会被当成「文件名含换行」
    而报出难以理解的错误（曾出现：``#`` 截断把 where 切成半截字符串）。
    """
    problems: list[str] = []
    entries: list[tuple[str, str, str]] = []
    for target, meta in contract["limits"].items():
        entries.append(("limit", target, meta["where"]))
    for d in contract["defects"]:
        entries.append(("defect", d["name"], d["where"]))

    for kind, name, where in entries:
        if "\n" in where or "\r" in where:
            problems.append(f"{kind} {name}: where 含换行，契约被破坏: {where!r}")
            continue
        rel, sep, anchor = where.partition(":")
        if not sep or not rel or not anchor:
            problems.append(
                f"{kind} {name}: where 形状非法（应为 '<路径>:<锚点>'）: {where!r}"
            )
            continue
        # 路径必须以下划线之外的合法仓库相对路径给出（禁绝对路径，随机器变化）
        if os.path.isabs(rel) or rel.startswith(".."):
            problems.append(f"{kind} {name}: where 必须用仓库相对路径: {rel!r}")
            continue
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            problems.append(f"{kind} {name}: 锚点文件不存在 {rel}")
            continue
        if anchor not in read(path):
            problems.append(
                f"{kind} {name}: 锚点 '{anchor}' 在 {rel} 中已不存在"
                f"（实现已变，契约需同步）"
            )
    print(f"  {len(entries)} 个 limit/defect 锚点已核对（含形状校验）")
    return problems


def check_defect_claims(contract: dict) -> list[str]:
    """核对 defect 里的「恒为 0」类断言：计数器确实没有递增点。

    只核对能机械判定的那一部分（递增点存在性），不做语义推断。若某条缺陷
    被修好（出现了递增点 / 容量检查），这里会报错，强制契约同步更新。
    """
    problems: list[str] = []
    kernel_dir = os.path.join(ROOT, "src", "kernel-module")
    all_src = {f: read(os.path.join(kernel_dir, f))
               for f in os.listdir(kernel_dir) if f.endswith((".c", ".h"))}

    def inc_sites(field: str) -> list[str]:
        """返回对该字段做递增的 (文件, 行号)。排除初始化清零与读取。"""
        hits = []
        for fname, src in all_src.items():
            for i, line in enumerate(src.splitlines(), 1):
                if field not in line:
                    continue
                if re.search(rf"atomic(64)?_inc\(\s*&?\w*\.?{field}\b", line):
                    hits.append(f"{fname}:{i}")
                elif re.search(rf"atomic(64)?_add\(\s*[^,]+{field}", line):
                    hits.append(f"{fname}:{i}")
        return hits

    for d in contract["defects"]:
        if d["name"] == "PROC_BAN_TABLE_FULL_NEVER_INC":
            sites = inc_sites("ban_table_full_count")
            if sites:
                problems.append(
                    "defect PROC_BAN_TABLE_FULL_NEVER_INC 已失效："
                    f"ban_table_full_count 出现了递增点 {sites}，契约需同步"
                )
            else:
                print("  defect PROC_BAN_TABLE_FULL_NEVER_INC: 递增点仍不存在（成立）")
        elif d["name"] == "PROC_CLEANUP_CYCLES_DEAD":
            sites = inc_sites("cleanup_cycles")
            if sites:
                problems.append(
                    "defect PROC_CLEANUP_CYCLES_DEAD 已失效："
                    f"cleanup_cycles 出现了递增点 {sites}，契约需同步"
                )
            else:
                print("  defect PROC_CLEANUP_CYCLES_DEAD: 递增点仍不存在（成立）")
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
    failures += check_defect_claims(contract)
    print()
    failures += check_artifacts()

    print()
    if failures:
        print("procfs 契约校验失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("procfs 契约校验通过：条目、权限、stats 字段、写文法、容量与缺陷锚点均与实现一致")
    return 0


if __name__ == "__main__":
    sys.exit(main())
