#!/usr/bin/env python3
"""三端布局一致性校验：生成物 vs 内核手写 vs daemon 手写。

为什么需要这一步
----------------
生成器自己产出的 ``_Static_assert`` 只能证明「生成物自洽」，不能证明
「生成物与原实现线格式相同」。若两者不等长，换用生成物就等于**静默改变
线协议**——内核与 daemon 会互相丢弃报文，且不会报错。因此必须分别拿
两侧的真实源码定义做第三方比对。

做法
----
1. 从 ``src/kernel-module/netlink.c`` **机械提取**结构体定义（不人工转录，
   避免引入抄写错误），与生成的头文件各自编译，逐字段比对 ``sizeof`` 与
   ``offsetof``。
2. 从 daemon 侧 Rust 结构体取 ``size_of`` 与 ``offset_of!``，同样逐字段比对。

比对**字段偏移**而非仅总长：字段顺序颠倒但总长相同的结构体，只看 sizeof
会漏掉，而线格式已经错了。

用法::

    python3 contract/verify_layout.py
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
KERNEL_NETLINK_C = os.path.join(ROOT, "src", "kernel-module", "netlink.c")
LAYOUT_JSON = os.path.join(GEN_DIR, "netlink_layout.json")

# 生成物结构名 = fw_ + snake(IDL 名)；两侧手写代码用各自的命名
KERNEL_TO_GEN = {
    "fw_nlmsg_hdr": "MsgHdr",
    "fw_nl_ddos_event": "DdosEvent",
    "fw_nl_ban_state_change": "BanStateChange",
    "fw_nl_whitelist_state_change": "WhitelistStateChange",
    "fw_nl_cmd_result": "CmdResult",
    "fw_nl_ban_cmd": "BanIp",
    "fw_nl_config_update": "SetConfig",
    "fw_nl_stats_response": "StatsResponse",
    "fw_nl_udp_port_item": "UdpPortItem",
    "fw_nl_icmp_type_item": "IcmpTypeItem",
    "fw_nl_scanner_item": "ScannerItem",
    "fw_nl_analysis_response": "AnalysisResponse",
    "fw_nl_ban_entry": "BanEntry",
    "fw_nl_list_bans_response": "ListBansResponse",
    "fw_nl_list_bans_query": "ListBansQuery",
    "fw_nl_whitelist_entry": "WhitelistEntry",
    "fw_nl_list_whitelist_response": "ListWhitelistResponse",
    "fw_nl_whitelist_cmd": "AddWhitelist",
    "fw_nl_rate_entry": "RateEntry",
    "fw_nl_list_rates_response": "ListRatesResponse",
    "fw_nl_config_ack": "ConfigAck",
}

# daemon 侧与生成物同形的结构体（其余 daemon 结构体与内核无共用布局）
RUST_TO_GEN = {
    "FwNlMsgHdr": "MsgHdr",
    "FwNlDdosEvent": "DdosEvent",
    "FwNlBanStateChange": "BanStateChange",
    "FwNlWhitelistStateChange": "WhitelistStateChange",
    "FwNlCmdResult": "CmdResult",
    "FwNlBanCmd": "BanIp",
    "FwNlConfigUpdate": "SetConfig",
    "FwNlConfigAck": "ConfigAck",
}


def snake(name: str) -> str:
    """与 gen.py 保持完全一致的命名转换（否则探针找不到生成的结构体）。"""
    out = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    out = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", out)
    return out.lower()


def gen_c_name(gen_name: str) -> str:
    return f"fw_{snake(gen_name)}"


def extract_kernel_structs(src: str) -> str:
    """机械提取 netlink.c 中结构体定义块与其依赖的数值宏。

    数值宏（如 ``FW_NL_ANALYSIS_MAX_UDP_PORTS``）用于数组长度，必须一并提取，
    否则探针无法编译。
    """
    blocks = []
    cur: list[str] = []
    in_block = False
    for line in src.splitlines():
        # 纯数值宏（不含表达式、不含类型）直接保留
        m = re.match(r"^#define\s+(\w+)\s+(\d+)\s*$", line)
        if m and not in_block:
            blocks.append(line)
            continue
        if not in_block:
            if re.match(r"^struct fw_nl\w*\s*\{", line):
                in_block = True
                cur = [line]
            continue
        cur.append(line)
        if re.match(r"^\}\s*__packed;", line):
            blocks.append("\n".join(cur))
            in_block = False
    if in_block:
        raise SystemExit("提取失败: netlink.c 中有未闭合的结构体定义")
    if not any(b.startswith("struct ") for b in blocks):
        raise SystemExit("提取失败: netlink.c 中未找到任何 struct fw_nl* 定义")
    return "\n".join(blocks)


def c_probe_source(defs: str, structs: list[str], fields: dict[str, list[str]]) -> str:
    """生成一个打印 sizeof/offsetof 的 C 探针。

    输出格式固定为 ``结构体 字段 size 偏移`` 或 ``结构体 - size``（无字段时）。
    """
    out = [
        "#include <stdio.h>",
        "#include <stddef.h>",
        "#include <linux/types.h>",
        "#ifndef __packed",
        "#define __packed __attribute__((packed))",
        "#endif",
        "",
        defs,
        "",
        "int main(void) {",
    ]
    for s in structs:
        out.append(
            f'    printf("%s - %zu -1\\n", "{s}", sizeof(struct {s}));'
        )
        for fn in fields.get(s, ()):
            out.append(
                f'    printf("%s {fn} %zu %zu\\n", "{s}", '
                f"sizeof(struct {s}), offsetof(struct {s}, {fn}));"
            )
    out.append("    return 0;")
    out.append("}")
    return "\n".join(out) + "\n"


def parse_probe(stdout: str) -> dict[str, dict[str, object]]:
    """把 ``结构体 [字段] size 偏移`` 解析成 {struct: {"size": n, "offsets": {...}}}。"""
    res: dict[str, dict[str, object]] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        sname, fname, size_s, off_s = parts
        entry = res.setdefault(sname, {"size": int(size_s), "offsets": {}})
        entry["size"] = int(size_s)
        if fname != "-":
            entry["offsets"][fname] = int(off_s)  # type: ignore[index]
    return res


def compile_and_run(src: str, workdir: str, tag: str) -> dict[str, dict[str, object]]:
    path = os.path.join(workdir, f"{tag}.c")
    exe = os.path.join(workdir, tag)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    proc = subprocess.run(
        ["cc", "-O0", "-o", exe, path], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise SystemExit(f"编译 {tag} 失败:\n{proc.stderr}")
    run = subprocess.run([exe], capture_output=True, text=True)
    if run.returncode != 0:
        raise SystemExit(f"运行 {tag} 失败:\n{run.stderr}")
    return parse_probe(run.stdout)


def rust_probe(structs: dict[str, list[str]]) -> dict[str, dict[str, object]]:
    """编译一段 Rust，打印 daemon 侧真实结构体的 size_of 与 offset_of!。

    这是**独立于 crate** 的探针：只用 rustc 直接编译那两个源文件。它们
    ``use anyhow::Result``，所以先离线编一个同名 rlib 作为 ``anyhow`` 替身，
    再通过 ``--extern anyhow=...`` 接入——这样文件里的路径解析方式与真实
    构建完全一致，替身不需要任何语义模拟。替身只提供 ``Result`` /
    ``bail!`` / ``anyhow!`` 这三个被引用到的名字。

    任何失败都抛 ``RuntimeError``（不「跳过」）：探针编不出来就等于 daemon
    侧未被校验，必须记成失败，否则会给出假的通过结论。
    """
    proto = os.path.join(ROOT, "src", "daemon", "netlink", "protocol.rs")
    responses = os.path.join(ROOT, "src", "daemon", "netlink", "responses.rs")
    anyhow_stub = """\
// verify_layout.py 的探针专用替身：只补结构体尺寸/偏移测量所需的三个名字。
#[derive(Debug)]
pub struct ProbeError;

impl core::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "probe error")
    }
}

impl core::error::Error for ProbeError {}

pub type Result<T> = core::result::Result<T, ProbeError>;

#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::core::result::Result::Err($crate::ProbeError)
    };
}

#[macro_export]
macro_rules! anyhow {
    ($($arg:tt)*) => {
        $crate::ProbeError
    };
}
"""
    with tempfile.TemporaryDirectory() as td:
        stub_src = os.path.join(td, "anyhow_stub.rs")
        with open(stub_src, "w", encoding="utf-8") as fh:
            fh.write(anyhow_stub)
        rlib = os.path.join(td, "libanyhow.rlib")
        stub = subprocess.run(
            ["rustc", "--edition", "2021", "--crate-name", "anyhow",
             "--crate-type", "rlib", "--out-dir", td, "-o", rlib, stub_src],
            capture_output=True,
            text=True,
        )
        if stub.returncode != 0:
            raise RuntimeError("anyhow 替身编译失败:\n" + stub.stderr[-4000:])

        src = os.path.join(td, "probe.rs")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("#![allow(dead_code, unused_imports)]\n")
            fh.write(f'#[path = r"{proto}"]\nmod protocol;\n')
            fh.write(f'#[path = r"{responses}"]\nmod responses;\n')
            fh.write("use protocol::*;\nuse responses::*;\n")
            fh.write("fn main() {\n")
            for sn, fns in structs.items():
                fh.write(
                    f'    println!("{sn} - {{}} -1", std::mem::size_of::<{sn}>());\n'
                )
                for fn_ in fns:
                    fh.write(
                        f'    println!("{sn} {fn_} {{}} {{}}", '
                        f"std::mem::size_of::<{sn}>(), "
                        f"std::mem::offset_of!({sn}, {fn_}));\n"
                    )
            fh.write("}\n")
        exe = os.path.join(td, "probe")
        proc = subprocess.run(
            ["rustc", "--edition", "2021", "-O", "--extern", f"anyhow={rlib}",
             "-o", exe, src],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "Rust 探针编译失败（daemon 结构体依赖了 protocol.rs / "
                "responses.rs 之外的东西？）:\n" + proc.stderr[-6000:]
            )
        run = subprocess.run([exe], capture_output=True, text=True)
        if run.returncode != 0:
            raise RuntimeError("Rust 探针运行失败:\n" + run.stderr[-2000:])
        return parse_probe(run.stdout)


def main() -> int:
    if not os.path.isfile(LAYOUT_JSON):
        print("错误: 未找到生成物，请先运行 gen.py", file=sys.stderr)
        return 2
    with open(LAYOUT_JSON, encoding="utf-8") as fh:
        layout = json.load(fh)
    layouts = layout["layouts"]
    gen_sizes = {n: v["size"] for n, v in layouts.items()}

    def gen_fields(idl: str) -> list[str]:
        """生成物里该结构体的定长字段名（不含变长尾部）。"""
        return [f["name"] for f in layouts[idl]["fields"] if not f.get("tail")]

    with open(KERNEL_NETLINK_C, encoding="utf-8") as fh:
        kernel_defs = extract_kernel_structs(fh.read())
    with open(os.path.join(GEN_DIR, "netlink_uapi.h"), encoding="utf-8") as fh:
        gen_header = fh.read().replace("#include <linux/types.h>", "")

    kernel_names = sorted(re.findall(r"^struct (fw_nl\w*)\s*\{", kernel_defs, re.M))
    gen_names = sorted(gen_c_name(n) for n in layouts)

    # 内核探针字段：由「内核结构体名 -> IDL 名 -> 生成物字段名」推出。
    # 内核结构体首字段可能是公共头 hdr，探针里保留原名即可（内核真实成员名）。
    kernel_fields: dict[str, list[str]] = {}
    kernel_field_map: dict[str, list[str]] = {}
    for kn in kernel_names:
        idl = KERNEL_TO_GEN.get(kn)
        if idl is None:
            continue
        fns = gen_fields(idl)
        kernel_fields[kn] = (["hdr"] if layouts[idl].get("kind") == "message" else []) + fns
        kernel_field_map[kn] = fns

    gen_fields_by_c: dict[str, list[str]] = {}
    for gname in gen_names:
        idl = next(n for n in layouts if gen_c_name(n) == gname)
        gen_fields_by_c[gname] = gen_fields(idl)

    r_fields = {
        rn: gen_fields(gi) for rn, gi in RUST_TO_GEN.items()
    }

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        k_res = compile_and_run(
            c_probe_source(kernel_defs, kernel_names, kernel_fields), td, "kernel"
        )
        g_res = compile_and_run(
            c_probe_source(gen_header, gen_names, gen_fields_by_c), td, "generated"
        )

    print("=== 内核手写 vs 生成物（C 侧，编译取 sizeof/offsetof）===")
    for kn in kernel_names:
        idl = KERNEL_TO_GEN.get(kn)
        if idl is None:
            print(f"  {kn:36} {k_res[kn]['size']:5}  （生成物无对应，跳过）")
            continue
        gn = gen_c_name(idl)
        ks, gs = int(k_res[kn]["size"]), int(g_res[gn]["size"])
        if ks != gs:
            failures.append(f"{kn}/{gn}: sizeof 内核 {ks} != 生成 {gs}")
        for fn_ in kernel_field_map[kn]:
            ko = k_res[kn]["offsets"].get(fn_)  # type: ignore[union-attr]
            go = g_res[gn]["offsets"].get(fn_)  # type: ignore[union-attr]
            if ko != go:
                failures.append(
                    f"{kn}/{gn}.{fn_}: offset 内核 {ko} != 生成 {go}"
                )
        mark = "OK " if ks == gs else "差异"
        print(f"  {mark} {kn:34} 内核={ks:5} 生成={gs:5}  字段 {len(kernel_field_map[kn])} 个")

    print()
    print("=== daemon 手写 vs 生成物（Rust 侧，编译取 size_of/offset_of）===")
    try:
        r_res = rust_probe({rn: r_fields[rn] for rn in RUST_TO_GEN})
    except RuntimeError as exc:
        print(f"  （失败）{exc}")
        failures.append(f"Rust 侧探针未产出结果: {exc}")
        r_res = {}
    for rn in sorted(RUST_TO_GEN):
        idl = RUST_TO_GEN[rn]
        gn = gen_c_name(idl)
        if rn not in r_res:
            failures.append(f"Rust 探针缺少 {rn}")
            continue
        rs = int(r_res[rn]["size"])
        gs = int(g_res[gn]["size"])
        if rs != gs:
            failures.append(f"{rn}/{gn}: size_of {rs} != 生成 {gs}")
        for fn_ in r_fields[rn]:
            ro = r_res[rn]["offsets"].get(fn_)  # type: ignore[union-attr]
            go = g_res[gn]["offsets"].get(fn_)  # type: ignore[union-attr]
            if ro != go:
                failures.append(f"{rn}/{gn}.{fn_}: offset daemon {ro} != 生成 {go}")
        mark = "OK " if rs == gs else "差异"
        print(f"  {mark} {rn:30} daemon={rs:5} 生成={gs:5}  字段 {len(r_fields[rn])} 个")

    print()
    failures.extend(check_artifacts())
    if failures:
        print("一致性校验失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("一致性校验通过：三端布局完全一致")
    return 0


def _toolchain_check(problems: list[str], rs_src: str, ts_src: str) -> None:
    """用各自工具链编译一对生成物（Rust + TS）。

    布局比对只覆盖手写代码，这里补上「产物能否被各自工具链接受」——
    生成器语法错误（如漏转义 Rust 关键字）不会在三方比对里暴露。
    """
    m = re.search(r"([\w.-]+\.rs)$", rs_src)
    rs_name = m.group(1) if m else os.path.basename(rs_src)
    if os.path.isfile(rs_src):
        with tempfile.TemporaryDirectory() as td:
            rlib = os.path.join(td, "c.rlib")
            proc = subprocess.run(
                ["rustc", "--edition", "2021", "--crate-type", "lib",
                 "-o", rlib, rs_src],
                capture_output=True, text=True,
            )
            if proc.returncode != 0:
                problems.append(f"{rs_name} 编译失败:\n" + proc.stderr[-3000:])
                print(f"  失败  {rs_name} 编译")
            else:
                print(f"  OK    {rs_name} 编译")

    m = re.search(r"([\w.-]+\.(?:ts|d\.ts))$", ts_src)
    ts_name = m.group(1) if m else os.path.basename(ts_src)
    # 前端依赖装在 frontend/ 下，tsc 也从那里找
    tsc = os.environ.get("TSC") or os.path.join(ROOT, "frontend", "node_modules", ".bin", "tsc")
    if not os.path.isfile(ts_src):
        return
    if os.path.isfile(tsc):
        proc = subprocess.run(
            [tsc, "--noEmit", "--strict", "--skipLibCheck", "--target", "es2020",
             "--lib", "es2020,dom", ts_src],
            capture_output=True, text=True, cwd=ROOT,
        )
        if proc.returncode != 0:
            problems.append(f"{ts_name} 类型检查失败:\n" + proc.stdout[-3000:])
            print(f"  失败  {ts_name} tsc --noEmit")
        else:
            print(f"  OK    {ts_name} tsc --noEmit")
    else:
        # 前端依赖未安装时不算失败，但必须显式说明「未校验」
        print(f"  跳过  {ts_name} tsc（未找到 {tsc}）")


def check_artifacts() -> list[str]:
    """确认生成物本身可用：Rust 契约能编译、TS 契约能过类型检查。"""
    problems: list[str] = []
    print("=== 生成物自检（各自工具链）===")
    _toolchain_check(
        problems,
        os.path.join(GEN_DIR, "netlink_contract.rs"),
        os.path.join(GEN_DIR, "netlink.d.ts"),
    )
    print()
    return problems


if __name__ == "__main__":
    sys.exit(main())
