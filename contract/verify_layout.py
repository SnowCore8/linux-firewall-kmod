#!/usr/bin/env python3
"""netlink 线格式一致性校验：生成物 vs 布局清单 vs daemon 消费方式。

为什么需要这一步
----------------
生成器自己产出的 ``_Static_assert`` 只能证明「生成物自洽」，不能证明
「生成物在 daemon 侧被解析成同一套布局」。若两侧不同（不同编译器、ABI、
packed 规则），换用生成物就等于**静默改变线协议**——内核与 daemon 会互相丢弃
报文，且不会报错。因此必须拿两侧的真实定义做第三方比对。

重写后的口径变化（Phase 1 / Phase 2.D）
--------------------------------------
旧实现把与契约同形的 ``__packed`` 结构体**手抄**在 ``netlink.c`` 里，旧校验器
从 ``netlink.c`` 机械提取结构体、与生成头逐字段比 ``sizeof``/``offsetof``。
两轮重写后两侧手写副本都消失了：

1. **内核侧**不再声明任何报文结构，一律 ``#include`` 生成头（经 ``fw_types.h``）。
   校验器改为**结构断言**（``check_kernel_structure``）：新实现目录里不得出现
   ``struct fw_nl*`` 定义，且必须经 ``fw_types.h`` 引入生成头。
2. **daemon 侧**最后由 ``src/daemon/kernel/codec`` 单点消费生成物（``crate::contract``），
   不再有手写副本可比。于是比对对象改为：**同一份生成物在 C 侧与 Rust 侧解析出的
   尺寸/偏移是否相同**——这是两边唯一的共同事实，也是「同一份定义、两种语言」的
   真正风险点（``IcmpTypeItem.type`` 等字段在两侧的打包行为必须一致）。
3. 为防「布局清单 JSON 与生成头 C 侧漂移」，新增一轮：编译生成头取
   ``sizeof``/``offsetof``，与 ``netlink_layout.json`` 逐字段比。JSON 是历史基准，
   生成头是内核实际编译的输入——两者必须一致，否则内核与 daemon 各自「与 JSON
   一致」却彼此不一致。

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
KERNEL_DIR = os.path.join(ROOT, "src", "kernel-module")
LAYOUT_JSON = os.path.join(GEN_DIR, "netlink_layout.json")

# 生成物结构名 = fw_ + snake(IDL 名)。
# 内核侧重写后**不再手写任何报文结构体**（一律 #include 生成头），故这里没有
# 「内核结构体名 -> IDL 名」映射——内核侧改为结构断言，见 check_kernel_structure()。

# 与 `gen.py::RUST_KEYWORDS` 保持一致：生成器对撞上 Rust 关键字的字段加 `r#`
# 前缀，探针引用同一字段时必须用同样写法。两处清单若漂移，探针会编译失败
# （显式报错），而不是给出错误的通过结论。
RUST_KEYWORDS = frozenset({
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await",
    "abstract", "become", "box", "do", "final", "macro", "override", "priv",
    "typeof", "unsized", "virtual", "yield", "try",
})

# daemon 侧不再手写任何线格式结构体：`src/daemon/kernel/codec` 是唯一的转义层，
# 它直接消费生成物，故「契约 ↔ 实现」由**编译器**对齐，本校验器不再比对手写副本。
#
# 那么这一轮比的是什么？生成物既是内核实际编译的输入（经 `fw_types.h`），也是
# daemon 的模块。C 侧与 Rust 侧解析同一份定义时是否得出**同一套**尺寸与偏移，
# 是两边唯一的共同事实；一旦不同（不同编译器/ABI/打包规则），内核与 daemon 会
# 各自「与自己的结构体一致」却彼此不一致，且不会报错。
#
# 映射覆盖生成物的**全部** 30 个结构（23 条报文 + 7 个公共/尾部结构），
# 由 `RUST_TO_GEN` 显式列出，`main()` 会断言它一个不缺。
RUST_TO_GEN = {
    # 公共头与尾部结构（无公共头/无自身偏移语义）
    "MsgHdr": "MsgHdr",
    "BanEntry": "BanEntry",
    "WhitelistEntry": "WhitelistEntry",
    "RateEntry": "RateEntry",
    "UdpPortItem": "UdpPortItem",
    "IcmpTypeItem": "IcmpTypeItem",
    "ScannerItem": "ScannerItem",
    # 接收方向报文
    "DdosEvent": "DdosEvent",
    "BanStateChange": "BanStateChange",
    "WhitelistStateChange": "WhitelistStateChange",
    "CmdResult": "CmdResult",
    "ConfigAck": "ConfigAck",
    "ConfigChange": "ConfigChange",
    "ListBansResponse": "ListBansResponse",
    "StatsResponse": "StatsResponse",
    "ListWhitelistResponse": "ListWhitelistResponse",
    "ListRatesResponse": "ListRatesResponse",
    "AnalysisResponse": "AnalysisResponse",
    "DaemonRegisterAck": "DaemonRegisterAck",
    # 发送方向报文
    "BanIp": "BanIp",
    "UnbanIp": "UnbanIp",
    "SetConfig": "SetConfig",
    "ListBansQuery": "ListBansQuery",
    "ListWhitelistQuery": "ListWhitelistQuery",
    "ListRatesQuery": "ListRatesQuery",
    "AddWhitelist": "AddWhitelist",
    "RemoveWhitelist": "RemoveWhitelist",
    "StatsQuery": "StatsQuery",
    "AnalysisQuery": "AnalysisQuery",
    "DaemonRegister": "DaemonRegister",
}


def snake(name: str) -> str:
    """与 gen.py 保持完全一致的命名转换（否则探针找不到生成的结构体）。"""
    out = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    out = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", out)
    return out.lower()


def gen_c_name(gen_name: str) -> str:
    return f"fw_{snake(gen_name)}"


def check_kernel_structure() -> list[str]:
    """内核侧结构断言：不手抄报文结构，只消费生成头。

    对应 defect ``KERNEL_NETLINK_STRUCTS_HANDWRITTEN``（status=fixed）：旧实现
    在 ``netlink.c`` 里手抄了 16 个与契约同形的 ``__packed`` 结构体，与生成头
    各改各的。新实现必须满足两点，否则「线格式只有一处」的纪律就被打破：

    (a) 重写后的 ``fw_*.c/h`` 中不存在 ``struct fw_nl*`` **定义**；
    (b) 生成头经 ``fw_types.h`` 引入（内核实际编译的线格式定义来自这里）。

    旧实现文件（``netlink.c`` 等）在 Phase 1 末删除，故不参与本断言——本断言
    只约束新实现，且**不**因为旧文件还在而漏过新文件里的手抄。
    """
    problems: list[str] = []
    new_files = [
        f for f in sorted(os.listdir(KERNEL_DIR))
        if f.startswith("fw_") and f.endswith((".c", ".h"))
    ]
    if not new_files:
        return ["错误: src/kernel-module 下未找到任何 fw_*.c/h 新实现文件"]

    for f in new_files:
        with open(os.path.join(KERNEL_DIR, f), encoding="utf-8") as fh:
            src = fh.read()
        for m in re.finditer(r"^struct (fw_nl\w*)\s*\{", src, re.M):
            problems.append(
                f"{f}: 手写了报文结构体 {m.group(1)}——内核侧不得声明任何报文结构，"
                f"应改由生成头提供"
            )
    if not problems:
        print(f"  {len(new_files)} 个新实现文件均未手写 struct fw_nl* 定义")

    with open(os.path.join(KERNEL_DIR, "fw_types.h"), encoding="utf-8") as fh:
        types_h = fh.read()
    if "#include" in types_h and "generated/netlink_uapi.h" in types_h:
        print("  fw_types.h 经 #include 引入生成头（线格式单处来源）")
    else:
        problems.append("fw_types.h 未引入 contract/generated/netlink_uapi.h")
    return problems


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


def rust_field_expr(name: str) -> str:
    """字段名 → Rust 标识符表达式。

    生成器对撞上 Rust 关键字的字段写成 ``r#type``（如 ``IcmpTypeItem.type``），
    探针必须用同样的写法引用，否则 ``offset_of!`` 直接编译失败。判据必须与生成器
    ``gen.py::RUST_KEYWORDS`` **完全一致**——注意 ``type`` 是 Rust 关键字但不是
    Python 关键字（Python 的 ``keyword`` 模块判不出来），故这里自带一份同名清单。
    布局清单里的名字是原始名，故按需补 ``r#`` 前缀。
    """
    return f"r#{name}" if name in RUST_KEYWORDS else name


def rust_probe(structs: dict[str, list[str]]) -> dict[str, dict[str, object]]:
    """编译生成物并打印其真实结构体的 size_of 与 offset_of!。

    探针**不依赖 daemon crate**，也**不需要手写结构体**——daemon 侧已无手写副本。
    做法是把生成物当成 daemon 里它本来的角色来编译：

    - ``contract`` 模块 = ``contract/generated/netlink_contract.rs``（daemon 里是
      ``crate::contract``）；
    - ``kernel::codec`` 模块 = ``src/daemon/kernel/codec/mod.rs``，按原样引入，
      只补 ``crate::contract`` 这一件事，证明「codec 仅依赖契约」这一分层成真。

    先编成 rlib 骨架，再编一个二进制探针通过 ``--extern`` 取用。任何失败都抛
    ``RuntimeError``（不「跳过」）：探针编不出来就等于生成物未被校验，必须记成
    失败，否则会给出假的通过结论。
    """
    gen_rs = os.path.join(GEN_DIR, "netlink_contract.rs")
    codec_mod = os.path.join(ROOT, "src", "daemon", "kernel", "codec", "mod.rs")
    with tempfile.TemporaryDirectory() as td:
        # crate 骨架：契约真相源 + codec（codec 内有 `pub mod messages;`，
        # 相对 codec/ 目录解析；`#[cfg(test)]` 的测试块不参与编译）。
        lib_src = os.path.join(td, "probe_lib.rs")
        with open(lib_src, "w", encoding="utf-8") as fh:
            fh.write("#![allow(dead_code, unused_imports, non_camel_case_types)]\n")
            fh.write(f'#[path = r"{gen_rs}"]\npub mod contract;\n')
            fh.write("#[allow(dead_code)]\npub mod kernel {\n")
            fh.write(f'    #[path = r"{codec_mod}"]\n    pub mod codec;\n')
            fh.write("}\n")
        rlib = os.path.join(td, "libprobe.rlib")
        skeleton = subprocess.run(
            ["rustc", "--edition", "2021", "--crate-name", "fwprobe",
             "--crate-type", "rlib", "-o", rlib, lib_src],
            capture_output=True,
            text=True,
        )
        if skeleton.returncode != 0:
            raise RuntimeError(
                "探针骨架编译失败（生成物不再是可用的 crate::contract 模块，"
                "或 codec 依赖了契约之外的东西）:\n" + skeleton.stderr[-6000:]
            )

        # 二进制探针：文件名为 measure.rs，避免与 extern crate 名冲突。
        src = os.path.join(td, "measure.rs")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("#![allow(dead_code, unused_imports)]\n")
            fh.write("use fwprobe::contract::*;\n")
            fh.write("fn main() {\n")
            for sn, fns in structs.items():
                fh.write(
                    f'    println!("{sn} - {{}} -1", std::mem::size_of::<{sn}>());\n'
                )
                for fn_ in fns:
                    fh.write(
                        f'    println!("{sn} {fn_} {{}} {{}}", '
                        f"std::mem::size_of::<{sn}>(), "
                        f"std::mem::offset_of!({sn}, {rust_field_expr(fn_)}));\n"
                    )
            fh.write("}\n")
        exe = os.path.join(td, "measure")
        proc = subprocess.run(
            ["rustc", "--edition", "2021", "-O", "--extern", f"fwprobe={rlib}",
             "-o", exe, src],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                "Rust 探针编译失败（生成物结构体无法用 size_of/offset_of 测量）:\n"
                + proc.stderr[-6000:]
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

    def gen_fields(idl: str) -> list[str]:
        """生成物里该结构体的定长字段名（不含变长尾部）。"""
        return [f["name"] for f in layouts[idl]["fields"] if not f.get("tail")]

    with open(os.path.join(GEN_DIR, "netlink_uapi.h"), encoding="utf-8") as fh:
        gen_header = fh.read().replace("#include <linux/types.h>", "")

    gen_names = sorted(gen_c_name(n) for n in layouts)

    gen_fields_by_c: dict[str, list[str]] = {}
    for gname in gen_names:
        idl = next(n for n in layouts if gen_c_name(n) == gname)
        gen_fields_by_c[gname] = gen_fields(idl)

    r_fields = {
        rn: gen_fields(gi) for rn, gi in RUST_TO_GEN.items()
    }

    failures: list[str] = []
    failures += check_kernel_structure()
    print()

    # 映射必须覆盖生成物的**全部**结构，否则新加的报文会在无人比对的情况下上线。
    covered = set(RUST_TO_GEN.values())
    missing = sorted(n for n in layouts if n not in covered)
    if missing:
        failures.append(
            "生成物里有结构未被 C↔Rust 布局比对覆盖：" + ", ".join(missing)
        )
    extra = sorted(n for n in covered if n not in layouts)
    if extra:
        failures.append(
            "布局比对引用了生成物中不存在的结构：" + ", ".join(extra)
        )
    if not missing and not extra:
        print(f"  C↔Rust 布局比对覆盖生成物全部 {len(layouts)} 个结构")
    print()

    with tempfile.TemporaryDirectory() as td:
        g_res = compile_and_run(
            c_probe_source(gen_header, gen_names, gen_fields_by_c), td, "generated"
        )

    # 生成头是内核真正编译的输入，布局清单 JSON 是 daemon 比对的基准。
    # 两侧分别与对方比对：任一漂移都会让内核与 daemon 各自的检查都「通过」
    # 而实际线格式已错——所以这一轮必须比。
    print("=== 生成头 vs 布局清单（C 侧，编译取 sizeof/offsetof）===")
    for gname in gen_names:
        idl = next(n for n in layouts if gen_c_name(n) == gname)
        js = int(layouts[idl]["size"])
        cs = int(g_res[gname]["size"])
        if js != cs:
            failures.append(f"{gname}: sizeof 生成头 {cs} != 布局清单 {js}")
        for fn_ in gen_fields_by_c[gname]:
            co = g_res[gname]["offsets"].get(fn_)  # type: ignore[union-attr]
            jo = next(
                f["offset"] for f in layouts[idl]["fields"] if f["name"] == fn_
            )
            if co != jo:
                failures.append(
                    f"{gname}.{fn_}: offset 生成头 {co} != 布局清单 {jo}"
                )
        mark = "OK " if js == cs else "差异"
        print(f"  {mark} {gname:34} 生成头={cs:5} 清单={js:5}  字段 {len(gen_fields_by_c[gname])} 个")

    print()
    print("=== 生成物：C 侧 vs Rust 侧（编译取 sizeof/offsetof）===")
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
            failures.append(f"{rn}/{gn}: Rust size_of {rs} != C sizeof {gs}")
        for fn_ in r_fields[rn]:
            ro = r_res[rn]["offsets"].get(fn_)  # type: ignore[union-attr]
            go = g_res[gn]["offsets"].get(fn_)  # type: ignore[union-attr]
            if ro != go:
                failures.append(f"{rn}/{gn}.{fn_}: offset Rust {ro} != C {go}")
        mark = "OK " if rs == gs else "差异"
        print(f"  {mark} {rn:30} Rust={rs:5} C={gs:5}  字段 {len(r_fields[rn])} 个")

    print()
    failures.extend(check_artifacts())
    if failures:
        print("一致性校验失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("一致性校验通过：生成头与布局清单一致，生成物在 C 侧与 Rust 侧的布局一致")
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
