#!/usr/bin/env python3
"""netlink 线格式一致性校验：生成头 vs 布局清单 vs 内核消费方式。

为什么需要这一步
----------------
生成器自己产出的 ``_Static_assert`` 只能证明「生成物自洽」，不能证明「生成物
被两侧解析成同一套布局」。若两侧不同（不同编译器、ABI、packed 规则），换用生成物
就等于**静默改变线协议**——内核与 daemon 会互相丢弃报文，且不会报错。因此必须拿
两侧的真实定义做第三方比对。

比的是三方，而不是一方
----------------------
1. **布局清单 JSON**（``netlink_layout.json``）：gen.py 从 IDL 算出的尺寸/偏移，
   是 daemon 侧 ``internal/contract`` 对齐用的基准（那条对齐由 Go 单测负责）。
2. **Python 独立重解析生成头**（``check_python_layout``）：按 packed 规则从
   ``netlink_uapi.h`` 的字段声明重新算一遍 sizeof/offsetof，不依赖任何编译器，
   也不复用 gen.py 的算术——生成器算错布局时这一轮会红。
3. **C 编译探针**（``check_c_layout``）：把生成头交给真实编译器取
   ``sizeof``/``offsetof``，覆盖「同一份头文件在不同 ABI 下是否还是同一套布局」
   这类 Python 重算看不见的问题。

三方两两比对，任一处漂移都是门禁失败。比对**字段偏移**而非仅总长：字段顺序颠倒
但总长相同的结构体，只看 sizeof 会漏掉，而线格式已经错了。

内核侧则做**结构断言**（``check_kernel_structure``）：重写后的 ``fw_*.c/h`` 不再
手抄报文结构体，一律 ``#include`` 生成头（经 ``fw_types.h``）。若有人重新手抄一份
与生成头各改各的，这里就会红。

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
UAPI_HEADER = os.path.join(GEN_DIR, "netlink_uapi.h")

# 生成物结构名 = fw_ + snake(IDL 名)。
# 内核侧不手写任何报文结构体（一律 #include 生成头），故这里没有
# 「内核结构名 -> IDL 名」映射——内核侧是结构断言，见 check_kernel_structure()。

# C 标量 -> 字节宽度。生成头里出现这张表之外的类型即视为无法核对（显式失败）。
C_SCALARS: dict[str, int] = {
    "__u8": 1,
    "__s8": 1,
    "__u16": 2,
    "__s16": 2,
    "__u32": 4,
    "__s32": 4,
    "__u64": 8,
    "__s64": 8,
    "__le16": 2,
    "__le32": 4,
    "__le64": 8,
    "char": 1,
    "__u8_pad": 1,
}

# 消息结构体（IDL 里 ``message``）由生成器在头部嵌入一个公共头字段，布局清单的
# fields 不含它——比对时把它当作唯一允许的前导差异，见 check_python_layout()。
MSG_HDR_FIELD = "hdr"

STRUCT_RE = re.compile(r"^struct (\w+) \{\n(.*?)^\} __packed;", re.M | re.S)
FIELD_RE = re.compile(
    r"^ {4}(?P<type>struct \w+|[A-Za-z_]\w*)\s+(?P<name>\w+)\s*(?:\[(?P<count>\d+)\])?;$",
    re.M,
)
TYPEDEF_RE = re.compile(
    r"^typedef (?P<base>\w+)\s+(?P<name>\w+)\s*(?:\[(?P<count>\d+)\])?;$", re.M
)
STATIC_ASSERT_RE = re.compile(
    r"_Static_assert\(sizeof\(struct (\w+)\) == (\d+),"
)


def snake(name: str) -> str:
    """与 gen.py 保持完全一致的命名转换（否则按 IDL 名找不到生成头的结构体）。"""
    out = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    out = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", out)
    return out.lower()


def gen_c_name(gen_name: str) -> str:
    return f"fw_{snake(gen_name)}"


def read_file(path: str, what: str) -> str:
    """读依赖文件；缺失即抛错（不「跳过」——跳过的门禁等于没门禁）。"""
    if not os.path.isfile(path):
        raise SystemExit(f"错误: 找不到{what}: {path}")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ============================================================================
# 内核侧结构断言
# ============================================================================


def check_kernel_structure() -> list[str]:
    """内核侧结构断言：不手抄报文结构，只消费生成头。

    对应 defect ``KERNEL_NETLINK_STRUCTS_HANDWRITTEN``（status=fixed）：旧实现
    在 ``netlink.c`` 里手抄了 16 个与契约同形的 ``__packed`` 结构体，与生成头
    各改各的。新实现必须满足两点，否则「线格式只有一处」的纪律就被打破：

    (a) ``fw_*.c/h`` 中不存在 ``struct fw_nl*`` **定义**；
    (b) 生成头经 ``fw_types.h`` 引入（内核实际编译的线格式定义来自这里）。
    """
    problems: list[str] = []
    if not os.path.isdir(KERNEL_DIR):
        return [f"错误: 找不到内核实现目录 {KERNEL_DIR}"]
    new_files = [
        f for f in sorted(os.listdir(KERNEL_DIR))
        if f.startswith("fw_") and f.endswith((".c", ".h"))
    ]
    if not new_files:
        return ["错误: src/kernel-module 下未找到任何 fw_*.c/h 新实现文件"]

    for f in new_files:
        src = read_file(os.path.join(KERNEL_DIR, f), f"内核文件 {f}")
        for m in re.finditer(r"^struct (fw_nl\w*)\s*\{", src, re.M):
            problems.append(
                f"{f}: 手写了报文结构体 {m.group(1)}——内核侧不得声明任何报文结构，"
                f"应改由生成头提供"
            )
    if not problems:
        print(f"  {len(new_files)} 个内核实现文件均未手写 struct fw_nl* 定义")

    types_h = read_file(os.path.join(KERNEL_DIR, "fw_types.h"), "内核 fw_types.h")
    if "#include" in types_h and "generated/netlink_uapi.h" in types_h:
        print("  fw_types.h 经 #include 引入生成头（线格式单处来源）")
    else:
        problems.append("fw_types.h 未引入 contract/generated/netlink_uapi.h")
    return problems


# ============================================================================
# 生成头的 Python 重解析（不依赖编译器）
# ============================================================================


def parse_header_structs(header: str) -> dict[str, list[tuple[str, str, int]]]:
    """把生成头解析成 ``{结构名: [(字段名, 类型串, 数组长度或 0)]}``。

    只认生成物自己的写法（4 空格缩进、``} __packed;`` 收尾）；出现解析不出的
    字段行不报错，但结构体缺失/字段缺失都会在后续比对里以差异形式暴露。
    """
    structs: dict[str, list[tuple[str, str, int]]] = {}
    for name, body in STRUCT_RE.findall(header):
        fields: list[tuple[str, str, int]] = []
        for m in FIELD_RE.finditer(body):
            count = int(m.group("count")) if m.group("count") else 0
            fields.append((m.group("name"), m.group("type").strip(), count))
        structs[name] = fields
    return structs


def parse_header_typedefs(header: str) -> dict[str, tuple[str, int]]:
    """``typedef __u8 addr16[16];`` -> ``{addr16: ("__u8", 16)}``。"""
    out: dict[str, tuple[str, int]] = {}
    for m in TYPEDEF_RE.finditer(header):
        out[m.group("name")] = (m.group("base"), int(m.group("count") or 1))
    return out


def parse_static_asserts(header: str) -> dict[str, int]:
    """生成头自带的 ``_Static_assert(sizeof(struct X) == N)`` 清单。"""
    return {n: int(v) for n, v in STATIC_ASSERT_RE.findall(header)}


def compute_layouts(
    structs: dict[str, list[tuple[str, str, int]]],
    typedefs: dict[str, tuple[str, int]],
) -> dict[str, tuple[int, dict[str, int]]]:
    """按 packed 规则算出每个结构体的 ``（总长, {字段名: 偏移}）``。

    packed 意味着**无隐式填充**：偏移就是前面字段宽度之和。空隙必须由 IDL 里显式的
    ``u8[N]`` 表达，所以这里不需要任何对齐表。
    """
    sizes: dict[str, int] = {}
    layouts: dict[str, tuple[int, dict[str, int]]] = {}

    def width(type_token: str, count: int, stack: tuple[str, ...]) -> int:
        base = type_token
        if base.startswith("struct "):
            ref = base[len("struct "):]
            if ref in stack:
                raise SystemExit(f"生成头里结构体递归定义: {' -> '.join(stack + (ref,))}")
            if ref not in structs:
                raise SystemExit(f"生成头里引用了未定义的结构体 {ref}")
            one = layout_of(ref, stack + (ref,))
        elif base in typedefs:
            tbase, tcount = typedefs[base]
            one = width(tbase, tcount, stack)
        elif base in C_SCALARS:
            one = C_SCALARS[base]
        else:
            raise SystemExit(f"生成头里出现无法定宽的类型 {base}")
        return one * (count if count > 1 else 1)

    def layout_of(name: str, stack: tuple[str, ...] = ()) -> int:
        if name in sizes:
            return sizes[name]
        off = 0
        offsets: dict[str, int] = {}
        for fname, ftype, fcount in structs[name]:
            offsets[fname] = off
            off += width(ftype, fcount, stack + (name,))
        sizes[name] = off
        layouts[name] = (off, offsets)
        return off

    for name in structs:
        layout_of(name)
    return layouts


def check_python_layout(
    layouts: dict[str, dict],
    computed: dict[str, tuple[int, dict[str, int]]],
    structs: dict[str, list[tuple[str, str, int]]],
) -> list[str]:
    """布局清单 JSON vs 生成头的 Python 重算结果，逐结构逐字段比对。"""
    problems: list[str] = []
    hdr_cname = gen_c_name("MsgHdr")
    if hdr_cname not in computed:
        return [f"生成头里没有消息头结构体 {hdr_cname}，无法比对字段偏移"]
    hdr_size = computed[hdr_cname][0]

    for idl, spec in sorted(layouts.items()):
        cname = gen_c_name(idl)
        if cname not in computed:
            problems.append(f"生成头里没有结构体 {cname}（布局清单里的 {idl}）")
            continue
        size, offsets = computed[cname]
        want_size = int(spec["size"])
        want_fields = [f for f in spec["fields"] if not f.get("tail")]
        want_names = [f["name"] for f in want_fields]
        got_fields = [f for f, _, _ in structs[cname]]

        # 消息结构体由生成器在头部嵌入一个 `struct fw_msg_hdr hdr`，而清单的 fields
        # 只列消息**自有**字段（offset 是含头后的绝对偏移）。因此这一个嵌入字段是
        # 唯一允许的差异，其余字段必须同名同序——多一个、少一个、顺序颠倒都是红。
        embedded = [f for f in got_fields if f not in set(want_names)]
        if embedded == [MSG_HDR_FIELD]:
            got_names = got_fields[1:]
            if offsets.get(MSG_HDR_FIELD) != 0:
                problems.append(
                    f"{cname}.{MSG_HDR_FIELD}: 嵌入的消息头偏移 "
                    f"{offsets.get(MSG_HDR_FIELD)} != 0"
                )
            elif want_names and int(want_fields[0]["offset"]) != hdr_size:
                problems.append(
                    f"{cname}: 清单首字段 offset {want_fields[0]['offset']} "
                    f"!= 消息头尺寸 {hdr_size}"
                )
        elif embedded:
            problems.append(
                f"{cname}: 生成头里有布局清单之外的字段 {', '.join(embedded)}"
            )
        else:
            got_names = got_fields
            if spec["kind"] == "message":
                problems.append(
                    f"{cname}: 消息结构体缺少嵌入的 {hdr_cname} 头字段"
                )

        if size != want_size:
            problems.append(
                f"{cname}: 生成头重算 sizeof {size} != 布局清单 {want_size}"
            )
        if got_names != want_names:
            problems.append(
                f"{cname}: 生成头字段序 {got_names} != 布局清单 {want_names}"
            )
        for f in want_fields:
            got = offsets.get(f["name"])
            if got != int(f["offset"]):
                problems.append(
                    f"{cname}.{f['name']}: 生成头重算 offset {got} != 布局清单 {f['offset']}"
                )
    return problems


def check_assertions(
    computed: dict[str, tuple[int, dict[str, int]]], asserts: dict[str, int]
) -> list[str]:
    """生成头自述的 ``_Static_assert`` 必须与重算结果一致，且覆盖全部结构体。

    这一轮挡的是「生成头被手改」或「生成器写出的断言与字段声明不符」——两种情况
    下内核编译会失败（好在是响的），但门禁不该等到编译才知道。
    """
    problems: list[str] = []
    for cname in sorted(computed):
        if cname not in asserts:
            problems.append(f"{cname}: 生成头缺少 _Static_assert(sizeof) 断言")
    for cname, want in sorted(asserts.items()):
        if cname not in computed:
            problems.append(f"生成头断言了不存在的结构体 {cname}")
            continue
        got = computed[cname][0]
        if got != want:
            problems.append(f"{cname}: 生成头 _Static_assert {want} != 字段重算 {got}")
    return problems


# ============================================================================
# C 编译探针（真实 ABI）
# ============================================================================


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


def check_c_layout(
    layouts: dict[str, dict], header: str
) -> tuple[list[str], dict[str, dict[str, object]]]:
    """生成头 vs 布局清单，两侧都由真实编译器报数。"""
    problems: list[str] = []
    names = sorted(gen_c_name(n) for n in layouts)
    fields_by_c: dict[str, list[str]] = {}
    for cname in names:
        idl = next(n for n in layouts if gen_c_name(n) == cname)
        fields_by_c[cname] = [f["name"] for f in layouts[idl]["fields"] if not f.get("tail")]

    with tempfile.TemporaryDirectory() as td:
        res = compile_and_run(
            c_probe_source(header.replace("#include <linux/types.h>", ""), names, fields_by_c),
            td,
            "generated",
        )

    print("=== 生成头 vs 布局清单（C 侧，编译取 sizeof/offsetof）===")
    for cname in names:
        idl = next(n for n in layouts if gen_c_name(n) == cname)
        if cname not in res:
            problems.append(f"C 探针缺少 {cname}")
            continue
        js = int(layouts[idl]["size"])
        cs = int(res[cname]["size"])
        if js != cs:
            problems.append(f"{cname}: sizeof 生成头 {cs} != 布局清单 {js}")
        for fn in fields_by_c[cname]:
            co = res[cname]["offsets"].get(fn)  # type: ignore[union-attr]
            jo = next(f["offset"] for f in layouts[idl]["fields"] if f["name"] == fn)
            if co != jo:
                problems.append(f"{cname}.{fn}: offset 生成头 {co} != 布局清单 {jo}")
        mark = "OK " if js == cs else "差异"
        print(
            f"  {mark} {cname:34} C={cs:5} 清单={js:5}  字段 {len(fields_by_c[cname])} 个"
        )
    return problems, res


def check_header_coverage(layouts: dict[str, dict], structs: dict[str, list]) -> list[str]:
    """生成头里的结构体集合必须与布局清单**完全**一致。

    少一个结构体意味着新报文在上线前没人比对过它的布局；多一个意味着生成头被人
    手改或 IDL 里有没被清单收录的结构。两种情况都不允许「默默通过」。
    """
    problems: list[str] = []
    want = {gen_c_name(n) for n in layouts}
    got = set(structs)
    missing = sorted(want - got)
    extra = sorted(got - want)
    if missing:
        problems.append("生成头缺少布局清单里的结构体：" + ", ".join(missing))
    if extra:
        problems.append("生成头里有布局清单之外的结构体：" + ", ".join(extra))
    if not problems:
        print(f"  生成头与布局清单结构体集合一致（{len(want)} 个），全部参与比对")
    return problems


# ============================================================================
# 产物自检
# ============================================================================


def run_tsc(tsc: str, src: str) -> tuple[bool, str, str]:
    """跑一次 ``tsc --noEmit``。

    返回 ``(是否真正执行, 诊断文本, 无法执行的原因)``：tsc 是 node 脚本，node 缺失
    或不可执行时它自己会返回 127 —— 那不是「类型检查通过」也不是「类型检查失败」，
    而是**根本没检查**，必须由调用方显式说明，不能混进失败列表里给出假结论。
    """
    try:
        ver = subprocess.run(
            [tsc, "--version"], capture_output=True, text=True, cwd=ROOT
        )
    except OSError as exc:
        return False, "", str(exc)
    if ver.returncode != 0:
        lines = (ver.stderr or ver.stdout).strip().splitlines()
        return False, "", (lines[0] if lines else "tsc --version 无输出")
    proc = subprocess.run(
        [tsc, "--noEmit", "--strict", "--skipLibCheck", "--target", "es2020",
         "--lib", "es2020,dom", src],
        capture_output=True, text=True, cwd=ROOT,
    )
    return True, (proc.stdout + proc.stderr)[-3000:], ""


def check_artifacts(ts_src: str) -> list[str]:
    """确认 TS 产物能被工具链接受。

    布局比对拿的是生成头的文本与编译结果，这里补上「前端消费的那份声明能否通过
    类型检查」——生成器语法错误不会在布局比对里暴露。工具链不可用时**显式说明
    未校验**（不伪装成通过），与 verify_http.py 同一口径。
    """
    problems: list[str] = []
    print("=== 生成物自检（TS 侧）===")
    ts_name = os.path.basename(ts_src)
    if not os.path.isfile(ts_src):
        raise SystemExit(f"错误: 找不到 TS 产物 {ts_src}，请先运行 gen.py")
    tsc = os.environ.get("TSC") or os.path.join(
        ROOT, "frontend", "node_modules", ".bin", "tsc"
    )
    if not os.path.isfile(tsc):
        print(f"  跳过  {ts_name} tsc（未找到 {tsc}）")
        return problems
    ran, diagnostics, why = run_tsc(tsc, ts_src)
    if not ran:
        print(f"  跳过  {ts_name} tsc（工具链不可用: {why}）")
        return problems
    if diagnostics.strip():
        problems.append(f"{ts_name} 类型检查失败:\n" + diagnostics)
        print(f"  失败  {ts_name} tsc --noEmit")
    else:
        print(f"  OK    {ts_name} tsc --noEmit")
    return problems


def main() -> int:
    if not os.path.isfile(LAYOUT_JSON):
        print("错误: 未找到生成物，请先运行 gen.py", file=sys.stderr)
        return 2
    with open(LAYOUT_JSON, encoding="utf-8") as fh:
        layout = json.load(fh)
    layouts = layout["layouts"]

    header = read_file(UAPI_HEADER, "生成头 netlink_uapi.h")
    structs = parse_header_structs(header)
    computed = compute_layouts(structs, parse_header_typedefs(header))

    failures: list[str] = []

    print("=== 内核侧结构断言 ===")
    failures += check_kernel_structure()
    print()

    print("=== 生成头 vs 布局清单（结构体集合）===")
    failures += check_header_coverage(layouts, structs)
    print()

    print("=== 生成头 vs 布局清单（Python 重算 sizeof/offsetof）===")
    py_problems = check_python_layout(layouts, computed, structs)
    failures += py_problems
    if not py_problems:
        print(f"  OK  {len(structs)} 个结构体的尺寸与全部字段偏移重算一致")
    else:
        for p in py_problems:
            print(f"  差异 {p}")
    print()

    print("=== 生成头自述断言 ===")
    assert_problems = check_assertions(computed, parse_static_asserts(header))
    failures += assert_problems
    if not assert_problems:
        print("  OK  每个结构体都有 _Static_assert，且与字段重算一致")
    else:
        for p in assert_problems:
            print(f"  差异 {p}")
    print()

    failures += check_c_layout(layouts, header)[0]
    print()

    failures += check_artifacts(os.path.join(GEN_DIR, "netlink.d.ts"))
    print()

    if failures:
        print("一致性校验失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        "一致性校验通过：布局清单、生成头（Python 重算 + C 编译 + 自述断言）三方一致，"
        "内核侧未手抄报文结构"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
