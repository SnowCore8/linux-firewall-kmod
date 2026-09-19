#!/usr/bin/env python3
"""契约生成器：从 .fwidl 单一真相源产出三端绑定。

用法::

    python3 contract/gen.py contract/netlink.fwidl --targets c,rust,json

产出目录：``contract/generated/``

设计要点
--------
1. **packed 布局**：所有结构体无隐式填充，字段按声明顺序紧排。需要空隙处必须在
   IDL 里显式写 ``u8[N]``，避免「靠对齐产生空隙」这种不可审查的隐含假设。
2. **静态校验在生成期完成**：枚举取值唯一且落在声明宽度内、位标志序号不越界、
   结构体名唯一、消息长度不突破 ``msg_len`` 的 u16 上限。校验失败即非零退出，
   不给下游留下「看起来生成成功、实际线格式错」的产物。
3. **容量余量打印**：变长消息会算出「u16 长度上限内最多可承载多少尾部条目」，
   防止再次出现历史上「一次返回全部条目导致 msg_len 回绕」的缺陷。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

# msg_len 是 u16，消息总长上限
MSG_LEN_MAX = 0xFFFF

# 标量类型 -> 字节宽度
SCALARS: Dict[str, int] = {
    "u8": 1,
    "u16": 2,
    "u32": 4,
    "u64": 8,
    "i16": 2,
    "i32": 4,
}

# Rust 关键字中会与常见协议字段名冲突的部分（如 ICMP 的 type）。
# 生成 Rust 结构体字段时需加 r# 前缀转义。
RUST_KEYWORDS = frozenset({
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
    "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super",
    "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await",
    "abstract", "become", "box", "do", "final", "macro", "override", "priv",
    "typeof", "unsized", "virtual", "yield", "try",
})


class ContractError(Exception):
    """契约解析或校验失败。"""


# ============================================================================
# 类型模型
# ============================================================================


class FType:
    """一个字段的类型。

    kind 取值：
      - ``int``    标量整数，``ref`` 是 ``u8`` 等宽度名
      - ``str``    定长 NUL 结尾字符串，``count`` 为字节数
      - ``bytes``  裸字节数组（``u8[N]``），``count`` 为字节数
      - ``alias``  指向 ``alias`` 声明，``ref`` 为其名字
      - ``struct`` 指向结构体声明，``ref`` 为其名字
    """

    __slots__ = ("kind", "ref", "count")

    def __init__(self, kind: str, ref: str = "", count: int = 0):
        self.kind = kind
        self.ref = ref
        self.count = count

    def __repr__(self) -> str:  # pragma: no cover - 仅用于报错信息
        if self.kind == "str":
            return f"str[{self.count}]"
        if self.kind == "bytes":
            return f"u8[{self.count}]"
        return self.ref if not self.count else f"{self.ref}[{self.count}]"


class Field:
    __slots__ = ("name", "type", "is_tail")

    def __init__(self, name: str, type_: FType, is_tail: bool = False):
        self.name = name
        self.type = type_
        self.is_tail = is_tail


class StructDecl:
    def __init__(self, name: str, line: int):
        self.name = name
        self.line = line
        self.fields: List[Field] = []


class MessageDecl:
    def __init__(self, name: str, line: int, msg_type: Optional[str] = None):
        self.name = name
        self.line = line
        self.msg_type = msg_type  # "MsgType::DDOS_EVENT"
        self.fields: List[Field] = []


class EnumDecl:
    def __init__(self, name: str, line: int, width: str):
        self.name = name
        self.line = line
        self.width = width
        self.members: List[Tuple[str, int]] = []


class BitsDecl:
    def __init__(self, name: str, line: int, width: str):
        self.name = name
        self.line = line
        self.width = width
        self.members: List[Tuple[str, int]] = []


class Contract:
    def __init__(self, path: str):
        self.path = path
        self.namespace = ""
        self.magic: Optional[Tuple[str, int]] = None
        self.aliases: Dict[str, FType] = {}
        self.structs: Dict[str, StructDecl] = {}
        self.messages: Dict[str, MessageDecl] = {}
        self.enums: Dict[str, EnumDecl] = {}
        self.bits_decls: Dict[str, BitsDecl] = {}
        # 解析顺序，保证生成产物顺序稳定
        self.order: List[Tuple[str, str]] = []


# ============================================================================
# 解析
# ============================================================================


def _strip_comment(line: str) -> str:
    """去掉 ``#`` 起的行尾注释（本格式无字符串字面量，故可简单切分）。"""
    idx = line.find("#")
    return line if idx < 0 else line[:idx]


_ARRAY_SUFFIX_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]$")


def _parse_type_token(tok: str, contract: Contract) -> FType:
    """把一个类型记号解析为 FType（不含数组后缀，后缀由调用方处理）。"""
    if tok in SCALARS:
        return FType("int", tok)
    m = re.fullmatch(r"str\[(\d+)\]", tok)
    if m:
        return FType("str", count=int(m.group(1)))
    m = re.fullmatch(r"u8\[(\d+)\]", tok)
    if m:
        return FType("bytes", count=int(m.group(1)))
    # alias 或结构体，稍后（全部读数后）再解析引用有效性
    return FType("alias_or_struct", tok)


def parse(path: str) -> Contract:
    contract = Contract(path)
    with open(path, "r", encoding="utf-8") as fh:
        raw_lines = fh.readlines()

    # 保留行号用于报错
    lines = [(i + 1, _strip_comment(l).strip()) for i, l in enumerate(raw_lines)]

    # 统一转成「声明块」形式：把 { ... } 展开为若干块
    idx = 0
    pending: List[Tuple[int, str]] = []  # 当前块内的内容行

    def flush_block(block: List[Tuple[int, str]], open_line: int, header: str) -> None:
        _parse_block(contract, header, open_line, block)

    block_header: Optional[str] = None
    block_open_line = 0

    while idx < len(lines):
        lineno, text = lines[idx]
        if not text:
            idx += 1
            continue
        if block_header is None:
            if text.endswith("{"):
                block_header = text[:-1].strip()
                block_open_line = lineno
                pending = []
                idx += 1
                continue
            if text == "}":
                raise ContractError(f"{path}:{lineno}: 出现孤立的 '}}'")
            _parse_toplevel(contract, text, lineno)
            idx += 1
        else:
            if text == "}":
                flush_block(pending, block_open_line, block_header)
                block_header = None
                pending = []
                idx += 1
                continue
            if text.endswith("{"):
                raise ContractError(f"{path}:{lineno}: 不支持嵌套块")
            pending.append((lineno, text))
            idx += 1

    if block_header is not None:
        raise ContractError(f"{path}:{block_open_line}: 块未闭合（缺少 '}}'）")

    _resolve_type_refs(contract)
    return contract


def _parse_toplevel(contract: Contract, text: str, lineno: int) -> None:
    m = re.fullmatch(r"namespace\s+(\w+)", text)
    if m:
        contract.namespace = m.group(1)
        return
    m = re.fullmatch(r"magic\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)", text)
    if m:
        contract.magic = (m.group(1), int(m.group(2), 0))
        return
    m = re.fullmatch(r"alias\s+(\w+)\s*=\s*(\S+)", text)
    if m:
        name, tok = m.group(1), m.group(2)
        if name in contract.aliases:
            raise ContractError(f"{contract.path}:{lineno}: alias {name} 重复定义")
        # alias 的右侧必须是 u8[N] 形式
        am = re.fullmatch(r"u8\[(\d+)\]", tok)
        if not am:
            raise ContractError(
                f"{contract.path}:{lineno}: alias {name} 只支持 u8[N] 形式，实际为 {tok}"
            )
        contract.aliases[name] = FType("bytes", count=int(am.group(1)))
        contract.order.append(("alias", name))
        return
    m = re.fullmatch(r"message\s+(\w+)\s*=\s*(\w+)\s*::\s*(\w+)", text)
    if m:
        name = m.group(1)
        if name in contract.messages:
            raise ContractError(f"{contract.path}:{lineno}: message {name} 重复定义")
        decl = MessageDecl(name, lineno, f"{m.group(2)}::{m.group(3)}")
        contract.messages[name] = decl
        contract.order.append(("message", name))
        return
    raise ContractError(f"{contract.path}:{lineno}: 无法解析的顶层声明: {text!r}")


def _parse_block(
    contract: Contract, header: str, open_line: int, body: List[Tuple[int, str]]
) -> None:
    m = re.fullmatch(r"enum\s+(\w+)\s*:\s*(\w+)", header)
    if m:
        width = m.group(2)
        if width not in SCALARS or SCALARS[width] == 0 or width.startswith("i"):
            raise ContractError(
                f"{contract.path}:{open_line}: enum 宽度必须是无符号整数类型，实际 {width}"
            )
        decl = EnumDecl(m.group(1), open_line, width)
        for lineno, text in body:
            mm = re.fullmatch(r"(\w+)\s*=\s*(-?\d+)", text)
            if not mm:
                raise ContractError(f"{contract.path}:{lineno}: 无法解析枚举成员: {text!r}")
            decl.members.append((mm.group(1), int(mm.group(2))))
        if m.group(1) in contract.enums or m.group(1) in contract.bits_decls:
            raise ContractError(f"{contract.path}:{open_line}: 枚举/位标志 {m.group(1)} 重复定义")
        contract.enums[decl.name] = decl
        contract.order.append(("enum", decl.name))
        return

    m = re.fullmatch(r"bits\s+(\w+)\s*:\s*(\w+)", header)
    if m:
        width = m.group(2)
        if width not in SCALARS or width.startswith("i"):
            raise ContractError(
                f"{contract.path}:{open_line}: bits 宽度必须是无符号整数类型，实际 {width}"
            )
        decl = BitsDecl(m.group(1), open_line, width)
        for lineno, text in body:
            mm = re.fullmatch(r"(\w+)\s*=\s*(\d+)", text)
            if not mm:
                raise ContractError(f"{contract.path}:{lineno}: 无法解析位标志: {text!r}")
            decl.members.append((mm.group(1), int(mm.group(2))))
        if decl.name in contract.enums or decl.name in contract.bits_decls:
            raise ContractError(f"{contract.path}:{open_line}: 枚举/位标志 {decl.name} 重复定义")
        contract.bits_decls[decl.name] = decl
        contract.order.append(("bits", decl.name))
        return

    m = re.fullmatch(r"(struct|message)\s+(\w+)", header)
    if m:
        kind, name = m.group(1), m.group(2)
        if name in contract.structs or name in contract.messages:
            raise ContractError(f"{contract.path}:{open_line}: {kind} {name} 重复定义")
        if kind == "struct":
            decl = StructDecl(name, open_line)
            target = contract.structs
        else:
            decl = MessageDecl(name, open_line, None)
            target = contract.messages
        target[name] = decl
        contract.order.append((kind, name))

        for lineno, text in body:
            tm = re.fullmatch(r"type\s*=\s*(\w+)\s*::\s*(\w+)", text)
            if tm:
                if kind != "message":
                    raise ContractError(
                        f"{contract.path}:{lineno}: struct 内不允许 'type = ...'"
                    )
                if decl.msg_type is not None:
                    raise ContractError(f"{contract.path}:{lineno}: type 重复声明")
                decl.msg_type = f"{tm.group(1)}::{tm.group(2)}"
                continue
            decl.fields.append(_parse_field(contract, text, lineno))
        if kind == "message" and decl.msg_type is None:
            raise ContractError(f"{contract.path}:{open_line}: message {name} 缺少 type 声明")
        return

    raise ContractError(f"{contract.path}:{open_line}: 无法解析的块头: {header!r}")


def _parse_field(contract: Contract, text: str, lineno: int) -> Field:
    """解析一行字段声明。

    支持的写法（``TYPE NAME`` / ``TYPE NAME[N]``）::

        u32 magic
        str[32] reason
        u8[3] pad
        u64 pkt_sizes[5]
        BanEntry tail
    """
    parts = text.split()
    if len(parts) != 2:
        raise ContractError(f"{contract.path}:{lineno}: 字段声明应为 '<类型> <名字>': {text!r}")
    type_tok, name_tok = parts

    count = 0
    nm = _ARRAY_SUFFIX_RE.fullmatch(name_tok)
    if nm:
        name, count = nm.group(1), int(nm.group(2))
        if count <= 0:
            raise ContractError(f"{contract.path}:{lineno}: 数组长度必须为正: {name_tok}")
    else:
        if not re.fullmatch(r"[A-Za-z_]\w*", name_tok):
            raise ContractError(f"{contract.path}:{lineno}: 字段名非法: {name_tok!r}")
        name = name_tok

    ftype = _parse_type_token(type_tok, contract)
    if count:
        # 类型记号自带 [N] 与名字自带 [N] 不允许同时出现
        if ftype.kind == "bytes" or ftype.kind == "str":
            raise ContractError(
                f"{contract.path}:{lineno}: {type_tok} 已含长度，名字不应再带 [N]"
            )
        ftype = FType(ftype.kind, ftype.ref, count)
    return Field(name, ftype)


def _resolve_type_refs(contract: Contract) -> None:
    """把 ``alias_or_struct`` 解析成 ``alias`` / ``struct``，并校验引用存在。"""

    def resolve(t: FType, where: str) -> FType:
        if t.kind != "alias_or_struct":
            return t
        if t.ref in contract.aliases:
            return FType("alias", t.ref, t.count)
        if t.ref in contract.structs or t.ref in contract.messages:
            return FType("struct", t.ref, t.count)
        raise ContractError(f"{where}: 引用了未定义的类型 {t.ref}")

    for kind, name in contract.order:
        if kind in ("struct", "message"):
            decl = contract.structs.get(name) or contract.messages.get(name)
            for f in decl.fields:
                f.type = resolve(f.type, f"{contract.path}:{decl.line}: {name}.{f.name}")
                # 尾部元素必须是结构体且不能是数组
                if f.name == "tail":
                    if f.type.kind != "struct" or f.type.count:
                        raise ContractError(
                            f"{contract.path}:{decl.line}: {name} 的 tail 必须是单个结构体类型"
                        )
                    f.is_tail = True


# ============================================================================
# 布局计算与校验
# ============================================================================


def struct_size(contract: Contract, name: str, _stack: Optional[List[str]] = None) -> int:
    """计算 packed 结构体的字节大小。"""
    return _layout(contract, name, _stack)[0]


def _layout(
    contract: Contract, name: str, _stack: Optional[List[str]] = None
) -> Tuple[int, List[Tuple[str, int, str, int]]]:
    """返回 ``(总大小, [(字段名, 偏移, 类型字符串, 字段大小), ...])``。"""
    stack = list(_stack or [])
    if name in stack:
        raise ContractError(f"结构体递归引用: {' -> '.join(stack + [name])}")
    stack.append(name)
    decl = contract.structs.get(name) or contract.messages.get(name)
    if decl is None:
        raise ContractError(f"未定义的结构体: {name}")

    offset = 0
    entries: List[Tuple[str, int, str, int, bool]] = []
    if isinstance(decl, MessageDecl):
        # 消息体前面固定带公共头
        hdr_size, _ = _layout(contract, "MsgHdr", stack)
        offset = hdr_size
    for f in decl.fields:
        fsize = field_size(contract, f, stack)
        entries.append((f.name, offset, str(f.type), fsize, f.is_tail))
        offset += fsize
    stack.pop()
    return offset, entries


def field_size(contract: Contract, f: Field, stack: List[str]) -> int:
    t = f.type
    mult = t.count if (t.kind in ("int", "alias", "struct") and t.count) else 1
    if t.kind == "int":
        return SCALARS[t.ref] * mult
    if t.kind in ("str", "bytes"):
        return t.count
    if t.kind == "alias":
        base = contract.aliases[t.ref]
        return base.count * mult
    if t.kind == "struct":
        return struct_size(contract, t.ref, stack) * mult
    raise ContractError(f"无法计算字段大小: {f.name} ({t})")


def validate(contract: Contract) -> List[str]:
    """执行全部静态校验，返回人类可读的提示行（校验失败抛 ContractError）。"""
    notes: List[str] = []

    # 魔数必须声明（线格式靠它辨别本协议报文）
    if contract.magic is None:
        raise ContractError("缺少 'magic NAME = 0x...' 声明")

    # 枚举：取值唯一、落在宽度内
    for name, decl in contract.enums.items():
        width_bits = SCALARS[decl.width] * 8
        seen: Dict[int, str] = {}
        for member, value in decl.members:
            if not (0 <= value < (1 << width_bits)):
                raise ContractError(
                    f"enum {name}: {member} = {value} 超出 {decl.width} 取值范围"
                )
            if value in seen:
                raise ContractError(
                    f"enum {name}: {member} 与 {seen[value]} 取值重复（{value}）"
                )
            seen[value] = member
        notes.append(f"enum {name}: {len(decl.members)} 个成员，宽度 {decl.width}")

    # 位标志：序号唯一、不越界
    for name, decl in contract.bits_decls.items():
        width_bits = SCALARS[decl.width] * 8
        seen_bit: Dict[int, str] = {}
        for member, bit in decl.members:
            if bit >= width_bits:
                raise ContractError(
                    f"bits {name}: {member} 位序号 {bit} 超出 {decl.width} 的 {width_bits} 位"
                )
            if bit in seen_bit:
                raise ContractError(
                    f"bits {name}: {member} 与 {seen_bit[bit]} 位序号重复（{bit}）"
                )
            seen_bit[bit] = member
        notes.append(f"bits {name}: {len(decl.members)} 个标志，宽度 {decl.width}")

    # 消息类型取值必须都在 MsgType 枚举里，且 msg_type 引用真实存在
    if "MsgType" not in contract.enums:
        raise ContractError("缺少 MsgType 枚举，无法校验消息类型")
    msg_values = dict(contract.enums["MsgType"].members)

    for name, decl in contract.messages.items():
        if not decl.msg_type:
            raise ContractError(f"message {name}: 缺少 msg_type")
        enum_name, member = decl.msg_type.split("::")
        if enum_name != "MsgType":
            raise ContractError(f"message {name}: msg_type 必须引用 MsgType")
        if member not in msg_values:
            raise ContractError(f"message {name}: MsgType::{member} 未定义")

    # 未覆盖的 MsgType 成员（允许，但提示出来，避免契约漏项）
    covered = {d.msg_type.split("::")[1] for d in contract.messages.values()}
    missing = [m for m, _ in contract.enums["MsgType"].members if m not in covered]
    if missing:
        notes.append(f"注意: MsgType 中未在任何 message 中出现的成员: {', '.join(missing)}")

    # 消息长度上限
    hdr_size = struct_size(contract, "MsgHdr")
    notes.append(f"公共头 MsgHdr: {hdr_size} 字节")
    for name, decl in contract.messages.items():
        size, entries = _layout(contract, name)
        tail = [f for f in decl.fields if f.is_tail]
        if tail:
            t = tail[0]
            elem = struct_size(contract, t.type.ref)
            fixed = size - elem
            max_elems = (MSG_LEN_MAX - fixed) // elem
            notes.append(
                f"message {name}: 定长 {fixed} 字节 + 尾部 {t.type.ref}({elem} 字节) × N；"
                f"u16 上限内最多 {max_elems} 条"
            )
            if fixed >= MSG_LEN_MAX:
                raise ContractError(
                    f"message {name}: 定长部分 {fixed} 已超出 msg_len 上限 {MSG_LEN_MAX}"
                )
            if max_elems < 1:
                raise ContractError(f"message {name}: 连 1 条尾部条目都放不下")
        else:
            if size > MSG_LEN_MAX:
                raise ContractError(
                    f"message {name}: 总长 {size} 超出 msg_len 上限 {MSG_LEN_MAX}"
                )
            notes.append(f"message {name}: 定长 {size} 字节")
        # 逐字段偏移在 layout JSON 中输出（供 verify_layout.py 做三端比对）
    return notes


# ============================================================================
# 命名转换
# ============================================================================


def snake(name: str) -> str:
    """``BanStateChange`` -> ``ban_state_change``。"""
    out = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    out = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", out)
    return out.lower()


def upper_snake(name: str) -> str:
    return snake(name).upper()


def pascal_from_upper_snake(name: str) -> str:
    """``DDOS_EVENT`` -> ``DdosEvent``。"""
    return "".join(p[:1].upper() + p[1:].lower() for p in name.split("_") if p)


# ============================================================================
# 产物：C 头
# ============================================================================


def emit_c(contract: Contract, guard: str) -> str:
    L: List[str] = []
    L.append("/* 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。 */")
    L.append("/* 单一真相源: %s */" % os.path.basename(contract.path))
    L.append("")
    L.append(f"#ifndef {guard}")
    L.append(f"#define {guard}")
    L.append("")
    L.append("#include <linux/types.h>")
    L.append("")

    if contract.magic:
        mname, mval = contract.magic
        L.append(f"#define {mname} 0x{mval:08X}U")
        L.append("")

    # 别名
    for name, t in contract.aliases.items():
        L.append(f"typedef __u8 {snake(name)}[{t.count}];")
    if contract.aliases:
        L.append("")

    # 枚举
    for name, decl in contract.enums.items():
        base = ("__u8", "__u16", "__u32", "__u64")[SCALARS[decl.width].bit_length() - 1]
        L.append(f"enum fw_{snake(name)} {{")
        for member, value in decl.members:
            L.append(f"    FW_{upper_snake(name)}_{member} = {value},")
        L.append("};")
        L.append(f"/* 枚举底层宽度 {decl.width} -> {base} */")
        L.append("")

    # 位标志
    for name, decl in contract.bits_decls.items():
        for member, bit in decl.members:
            L.append(f"#define FW_{upper_snake(name)}_{member} (1U << {bit})")
        L.append("")

    # 结构体与消息
    for kind, name in contract.order:
        if kind == "struct":
            decl = contract.structs[name]
            L.append(f"struct fw_{snake(name)} {{")
            _emit_c_fields(L, contract, decl.fields, indent="    ", skip_tail=True)
            L.append("} __packed;")
            _emit_c_assert(L, contract, name)
            L.append("")
        elif kind == "message":
            decl = contract.messages[name]
            L.append(f"struct fw_{snake(name)} {{")
            L.append("    struct fw_msg_hdr hdr;")
            _emit_c_fields(L, contract, decl.fields, indent="    ", skip_tail=True)
            L.append("} __packed;")
            _emit_c_assert(L, contract, name)
            # MsgType 枚举成员（FW_MSG_TYPE_*）在文件开头已由枚举给出，
            # 此处不再重复 #define（重复会自遮蔽成未定义标识符）。
            tail = [f for f in decl.fields if f.is_tail]
            if tail:
                t = tail[0]
                size, _ = _layout(contract, name)
                elem = struct_size(contract, t.type.ref)
                fixed = size - elem
                max_elems = (MSG_LEN_MAX - fixed) // elem
                L.append(
                    f"/* 其后紧跟 count 个 struct fw_{snake(t.type.ref)}；"
                    f"u16 长度上限内最多 {max_elems} 条 */"
                )
            L.append("")

    L.append(f"#endif /* {guard} */")
    L.append("")
    return "\n".join(L)


def _emit_c_fields(
    L: List[str], contract: Contract, fields: List[Field], indent: str, skip_tail: bool
) -> None:
    for f in fields:
        if skip_tail and f.is_tail:
            continue
        L.append(f"{indent}{_c_type(contract, f.type, f.name)};")


def _c_type(contract: Contract, t: FType, name: str) -> str:
    """生成 C 字段声明（含数组后缀）。

    数组维度在 C 里附着于声明符而非类型名，故必须与字段名一起拼出：
    ``__u8 reason[32]``；alias 本身已是 typedef 数组（``addr16`` -> ``__u8[16]``），
    直接使用别名即可，只有形如 ``addr16 x[2]`` 才额外追加维度。
    """
    if t.kind == "int":
        base = {"u8": "__u8", "u16": "__u16", "u32": "__u32", "u64": "__u64",
                "i16": "__s16", "i32": "__s32"}[t.ref]
        return f"{base} {name}[{t.count}]" if t.count else f"{base} {name}"
    if t.kind == "str":
        return f"__u8 {name}[{t.count}]"
    if t.kind == "bytes":
        return f"__u8 {name}[{t.count}]"
    if t.kind == "alias":
        return f"{snake(t.ref)} {name}[{t.count}]" if t.count else f"{snake(t.ref)} {name}"
    if t.kind == "struct":
        base = f"struct fw_{snake(t.ref)}"
        return f"{base} {name}[{t.count}]" if t.count else f"{base} {name}"
    raise ContractError(f"无法生成 C 类型: {t}")


def _emit_c_assert(L: List[str], contract: Contract, name: str) -> None:
    """断言该 C 结构体的 sizeof。

    变长消息的尾部字段不出现在 C 结构体里（其条目按需跟在定长部分之后），
    故此处必须断言**定长部分**，否则会凭空多算一个尾部元素。
    """
    size = gen_wire_size(contract, name)
    L.append(
        f'_Static_assert(sizeof(struct fw_{snake(name)}) == {size}, '
        f'"{snake(name)} 布局必须为 {size} 字节");'
    )


# ============================================================================
# 产物：Rust
# ============================================================================


def _rust_ident(name: str) -> str:
    """字段/类型名可能撞上 Rust 关键字（如 ICMP 的 ``type``），加 r# 转义。"""
    return f"r#{name}" if name in RUST_KEYWORDS else name


def emit_rust(contract: Contract) -> str:
    L: List[str] = []
    L.append("// 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。")
    L.append("// 单一真相源: %s" % os.path.basename(contract.path))
    L.append("")
    L.append("#![allow(dead_code)]")
    L.append("#![allow(non_camel_case_types)]")
    L.append("")
    L.append("/// 契约承诺的字节序：全部多字节整数为大端。")
    L.append("pub const FW_CONTRACT_ENDIAN: &str = \"big\";")
    L.append("")
    if contract.magic:
        mname, mval = contract.magic
        L.append(f"pub const {mname}: u32 = 0x{mval:08X};")
        L.append("")

    for name, t in contract.aliases.items():
        L.append(f"pub type {snake(name)} = [u8; {t.count}];")
    if contract.aliases:
        L.append("")

    for name, decl in contract.enums.items():
        L.append(f"#[repr({decl.width})]")
        L.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
        L.append(f"pub enum {name} {{")
        for member, value in decl.members:
            L.append(f"    {pascal_from_upper_snake(member)} = {value},")
        L.append("}")
        L.append("")

    for name, decl in contract.bits_decls.items():
        L.append(f"pub mod {snake(name)} {{")
        for member, bit in decl.members:
            L.append(f"    pub const {member}: {decl.width} = 1 << {bit};")
        L.append("}")
        L.append("")

    for kind, name in contract.order:
        if kind not in ("struct", "message"):
            continue
        decl = contract.structs.get(name) or contract.messages.get(name)
        L.append("#[repr(C, packed)]")
        L.append("#[derive(Debug, Clone, Copy)]")
        L.append(f"pub struct {name} {{")
        if isinstance(decl, MessageDecl):
            L.append("    pub hdr: MsgHdr,")
        for f in decl.fields:
            if f.is_tail:
                continue
            L.append(f"    pub {_rust_ident(f.name)}: {_rust_type(contract, f.type)},")
        L.append("}")
        size, entries = _layout(contract, name)
        tail = [f for f in decl.fields if f.is_tail]
        struct_bytes = gen_wire_size(contract, name)
        L.append("")
        L.append(f"impl {name} {{")
        L.append(f"    /// 线格式字节数（packed，无填充；变长消息为定长部分）")
        L.append(f"    pub const WIRE_SIZE: usize = {struct_bytes};")
        if isinstance(decl, MessageDecl):
            _, member = decl.msg_type.split("::")
            L.append(f"    /// 对应的 MsgType 取值")
            L.append(f"    pub const MSG_TYPE: MsgType = MsgType::{pascal_from_upper_snake(member)};")
        if tail:
            t = tail[0]
            elem = struct_size(contract, t.type.ref)
            fixed = struct_bytes
            max_elems = (MSG_LEN_MAX - fixed) // elem
            L.append(f"    /// 定长部分字节数")
            L.append(f"    pub const FIXED_SIZE: usize = {fixed};")
            L.append(f"    /// 尾部元素类型与其字节数")
            L.append(f"    pub const TAIL_ELEM_SIZE: usize = {elem};")
            L.append(f"    /// u16 长度上限内可承载的最大尾部条目数")
            L.append(f"    pub const MAX_TAIL_ENTRIES: usize = {max_elems};")
        L.append("    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）")
        L.append("    pub const FIELD_OFFSETS: &[(&str, usize)] = &[")
        for fname, off, _t, _s, istail in entries:
            if istail:
                continue
            L.append(f'        ("{fname}", {off}),')
        L.append("    ];")
        L.append("}")
        L.append("")
    return "\n".join(L)


def _rust_type(contract: Contract, t: FType) -> str:
    if t.kind == "int":
        rust = {"u8": "u8", "u16": "u16", "u32": "u32", "u64": "u64",
                "i16": "i16", "i32": "i32"}[t.ref]
        return f"[{rust}; {t.count}]" if t.count else rust
    if t.kind == "str":
        return f"[u8; {t.count}]"
    if t.kind == "bytes":
        return f"[u8; {t.count}]"
    if t.kind == "alias":
        base = contract.aliases[t.ref]
        return f"[{snake(t.ref)}; {t.count}]" if t.count else f"{snake(t.ref)}"
    if t.kind == "struct":
        return f"[{t.ref}; {t.count}]" if t.count else t.ref
    raise ContractError(f"无法生成 Rust 类型: {t}")


# ============================================================================
# 产物：TS
# ============================================================================


def emit_ts(contract: Contract) -> str:
    L: List[str] = []
    L.append("// 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。")
    L.append("// 单一真相源: %s" % os.path.basename(contract.path))
    L.append("// 注意：netlink 线格式只涉及内核与 daemon；本 TS 产物供调试工具使用。")
    L.append("")
    if contract.magic:
        mname, mval = contract.magic
        L.append(f"export const {mname} = 0x{mval:08X};")
        L.append("")

    for name, decl in contract.enums.items():
        L.append(f"export enum {name} {{")
        for member, value in decl.members:
            L.append(f"  {pascal_from_upper_snake(member)} = {value},")
        L.append("}")
        L.append("")

    for name, decl in contract.bits_decls.items():
        L.append(f"export const {name} = {{")
        for member, bit in decl.members:
            L.append(f"  {member}: 1 << {bit},")
        L.append("} as const;")
        L.append("")

    for kind, name in contract.order:
        if kind not in ("struct", "message"):
            continue
        decl = contract.structs.get(name) or contract.messages.get(name)
        L.append(f"export interface {name} {{")
        if isinstance(decl, MessageDecl):
            L.append("  hdr: MsgHdr;")
        for f in decl.fields:
            if f.is_tail:
                continue
            L.append(f"  {f.name}: {_ts_type(contract, f.type)};")
        L.append("}")
        L.append("")

    L.append("/**")
    L.append(" * 每种结构体/消息的线格式字节数（packed，无填充）。")
    L.append(" * 变长尾部的条目不计入：条目按 count 字段个跟在定长部分之后。")
    L.append(" */")
    L.append("export const WIRE_SIZES: Record<string, number> = {")
    for kind, name in contract.order:
        if kind not in ("struct", "message"):
            continue
        L.append(f"  {name}: {gen_wire_size(contract, name)},")
    L.append("};")
    L.append("")
    L.append("/** 变长消息的分页上限：count 最大取值、定长部分字节数、单条字节数。 */")
    L.append("export const TAIL_LIMITS: Record<string, {"
             " maxEntries: number; fixedSize: number; elemSize: number }> = {")
    for kind, name in contract.order:
        if kind != "message":
            continue
        decl = contract.messages[name]
        tail = [f for f in decl.fields if f.is_tail]
        if not tail:
            continue
        elem = struct_size(contract, tail[0].type.ref)
        fixed = gen_wire_size(contract, name)
        L.append(
            f"  {name}: {{ maxEntries: {(MSG_LEN_MAX - fixed) // elem}, "
            f"fixedSize: {fixed}, elemSize: {elem} }},"
        )
    L.append("};")
    L.append("")
    return "\n".join(L)


def gen_wire_size(contract: Contract, name: str) -> int:
    """结构体自身的字节数。

    变长尾部不入结构体（条目按需跟在定长部分之后），故须扣除一个尾部元素。
    """
    size, _ = _layout(contract, name)
    decl = contract.structs.get(name) or contract.messages.get(name)
    tail = [f for f in decl.fields if f.is_tail]
    return size - struct_size(contract, tail[0].type.ref) if tail else size


def _ts_type(contract: Contract, t: FType) -> str:
    if t.kind == "int":
        return "number"
    if t.kind == "str":
        return "string"
    if t.kind == "bytes":
        return "Uint8Array"
    if t.kind == "alias":
        return "Uint8Array"
    if t.kind == "struct":
        return f"{t.ref}[]" if t.count else t.ref
    raise ContractError(f"无法生成 TS 类型: {t}")


# ============================================================================
# 产物：JSON 布局清单
# ============================================================================


def emit_json(contract: Contract, notes: List[str]) -> str:
    doc: Dict[str, object] = {
        "source": os.path.basename(contract.path),
        "namespace": contract.namespace,
        "endianness": "big",
        "packed": True,
        "msg_len_max": MSG_LEN_MAX,
        "notes": notes,
    }
    if contract.magic:
        doc["magic"] = {"name": contract.magic[0], "value": contract.magic[1]}

    doc["aliases"] = {n: {"bytes": t.count} for n, t in contract.aliases.items()}
    doc["enums"] = {
        n: {"width": d.width, "members": {m: v for m, v in d.members}}
        for n, d in contract.enums.items()
    }
    doc["bits"] = {
        n: {"width": d.width, "members": {m: b for m, b in d.members}}
        for n, d in contract.bits_decls.items()
    }

    layouts: Dict[str, object] = {}
    for kind, name in contract.order:
        if kind not in ("struct", "message"):
            continue
        size, entries = _layout(contract, name)
        decl = contract.structs.get(name) or contract.messages.get(name)
        tail = [f for f in decl.fields if f.is_tail]
        # size 始终是「该结构体本身的字节数」；变长消息的尾部条目不入结构体，
        # 其容量信息放在 tail 段（fixed_size / elem_size / max_entries）。
        struct_bytes = gen_wire_size(contract, name)
        item: Dict[str, object] = {
            "kind": kind,
            "size": struct_bytes,
            "fields": [
                {"name": fn, "offset": off, "size": fs, "type": ts, "tail": istail}
                for fn, off, ts, fs, istail in entries
            ],
        }
        if isinstance(decl, MessageDecl):
            item["msg_type"] = decl.msg_type
        if tail:
            t = tail[0]
            elem = struct_size(contract, t.type.ref)
            item["tail"] = {
                "elem": t.type.ref,
                "elem_size": elem,
                "fixed_size": struct_bytes,
                "max_entries": (MSG_LEN_MAX - struct_bytes) // elem,
            }
        layouts[name] = item
    doc["layouts"] = layouts
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


# ============================================================================
# 入口
# ============================================================================

# 各契约的默认产物与 C 头保护宏
CONTRACTS: Dict[str, Dict[str, object]] = {
    "netlink.fwidl": {
        "targets": ["c", "rust", "json"],
        "out": {
            "c": "netlink_uapi.h",
            "rust": "netlink_contract.rs",
            "ts": "netlink.d.ts",
            "json": "netlink_layout.json",
        },
        "c_guard": "FW_CONTRACT_NETLINK_UAPI_H",
    },
}


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="从 .fwidl 生成三端契约绑定")
    ap.add_argument("source", help=".fwidl 文件路径")
    ap.add_argument("--out-dir", default="contract/generated", help="产物输出目录")
    ap.add_argument("--targets", default=None, help="逗号分隔的产物: c,rust,ts,json")
    ap.add_argument("--check", action="store_true", help="只校验并打印布局，不写文件")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.source):
        print(f"错误: 找不到 {args.source}", file=sys.stderr)
        return 2

    base = os.path.basename(args.source)
    cfg = CONTRACTS.get(base, {})
    targets = (
        [t.strip() for t in args.targets.split(",") if t.strip()]
        if args.targets
        else list(cfg.get("targets", ["c", "rust", "json"]))
    )
    out_names: Dict[str, str] = dict(cfg.get("out", {}))
    c_guard = str(cfg.get("c_guard", "FW_CONTRACT_GENERATED_H"))

    try:
        contract = parse(args.source)
        notes = validate(contract)
    except ContractError as exc:
        print(f"契约校验失败: {exc}", file=sys.stderr)
        return 1

    print(f"契约 {base}: 校验通过")
    for n in notes:
        print(f"  - {n}")

    if args.check:
        return 0

    os.makedirs(args.out_dir, exist_ok=True)
    emitted: List[str] = []
    for t in targets:
        if t == "c":
            content, fname = emit_c(contract, c_guard), out_names.get("c", "generated.h")
        elif t == "rust":
            content, fname = emit_rust(contract), out_names.get("rust", "generated.rs")
        elif t == "ts":
            content, fname = emit_ts(contract), out_names.get("ts", "generated.d.ts")
        elif t == "json":
            content, fname = emit_json(contract, notes), out_names.get("json", "layout.json")
        else:
            print(f"错误: 未知产物类型 {t}", file=sys.stderr)
            return 2
        dest = os.path.join(args.out_dir, fname)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(content)
        emitted.append(dest)

    for p in emitted:
        print(f"  已写出 {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
