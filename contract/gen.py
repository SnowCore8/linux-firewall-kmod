#!/usr/bin/env python3
"""契约生成器：从 .fwidl 单一真相源产出各端绑定。

用法::

    python3 contract/gen.py                                  # 全部登记在册的契约
    python3 contract/gen.py contract/netlink.fwidl --targets c,json

产出目录：``contract/generated/``

三种契约、各自的消费者：

* ``netlink.fwidl``（字节布局）→ C 头（内核）+ TS（面板）+ JSON（daemon 的
  ``internal/contract`` 对齐用）
* ``procfs.fwidl``（命令文法）→ C 头（内核）+ JSON
* ``http.fwidl``（路由表 + JSON 形状 + 错误模型）→ Go（daemon 注册用的路由表）
  + TS（面板不得再手写字面量）+ JSON

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
    """去掉 ``#`` 起的行尾注释。

    必须**跳过双引号内的内容**：文本协议契约（``textproto``）里有锚点字符串，
    例如 ``where = "docs/.../procfs.md:Remaining(s)"`` 甚至 ``"...:### 封禁 IP 列表"``，
    其中可能含 ``#``。早期实现直接 ``find("#")`` 会把字符串从 ``#`` 处截断，
    产出「锚点被切掉一半」的畸形值，而且不报错——是静默的数据损坏。
    """
    out: list[str] = []
    in_str = False
    escaped = False
    for ch in line:
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == "#":
            break
        if ch == '"':
            in_str = True
        out.append(ch)
    return "".join(out)


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
# 文本协议契约（procfs）
#
# 与二进制 IDL 共用同一份生成器、同一套「生成物 vs 手写源码」的第三方校验
# 纪律，但形状完全不同：二进制侧关心字节布局，文本侧关心「命令文法 + 行文本
# 格式 + 条目权限 + 容量事实 + 已核实缺陷」。
# ============================================================================


class ProcFile:
    """procfs 的一个条目：路径、权限、读侧格式强度。"""

    __slots__ = ("name", "line", "mode", "access", "read_format", "summary")

    def __init__(self, name: str, line: int):
        self.name = name
        self.line = line
        self.mode = 0
        self.access = ""
        self.read_format = "unstable"
        self.summary = ""


class WriteGrammar:
    __slots__ = ("target", "line", "forms")

    def __init__(self, target: str, line: int):
        self.target = target
        self.line = line
        self.forms: List[Tuple[str, str]] = []  # (命令形式, "Enum::MEMBER")


class KeyBlock:
    __slots__ = ("target", "line", "keys")

    def __init__(self, target: str, line: int):
        self.target = target
        self.line = line
        self.keys: List[Tuple[str, str]] = []  # (key, 数值类型)


class LimitBlock:
    __slots__ = ("target", "line", "entries", "note", "where")

    def __init__(self, target: str, line: int):
        self.target = target
        self.line = line
        self.entries: Optional[int] = None
        self.note = ""
        self.where = ""


class Defect:
    """一条已核实的实现缺陷。

    ``where`` 指向**缺陷现场**（实现里那处代码/文档），校验器核对它仍在。
    ``status`` 记录处置结论，决定校验器核对哪一侧：

      open     —— 未修，``where`` 必须仍存在（默认值，兼容早期契约）
      fixed    —— 已修，``where`` 反过来必须**已消失**，``fix`` 指向修复证据
                  的锚点且必须存在。防止「契约说修好了、代码其实没动」。
      retained —— 有意保留，``where`` 指向源码里说明「有意保留」的注释，
                  必须存在。理由写在 ``text`` 与 ``reason`` 里。

    ``fix`` 与 ``reason`` 仅分别在 fixed / retained 时使用。

    ``resolution`` 是**本轮重写已经锁定、但代码修复尚未落地**的处置结论
    （例如「统一为百分数」「两条流各自独立上限」）。它与 ``status`` 的区别：
    status 描述**代码当前**的状态，resolution 描述**已决定的去向**。当修复
    真正落地时，resolution 应上升为 fix / reason 并同步 status。没有它，
    决策只存在于设计文档里，实现阶段可能再次漂移。
    """

    __slots__ = ("name", "line", "severity", "where", "text", "status", "fix",
                 "reason", "resolution")

    def __init__(self, name: str, line: int):
        self.name = name
        self.line = line
        self.severity = ""
        self.where = ""
        self.text = ""
        self.status = "open"
        self.fix = ""
        self.reason = ""
        self.resolution = ""


class TextProtoContract:
    def __init__(self, path: str):
        self.path = path
        self.name = ""
        self.namespace = ""
        self.root = ""
        self.enums: Dict[str, EnumDecl] = {}
        self.enum_order: List[str] = []
        self.files: Dict[str, ProcFile] = {}
        self.file_order: List[str] = []
        self.writes: Dict[str, WriteGrammar] = {}
        self.keys: Dict[str, KeyBlock] = {}
        self.limits: Dict[str, LimitBlock] = {}
        self.limit_order: List[str] = []
        self.defects: List[Defect] = []


_KV_RE = re.compile(r"^(\w+)\s*=\s*(.*)$")
_FORM_RE = re.compile(r'^"([^"]*)"\s*=\s*(\w+)\s*::\s*(\w+)$')

READ_FORMATS = ("machine", "unstable", "none")
ACCESS_VALUES = ("r", "rw")
SEVERITIES = ("low", "medium", "high")
# 缺陷处置结论：未修 / 已修 / 有意保留（见 Defect 的文档字符串）
DEFECT_STATUSES = ("open", "fixed", "retained")
NUM_TYPES = ("u8", "u16", "u32", "u64", "i32", "i64")


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _kv(path: str, lineno: int, text: str) -> Tuple[str, str]:
    m = _KV_RE.fullmatch(text)
    if not m:
        raise ContractError(f"{path}:{lineno}: 期望 '<字段> = <值>': {text!r}")
    return m.group(1), _unquote(m.group(2).strip())


def detect_format(path: str) -> str:
    """按首个有效行判断契约类型。

    ``httpproto ...`` 走 HTTP 契约，``textproto ...`` 走 procfs 文本协议，
    其余一律按 netlink 二进制线格式处理。
    """
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = _strip_comment(line).strip()
            if s:
                if s.startswith("httpproto "):
                    return "http"
                return "textproto" if s.startswith("textproto ") else "binary"
    raise ContractError(f"{path}: 空文件")


def parse_textproto(path: str) -> TextProtoContract:
    contract = TextProtoContract(path)
    with open(path, "r", encoding="utf-8") as fh:
        raw_lines = fh.readlines()
    lines = [(i + 1, _strip_comment(l).strip()) for i, l in enumerate(raw_lines)]

    idx = 0
    block_header: Optional[str] = None
    block_open_line = 0
    pending: List[Tuple[int, str]] = []

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
            else:
                if text == "}":
                    raise ContractError(f"{path}:{lineno}: 出现孤立的 '}}'")
                _textproto_toplevel(contract, text, lineno)
            idx += 1
            continue
        if text == "}":
            _textproto_block(contract, block_header, block_open_line, pending)
            block_header = None
            pending = []
        elif text.endswith("{"):
            raise ContractError(f"{path}:{lineno}: 不支持嵌套块")
        else:
            pending.append((lineno, text))
        idx += 1

    if block_header is not None:
        raise ContractError(f"{path}:{block_open_line}: 块未闭合（缺少 '}}'）")
    return contract


def _textproto_toplevel(contract: TextProtoContract, text: str, lineno: int) -> None:
    m = re.fullmatch(r"textproto\s+(\w+)", text)
    if m:
        contract.name = m.group(1)
        return
    m = re.fullmatch(r"namespace\s+(\w+)", text)
    if m:
        contract.namespace = m.group(1)
        return
    m = re.fullmatch(r'root\s+"([^"]*)"', text)
    if m:
        contract.root = m.group(1)
        return
    raise ContractError(f"{contract.path}:{lineno}: 无法解析的顶层声明: {text!r}")


def _textproto_block(
    contract: TextProtoContract,
    header: str,
    open_line: int,
    body: List[Tuple[int, str]],
) -> None:
    path = contract.path

    m = re.fullmatch(r"enum\s+(\w+)\s*:\s*(\w+)", header)
    if m:
        width = m.group(2)
        if width not in SCALARS or width.startswith("i"):
            raise ContractError(f"{path}:{open_line}: enum 宽度必须是无符号整数类型: {width}")
        if m.group(1) in contract.enums:
            raise ContractError(f"{path}:{open_line}: enum {m.group(1)} 重复定义")
        decl = EnumDecl(m.group(1), open_line, width)
        for lineno, text in body:
            mm = re.fullmatch(r"(\w+)\s*=\s*(-?\d+)", text)
            if not mm:
                raise ContractError(f"{path}:{lineno}: 无法解析枚举成员: {text!r}")
            decl.members.append((mm.group(1), int(mm.group(2))))
        contract.enums[decl.name] = decl
        contract.enum_order.append(decl.name)
        return

    m = re.fullmatch(r"file\s+(\w+)", header)
    if m:
        name = m.group(1)
        if name in contract.files:
            raise ContractError(f"{path}:{open_line}: file {name} 重复定义")
        decl = ProcFile(name, open_line)
        for lineno, text in body:
            k, v = _kv(path, lineno, text)
            if k == "mode":
                try:
                    decl.mode = int(v, 8)
                except ValueError:
                    raise ContractError(f"{path}:{lineno}: mode 必须为八进制字面量: {v!r}")
            elif k == "access":
                decl.access = v
            elif k == "read_format":
                decl.read_format = v
            elif k == "summary":
                decl.summary = v
            else:
                raise ContractError(f"{path}:{lineno}: file 不认识的字段 {k!r}")
        contract.files[name] = decl
        contract.file_order.append(name)
        return

    m = re.fullmatch(r"write\s+(\w+)", header)
    if m:
        target = m.group(1)
        if target in contract.writes:
            raise ContractError(f"{path}:{open_line}: write {target} 重复定义")
        decl = WriteGrammar(target, open_line)
        for lineno, text in body:
            fm = _FORM_RE.fullmatch(text)
            if not fm:
                raise ContractError(
                    f'{path}:{lineno}: 写文法应为 \'"<形式>" = Enum::MEMBER\': {text!r}'
                )
            decl.forms.append((fm.group(1), f"{fm.group(2)}::{fm.group(3)}"))
        contract.writes[target] = decl
        return

    m = re.fullmatch(r"key\s+(\w+)", header)
    if m:
        target = m.group(1)
        if target in contract.keys:
            raise ContractError(f"{path}:{open_line}: key {target} 重复定义")
        decl = KeyBlock(target, open_line)
        for lineno, text in body:
            km = re.fullmatch(r'"([^"]*)"\s*=\s*(\w+)', text)
            if not km:
                raise ContractError(f'{path}:{lineno}: key 行应为 \'"<key>" = <数值类型>\': {text!r}')
            decl.keys.append((km.group(1), km.group(2)))
        contract.keys[target] = decl
        return

    m = re.fullmatch(r"limit\s+(\w+)", header)
    if m:
        target = m.group(1)
        if target in contract.limits:
            raise ContractError(f"{path}:{open_line}: limit {target} 重复定义")
        decl = LimitBlock(target, open_line)
        for lineno, text in body:
            k, v = _kv(path, lineno, text)
            if k == "entries":
                if v == "none":
                    decl.entries = None
                else:
                    try:
                        decl.entries = int(v)
                    except ValueError:
                        raise ContractError(f"{path}:{lineno}: entries 应为正整数或 none: {v!r}")
            elif k == "note":
                decl.note = v
            elif k == "where":
                decl.where = v
            else:
                raise ContractError(f"{path}:{lineno}: limit 不认识的字段 {k!r}")
        contract.limits[target] = decl
        contract.limit_order.append(target)
        return

    m = re.fullmatch(r"defect\s+(\w+)", header)
    if m:
        decl = Defect(m.group(1), open_line)
        for lineno, text in body:
            k, v = _kv(path, lineno, text)
            if k == "severity":
                decl.severity = v
            elif k == "status":
                decl.status = v
            elif k == "where":
                decl.where = v
            elif k == "fix":
                decl.fix = v
            elif k == "reason":
                decl.reason = v
            elif k == "resolution":
                decl.resolution = v
            elif k == "text":
                decl.text = v
            else:
                raise ContractError(f"{path}:{lineno}: defect 不认识的字段 {k!r}")
        contract.defects.append(decl)
        return

    raise ContractError(f"{path}:{open_line}: 无法解析的块头: {header!r}")


def validate_textproto(contract: TextProtoContract) -> List[str]:
    notes: List[str] = []
    path = contract.path

    if not contract.name:
        raise ContractError("缺少 'textproto <名字>' 声明")
    if not contract.namespace:
        raise ContractError("缺少 'namespace <名字>' 声明")
    if not contract.root.startswith("/"):
        raise ContractError(f"root 必须是绝对路径，实际 {contract.root!r}")

    for name in contract.enum_order:
        decl = contract.enums[name]
        bits = SCALARS[decl.width] * 8
        seen: Dict[int, str] = {}
        for member, value in decl.members:
            if not (0 <= value < (1 << bits)):
                raise ContractError(f"enum {name}: {member} = {value} 超出 {decl.width} 取值范围")
            if value in seen:
                raise ContractError(f"enum {name}: {member} 与 {seen[value]} 取值重复（{value}）")
            seen[value] = member
        notes.append(f"enum {name}: {len(decl.members)} 个成员，宽度 {decl.width}")

    if not contract.files:
        raise ContractError("契约未声明任何 file 条目")

    for name in contract.file_order:
        f = contract.files[name]
        if f.mode == 0:
            raise ContractError(f"file {name}: 缺少 mode")
        if f.access not in ACCESS_VALUES:
            raise ContractError(f"file {name}: access 必须是 {'/'.join(ACCESS_VALUES)}，实际 {f.access!r}")
        if f.read_format not in READ_FORMATS:
            raise ContractError(
                f"file {name}: read_format 必须是 {'/'.join(READ_FORMATS)}，实际 {f.read_format!r}"
            )
        if f.access == "r" and f.read_format == "none":
            raise ContractError(f"file {name}: 只读文件不能声明 read_format = none")
        notes.append(
            f"file {name}: mode {f.mode:04o} {f.access} read_format={f.read_format}"
        )

    # 写文法必须指向已声明且可写的条目；可写条目必须有写文法
    for target, decl in contract.writes.items():
        f = contract.files.get(target)
        if f is None:
            raise ContractError(f"write {target}: 对应的 file 未声明")
        if "w" not in f.access:
            raise ContractError(f"write {target}: 该条目 access={f.access}，不可写")
        if not decl.forms:
            raise ContractError(f"write {target}: 未声明任何命令形式")
        forms = [form for form, _ in decl.forms]
        if len(set(forms)) != len(forms):
            raise ContractError(f"write {target}: 命令形式重复")
        for form, ref in decl.forms:
            enum_name, member = ref.split("::")
            if enum_name not in contract.enums:
                raise ContractError(f"write {target}: 引用了未定义的 enum {enum_name}")
            if member not in dict(contract.enums[enum_name].members):
                raise ContractError(f"write {target}: {ref} 未在 enum 中定义")
        notes.append(f"write {target}: {len(decl.forms)} 种形式")
    for name in contract.file_order:
        if "w" in contract.files[name].access and name not in contract.writes:
            raise ContractError(f"file {name}: 可写但缺少 write 块")

    # key 块只能挂 machine 文件上；machine 文件必须有 key 块
    seen_key: Dict[str, str] = {}
    for target, decl in contract.keys.items():
        f = contract.files.get(target)
        if f is None:
            raise ContractError(f"key {target}: 对应的 file 未声明")
        if f.read_format != "machine":
            raise ContractError(
                f"key {target}: 只有 read_format = machine 的条目才有机器可读 key，"
                f"实际为 {f.read_format}"
            )
        keys = [k for k, _ in decl.keys]
        if len(set(keys)) != len(keys):
            raise ContractError(f"key {target}: key 名重复")
        for k, t in decl.keys:
            if t not in NUM_TYPES:
                raise ContractError(f"key {target}: {k} 的数值类型 {t!r} 不在 {NUM_TYPES}")
            # C 头把全部 key 展开成同一命名空间的宏，重名会直接编译失败
            if k in seen_key and seen_key[k] != target:
                raise ContractError(
                    f"key {target}: {k} 与 key {seen_key[k]} 重名（同一张宏表内必须唯一）"
                )
            seen_key[k] = target
        notes.append(f"key {target}: {len(decl.keys)} 个机器可读字段")
    for name in contract.file_order:
        if contract.files[name].read_format == "machine" and name not in contract.keys:
            raise ContractError(f"file {name}: 声明为 machine 但缺少 key 块")

    for target in contract.limit_order:
        decl = contract.limits[target]
        if decl.entries is not None and decl.entries <= 0:
            raise ContractError(f"limit {target}: entries 必须为正整数或 none")
        if not decl.where or ":" not in decl.where:
            raise ContractError(f"limit {target}: 必须给出 'where = <文件>:<锚点>' 供校验器核对")
        desc = "无上限" if decl.entries is None else f"{decl.entries} 条"
        notes.append(f"limit {target}: {desc}（锚点 {decl.where}）")

    for decl in contract.defects:
        if decl.severity not in SEVERITIES:
            raise ContractError(
                f"defect {decl.name}: severity 必须是 {'/'.join(SEVERITIES)}，实际 {decl.severity!r}"
            )
        if decl.status not in DEFECT_STATUSES:
            raise ContractError(
                f"defect {decl.name}: status 必须是 {'/'.join(DEFECT_STATUSES)}，实际 {decl.status!r}"
            )
        if not decl.where or ":" not in decl.where:
            raise ContractError(f"defect {decl.name}: 必须给出 'where = <文件>:<锚点>'")
        if decl.status == "fixed" and (not decl.fix or ":" not in decl.fix):
            raise ContractError(
                f"defect {decl.name}: status=fixed 必须给出 'fix = <文件>:<锚点>' 作为修复证据"
            )
        if decl.status != "fixed" and decl.fix:
            raise ContractError(
                f"defect {decl.name}: 仅 status=fixed 可给 fix（当前 status={decl.status}）"
            )
        if decl.status == "retained" and not decl.reason:
            raise ContractError(
                f"defect {decl.name}: status=retained 必须给出 reason 说明为何有意保留"
            )
        if decl.status != "retained" and decl.reason:
            raise ContractError(
                f"defect {decl.name}: 仅 status=retained 可给 reason（当前 status={decl.status}）"
            )
        if not decl.text:
            raise ContractError(f"defect {decl.name}: 缺少 text")
    if contract.defects:
        fixed = sum(1 for d in contract.defects if d.status == "fixed")
        retained = sum(1 for d in contract.defects if d.status == "retained")
        notes.append(
            f"缺陷记录: {len(contract.defects)} 条（已修 {fixed} / 有意保留 {retained} / "
            f"未修 {len(contract.defects) - fixed - retained}；由 verify_*.py 到源码核对锚点）"
        )

    return notes


def _tp_macro(prefix: str, name: str) -> str:
    return prefix + upper_snake(name)


def emit_c_textproto(contract: TextProtoContract, guard: str) -> str:
    L: List[str] = []
    L.append("/* 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。 */")
    L.append("/* 单一真相源: %s（文本协议契约，非二进制线格式） */" % os.path.basename(contract.path))
    L.append("")
    L.append(f"#ifndef {guard}")
    L.append(f"#define {guard}")
    L.append("")
    L.append("/* procfs 根目录 */")
    L.append(f'#define FW_PROCFS_ROOT "{contract.root}"')
    L.append("")

    L.append("/* 条目路径与权限位（权限位即 proc_create 的 mode 实参） */")
    for name in contract.file_order:
        f = contract.files[name]
        mac = _tp_macro("FW_PROCFS_", name)
        L.append(f'#define {mac}_PATH "{contract.root}/{f.name}"')
        L.append(f"#define {mac}_MODE 0{f.mode:03o}")
    L.append("")

    for ename in contract.enum_order:
        decl = contract.enums[ename]
        for member, value in decl.members:
            L.append(f"#define FW_PROCFS_{upper_snake(ename)}_{member} {value}")
        L.append("")

    for target, decl in contract.writes.items():
        mac = _tp_macro("FW_PROCFS_", target)
        for form, ref in decl.forms:
            member = ref.split("::")[1]
            L.append(f'#define {mac}_FORM_{member} "{form}"')
        L.append("")

    for target, decl in contract.keys.items():
        for k, t in decl.keys:
            L.append(f'#define FW_PROCFS_KEY_{upper_snake(k)} "{k}"')
        L.append("")

    L.append("/* 容量上限；未列出的表表示实现中无条目上限 */")
    for target in contract.limit_order:
        decl = contract.limits[target]
        mac = _tp_macro("FW_PROCFS_LIMIT_", target)
        if decl.entries is None:
            L.append(f"/* {target}: 无上限（{decl.note}） */")
        else:
            L.append(f"#define {mac} {decl.entries}")
    L.append("")
    L.append(f"#endif /* {guard} */")
    L.append("")
    return "\n".join(L)


def emit_json_textproto(contract: TextProtoContract, notes: List[str]) -> str:
    doc: Dict[str, object] = {
        "source": os.path.basename(contract.path),
        "kind": "textproto",
        "name": contract.name,
        "namespace": contract.namespace,
        "root": contract.root,
        "notes": notes,
        "files": {
            name: {
                "path": f"{contract.root}/{name}",
                "mode": f"0{contract.files[name].mode:03o}",
                "access": contract.files[name].access,
                "read_format": contract.files[name].read_format,
                "summary": contract.files[name].summary,
            }
            for name in contract.file_order
        },
        "enums": {
            n: {"width": contract.enums[n].width, "members": {m: v for m, v in contract.enums[n].members}}
            for n in contract.enum_order
        },
        "writes": {
            target: {
                "forms": [
                    {"pattern": form, "op": ref} for form, ref in decl.forms
                ]
            }
            for target, decl in contract.writes.items()
        },
        "keys": {
            target: {k: t for k, t in decl.keys}
            for target, decl in contract.keys.items()
        },
        "limits": {
            target: {
                "entries": contract.limits[target].entries,
                "note": contract.limits[target].note,
                "where": contract.limits[target].where,
            }
            for target in contract.limit_order
        },
        "defects": [
            {
                "name": d.name,
                "severity": d.severity,
                "status": d.status,
                "where": d.where,
                "fix": d.fix,
                "reason": d.reason,
                "resolution": d.resolution,
                "text": d.text,
            }
            for d in contract.defects
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


# ============================================================================
# HTTP 契约：路由表 + JSON 类型 + 信封 + 认证 + 安全头 + SSE
# ============================================================================
#
# 与前两种契约的差别：netlink 关心**字节布局**，procfs 关心**命令文法**，
# HTTP 关心**路由表 + JSON 形状 + 错误模型**。共同点仍是那份纪律：契约声明的
# 每一条都要能到源码里机械核对，核不上就门禁失败。


HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")
ROUTE_AUTH = ("none", "required")
ROUTE_RETURNS = ("type", "text", "bytes", "stream")
HEADER_SCOPES = ("all", "api", "webui")
ERR_SHAPES = ("envelope", "text", "framework_default")
TYPE_KINDS = ("type", "request")

# 契约标量类型 -> TS 类型（把契约里的字段类型推导成前端应有的 TS 类型）
TYPE_SCALAR_TS: Dict[str, str] = {
    "i8": "number",
    "i16": "number",
    "i32": "number",
    "i64": "number",
    "isize": "number",
    "u8": "number",
    "u16": "number",
    "u32": "number",
    "u64": "number",
    "usize": "number",
    "f32": "number",
    "f64": "number",
    "bool": "boolean",
    "String": "string",
    "str": "string",
}


class HttpField:
    """一个 JSON 字段：契约里的 key 与它的契约类型（见 contract_type_to_ts）。"""

    __slots__ = ("key", "ftype", "line")

    def __init__(self, key: str, ftype: str, line: int):
        self.key = key
        self.ftype = ftype
        self.line = line


class HttpType:
    """一个 JSON 载荷类型（响应或请求体）。"""

    __slots__ = ("name", "line", "kind", "params", "fields", "ts_name", "inline")

    def __init__(self, name: str, line: int, kind: str):
        self.name = name
        self.line = line
        self.kind = kind  # type | request
        self.params: List[str] = []
        self.fields: List[HttpField] = []
        # 前端 interface 名（仅当与 daemon 侧结构体名不同时才写，例如 daemon 的
        # `WhitelistEntryResponse` 对前端的 `WhitelistEntry`）
        self.ts_name: Optional[str] = None
        # 响应形状内联在 handler 里、没有具名结构体（例如 sse-status 这类
        # 由 handler 现拼的载荷）。此时核对的是 handler 里写出的 JSON key。
        self.inline: bool = False

    def has_param(self, p: str) -> bool:
        return p in self.params


class HttpRoute:
    __slots__ = (
        "method",
        "path",
        "line",
        "auth",
        "handler",
        "returns",
        "status",
        "alt_status",
        "codes",
        "max_connections",
        "events",
        "keepalive_secs",
        "note",
    )

    def __init__(self, method: str, path: str, line: int):
        self.method = method
        self.path = path
        self.line = line
        self.auth = ""
        self.handler = ""
        self.returns = ""
        self.status: Optional[int] = None
        self.alt_status: Optional[int] = None
        self.codes: List[int] = []
        self.max_connections: Optional[int] = None
        self.events: List[str] = []
        self.keepalive_secs: Optional[int] = None
        self.note = ""


class ErrorModel:
    """一种错误形状。校验器按 `shape`/`statuses`/`body` 到实现侧核对语义——
    路由注册串本身就是锚点，这里不再维护源码位置。"""

    __slots__ = ("name", "line", "shape", "statuses", "body", "note")

    def __init__(self, name: str, line: int):
        self.name = name
        self.line = line
        self.shape = ""
        self.statuses: List[int] = []
        self.body = ""
        self.note = ""


class StatusCodeDecl:
    __slots__ = ("value", "line", "status", "text")

    def __init__(self, value: int, line: int):
        self.value = value
        self.line = line
        self.status = 0
        self.text = ""


class HeaderDecl:
    __slots__ = ("name", "line", "scope", "value", "value_webui")

    def __init__(self, name: str, line: int):
        self.name = name
        self.line = line
        self.scope = ""
        self.value = ""
        self.value_webui = ""


class HttpContract:
    def __init__(self, path: str):
        self.path = path
        self.name = ""
        self.namespace = ""
        self.base = ""
        self.envelope: Optional[HttpType] = None
        self.auth: Dict[str, str] = {}
        self.headers: Dict[str, HeaderDecl] = {}
        self.routes: List[HttpRoute] = []
        self.types: Dict[str, HttpType] = {}
        self.type_order: List[str] = []
        self.codes: Dict[int, StatusCodeDecl] = {}
        self.code_order: List[int] = []
        self.err_models: Dict[str, ErrorModel] = {}
        self.err_order: List[str] = []
        self.defects: List[Defect] = []

    def route_keys(self) -> List[Tuple[str, str]]:
        return [(r.method, r.path) for r in self.routes]


def _unescape(s: str) -> str:
    """把引号值里的转义序列还原（HTTP 契约专用，不改动 textproto 的既有行为）。

    需要它是因为错误响应体与安全头值里确实含 `\\n`：`"401 Unauthorized\\n"`
    若不解转义，核对源码时会比对失败或产生误报。
    """
    out: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            mapping = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"'}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _unquote_esc(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return _unescape(v[1:-1])
    return v


def _http_kv(path: str, lineno: int, text: str) -> Tuple[str, str]:
    m = _KV_RE.fullmatch(text)
    if not m:
        raise ContractError(f"{path}:{lineno}: 期望 '<字段> = <值>': {text!r}")
    return m.group(1), _unquote_esc(m.group(2))


def _int_csv(path: str, lineno: int, field: str, v: str) -> List[int]:
    try:
        return [int(x.strip()) for x in v.split(",") if x.strip()]
    except ValueError:
        raise ContractError(f"{path}:{lineno}: {field} 应为逗号分隔的整数: {v!r}")


def _str_csv(v: str) -> List[str]:
    return [x.strip() for x in v.split(",") if x.strip()]


def parse_http(path: str) -> HttpContract:
    contract = HttpContract(path)
    with open(path, "r", encoding="utf-8") as fh:
        raw_lines = fh.readlines()
    lines = [(i + 1, _strip_comment(l).strip()) for i, l in enumerate(raw_lines)]

    idx = 0
    block_header: Optional[str] = None
    block_open_line = 0
    pending: List[Tuple[int, str]] = []

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
            else:
                if text == "}":
                    raise ContractError(f"{path}:{lineno}: 出现孤立的 '}}'")
                _http_toplevel(contract, text, lineno)
            idx += 1
            continue
        if text == "}":
            _http_block(contract, block_header, block_open_line, pending)
            block_header = None
            pending = []
        elif text.endswith("{"):
            raise ContractError(f"{path}:{lineno}: 不支持嵌套块")
        else:
            pending.append((lineno, text))
        idx += 1

    if block_header is not None:
        raise ContractError(f"{path}:{block_open_line}: 块未闭合（缺少 '}}'）")
    return contract


def _http_toplevel(contract: HttpContract, text: str, lineno: int) -> None:
    m = re.fullmatch(r"httpproto\s+(\w+)", text)
    if m:
        contract.name = m.group(1)
        return
    m = re.fullmatch(r"namespace\s+(\w+)", text)
    if m:
        contract.namespace = m.group(1)
        return
    m = re.fullmatch(r'base\s+"([^"]*)"', text)
    if m:
        contract.base = m.group(1)
        return
    raise ContractError(f"{contract.path}:{lineno}: 无法解析的顶层声明: {text!r}")


_TYPE_FIELD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+)$")


def _http_block(
    contract: HttpContract,
    header: str,
    open_line: int,
    body: List[Tuple[int, str]],
) -> None:
    path = contract.path

    # ---- 信封 -------------------------------------------------------------
    if header == "envelope":
        if contract.envelope is not None:
            raise ContractError(f"{path}:{open_line}: envelope 重复定义")
        env = HttpType("ApiResponse", open_line, "type")
        env.params = ["T"]
        for lineno, text in body:
            fm = _TYPE_FIELD_RE.fullmatch(text)
            if not fm:
                raise ContractError(f"{path}:{lineno}: envelope 字段应为 '<key>: <契约类型>': {text!r}")
            env.fields.append(HttpField(fm.group(1), fm.group(2).strip(), lineno))
        contract.envelope = env
        return

    # ---- 认证 -------------------------------------------------------------
    if header == "auth":
        for lineno, text in body:
            k, v = _http_kv(path, lineno, text)
            if k == "statuses":
                raise ContractError(f"{path}:{lineno}: auth 不支持 statuses")
            contract.auth[k] = v
        return

    # ---- 安全头 -----------------------------------------------------------
    m = re.fullmatch(r'header\s+"([^"]+)"', header)
    if m:
        name = m.group(1)
        if name in contract.headers:
            raise ContractError(f"{path}:{open_line}: header {name} 重复定义")
        decl = HeaderDecl(name, open_line)
        for lineno, text in body:
            k, v = _http_kv(path, lineno, text)
            if k == "scope":
                decl.scope = v
            elif k == "value":
                decl.value = v
            elif k == "value_webui":
                decl.value_webui = v
            elif k == "when":
                raise ContractError(f"{path}:{lineno}: header 用 scope 表达生效范围，不用 when")
            else:
                raise ContractError(f"{path}:{lineno}: header 不认识的字段 {k!r}")
        contract.headers[name] = decl
        return

    # ---- 路由 -------------------------------------------------------------
    m = re.fullmatch(r"route\s+(\w+)\s+\"([^\"]*)\"", header)
    if m:
        method = m.group(1).upper()
        if method not in HTTP_METHODS:
            raise ContractError(f"{path}:{open_line}: 未知 HTTP 方法 {method!r}")
        decl = HttpRoute(method, m.group(2), open_line)
        for lineno, text in body:
            k, v = _http_kv(path, lineno, text)
            if k == "auth":
                decl.auth = v
            elif k == "handler":
                decl.handler = v
            elif k == "returns":
                decl.returns = v
            elif k == "status":
                try:
                    decl.status = int(v)
                except ValueError:
                    raise ContractError(f"{path}:{lineno}: status 应为整数: {v!r}")
            elif k == "alt_status":
                try:
                    decl.alt_status = int(v)
                except ValueError:
                    raise ContractError(f"{path}:{lineno}: alt_status 应为整数: {v!r}")
            elif k == "codes":
                decl.codes = _int_csv(path, lineno, "codes", v)
            elif k == "max_connections":
                try:
                    decl.max_connections = int(v)
                except ValueError:
                    raise ContractError(f"{path}:{lineno}: max_connections 应为整数: {v!r}")
            elif k == "events":
                decl.events = _str_csv(v)
            elif k == "keepalive_secs":
                try:
                    decl.keepalive_secs = int(v)
                except ValueError:
                    raise ContractError(f"{path}:{lineno}: keepalive_secs 应为整数: {v!r}")
            elif k == "note":
                decl.note = v
            else:
                raise ContractError(f"{path}:{lineno}: route 不认识的字段 {k!r}")
        contract.routes.append(decl)
        return

    # ---- 错误形状 ---------------------------------------------------------
    m = re.fullmatch(r"errmodel\s+(\w+)", header)
    if m:
        name = m.group(1)
        if name in contract.err_models:
            raise ContractError(f"{path}:{open_line}: errmodel {name} 重复定义")
        decl = ErrorModel(name, open_line)
        for lineno, text in body:
            k, v = _http_kv(path, lineno, text)
            if k == "shape":
                decl.shape = v
            elif k == "where":
                raise ContractError(
                    f"{path}:{lineno}: 契约不维护源码位置锚点，删除 where"
                )
            elif k == "statuses":
                decl.statuses = _int_csv(path, lineno, "statuses", v)
            elif k == "body":
                decl.body = v
            elif k == "note":
                decl.note = v
            else:
                raise ContractError(f"{path}:{lineno}: errmodel 不认识的字段 {k!r}")
        contract.err_models[name] = decl
        contract.err_order.append(name)
        return

    # ---- 业务码 -----------------------------------------------------------
    m = re.fullmatch(r"code\s+(-?\d+)", header)
    if m:
        value = int(m.group(1))
        if value in contract.codes:
            raise ContractError(f"{path}:{open_line}: code {value} 重复定义")
        decl = StatusCodeDecl(value, open_line)
        for lineno, text in body:
            k, v = _http_kv(path, lineno, text)
            if k == "status":
                try:
                    decl.status = int(v)
                except ValueError:
                    raise ContractError(f"{path}:{lineno}: status 应为整数: {v!r}")
            elif k == "text":
                decl.text = v
            else:
                raise ContractError(f"{path}:{lineno}: code 不认识的字段 {k!r}")
        contract.codes[value] = decl
        contract.code_order.append(value)
        return

    # ---- 载荷类型 ---------------------------------------------------------
    m = re.fullmatch(r"(type|request)\s+(\w+)(?:<([^>]*)>)?", header)
    if m:
        kind = "request" if m.group(1) == "request" else "type"
        name = m.group(2)
        if name in contract.types:
            raise ContractError(f"{path}:{open_line}: 类型 {name} 重复定义")
        decl = HttpType(name, open_line, kind)
        if m.group(3):
            decl.params = [p.strip() for p in m.group(3).split(",") if p.strip()]
        for lineno, text in body:
            # 指令行用 '='（`ts_name = "X"` / `inline = true`），字段行用 ':'，
            # 二者不会混淆。
            dm = re.fullmatch(r"(\w+)\s*=\s*(.+)", text)
            if dm and dm.group(1) in ("ts_name", "inline"):
                key, val = dm.group(1), _unquote_esc(dm.group(2))
                if key == "ts_name":
                    if not re.fullmatch(r"[A-Za-z_]\w*", val):
                        raise ContractError(f"{path}:{lineno}: ts_name 应为合法标识符: {val!r}")
                    decl.ts_name = val
                else:
                    if val not in ("true", "false"):
                        raise ContractError(f"{path}:{lineno}: inline 应为 true/false: {val!r}")
                    decl.inline = val == "true"
                continue
            fm = _TYPE_FIELD_RE.fullmatch(text)
            if not fm:
                raise ContractError(
                    f"{path}:{lineno}: {kind} 字段应为 '<JSON key>: <契约类型>': {text!r}"
                )
            decl.fields.append(HttpField(fm.group(1), fm.group(2).strip(), lineno))
        contract.types[name] = decl
        contract.type_order.append(name)
        return

    # ---- 缺陷 -------------------------------------------------------------
    # 字段集与 textproto 侧一致：status/fix/reason 缺一不可，否则退役旧读路径
    # 后无法把缺陷记成「已修」（status=fixed 要求给出 fix 作为修复证据）。
    m = re.fullmatch(r"defect\s+(\w+)", header)
    if m:
        decl = Defect(m.group(1), open_line)
        for lineno, text in body:
            k, v = _http_kv(path, lineno, text)
            if k == "severity":
                decl.severity = v
            elif k == "status":
                decl.status = v
            elif k == "where":
                raise ContractError(
                    f"{path}:{lineno}: 契约不维护源码位置锚点，删除 where"
                )
            elif k == "fix":
                decl.fix = v
            elif k == "reason":
                decl.reason = v
            elif k == "resolution":
                decl.resolution = v
            elif k == "text":
                decl.text = v
            else:
                raise ContractError(f"{path}:{lineno}: defect 不认识的字段 {k!r}")
        contract.defects.append(decl)
        return

    raise ContractError(f"{path}:{open_line}: 无法解析的块头: {header!r}")


# 契约字段类型 -> TS 类型。只覆盖契约里实际会用到的形状：标量、String、bool、
# Vec<T>、Option<T>、以及具名类型引用（含泛型实参）。
def contract_type_to_ts(decl: str) -> str:
    t = decl.strip()
    m = re.fullmatch(r"Vec\s*<\s*(.+)\s*>", t)
    if m:
        return f"{contract_type_to_ts(m.group(1))}[]"
    # 定长数组 `[T; N]`：TS 无对应语法，退化为 T[]（长度在线上 JSON 里仍然体现）
    m = re.fullmatch(r"\[\s*(.+?)\s*;\s*\d+\s*\]", t)
    if m:
        return f"{contract_type_to_ts(m.group(1))}[]"
    # 引用（含 `&'static str` 这种带生命周期的）：剥掉引用与生命周期再推导
    m = re.fullmatch(r"&\s*(?:'\w+\s*)?(.+)", t)
    if m:
        return contract_type_to_ts(m.group(1))
    m = re.fullmatch(r"Option\s*<\s*(.+)\s*>", t)
    if m:
        return f"{contract_type_to_ts(m.group(1))} | null"
    if t in TYPE_SCALAR_TS:
        return TYPE_SCALAR_TS[t]
    return t


def validate_http(contract: HttpContract) -> List[str]:
    notes: List[str] = []
    path = contract.path

    if not contract.name:
        raise ContractError("缺少 'httpproto <名字>' 声明")
    if not contract.namespace:
        raise ContractError("缺少 'namespace <名字>' 声明")
    if not contract.base.startswith("/"):
        raise ContractError(f"base 必须以 '/' 开头，实际 {contract.base!r}")
    if contract.envelope is None:
        raise ContractError("缺少 envelope 块")
    if not contract.routes:
        raise ContractError("契约未声明任何 route")

    env_keys = [f.key for f in contract.envelope.fields]
    if env_keys != ["code", "data", "message"]:
        raise ContractError(
            f"envelope 字段必须恰为 code/data/message（顺序亦然），实际 {env_keys}"
        )
    notes.append(f"信封 {contract.envelope.name}: {' / '.join(env_keys)}")

    for req in ("failure_threshold", "lockout_seconds", "unauthorized_status"):
        if req not in contract.auth:
            raise ContractError(f"auth 缺少必填项 {req}")
    for k, v in contract.auth.items():
        if k in ("failure_threshold", "lockout_seconds", "unauthorized_status"):
            try:
                int(v)
            except ValueError:
                raise ContractError(f"auth.{k} 应为整数，实际 {v!r}")
    notes.append(
        "认证: 失败 "
        f"{contract.auth['failure_threshold']} 次锁 {contract.auth['lockout_seconds']}s，"
        f"未授权状态码 {contract.auth['unauthorized_status']}"
    )

    for name, decl in contract.headers.items():
        if decl.scope not in HEADER_SCOPES:
            raise ContractError(f"header {name}: scope 必须是 {HEADER_SCOPES} 之一，实际 {decl.scope!r}")
        if not decl.value:
            raise ContractError(f"header {name}: 缺少 value")
    notes.append(f"安全头 {len(contract.headers)} 条")

    seen_routes: Dict[Tuple[str, str], int] = {}
    for r in contract.routes:
        key = (r.method, r.path)
        if key in seen_routes:
            raise ContractError(f"路由 {r.method} {r.path} 重复定义（第 {seen_routes[key]} 行已有）")
        seen_routes[key] = r.line
        if r.auth not in ROUTE_AUTH:
            raise ContractError(f"{r.method} {r.path}: auth 必须是 {ROUTE_AUTH} 之一，实际 {r.auth!r}")
        if not r.handler:
            raise ContractError(f"{r.method} {r.path}: 缺少 handler")
        if r.returns not in ROUTE_RETURNS:
            raise ContractError(
                f"{r.method} {r.path}: returns 必须是 {ROUTE_RETURNS} 之一，实际 {r.returns!r}"
            )
        if r.returns == "stream":
            if r.max_connections is None:
                raise ContractError(f"{r.method} {r.path}: stream 路由必须声明 max_connections")
            if not r.events:
                raise ContractError(f"{r.method} {r.path}: stream 路由必须声明 events")
        else:
            for k in ("max_connections", "events", "keepalive_secs"):
                if getattr(r, k):
                    raise ContractError(f"{r.method} {r.path}: 非 stream 路由不得声明 {k}")
        if r.status is None:
            raise ContractError(f"{r.method} {r.path}: 缺少 status")
        for c in r.codes:
            if c not in contract.codes:
                raise ContractError(f"{r.method} {r.path}: 引用了未声明的业务码 {c}")

    # 业务码被引用的必须已声明，且每个已声明的码都应至少被一条路由引用
    referenced: set = set()
    for r in contract.routes:
        referenced.update(r.codes)
    for value in contract.code_order:
        if value not in referenced:
            notes.append(f"业务码 {value} 已声明但没有任何路由引用（可能是没落地的码）")

    n_none = sum(1 for r in contract.routes if r.auth == "none")
    notes.append(
        f"路由 {len(contract.routes)} 条（无认证 {n_none} / 需认证 {len(contract.routes) - n_none}）"
    )

    streams = [r for r in contract.routes if r.returns == "stream"]
    for s in streams:
        notes.append(
            f"SSE {s.method} {s.path}: 上限 {s.max_connections} 连接，"
            f"{len(s.events)} 个事件"
        )

    for name in contract.err_order:
        d = contract.err_models[name]
        if d.shape not in ERR_SHAPES:
            raise ContractError(f"errmodel {name}: shape 必须是 {ERR_SHAPES} 之一，实际 {d.shape!r}")
        if not d.statuses:
            raise ContractError(f"errmodel {name}: 缺少 statuses")
        if d.shape == "text" and not d.body:
            raise ContractError(f"errmodel {name}: text 形状必须给出 body")
    notes.append(f"错误形状 {len(contract.err_order)} 种")

    for name in contract.type_order:
        d = contract.types[name]
        keys: Dict[str, int] = {}
        for f in d.fields:
            if f.key in keys:
                raise ContractError(f"{name}: 字段 {f.key} 重复")
            keys[f.key] = f.line
            if not f.ftype:
                raise ContractError(f"{name}.{f.key}: 缺少字段类型")
        scope = f"（泛型参数 {'、'.join(d.params)}）" if d.params else ""
        notes.append(f"{'请求' if d.kind == 'request' else '响应'} {name}: {len(d.fields)} 个字段{scope}")

    # 与 validate_textproto 同一套规则：契约自己在**生成期**就把「说修好了、
    # 代码其实没动」这类谎话挡住，而不是等到 verify_*.py 才发现。
    for decl in contract.defects:
        if decl.severity not in SEVERITIES:
            raise ContractError(
                f"defect {decl.name}: severity 必须是 {'/'.join(SEVERITIES)}，实际 {decl.severity!r}"
            )
        if decl.status not in DEFECT_STATUSES:
            raise ContractError(
                f"defect {decl.name}: status 必须是 {'/'.join(DEFECT_STATUSES)}，实际 {decl.status!r}"
            )
        if decl.status == "fixed" and (not decl.fix or ":" not in decl.fix):
            raise ContractError(
                f"defect {decl.name}: status=fixed 必须给出 'fix = <文件>:<锚点>' 作为修复证据"
            )
        if decl.status != "fixed" and decl.fix:
            raise ContractError(
                f"defect {decl.name}: 仅 status=fixed 可给 fix（当前 status={decl.status}）"
            )
        if decl.status == "retained" and not decl.reason:
            raise ContractError(
                f"defect {decl.name}: status=retained 必须给出 reason 说明为何有意保留"
            )
        if decl.status != "retained" and decl.reason:
            raise ContractError(
                f"defect {decl.name}: 仅 status=retained 可给 reason（当前 status={decl.status}）"
            )
        if not decl.text:
            raise ContractError(f"defect {decl.name}: 缺少 text")
    if contract.defects:
        fixed = sum(1 for d in contract.defects if d.status == "fixed")
        retained = sum(1 for d in contract.defects if d.status == "retained")
        notes.append(
            f"缺陷记录: {len(contract.defects)} 条（已修 {fixed} / 有意保留 {retained} / "
            f"未修 {len(contract.defects) - fixed - retained}；由 verify_http.py 核对语义）"
        )
    return notes


# Go 侧的方法名惯例：契约里是大写 HTTP 方法，Go 标识符用首字母大写的驼峰。
GO_METHOD_IDENT: Dict[str, str] = {
    "GET": "Get",
    "POST": "Post",
    "PUT": "Put",
    "DELETE": "Delete",
    "PATCH": "Patch",
    "HEAD": "Head",
    "OPTIONS": "Options",
}


def go_path(path: str) -> str:
    """契约路径 -> ``net/http.ServeMux`` 路径。

    契约的参数槽写作 ``:ip``（Express/axum 的历史写法），Go 1.22 起的模式写作
    ``{ip}``；契约的多段通配写作 ``*path``，Go 侧对应 ``{path...}``。**通配不能原样
    保留**：ServeMux 只在没有方法前缀时才把 ``*name`` 当旧式通配，而本契约的注册串一律
    带方法（``GET /static/*path``），那时它匹配的是字面量 ``*path`` 这一段，真资源全部
    落到 ``GET /`` 上去。除这两种记号外不做任何改写，注册串与契约路径仍一一对应。
    """
    return re.sub(r"\*([A-Za-z_]\w*)", r"{\1...}", re.sub(r":([A-Za-z_]\w*)", r"{\1}", path))


def go_camel(text: str) -> str:
    """按非字母数字切块后逐块首字母大写拼接（契约里的路径 token 均为小写）。"""
    return "".join(t[0].upper() + t[1:] for t in re.split(r"[^A-Za-z0-9]+", text) if t)


def go_route_ident(route: HttpRoute) -> str:
    return "Route" + GO_METHOD_IDENT[route.method] + go_camel(route.path)


def go_sse_ident(route: HttpRoute) -> str:
    return go_camel(route.path)


# 契约取值 -> Go 常量名。枚举本身在 validate_http 里已约束到这几个值。
GO_AUTH_IDENT: Dict[str, str] = {"none": "AuthNone", "required": "AuthRequired"}
GO_RETURNS_IDENT: Dict[str, str] = {
    "type": "ReturnsType",
    "text": "ReturnsText",
    "bytes": "ReturnsBytes",
    "stream": "ReturnsStream",
}
GO_HEADER_SCOPE_IDENT: Dict[str, str] = {
    "all": "HeaderScopeAll",
    "api": "HeaderScopeAPI",
    "webui": "HeaderScopeWebUI",
}


def go_code_ident(value: int) -> str:
    if value == 0:
        return "CodeOK"
    if value < 0:
        return f"CodeNeg{abs(value)}"
    return f"Code{value}"


def emit_go_http(contract: HttpContract) -> str:
    """产出 daemon 侧消费的 Go 绑定：路由常量 + 路由表 + 业务码 + SSE + 安全头。

    只给常量与表，不给 handler 骨架——注册哪些 handler、载荷结构体长什么样是
    ``internal/http`` 的实现细节，契约管的是字面量只有一份。
    """
    L: List[str] = []
    a = L.append

    a("// 由 contract/http.fwidl 生成 —— 请勿手工编辑。")
    a("//")
    a("// 守护进程 HTTP 接口的注册串、业务码、SSE 上限与安全头单一真相源：路由在")
    a("// net/http.ServeMux 上注册时引用这里的常量与表，实现里不得再手打一遍路径")
    a("// 字面量。contract/verify_http.py 拿 routes.go 里出现的注册串与本表的")
    a("// Pattern 逐项核对，任何一侧多出来都算门禁失败。")
    a("//")
    a("// 消费方式：本文件由 gen.py 直接写进 daemon 的 module 内")
    a("// （src/daemon/internal/httpcontract/）——Go 只认 module 根之下的目录为包，")
    a("// 放在 contract/ 下就 import 不到。字面量的唯一来源仍是 contract/http.fwidl。")
    a("package httpcontract")
    a("")
    a("// 契约标识。")
    a("const (")
    a("\t// ContractName 是契约名（httpproto 块声明）。")
    a(f"\tContractName = {json.dumps(contract.name)}")
    a("\t// APIBase 是 RESTful 端点共用的前缀；SPA 页面、静态资源与健康检查在其外。")
    a(f"\tAPIBase = {json.dumps(contract.base)}")
    a(")")
    a("")

    # ---- 鉴权参数 ----
    auth = contract.auth
    a("// 鉴权参数。凭据来自配置的 metrics_username / metrics_password，两项都为空")
    a("// 才视为「未配置认证」；连续失败达到阈值后锁定的窗口内一律拒绝（含正确凭据）。")
    a("const (")
    a("\t// AuthFailureThreshold 是触发锁定前的连续失败次数。")
    a(f"\tAuthFailureThreshold = {int(auth['failure_threshold'])}")
    a("\t// AuthLockoutSeconds 是一次锁定持续的秒数。")
    a(f"\tAuthLockoutSeconds = {int(auth['lockout_seconds'])}")
    a("\t// AuthUnauthorizedStatus 是凭据缺失/错误时的 HTTP 状态码（纯文本形状，不经信封）。")
    a(f"\tAuthUnauthorizedStatus = {int(auth['unauthorized_status'])}")
    if "token_query" in auth:
        a("\t// AuthTokenQuery 是允许以查询参数携带凭据的键名（重定向必须原样保留 query）。")
        a(f"\tAuthTokenQuery = {json.dumps(auth['token_query'])}")
    if "scheme" in auth:
        a("\t// AuthScheme 是 Authorization 头里的凭据方案。")
        a(f"\tAuthScheme = {json.dumps(auth['scheme'])}")
    a(")")
    a("")

    # ---- 路由表字段的取值域 ----
    a("// 路由表字段的取值域，与契约里的枚举一一对应。")
    a("const (")
    a("\t// AuthNone 表示带与不带凭据都放行。")
    a('\tAuthNone = "none"')
    a("\t// AuthRequired 表示未带凭据（或凭据不符）必须返回未授权状态码。")
    a('\tAuthRequired = "required"')
    a("\t// ReturnsType 经信封返回 JSON 载荷。")
    a('\tReturnsType = "type"')
    a("\t// ReturnsText 不经信封，直接返回纯文本。")
    a('\tReturnsText = "text"')
    a("\t// ReturnsBytes 是二进制响应（静态文件）。")
    a('\tReturnsBytes = "bytes"')
    a("\t// ReturnsStream 是长连接 SSE，必须声明连接上限与事件名。")
    a('\tReturnsStream = "stream"')
    a("\t// HeaderScopeAll 表示安全头施加在所有响应上。")
    a('\tHeaderScopeAll = "all"')
    a("\t// HeaderScopeAPI 表示只施加在 API 响应上。")
    a('\tHeaderScopeAPI = "api"')
    a("\t// HeaderScopeWebUI 表示只施加在面板页面响应上。")
    a('\tHeaderScopeWebUI = "webui"')
    a(")")
    a("")

    # ---- 信封 ----
    env_keys = ", ".join(json.dumps(f.key) for f in contract.envelope.fields)
    a("// EnvelopeFields 是统一信封的 JSON key，顺序即契约顺序。三字段恒定存在：")
    a("// 成功时 code=0、data 为载荷；失败时 code 为业务码、data 为 null。")
    a(f"var EnvelopeFields = []string{{{env_keys}}}")
    a("")

    # ---- 业务码 ----
    a("// 业务码（信封里的 code 字段）。它与 HTTP 状态码是两套编号：状态码表达")
    a("// 「请求是否被处理」，业务码表达「为什么失败」，映射见 CodeHTTPStatus。")
    a("const (")
    for value in contract.code_order:
        d = contract.codes[value]
        a(f"\t// {go_code_ident(value)}：{d.text}")
        a(f"\t{go_code_ident(value)} = {value}")
    a(")")
    a("")
    a("// CodeHTTPStatus 是业务码到成功/失败 HTTP 状态码的映射。")
    a("var CodeHTTPStatus = map[int]int{")
    for value in contract.code_order:
        d = contract.codes[value]
        a(f"\t// {d.text}")
        a(f"\t{go_code_ident(value)}: {d.status},")
    a("}")
    a("")

    # ---- 路由注册串 ----
    a("// 路由注册串（net/http.ServeMux 的 \"METHOD /path\" 模式）。注释里的路径是")
    a("// 契约原文，鉴权列的是契约语义：required = 未带凭据必须 401，none = 带与不带")
    a("// 都放行。")
    a("const (")
    idents: Dict[Tuple[str, str], str] = {}
    seen: Dict[str, Tuple[str, str]] = {}
    for r in contract.routes:
        ident = go_route_ident(r)
        if ident in seen:
            raise ContractError(
                f"Go 标识符 {ident} 冲突：{seen[ident]} 与 {r.method} {r.path}"
                "（契约路径需要在去掉标点后有唯一的名字）"
            )
        seen[ident] = (r.method, r.path)
        idents[(r.method, r.path)] = ident
        auth_note = "需认证" if r.auth == "required" else "无认证"
        a(f"\t// {r.method} {r.path} → {r.handler}（{auth_note}）")
        a(f"\t{ident} = {json.dumps(r.method + ' ' + go_path(r.path))}")
    a(")")
    a("")

    # ---- SSE ----
    streams = [r for r in contract.routes if r.returns == "stream"]
    if streams:
        a("// 两条 SSE 流各自独立计数：上限与心跳按流声明，互不共享。诊断端点必须")
        a("// 同时报告两条流，否则前端按一条流的上限推断另一条会误判 503。")
        a("const (")
        for r in streams:
            suffix = go_sse_ident(r)
            a(f"\t// SSEMaxConnections{suffix} 是 {r.method} {r.path} 的并发连接上限。")
            a(f"\tSSEMaxConnections{suffix} = {r.max_connections}")
            if r.keepalive_secs:
                a(f"\t// SSEKeepaliveSeconds{suffix} 是 {r.method} {r.path} 的心跳间隔。")
                a(f"\tSSEKeepaliveSeconds{suffix} = {r.keepalive_secs}")
        a(")")
        a("")
        a("// 各流的事件名。发布侧必须逐字发这些名字（event: 行），前端订阅侧同此。")
        for r in streams:
            suffix = go_sse_ident(r)
            evs = ", ".join(json.dumps(e) for e in r.events)
            a(f"var SSEEventNames{suffix} = []string{{{evs}}}")
        a("")

    # ---- 路由表 ----
    a("// Route 是契约里的一条路由。Pattern 用于注册，Path 用于生成链接与重定向。")
    a("type Route struct {")
    a("\t// Pattern 是 ServeMux 注册串，逐字用于 mux.HandleFunc(Route.X, handler)。")
    a("\tPattern string")
    a("\t// Path 是去掉方法的路径，参数槽为 Go 写法（契约的 `:ip` 写作 `{ip}`）。")
    a("\tPath string")
    a("\t// Method 是 HTTP 方法，与 Pattern 的前缀一致。")
    a("\tMethod string")
    a("\t// Auth 取 AuthNone / AuthRequired。")
    a("\tAuth string")
    a("\t// Handler 是契约里的逻辑 handler 名（`handle_*`），用于对账与诊断输出；")
    a("\t// 不要求 Go 侧存在同名符号——注册串才是锚点。")
    a("\tHandler string")
    a("\t// Returns 取 Returns* 之一。")
    a("\tReturns string")
    a("\t// Status 是成功路径的 HTTP 状态码。")
    a("\tStatus int")
    a("\t// AltStatus 是同一路由上「成功但语义不同」的另一个状态码，0 表示没有。")
    a("\tAltStatus int")
    a("\t// Codes 是该路由可能返回的信封业务码，空表示只有成功路径。")
    a("\tCodes []int")
    a("\t// MaxConnections 是 stream 路由的连接上限，0 表示非 stream。")
    a("\tMaxConnections int")
    a("\t// Events 是 stream 路由的事件名全集。")
    a("\tEvents []string")
    a("\t// KeepaliveSecs 是 stream 路由的心跳间隔，0 表示契约未声明。")
    a("\tKeepaliveSecs int")
    a("}")
    a("")
    a("// Routes 是完整路由表，顺序与 contract/http.fwidl 的声明顺序一致。")
    a("var Routes = []Route{")
    for r in contract.routes:
        parts = [
            f"Pattern: {idents[(r.method, r.path)]}",
            f"Path: {json.dumps(go_path(r.path))}",
            f"Method: {json.dumps(r.method)}",
            f"Auth: {GO_AUTH_IDENT[r.auth]}",
            f"Handler: {json.dumps(r.handler)}",
            f"Returns: {GO_RETURNS_IDENT[r.returns]}",
            f"Status: {r.status}",
        ]
        if r.alt_status:
            parts.append(f"AltStatus: {r.alt_status}")
        if r.codes:
            parts.append(
                "Codes: []int{" + ", ".join(go_code_ident(c) for c in r.codes) + "}"
            )
        if r.returns == "stream":
            suffix = go_sse_ident(r)
            parts.append(f"MaxConnections: SSEMaxConnections{suffix}")
            parts.append(f"Events: SSEEventNames{suffix}")
            if r.keepalive_secs:
                parts.append(f"KeepaliveSecs: SSEKeepaliveSeconds{suffix}")
        a("\t{" + ", ".join(parts) + "},")
    a("}")
    a("")

    # ---- 安全头 ----
    a("// 安全头的名与值：中间件逐条引用这里的常量写响应头，实现里不出现第二份字符串。")
    a("// 标识符由头名派生（`X-Frame-Options` -> HeaderXFrameOptions），值由契约声明派生；")
    a("// `…ValueWebUI` 仅在契约给了 webui 分支值时存在。")
    a("const (")
    for name, d in contract.headers.items():
        ident = "Header" + go_camel(name)
        a(f"\t// {ident} 是头名 `{name}`（scope={d.scope}）。")
        a(f"\t{ident} = {json.dumps(name)}")
        a(f"\t// {ident}Value 是契约声明的 {name} 取值。")
        a(f"\t{ident}Value = {json.dumps(d.value)}")
        if d.value_webui:
            a(f"\t// {ident}ValueWebUI 是面板（HTML/JS 同源加载）响应用值。")
            a(f"\t{ident}ValueWebUI = {json.dumps(d.value_webui)}")
    a(")")
    a("")

    a("// SecurityHeader 是中间件统一施加的安全头。")
    a("type SecurityHeader struct {")
    a("\tName string")
    a("\t// Scope 取 HeaderScope* 之一，指明头施加在哪一类响应上。")
    a("\tScope string")
    a("\tValue string")
    a("\t// ValueWebUI 非空时，Web UI 页面响应用它替代 Value（SPA 需要更宽的 CSP）。")
    a("\tValueWebUI string")
    a("}")
    a("")
    a("// SecurityHeaders 是安全头全集，顺序与契约声明顺序一致。")
    a("var SecurityHeaders = []SecurityHeader{")
    for name, d in contract.headers.items():
        parts = [
            f"Name: {json.dumps(name)}",
            f"Scope: {GO_HEADER_SCOPE_IDENT[d.scope]}",
            f"Value: {json.dumps(d.value)}",
        ]
        if d.value_webui:
            parts.append(f"ValueWebUI: {json.dumps(d.value_webui)}")
        a("\t{" + ", ".join(parts) + "},")
    a("}")
    a("")

    # ---- 查询辅助 ----
    a("// RouteByPattern 按注册串查契约路由。")
    a("func RouteByPattern(pattern string) (Route, bool) {")
    a("\tfor _, r := range Routes {")
    a("\t\tif r.Pattern == pattern {")
    a("\t\t\treturn r, true")
    a("\t\t}")
    a("\t}")
    a("\treturn Route{}, false")
    a("}")
    a("")
    a("// RouteByMethodPath 按方法与路径查契约路由；路径可传契约写法（`:ip`）或")
    a("// Go 写法（`{ip}`），两种拼写在 GoPath 里归一。")
    a("func RouteByMethodPath(method, path string) (Route, bool) {")
    a("\twant := method + \" \" + GoPath(path)")
    a("\tfor _, r := range Routes {")
    a("\t\tif r.Pattern == want {")
    a("\t\t\treturn r, true")
    a("\t\t}")
    a("\t}")
    a("\treturn Route{}, false")
    a("}")
    a("")
    a("// Patterns 返回全部注册串，顺序同 Routes；契约测试用它逐条比对实现侧的注册。")
    a("func Patterns() []string {")
    a("\tout := make([]string, 0, len(Routes))")
    a("\tfor _, r := range Routes {")
    a("\t\tout = append(out, r.Pattern)")
    a("\t}")
    a("\treturn out")
    a("}")
    a("")
    a("// GoPath 把契约路径的参数槽 `:name` 转成 ServeMux 的 `{name}`，把多段通配")
    a("// `*name` 转成 `{name...}`，其余原样。通配必须转：ServeMux 只在**没有**方法前缀")
    a("// 时才认旧式 `*name`，而本契约的注册串条条带方法，留着 `*name` 就变成匹配字面量。")
    a("func GoPath(path string) string {")
    a("\tout := []byte{}")
    a("\tfor i := 0; i < len(path); i++ {")
    a("\t\tif path[i] == ':' && i+1 < len(path) && isIdentStart(path[i+1]) {")
    a("\t\t\tout = append(out, '{')")
    a("\t\t\ti++")
    a("\t\t\tfor i < len(path) && isIdentByte(path[i]) {")
    a("\t\t\t\tout = append(out, path[i])")
    a("\t\t\t\ti++")
    a("\t\t\t}")
    a("\t\t\tout = append(out, '}')")
    a("\t\t\ti--")
    a("\t\t\tcontinue")
    a("\t\t}")
    a("\t\tif path[i] == '*' && i+1 < len(path) && isIdentStart(path[i+1]) {")
    a("\t\t\tout = append(out, '{')")
    a("\t\t\ti++")
    a("\t\t\tfor i < len(path) && isIdentByte(path[i]) {")
    a("\t\t\t\tout = append(out, path[i])")
    a("\t\t\t\ti++")
    a("\t\t\t}")
    a("\t\t\tout = append(out, '.', '.', '.', '}')")
    a("\t\t\ti--")
    a("\t\t\tcontinue")
    a("\t\t}")
    a("\t\tout = append(out, path[i])")
    a("\t}")
    a("\treturn string(out)")
    a("}")
    a("")
    a("func isIdentStart(b byte) bool {")
    a("\treturn b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')")
    a("}")
    a("")
    a("func isIdentByte(b byte) bool {")
    a("\treturn isIdentStart(b) || (b >= '0' && b <= '9')")
    a("}")
    a("")
    return "\n".join(L)


def emit_ts_http(contract: HttpContract) -> str:
    L: List[str] = []
    L.append("/**")
    L.append(" * 由 contract/http.fwidl 生成 —— 请勿手工编辑。")
    L.append(" *")
    L.append(" * 守护进程 HTTP 接口的路径与 SSE 事件名单一真相源。前端不得再手写这些字面量。")
    L.append(" */")
    L.append("")
    L.append(f"/** API 前缀：{contract.base} */")
    L.append(f"export const API_BASE = {json.dumps(contract.base)}")
    L.append("")

    # 鉴权参数：登录页的提示文案（连续失败多少次、锁多久）与 401 判定都从这里取，
    # 不写在视图里——那两个数字是契约的 auth 段说了算，抄一份进 TSX 就是第二个真相源。
    auth = contract.auth
    L.append("/** 鉴权参数：scheme、query 凭据键名、失败计数阈值与锁定时长 */")
    L.append("export const AUTH = {")
    L.append(f"  /** `Authorization: {auth['scheme']} …` 里的凭据方案 */")
    L.append(f"  SCHEME: {json.dumps(auth['scheme'])},")
    if "token_query" in auth:
        L.append("  /** EventSource 不能设请求头，凭据走这个查询参数 */")
        L.append(f"  TOKEN_QUERY: {json.dumps(auth['token_query'])},")
    L.append("  /** 触发锁定前的连续失败次数 */")
    L.append(f"  FAILURE_THRESHOLD: {int(auth['failure_threshold'])},")
    L.append("  /** 一次锁定持续的秒数（锁定期内正确凭据同样被拒） */")
    L.append(f"  LOCKOUT_SECONDS: {int(auth['lockout_seconds'])},")
    L.append("  /** 凭据缺失/错误时的 HTTP 状态码（纯文本形状，不经信封） */")
    L.append(f"  UNAUTHORIZED_STATUS: {int(auth['unauthorized_status'])},")
    L.append("} as const")
    L.append("")

    L.append("/** 全部路由路径（与守护进程注册的字面量逐字一致） */")
    L.append("export const ROUTES = {")
    for r in contract.routes:
        ident = re.sub(r"[^A-Za-z0-9]+", "_", f"{r.method}_{r.path}").strip("_").upper()
        L.append(f"  /** `{r.method} {r.path}` */")
        L.append(f"  {ident}: {json.dumps(r.path)},")
    L.append("} as const")
    L.append("")
    for r in contract.routes:
        if r.returns != "stream":
            continue
        ident = re.sub(r"[^A-Za-z0-9]+", "_", r.path).strip("_").upper()
        L.append(f"/** `{r.path}` 的事件名联合类型（上限 {r.max_connections} 连接） */")
        L.append(
            "export type SseEvents"
            + "".join(p.capitalize() for p in ident.lower().split("_"))
            + " = "
            + " | ".join(json.dumps(e) for e in r.events)
        )
        L.append("")

    # 载荷类型 -> TS interface。前端 types.ts 必须与此逐字段一致
    # （verify_http.py 的跨层核对以此为真相源）。
    if contract.type_order:
        L.append("/** 响应/请求载荷类型（字段与 daemon 序列化出的 JSON key 一一对应） */")
        for name in contract.type_order:
            d = contract.types[name]
            if d.inline:
                continue  # 内联形状无具名结构体，字段已在 handler 内核对
            ifname = d.ts_name or name
            generic = f"<{', '.join(d.params)}>" if d.params else ""
            L.append(f"/** 契约类型 `{name}`{'（前端名）' if d.ts_name else ''} */")
            L.append(f"export interface {ifname}{generic} {{")
            for f in d.fields:
                L.append(f"  {f.key}: {contract_type_to_ts(f.ftype)}")
            L.append("}")
            L.append("")
    return "\n".join(L)


def emit_json_http(contract: HttpContract, notes: List[str]) -> str:
    env = contract.envelope
    doc: Dict[str, object] = {
        "source": os.path.basename(contract.path),
        "kind": "http",
        "name": contract.name,
        "namespace": contract.namespace,
        "base": contract.base,
        "notes": notes,
        "envelope": {
            "name": env.name,
            "params": env.params,
            "fields": [{"key": f.key, "type": f.ftype} for f in env.fields],
        },
        "auth": contract.auth,
        "headers": {
            name: {
                "scope": d.scope,
                "value": d.value,
                "value_webui": d.value_webui,
            }
            for name, d in contract.headers.items()
        },
        "routes": [
            {
                "method": r.method,
                "path": r.path,
                "auth": r.auth,
                "handler": r.handler,
                "returns": r.returns,
                "status": r.status,
                "alt_status": r.alt_status,
                "codes": r.codes,
                "max_connections": r.max_connections,
                "events": r.events,
                "keepalive_secs": r.keepalive_secs,
                "note": r.note,
            }
            for r in contract.routes
        ],
        "types": {
            name: {
                "kind": contract.types[name].kind,
                "params": contract.types[name].params,
                "ts_name": contract.types[name].ts_name or name,
                "inline": contract.types[name].inline,
                "fields": [
                    {"key": f.key, "type": f.ftype} for f in contract.types[name].fields
                ],
            }
            for name in contract.type_order
        },
        "codes": {
            str(v): {"status": contract.codes[v].status, "text": contract.codes[v].text}
            for v in contract.code_order
        },
        "errmodels": {
            name: {
                "shape": contract.err_models[name].shape,
                "statuses": contract.err_models[name].statuses,
                "body": contract.err_models[name].body,
                "note": contract.err_models[name].note,
            }
            for name in contract.err_order
        },
        "defects": [
            {
                "name": d.name,
                "severity": d.severity,
                "status": d.status,
                "fix": d.fix,
                "reason": d.reason,
                "resolution": d.resolution,
                "text": d.text,
            }
            for d in contract.defects
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


# ============================================================================
# 入口
# ============================================================================

# 各契约的默认产物与 C 头保护宏（不写 --targets 时用这里的默认值）
CONTRACTS: Dict[str, Dict[str, object]] = {
    "netlink.fwidl": {
        "targets": ["c", "ts", "json"],
        "out": {
            "c": "netlink_uapi.h",
            "ts": "netlink.d.ts",
            "json": "netlink_layout.json",
        },
        "c_guard": "FW_CONTRACT_NETLINK_UAPI_H",
    },
    "procfs.fwidl": {
        # 前端不接触 procfs，故不产出 TS 产物（无消费者不生成，避免死产物）
        "targets": ["c", "json"],
        "out": {
            "c": "procfs_uapi.h",
            "json": "procfs_layout.json",
        },
        "c_guard": "FW_CONTRACT_PROCFS_UAPI_H",
    },
    "http.fwidl": {
        # HTTP 契约是 daemon 与前端之间的接口，故产出 Go 侧路由表与 TS 侧常量；
        # 无 C 产物（内核不经由 HTTP 暴露任何东西）。
        "targets": ["go", "ts", "json"],
        "out": {
            "go": "http_contract.go",
            "ts": "http_contract.ts",
            "json": "http_layout.json",
        },
        # Go 产物不落 contract/generated，而是直接写进 daemon 的 module：Go 以 module
        # 根（src/daemon）为界，界外目录不是包，跨界 import 编不过。写两份同内容文件
        # 会制造「哪份是真相」的歧义，所以只写 module 里那一份——门禁读的也是它。
        "in_module": {
            "go": os.path.join("src", "daemon", "internal", "httpcontract", "http_contract.go"),
        },
    },
}


def generate(source: str, targets: Optional[List[str]], out_dir: str, check: bool) -> int:
    """校验一份契约并按需产出绑定。返回 0 通过、1 校验失败、2 用法错误。"""
    base = os.path.basename(source)
    cfg = CONTRACTS.get(base, {})
    chosen = (
        [t.strip() for t in targets if t.strip()]
        if targets
        else list(cfg.get("targets", ["c", "json"]))
    )
    out_names: Dict[str, str] = dict(cfg.get("out", {}))
    # 少数产物必须落在消费方自己的目录树里（Go 契约进 module），路径按仓库根解析。
    in_module: Dict[str, str] = dict(cfg.get("in_module", {}))
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c_guard = str(cfg.get("c_guard", "FW_CONTRACT_GENERATED_H"))

    try:
        kind = detect_format(source)
        if kind == "http":
            http = parse_http(source)
            notes = validate_http(http)
        elif kind == "textproto":
            tp = parse_textproto(source)
            notes = validate_textproto(tp)
        else:
            binary = parse(source)
            notes = validate(binary)
    except ContractError as exc:
        print(f"契约校验失败（{base}）: {exc}", file=sys.stderr)
        return 1

    print(f"契约 {base}: 校验通过（{kind}）")
    for n in notes:
        print(f"  - {n}")

    if check:
        return 0

    os.makedirs(out_dir, exist_ok=True)
    emitted: List[str] = []
    try:
        for t in chosen:
            if kind == "http":
                # HTTP 契约描述的是 daemon↔前端的接口，没有字节布局也没有 C 消费者
                if t == "go":
                    content, fname = emit_go_http(http), out_names.get("go", "generated.go")
                elif t == "ts":
                    content, fname = emit_ts_http(http), out_names.get("ts", "generated.ts")
                elif t == "json":
                    content, fname = emit_json_http(http, notes), out_names.get("json", "layout.json")
                else:
                    raise ContractError(f"HTTP 契约不支持产物类型 {t!r}")
            elif kind == "textproto":
                # 文本协议没有字节布局，故没有 TS 产物（前端不接触 procfs）
                if t == "c":
                    content, fname = emit_c_textproto(tp, c_guard), out_names.get("c", "generated.h")
                elif t == "json":
                    content, fname = emit_json_textproto(tp, notes), out_names.get("json", "layout.json")
                else:
                    raise ContractError(f"文本协议契约不支持产物类型 {t!r}")
            elif t == "c":
                content, fname = emit_c(binary, c_guard), out_names.get("c", "generated.h")
            elif t == "ts":
                content, fname = emit_ts(binary), out_names.get("ts", "generated.d.ts")
            elif t == "json":
                content, fname = emit_json(binary, notes), out_names.get("json", "layout.json")
            else:
                raise ContractError(f"未知产物类型 {t!r}")
            dest = os.path.join(out_dir, fname)
            if t in in_module:
                dest = os.path.join(repo_root, in_module[t])
                os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(content)
            emitted.append(dest)
    except ContractError as exc:
        print(f"产物生成失败（{base}）: {exc}", file=sys.stderr)
        return 1

    for p in emitted:
        print(f"  已写出 {p}")
    return 0


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="从 .fwidl 生成各端契约绑定")
    ap.add_argument(
        "source",
        nargs="?",
        help=".fwidl 文件路径；省略时处理 contract/ 下登记的全部契约",
    )
    ap.add_argument("--out-dir", default="contract/generated", help="产物输出目录")
    ap.add_argument("--targets", default=None, help="逗号分隔的产物: c,go,ts,json")
    ap.add_argument("--check", action="store_true", help="只校验并打印布局，不写文件")
    args = ap.parse_args(argv)

    targets = args.targets.split(",") if args.targets else None

    if args.source:
        if not os.path.isfile(args.source):
            print(f"错误: 找不到 {args.source}", file=sys.stderr)
            return 2
        sources = [args.source]
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        sources = [os.path.join(here, name) for name in sorted(CONTRACTS)]

    for src in sources:
        code = generate(src, targets, args.out_dir, args.check)
        if code:
            return code
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
