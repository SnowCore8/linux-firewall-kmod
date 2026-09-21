#!/usr/bin/env python3
"""HTTP 契约一致性校验：契约 vs daemon 路由/响应结构体 + 前端 TS 类型。

为什么需要这一步
----------------
``gen.py`` 只保证**契约自身自洽**（路由不重复、业务码都被引用、stream 路由
都有上限……），完全没有核对契约是不是在描述真实接口。HTTP 契约比前两种更
容易撒谎，因为它横跨三个表面：

* daemon 的 axum 路由注册（路径与方法）
* daemon 的 Rust 响应结构体（JSON 字段与类型）
* 前端的 TS 类型与端点封装（同一批字段的另一个副本）

任何一处对不上，表现都是「页面某个字段永远是 undefined」或「请求 404」，
而不是编译错误——所以必须机械核对。

做法（全部为机械核对，不做语义推断）
------------------------------------
1. ``handler.rs`` 里 ``.route("<路径>", <method>(<handler>))`` 的集合必须与契约
   **逐条**相同：路径、方法、handler、以及它落在 public 组还是 protected 组。
2. 认证常量（失败阈值 / 锁定秒数）与两条 SSE 的连接上限必须与契约数值相同。
3. 信封 ``ApiResponse`` 的字段必须恰为 code/data/message。
4. 每个声明的业务码必须在源码里出现 ``::error(<码>`` 调用点。
5. ``errmodel`` 的文本形状必须能在源码里找到该响应体原文；``axum_default``
   形状必须能在源码里找到它声明的提取器。
6. 安全头的值（含 Web UI 分支的 CSP）必须逐字出现在中间件里。
7. SSE 事件的每个事件名必须在推送侧与订阅侧都存在。
8. 每个载荷类型的每个字段必须能在对应 Rust 结构体里找到（容忍 serde 会把
   ``r#type`` 序列化成 ``type``）；以及该结构体确实派生 ``Serialize``。
9. **跨层**：同一字段必须同时出现在前端 ``types.ts``；契约里每条路由都必须
   在前端 ``endpoints.ts`` 有消费者，且前端不得调用契约外的路径。
10. ``where`` 锚点必须仍存在，且形状合法。

用法::

    python3 contract/verify_http.py
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
LAYOUT_JSON = os.path.join(GEN_DIR, "http_layout.json")

HANDLER_RS = os.path.join(ROOT, "src", "daemon", "http_exporter", "handler.rs")
HTTP_MOD_RS = os.path.join(ROOT, "src", "daemon", "http_exporter", "mod.rs")
AUTH_RS = os.path.join(ROOT, "src", "daemon", "http_exporter", "auth.rs")
# 已迁入 `api` 层的 SSE 引擎（两条流的上限、事件名、keep-alive 都在这里）
SSE_RS = os.path.join(ROOT, "src", "daemon", "api", "sse.rs")
LOG_VIEWER_RS = os.path.join(ROOT, "src", "daemon", "web_ui", "log_viewer.rs")
# 统一信封（ApiResponse / PaginatedResponse / ApiError / BusinessCode）
ENVELOPE_RS = os.path.join(ROOT, "src", "daemon", "api", "envelope.rs")
# 已迁入 `api` 层的路由装配与其余 handler（两组由 check_routes 合并核对）
API_ROUTER_RS = os.path.join(ROOT, "src", "daemon", "api", "router.rs")
# E 的修复面：旧读路径（`get_active_bans` 的写副作用）与新的周期清理装配点
BAN_OPS_RS = os.path.join(ROOT, "src", "daemon", "web_ui", "ban_ops.rs")
SCHEDULER_RS = os.path.join(ROOT, "src", "daemon", "runtime", "scheduler.rs")
MAIN_RS = os.path.join(ROOT, "src", "daemon", "main.rs")

TS_TYPES = os.path.join(ROOT, "frontend", "src", "api", "types.ts")
TS_ENDPOINTS = os.path.join(ROOT, "frontend", "src", "api", "endpoints.ts")

# Rust 源码根目录：逐个文件读入，用于「字段是否存在于结构体」的核对。
# `api` 排在最前——同一批载荷类型在 `web_ui` 里还有一份旧副本（尚未退役），
# 若把 `web_ui` 放前面，核对会落在旧结构体上、把已迁入的字段漂移漏掉。
RUST_SRC_DIRS = [
    os.path.join(ROOT, "src", "daemon", "api"),
    os.path.join(ROOT, "src", "daemon", "types"),
    os.path.join(ROOT, "src", "daemon", "history_snapshot"),
    os.path.join(ROOT, "src", "daemon"),
    os.path.join(ROOT, "src", "daemon", "web_ui"),
]

# 认证常量名 -> 契约里的键
AUTH_CONSTS = {
    "failure_threshold": "AUTH_FAILURE_THRESHOLD",
    "lockout_seconds": "AUTH_LOCKOUT_DURATION",
}

# SSE 路径 -> 源码里的连接上限常量名
#
# 两个常量现在都住在 `src/daemon/api/sse.rs`（`SseStatus` 同时持有两条流的计数器），
# 靠**常量名**而不是「路径里含不含 events」来选取，避免再出现「按路径猜文件」的脆弱对应。
SSE_LIMIT_CONST = {
    "/api/v1/events": "MAX_SSE_CONNECTIONS",
    "/api/v1/logs/stream": "MAX_LOG_SSE_CONNECTIONS",
}

# 契约里的路径参数写法 -> 前端 endpoints.ts 里的模板串写法
PARAM_RE = re.compile(r":(\w+)")


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _fn_body(src: str, name: str) -> str | None:
    """取 ``fn <name>(...)`` 的函数体（按花括号配平），找不到返回 None。

    用于核对某个 handler **内部**用了什么、没用什么——全文 includes 会被
    别处的同名标识符干扰（例如 handle_health 的断言要求函数体内不得出现
    ApiResponse，而文件里其它 handler 必然出现）。
    """
    m = re.search(rf"\bfn\s+{re.escape(name)}\s*[(<]", src)
    if not m:
        return None
    i = src.find("{", m.end())
    if i < 0:
        return None
    depth = 0
    start = i
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start: i + 1]
        i += 1
    return None


def rust_sources() -> dict:
    """返回 {仓库相对路径: 源码}，覆盖 daemon 侧全部 .rs。"""
    out = {}
    for d in RUST_SRC_DIRS:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".rs"):
                continue
            p = os.path.join(d, f)
            out[os.path.relpath(p, ROOT)] = read(p)
    return out


# ---------------------------------------------------------------------------
# 1. 路由表
# ---------------------------------------------------------------------------

# 尾部允许 ``get(handler),`` 这种多行写法带的尾随逗号（否则 11 条路由会被漏解析）
_ROUTE_RE = re.compile(
    r'\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|delete|patch|head|options)\s*\(\s*(\w+)\s*\)\s*,?\s*\)',
    re.S,
)


def split_router_groups(src: str, api_router_src: str) -> tuple[str, str, str, str]:
    """把退役期的四个路由组分别切出来：public / 未迁入 / 已迁入 / 探针。

    退役期（`api` 逐步接手旧 `http_exporter`）的路由分散在**两个文件**，必须分别切：

      * public 组（无认证，SPA 外壳与静态资源）—— `handler.rs::build_router`
      * 未迁入的需认证组 —— `handler.rs::legacy_protected_routes`（路径字面量）
      * 已迁入的需认证组 —— `api/router.rs::protected_routes`
        （登记的是 `path::ROUTE_*` 常量，不是字面量）
      * 探针组（`/health`、`/healthz`）—— `api/router.rs::health_routes`

    两组合并后才等于契约的需认证路由全集；只读一处会漏掉另一半。任一锚点缺失
    即返回空串，由调用方报错（不静默放过）。
    """
    m_pub = re.search(r"let\s+public_routes\s*=\s*Router::new\(\)", src)
    m_pro = re.search(r"let\s+mut\s+protected_routes\s*=\s*legacy_protected_routes\(\)", src)
    if not m_pub or not m_pro:
        return "", "", "", ""
    return (
        src[m_pub.start(): m_pro.start()],
        _fn_body(src, "legacy_protected_routes") or "",
        _fn_body(api_router_src, "protected_routes") or "",
        _fn_body(api_router_src, "health_routes") or "",
    )


def _resolve_path_consts(src: str, prefix: str = "path::") -> dict:
    """把源码片段里用到的 ``path::ROUTE_*`` 常量按生成物解成路径字面量。

    已迁入组登记的是**标识符**而不是字面量（`path::ROUTE_GET_API_V1_BANS`），
    直接扫字符串会看到零条路由。这里到 ``contract/generated/http_contract.rs``
    的 ``path`` 模块查表——那张表本身就由 `http.fwidl` 生成，等价于回到契约。
    """
    gen = read(os.path.join(GEN_DIR, "http_contract.rs"))
    table = dict(re.findall(r'pub\s+const\s+(ROUTE_\w+)\s*:\s*&str\s*=\s*"([^"]*)"', gen))
    out = {}
    for name in re.findall(rf"{re.escape(prefix)}(\w+)", src):
        if name in table:
            out[name] = table[name]
    return out


def check_routes(contract: dict) -> list[str]:
    problems: list[str] = []
    src = read(HANDLER_RS)
    api_router = read(API_ROUTER_RS)
    pub_src, legacy_src, api_src, health_src = split_router_groups(src, api_router)
    if not pub_src or not legacy_src:
        return ["未能在 handler.rs 的 build_router 里切出 public/未迁入两个路由组"]
    if not api_src:
        return ["未能在 api/router.rs 里切出 protected_routes 路由组"]

    def parse(segment: str, group: str) -> dict:
        found = {}
        for m in _ROUTE_RE.finditer(segment):
            path, method, handler = m.group(1), m.group(2).upper(), m.group(3)
            found[(method, path)] = (handler, group)
        return found

    actual = {}
    actual.update(parse(pub_src, "none"))
    actual.update(parse(legacy_src, "required"))
    # 探针组与已迁入组一样登记 `path::ROUTE_*` 常量，同样按生成物解回字面量。
    for segment in (health_src, api_src):
        consts = _resolve_path_consts(segment)
        for m in re.finditer(
            r"\.route\(\s*(path::\w+)\s*,\s*(get|post|put|delete)\s*\(\s*(\w+)\s*\)",
            segment,
        ):
            const_name, method, handler = (
                m.group(1).rsplit("::", 1)[-1],
                m.group(2).upper(),
                m.group(3),
            )
            if const_name not in consts:
                problems.append(
                    f"已迁入路由组引用了生成物里没有的常量 path::{const_name}"
                    "（契约需重新生成？）"
                )
                continue
            group = "none" if segment is health_src else "required"
            actual[(method, consts[const_name])] = (handler, group)

    declared = {}
    for r in contract["routes"]:
        declared[(r["method"].upper(), r["path"])] = r

    for key, r in sorted(declared.items()):
        if key not in actual:
            problems.append(
                f"路由 {key[0]} {key[1]} 在 handler.rs / api/router.rs 中不存在"
                f"（契约声明 handler {r['handler']}）"
            )
            continue
        handler, group = actual[key]
        if r["auth"] != group:
            problems.append(
                f"路由 {key[0]} {key[1]}: 契约 auth={r['auth']} 但源码落在 {group} 组"
            )
        if handler != r["handler"]:
            problems.append(
                f"路由 {key[0]} {key[1]}: 源码 handler {handler} != 契约 {r['handler']}"
            )
    for key in sorted(actual):
        if key not in declared:
            problems.append(
                f"handler.rs / api/router.rs 中存在契约未声明的路由 {key[0]} {key[1]}"
            )

    n_none = sum(1 for r in contract["routes"] if r["auth"] == "none")
    print(
        f"  契约 {len(declared)} 条路由 / 源码 {len(actual)} 条"
        f"（无认证 {n_none}；已迁入组按 path::ROUTE_* 常量解析）"
    )
    return problems


# ---------------------------------------------------------------------------
# 2. 认证常量与 SSE 连接上限
# ---------------------------------------------------------------------------


def _const_value(src: str, name: str) -> int | None:
    m = re.search(rf"\b(?:pub\s+)?const\s+{name}\s*:\s*\w+\s*=\s*([^;]+);", src)
    if not m:
        return None
    expr = m.group(1)
    # 支持 `60`、`60 * 1000`、`10` 这类常量表达式
    try:
        return int(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - 只允许算术
    except Exception:
        try:
            return int(expr.strip())
        except ValueError:
            return None


def check_auth_constants(contract: dict) -> list[str]:
    problems: list[str] = []
    src = read(HTTP_MOD_RS)
    for key, const in AUTH_CONSTS.items():
        actual = _const_value(src, const)
        want = int(contract["auth"][key])
        if actual is None:
            problems.append(f"auth.{key}: 在 http_exporter/mod.rs 中找不到常量 {const}")
        elif actual != want:
            problems.append(f"auth.{key}: 契约 {want} != 源码 {const}={actual}")
        else:
            print(f"  auth.{key}: {actual} == {const}")

    # 未授权响应体与「不发 WWW-Authenticate」两条断言
    auth_src = read(AUTH_RS)
    body = contract["errmodels"].get("AUTH_UNAUTHORIZED", {}).get("body")
    if body:
        token = body.strip()
        if token and token not in auth_src:
            problems.append(
                f"errmodel AUTH_UNAUTHORIZED: 响应体 {token!r} 未出现在 http_exporter/auth.rs"
            )
        else:
            print(f"  errmodel AUTH_UNAUTHORIZED: 响应体在 auth.rs 中存在")
    # 「不发 WWW-Authenticate」只能核对**真实的头构造点**：auth.rs 的文档注释
    # 里逐字解释了「有意不发它」，全文 includes 会因此假阳性。header 只可能经
    # HeaderValue::from_static / from_str 或 headers.insert / append 构造。
    header_ctor = re.compile(
        r"""(?:HeaderValue::from_(?:static|str)|headers?\.(?:insert|append))
            \s*\(\s*"?WWW[-_]AUTHENTICATE"?""",
        re.X | re.I,
    )
    if header_ctor.search(auth_src):
        problems.append(
            "auth.rs 里真的构造了 WWW-Authenticate 响应头 —— 契约声明有意不发送"
            "该头（会让浏览器弹原生对话框、fetch 挂起）"
        )
    else:
        print("  auth: auth.rs 未构造 WWW-Authenticate（符合契约）")
    return problems


def check_sse_limits(contract: dict) -> list[str]:
    problems: list[str] = []
    # 两条流的上限常量都在 `api/sse.rs`：`SseStatus` 同时持有 events / logs 两组
    # 计数器，上限常量自然与它同处。日志流引擎（log_viewer.rs）只持有自己的那条流。
    src = read(SSE_RS)
    for r in contract["routes"]:
        if r["returns"] != "stream":
            continue
        const = SSE_LIMIT_CONST.get(r["path"])
        if const is None:
            problems.append(f"SSE {r['path']}: 校验器不知道其上限常量名")
            continue
        actual = _const_value(src, const)
        if actual is None:
            problems.append(f"SSE {r['path']}: 在 api/sse.rs 中找不到常量 {const}")
        elif actual != r["max_connections"]:
            problems.append(
                f"SSE {r['path']}: 契约上限 {r['max_connections']} != 源码 {const}={actual}"
            )
        else:
            print(f"  SSE {r['path']}: 上限 {actual} == {const}")
    return problems


# ---------------------------------------------------------------------------
# 3. 信封
# ---------------------------------------------------------------------------


def check_envelope(contract: dict) -> list[str]:
    problems: list[str] = []
    src = read(ENVELOPE_RS)
    m = re.search(r"struct\s+ApiResponse\s*<[^>]*>\s*\{", src)
    if not m:
        return ["未能在 src/daemon/api/envelope.rs 中定位 struct ApiResponse"]
    i = m.end()
    depth = 1
    while i < len(src) and depth:
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
        i += 1
    body = src[m.end(): i - 1]
    fields = re.findall(r"^\s*pub\s+(\w+)\s*:", body, re.M)
    declared = [f["key"] for f in contract["envelope"]["fields"]]
    if fields != declared:
        problems.append(f"信封字段: 源码 {fields} != 契约 {declared}")
    else:
        print(f"  信封 {contract['envelope']['name']}: 字段 {fields} 一致")

    # 成功路径的 message 必须是空串
    if not re.search(r"message\s*:\s*String::new\(\)", src):
        problems.append("信封 ok() 未把 message 置为空串（契约声明成功时 message 为空）")
    # 失败信封的 data 必须是 `()`（序列化成 null），不能是别的占位。
    if not re.search(r"data\s*:\s*\(\s*\)", src):
        problems.append("失败信封的 data 不是 ()（契约声明失败时 data 为 null）")
    return problems


# ---------------------------------------------------------------------------
# 4. 业务码
# ---------------------------------------------------------------------------


def check_codes(contract: dict) -> list[str]:
    """每个非零业务码必须有一个真实的构造点。

    退役期里构造点分两处，都要覆盖：

      * `api/envelope.rs` 的 `BusinessCode` 枚举（码值在这里唯一定义）
      * `api/routes/*.rs`（已迁入的 7 个码）与 `http_exporter/handler.rs`（未迁入的
        50002 / 40005，以及历史库任务失败路径）

    旧实现靠 `::error(<码` 的字面调用点判定；新实现把码升级成枚举，字面量因此从
    调用点消失，改为核对「枚举变体存在 + 有构造该变体的位置」。
    """
    problems: list[str] = []
    envelope = read(ENVELOPE_RS)
    api_routes = "".join(
        read(os.path.join(ROOT, "src", "daemon", "api", "routes", f))
        for f in sorted(os.listdir(os.path.join(ROOT, "src", "daemon", "api", "routes")))
        if f.endswith(".rs")
    )
    handler = read(HANDLER_RS)
    # 枚举定义里必须逐字出现该码值（`Self::X => 40001,`）
    for value, meta in sorted(contract["codes"].items(), key=lambda kv: int(kv[0])):
        code = int(value)
        if code == 0:
            continue
        if not re.search(rf"=>\s*{code}\s*,", envelope):
            problems.append(
                f"业务码 {code}（HTTP {meta['status']}）：未在 api/envelope.rs 的"
                f" BusinessCode 中定义"
            )
            continue
        # 构造点：`BusinessCode::<变体>` 出现在路由或旧 handler 里
        variant = re.search(rf"(\w+)\s*=>\s*{code}\s*,", envelope)
        name = variant.group(1) if variant else None
        hit = False
        if name:
            hit = bool(
                re.search(rf"BusinessCode::{name}\b", api_routes)
                or re.search(rf"BusinessCode::{name}\b", handler)
            )
        # 旧 handler 没有枚举，仍用字面 `::error(<码`
        literal = f"::error({code}" in handler or f"::error({code}," in handler
        if not hit and not literal:
            problems.append(
                f"业务码 {code}（HTTP {meta['status']}）：api/routes 与 handler.rs 中"
                f" 都没有构造点（既无 BusinessCode::{name or '?'} 也无 ::error({code}）"
            )
    print(f"  业务码 {len(contract['codes'])} 个已核对（枚举定义 + 构造点）")
    return problems


# ---------------------------------------------------------------------------
# 5. 错误形状
# ---------------------------------------------------------------------------


def check_errmodels(contract: dict) -> list[str]:
    problems: list[str] = []
    handler = read(HANDLER_RS)
    auth = read(AUTH_RS)
    # axum 提取器的真实使用点已随路由迁到 `api/routes/*.rs`；handler.rs 只剩
    # 静态资源与日志两处。两个目录都要扫，否则 `Path(<` 这类断言会假失败。
    api_routes = "".join(
        read(os.path.join(ROOT, "src", "daemon", "api", "routes", f))
        for f in sorted(os.listdir(os.path.join(ROOT, "src", "daemon", "api", "routes")))
        if f.endswith(".rs")
    )
    extractor_src = handler + api_routes
    for name, d in contract["errmodels"].items():
        if d["shape"] == "text":
            body = d["body"].strip()
            if body and body not in handler and body not in auth:
                problems.append(
                    f"errmodel {name}: 文本响应体 {body!r} 未出现在 handler.rs / auth.rs"
                )
        elif d["shape"] == "axum_default":
            # 默认错误由提取器产生：源码里必须真的用了对应的提取器
            for extractor in ("Json", "Query", "Path"):
                if extractor in d["note"] and not re.search(
                    rf"\b{extractor}\s*[(<]", extractor_src
                ):
                    problems.append(
                        f"errmodel {name}: 契约声明由 {extractor} 提取器产生默认错误，"
                        f"但 handler.rs / api/routes 都未使用 {extractor}"
                    )
    print(f"  错误形状 {len(contract['errmodels'])} 种已核对")
    return problems


# ---------------------------------------------------------------------------
# 6. 安全头
# ---------------------------------------------------------------------------


def check_headers(contract: dict) -> list[str]:
    problems: list[str] = []
    src = read(HANDLER_RS)
    for name, d in contract["headers"].items():
        for label, value in (("value", d["value"]), ("value_webui", d["value_webui"])):
            if not value:
                continue
            if value not in src:
                problems.append(f"header {name}.{label} 的值未逐字出现在 security_headers_middleware")
        if d["scope"] == "webui" and "is_webui" not in src:
            problems.append("header 声明了 webui 分支，但中间件里找不到 is_webui 判断")
    print(f"  安全头 {len(contract['headers'])} 条已核对")
    return problems


# ---------------------------------------------------------------------------
# 7. SSE 事件（推送侧 + 订阅侧）
# ---------------------------------------------------------------------------


def check_sse_events(contract: dict) -> list[str]:
    """推送侧与订阅侧的事件名核对，**按引擎而非按路径**分派。

    两条流的事件名来源不同，不能共用一套文字扫描：

      * ``/api/v1/events``（`api/sse.rs`）—— 域事件名不是字面量，由
        `state/hub.rs` 的 `Domain::name()` 产生（`stats`/`bans`/`jails`/
        `whitelist`/`rates`），推送点写作 `StreamMessage::new(domain.name(), …)`；
        只有 `connected` 是字面量。故这里改成核对「`Domain::name()` 的返回值集合
        覆盖契约的域事件」+「connected 有字面量推送点」。
      * ``/api/v1/logs/stream``（`log_viewer.rs`）—— 三个事件都是字面量
        `.event("…")`，沿用原来的直接扫描。
    """
    problems: list[str] = []
    events_src = read(SSE_RS)
    hub_src = read(os.path.join(ROOT, "src", "daemon", "state", "hub.rs"))
    logs_src = read(LOG_VIEWER_RS)
    subscribe = read(os.path.join(ROOT, "frontend", "src", "hooks", "useSse.ts"))
    logs_page = read(os.path.join(ROOT, "frontend", "src", "views", "Logs.tsx"))
    # `Domain::name()` 实际返回的字符串集合，例如 {"stats", "bans", ...}
    domain_names = set(re.findall(r'Self::\w+\s*=>\s*"(\w+)"', hub_src))
    for r in contract["routes"]:
        if r["returns"] != "stream":
            continue
        if r["path"] == "/api/v1/events":
            src, consumer, consumer_name = events_src, subscribe, "useSse.ts"
            for ev in r["events"]:
                if ev == "connected":
                    # 连接建立事件是字面量推送点。
                    if "StreamMessage::new(\"connected\"" not in src:
                        problems.append(
                            "SSE /api/v1/events: 事件 'connected' 无字面量推送点"
                        )
                elif f'"{ev}"' not in src and ev not in domain_names:
                    problems.append(
                        f"SSE /api/v1/events: 事件 {ev!r} 既非 Domain::name() 的返回值"
                        f"（实际 {sorted(domain_names)}），也无字面量推送点"
                    )
                if f"'{ev}'" not in consumer and f'"{ev}"' not in consumer:
                    problems.append(
                        f"SSE /api/v1/events: 事件 {ev!r} 在前端订阅侧找不到（{consumer_name}）"
                    )
        else:
            src, consumer, consumer_name = logs_src, logs_page, "Logs.tsx"
            for ev in r["events"]:
                if f'.event("{ev}")' not in src:
                    problems.append(f"SSE {r['path']}: 事件 {ev!r} 在 log_viewer.rs 中无推送点")
                if f"'{ev}'" not in consumer and f'"{ev}"' not in consumer:
                    problems.append(
                        f"SSE {r['path']}: 事件 {ev!r} 在前端订阅侧找不到（{consumer_name}）"
                    )
        print(f"  SSE {r['path']}: {len(r['events'])} 个事件已核对（推送 + 订阅）")
    return problems


# ---------------------------------------------------------------------------
# 8. 载荷类型（Rust 侧）
# ---------------------------------------------------------------------------


def find_struct(srcs: dict, name: str) -> tuple[str, str, str] | None:
    """返回 (相对路径, 完整源码, 结构体体部) 或 None。支持带泛型参数的结构体。"""
    pat = re.compile(rf"struct\s+{re.escape(name)}\s*(?:<[^>]*>)?\s*\{{")
    for rel, src in srcs.items():
        m = pat.search(src)
        if not m:
            continue
        i = m.end()
        depth = 1
        while i < len(src) and depth:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        # 派生宏：向 struct 关键字之前回看一段
        head = src[max(0, m.start() - 600): m.start()]
        derives = head.rsplit("}", 1)[-1] if "}" in head else head
        return rel, derives, src[m.end(): i - 1]
    return None


def struct_field_names(body: str) -> list[str]:
    """结构体里 pub 字段的名字（raw identifier ``r#x`` 归一化成 ``x``）。"""
    names = []
    for m in re.finditer(r"^\s*pub\s+(?:r#)?(\w+)\s*:", body, re.M):
        names.append(m.group(1))
    return names


def check_types_rust(contract: dict) -> list[str]:
    problems: list[str] = []
    srcs = rust_sources()
    for name, decl in contract["types"].items():
        if decl.get("inline"):
            # 内联形状（没有具名 struct，如早期的 sse-status serde_json::json!）改为
            # 核对 JSON key 出现在对应的 handler 里。当前契约已把 sse-status 升级为
            # 具名结构体（`api/payloads.rs`），这条分支保留给将来真正的内联形状。
            handler = read(HANDLER_RS)
            for f in decl["fields"]:
                if f'"{f["key"]}"' not in handler:
                    problems.append(
                        f"内联类型 {name}: JSON key {f['key']!r} 未出现在 handler.rs"
                    )
            print(f"  内联类型 {name}: {len(decl['fields'])} 个 JSON key 已在 handler.rs 核对")
            continue
        found = find_struct(srcs, name)
        if found is None:
            problems.append(f"类型 {name}: 未能在 daemon 源码里找到同名 struct")
            continue
        rel, derives, body = found
        # 响应类型只序列化，请求体只反序列化（部分结构体两者都派生，也满足各自侧）
        want = "Deserialize" if decl["kind"] == "request" else "Serialize"
        if want not in derives:
            problems.append(f"类型 {name}（{rel}）: 未派生 {want}")
        actual = struct_field_names(body)
        for f in decl["fields"]:
            if f["key"] not in actual:
                problems.append(
                    f"类型 {name}（{rel}）: 契约字段 {f['key']!r} 在 struct 中不存在"
                    f"（实际字段 {actual}）"
                )
        for extra in actual:
            if extra not in [f["key"] for f in decl["fields"]]:
                problems.append(f"类型 {name}（{rel}）: struct 字段 {extra!r} 未在契约中声明")
    print(f"  载荷类型 {len(contract['types'])} 个：Rust 字段已逐项核对")
    return problems


# ---------------------------------------------------------------------------
# 9. 跨层：前端 TS 类型与端点
# ---------------------------------------------------------------------------


def parse_ts_interfaces(src: str) -> dict:
    """{类型名: [字段名]}，只取 interface（type 别名由契约单独处理）。"""
    out = {}
    for m in re.finditer(r"export\s+interface\s+(\w+)(?:\s*<[^>]*>)?\s*\{", src):
        i = m.end()
        depth = 1
        while i < len(src) and depth:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        body = src[m.end(): i - 1]
        names = []
        for line in body.splitlines():
            s = line.strip()
            if not s or s.startswith("//") or s.startswith("*") or s.startswith("/*"):
                continue
            fm = re.match(r"([A-Za-z_]\w*)\??\s*:", s)
            if fm:
                names.append(fm.group(1))
        out[m.group(1)] = names
    return out


def check_types_frontend(contract: dict) -> list[str]:
    problems: list[str] = []
    ts = parse_ts_interfaces(read(TS_TYPES))
    checked = 0
    for name, decl in contract["types"].items():
        if decl["kind"] == "request":
            continue  # 请求体由 endpoints.ts 的泛型参数体现，不单独在 types.ts 重复声明
        if decl.get("inline"):
            continue  # 内联形状在前端由调用点就地声明，不做跨层字段核对
        # 前端 interface 名可与 Rust 结构体名不同（契约用 ts_name 显式声明）
        iface = decl.get("ts_name") or name
        if iface not in ts:
            problems.append(
                f"类型 {name}: 前端 types.ts 中缺少 interface {iface}"
                + (f"（契约声明 ts_name={iface}）" if decl.get("ts_name") else "")
            )
            continue
        checked += 1
        actual = ts[iface]
        for f in decl["fields"]:
            if f["key"] not in actual:
                problems.append(f"类型 {name}: 前端缺少字段 {f['key']!r}（实际 {actual}）")
        for extra in actual:
            if extra not in [f["key"] for f in decl["fields"]]:
                problems.append(f"类型 {name}: 前端多出字段 {extra!r}（契约中未声明）")
    print(f"  前端 types.ts: {checked} 个 interface 已与契约逐项对照字段")
    return problems


def strip_ts_comments(src: str) -> str:
    """去掉 TS 里的块注释与行注释。

    注释里的示例路径（`` `/api/v1/whitelist/10.0.0.0/8` ``）只是说明文字，
    不剥离会被当成"契约外路径"。endpoints.ts 的字符串字面量中不含 ``//``
    与 ``/*``，因此按注释剥离不会误伤真实调用。
    """
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def check_routes_frontend(contract: dict) -> list[str]:
    """契约的每条路由必须在前端有消费者；前端不得调用契约外的路径。"""
    problems: list[str] = []
    src = strip_ts_comments(read(TS_ENDPOINTS))

    # 收集前端出现的所有 /api/v1 路径字面量。
    # 注意：三个字符类都必须含反引号——开头那个漏掉反引号时，模板串
    # （`` `/api/v1/bans/${...}/detail` ``）整体不会被匹配，会误报"前端未调用"。
    front_paths = set(re.findall(r"['\"`](/api/v1[^'\"`]*)['\"`]", src))
    # 去掉模板串里的 ${...} 之后的残余，统一成契约的 :param 写法
    normalized = set()
    for p in front_paths:
        p = p.rstrip("/")
        normalized.add(p)

    declared_paths = {r["path"].rstrip("/") for r in contract["routes"]}
    # 前端用模板串拼路径参数：把契约的 :ip 还原成 .* 后做匹配
    def matches(declared: str, front: str) -> bool:
        pat = "^" + PARAM_RE.sub(r"[^/]+", re.escape(declared).replace(r"\:", ":")) + "$"
        return re.search(pat, front) is not None

    missing = []
    for r in contract["routes"]:
        if not r["path"].startswith("/api/v1"):
            continue  # /health 等由 checkHealth 这类显式调用覆盖，单独核对
        if r["path"] == "/api/v1/events":
            continue  # SSE 地址是常量而非字符串字面量，由 check_sse_events 覆盖
        hit = any(matches(r["path"], f) for f in normalized)
        if not hit:
            missing.append(f"{r['method']} {r['path']}")
    for m in missing:
        problems.append(f"前端 endpoints.ts 未调用契约路由 {m}")

    # 反向：前端调了契约外的路径
    for f in sorted(normalized):
        if any(matches(d, f) for d in declared_paths):
            continue
        problems.append(f"前端 endpoints.ts 调用了契约外的路径 {f}")

    print(
        f"  前端 endpoints.ts: 出现 {len(normalized)} 条 /api/v1 路径，"
        f"与契约 {len(declared_paths)} 条双向核对"
    )
    return problems


# ---------------------------------------------------------------------------
# 10. where 锚点
# ---------------------------------------------------------------------------


def _shape_ok(kind: str, where: str, problems: list[str], field: str = "where") -> bool:
    """校验 ``<相对路径>:<非空锚点>`` 的形状，不合法时记问题并返回 False。"""
    if not where or "\n" in where or "\r" in where:
        problems.append(f"{kind}: {field} 为空或含换行，契约被破坏: {where!r}")
        return False
    rel, sep, anchor = where.partition(":")
    if not sep or not rel or not anchor:
        problems.append(f"{kind}: {field} 形状非法（应为 '<路径>:<锚点>'）: {where!r}")
        return False
    if os.path.isabs(rel) or rel.startswith(".."):
        problems.append(f"{kind}: {field} 必须用仓库相对路径: {rel!r}")
        return False
    return True


def _anchor_exists(where: str) -> bool:
    """``where/fix`` 的锚点是否仍在仓库里。文件不存在视为「已消失」。"""
    rel, sep, anchor = where.partition(":")
    if not sep:
        return False
    path = os.path.join(ROOT, rel)
    if not os.path.isfile(path):
        return False
    return anchor in read(path)


def _anchor_ok(kind: str, where: str, problems: list[str]) -> bool:
    """形状合法**且**锚点仍在——用于 errmodel 这种「必须仍在」的锚点。"""
    if not _shape_ok(kind, where, problems):
        return False
    if _anchor_exists(where):
        return True
    rel, _, anchor = where.partition(":")
    if os.path.isfile(os.path.join(ROOT, rel)):
        problems.append(f"{kind}: 锚点 {anchor!r} 在 {rel} 中已不存在（实现已变，契约需同步）")
    else:
        problems.append(f"{kind}: 锚点文件不存在 {rel}")
    return False


def check_anchors(contract: dict) -> list[str]:
    """核对 errmodel 与 defect 的 where / fix 锚点（defect 按 status 分派）。

    errmodel 的 where 必须**仍在**（错误形状还在实现里）。

    defect 按 status 分派，与 ``verify_procfs.py`` 同一套语义：

      open     —— 缺陷未修，``where`` 必须仍存在
      retained —— 有意保留，``where`` 必须指向源码里说明「有意保留」的注释
      fixed    —— 已修，``where`` 反过来必须**已消失**，``fix`` 指向修复证据且必须存在

    形状校验：锚点必须是 ``<相对路径>:<非空锚点>``，且路径在仓库内。不这样校验，
    一条被截断/含换行的 where 会被当成「文件名含换行」报出难以理解的错误。
    """
    problems: list[str] = []
    n_ok = 0

    for name, d in contract["errmodels"].items():
        if _anchor_ok(f"errmodel {name}", d["where"], problems):
            n_ok += 1

    for d in contract["defects"]:
        kind, status, where = f"defect {d['name']}", d["status"], d["where"]
        if not _shape_ok(kind, where, problems):
            continue
        w_exists = _anchor_exists(where)
        if status in ("open", "retained"):
            if w_exists:
                n_ok += 1
            else:
                problems.append(f"{kind}: status={status} 但 where 锚点 '{where}' 不存在")
        elif status == "fixed":
            if w_exists:
                rel = where.partition(":")[0]
                problems.append(
                    f"{kind}: status=fixed 但旧现场 '{where}' 仍在 "
                    f"（{rel} 若属旧实现应删除；若实现已修则契约需改判）"
                )
            else:
                n_ok += 1
            fix = d.get("fix") or ""
            if not _shape_ok(kind, fix, problems, field="fix"):
                continue
            if _anchor_exists(fix):
                n_ok += 1
            else:
                problems.append(f"{kind}: status=fixed 但修复证据锚点 '{fix}' 不存在")
        else:
            problems.append(f"{kind}: 未知 status {status!r}")

    print(f"  {n_ok} 个 where/fix 锚点核对通过（含形状与 status 分派）")
    return problems


# ---------------------------------------------------------------------------
# 11. 已核实缺陷的机械断言
# ---------------------------------------------------------------------------


def check_defect_claims(contract: dict) -> list[str]:
    """对能机械判定的 defect 做断言；缺陷被修好则门禁失败，强制契约同步。

    每条断言都只在**源码里真实存在该缺陷**时通过。任何一条被修好（单位统一、
    今日窗口落地、total_detected 补齐……）都会在这里失败，提醒契约同步——契约
    不能说一件代码里已经不成立的事。

    已改判为 ``fixed`` / ``retained`` 的缺陷不再在此断言：``fixed`` 的旧现场
    已消失，机械断言本就不可能成立；``retained`` 的有意保留由源码注释承载，
    断言见下方 ``HTTP_HEALTH_NOT_ENVELOPED`` 分支。
    """
    problems: list[str] = []
    declared = {d["name"] for d in contract["defects"]}
    asserted: set[str] = set()

    def ok(name: str, msg: str) -> None:
        asserted.add(name)
        print(f"  defect {name}: {msg}（成立）")

    def fail(name: str, msg: str) -> None:
        asserted.add(name)
        problems.append(f"defect {name} 已失效：{msg}，契约需同步")

    for d in contract["defects"]:
        name = d["name"]
        if name == "HTTP_RECIDIVISM_RATE_UNIT":
            # 同名不同单位必须**同时**成立：一处乘 100、一处不乘。
            ratio = read(os.path.join(ROOT, "src", "daemon", "web_ui", "stats.rs"))
            level = read(os.path.join(ROOT, "src", "daemon", "web_ui", "analysis.rs"))
            pct = re.search(
                r"recidivism_rate\s*=\s*if\s+total_ips\s*>\s*0\s*\{[^}]*\}\s*else",
                ratio,
                re.S,
            )
            if pct and "* 100.0" in pct.group(0):
                has_pct = True
            else:
                has_pct = False
            # BanLevelEffectiveness.recidivism_rate 赋的是纯比例（不含 * 100）
            m = re.search(r"recidivism_rate:\s*(\w+)\s*,", level)
            plain = bool(m) and not re.search(
                rf"recidivism_rate\s*=\s*\w+\s*\*\s*100", level
            )
            if has_pct and plain:
                ok(name, "stats.rs 是百分数(0-100) 而 analysis.rs 是比例(0-1)")
            else:
                fail(name, f"单位已统一（stats 百分数={has_pct}，analysis 比例={plain}）")
        elif name == "HTTP_TODAY_BANS_EQUALS_TOTAL":
            # today_bans 与 total_bans 取的是同一个原子量。修复后会不同。
            src = read(os.path.join(ROOT, "src", "daemon", "web_ui", "stats.rs"))
            t = re.search(r"let\s+today_bans\s*=\s*(.+?);", src, re.S)
            tot = re.search(r"let\s+total_bans\s*=\s*(.+?);", src, re.S)
            if t and tot:
                def norm(s: str) -> str:
                    return re.sub(r"\s+", "", s)

                if norm(t.group(1)) == norm(tot.group(1)):
                    ok(name, "today_bans 与 total_bans 读取的是同一个值")
                else:
                    fail(name, "today_bans 与 total_bans 已是不同取值")
            else:
                fail(name, "stats.rs 里找不到 today_bans / total_bans 的取值语句")
        elif name == "HTTP_THRESHOLD_RECOMMENDATION_ZERO_AMBIGUOUS":
            # maintain 分支取 current 而非 0，不存在「0=无需调整」的生成点。
            src = read(
                os.path.join(ROOT, "src", "daemon", "history_snapshot", "threshold_analysis.rs")
            )
            if re.search(r'recommended_threshold:\s*recommended\b', src) and re.search(
                r'"maintain"\.to_string\(\)', src
            ):
                ok(name, "maintain 分支返回原阈值，从不产生 0")
            else:
                fail(name, "推荐阈值的生成分支已改变")
        elif name == "HTTP_SERVICE_PROBE_NO_TOTAL":
            # ServiceProbeResponse 缺 total_detected，而 PortScanResponse 有。
            src = read(os.path.join(ROOT, "src", "daemon", "web_ui", "packet_analysis.rs"))
            probe = re.search(r"struct\s+ServiceProbeResponse\s*\{(.*?)\}", src, re.S)
            scan = re.search(r"struct\s+PortScanResponse\s*\{(.*?)\}", src, re.S)
            if probe and scan:
                if "total_detected" not in probe.group(1) and "total_detected" in scan.group(1):
                    ok(name, "ServiceProbeResponse 仍无 total_detected（PortScanResponse 有）")
                else:
                    fail(name, "ServiceProbeResponse 已补上 total_detected 或 PortScanResponse 已移除")
            else:
                fail(name, "packet_analysis.rs 里找不到两个 Response 结构体")
        elif name == "HTTP_HEALTH_NOT_ENVELOPED":
            # status=retained：裸状态码是**有意保留**的探针语义。断言它仍然裸着，
            # 且源码里写明了这是有意例外——一旦有人套上信封，这里会失败。
            runtime_src = read(os.path.join(ROOT, "src", "daemon", "api", "routes", "runtime.rs"))
            body = _fn_body(runtime_src, "handle_health")
            if body is None:
                fail(name, "api/routes/runtime.rs 里找不到 fn handle_health")
            elif "ApiResponse" in body or "ApiError" in body:
                fail(name, "handle_health 已改为经过信封（有意保留的裸状态码被改掉）")
            elif "non-enveloped" not in runtime_src and "有意例外" not in runtime_src:
                fail(name, "runtime.rs 未写明 /health 的裸状态码是有意保留")
            else:
                ok(name, "handle_health 仍直接返回裸 JSON，且源码写明是有意例外")
        elif name == "HTTP_READ_PATH_WRITES_STATE":
            # status=fixed：读路径的写副作用已删，且清理任务**真的接进了生产**。
            #
            # 只判「旧锚点消失」不够——本条缺陷此前正是以「新侧已就位、只差装配」的
            # 形态挂着（Bans::purge_expired 已写好但无人调用）。故这里额外要求
            # main.rs 装配 runtime::spawn_periodic、调度器回调里真的调用
            # purge_expired_bans：否则「读路径不再清、也没有别人清」只是把缺陷换了个
            # 马甲（过期条目会永久滞留）。
            ban_ops = read(BAN_OPS_RS)
            body = _fn_body(ban_ops, "get_active_bans")
            reads = body is not None and "purge_expired" not in body
            scheduler = read(SCHEDULER_RS)
            purge_called = "purge_expired_bans" in scheduler
            main_src = read(MAIN_RS)
            wired = "spawn_periodic" in main_src
            if reads and purge_called and wired:
                ok(name, "get_active_bans 读路径已无 purge，周期清理由 main.rs 装配的调度器驱动")
            else:
                fail(
                    name,
                    "读路径或装配状态不符"
                    f"（读路径无purge={reads} 调度器调用={purge_called} main装配={wired}）",
                )
        elif name == "HTTP_LOG_SSE_LIMIT_DOC_DRIFT":
            # status=fixed：误导性注释已修正。断言旧注释**已消失**、新注释**在**，
            # 且两条流的上限常量各自独立且不等（10 / 5）——修复的是注释不是实现。
            logs = read(LOG_VIEWER_RS)
            sse = read(SSE_RS)
            m10 = re.search(r"const\s+MAX_SSE_CONNECTIONS\s*:\s*usize\s*=\s*(\d+)", sse)
            m5 = re.search(r"const\s+MAX_LOG_SSE_CONNECTIONS\s*:\s*usize\s*=\s*(\d+)", sse)
            old_doc = "SSE 连接与 Web UI SSE 共享" in logs
            new_doc = "各自独立计数与上限" in logs
            if m10 and m5 and not old_doc and new_doc and m10.group(1) != m5.group(1):
                ok(
                    name,
                    f"误导性『共享』注释已消失、新注释在位，两值独立且不等"
                    f"（{m10.group(1)} / {m5.group(1)}）",
                )
            else:
                fail(
                    name,
                    "旧注释仍在或新注释缺失"
                    f"（old={old_doc} new={new_doc} 10={bool(m10)} 5={bool(m5)}）",
                )
        elif name == "HTTP_BANS_DUAL_SHAPE":
            # status=fixed：服务端只留单一形状（分页信封），前端也必须只剩一层返回类型。
            # 这条缺陷此前是「服务端修了、契约写了 fixed，前端却仍按裸数组取用」——
            # 断言前端**已删除**重载与运行期分支，否则契约在说一件代码里不成立的事。
            src = strip_ts_comments(read(TS_ENDPOINTS))
            overloads = len(re.findall(r"export\s+function\s+getBans\s*\(", src))
            bare = "Promise<BanResponse[]>" in src
            paged = "Promise<PaginatedResponse<BanResponse>>" in src
            if overloads == 1 and paged and not bare:
                ok(name, "getBans 只有单一分页形状（无重载、无裸数组返回类型）")
            else:
                fail(
                    name,
                    "前端仍保留裸数组形状"
                    f"（getBans 定义 {overloads} 处，裸数组={bare}，分页={paged}）",
                )
        elif name == "HTTP_BAN_SORT_DOC_INCOMPLETE":
            # doc 只列 4 值、实现 7 值，且前端 union 与实现一致。
            # 实现里 6 个是 Some("...") 臂，第 7 个 banned_at_desc 落在 `_` 默认臂
            # （靠行尾注释标注），所以要单独把默认值捞出来。
            src = read(os.path.join(ROOT, "src", "daemon", "web_ui", "ban_ops.rs"))
            doc = re.search(r"排序字段（可选）[^\n]*", src)
            block = re.search(
                r"match\s+sort_by\.as_deref\(\)\s*\{(.*?)\n    \}", src, re.S
            )
            ts = read(TS_TYPES)
            mts = re.search(r"export\s+type\s+BanSortKey\s*=(.*?)(?:\n\n|\Z)", ts, re.S)
            keys = re.findall(r"'([a-z_]+)'", mts.group(1)) if mts else []
            if not doc or not block or not keys:
                fail(name, "找不到 sort_by 文档 / match 块 / 前端 BanSortKey")
            else:
                impl_set = set(re.findall(r'Some\("(\w+)"\)', block.group(1)))
                dflt = re.search(r"_[\s\S]*?//\s*(\w+_\w+)", block.group(1))
                if dflt:
                    impl_set.add(dflt.group(1))
                doc_keys = set(re.findall(r"[a-z][a-z_]*_(?:asc|desc)\b", doc.group(0)))
                ts_set = set(keys)
                if impl_set == ts_set and doc_keys < impl_set:
                    ok(
                        name,
                        f"doc 仅列 {len(doc_keys)} 值，实现与前端同为 {len(impl_set)} 值",
                    )
                else:
                    fail(
                        name,
                        "取值集合已对齐"
                        f"（doc={len(doc_keys)} impl={len(impl_set)} ts={len(ts_set)}）",
                    )

    # 契约里声明了缺陷却没有机械断言 —— 显式报出来，避免「看着有 defect 段
    # 就以为都校验了」的假安全感。
    # （errmodel 的 where 存在性由 check_anchors 覆盖，不在此列。）
    unasserted = sorted(declared - asserted)
    if unasserted:
        print(f"  提示：以下 defect 仅有锚点核对，无机械断言：{', '.join(unasserted)}")
    return problems


def check_artifacts() -> list[str]:
    """确认 HTTP 生成物本身可用：Rust 契约能编译、TS 契约能过类型检查。"""
    problems: list[str] = []
    print("=== 生成物自检（各自工具链）===")
    rs_src = os.path.join(GEN_DIR, "http_contract.rs")
    with tempfile.TemporaryDirectory() as td:
        rlib = os.path.join(td, "h.rlib")
        proc = subprocess.run(
            ["rustc", "--edition", "2021", "--crate-type", "lib", "-o", rlib, rs_src],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            problems.append("http_contract.rs 编译失败:\n" + proc.stderr[-3000:])
            print("  失败  http_contract.rs 编译")
        else:
            print("  OK    http_contract.rs 编译")

    ts_src = os.path.join(GEN_DIR, "http_contract.ts")
    tsc = os.environ.get("TSC") or os.path.join(ROOT, "frontend", "node_modules", ".bin", "tsc")
    if os.path.isfile(tsc):
        proc = subprocess.run(
            [tsc, "--noEmit", "--strict", "--skipLibCheck", "--target", "es2020",
             "--lib", "es2020,dom", ts_src],
            capture_output=True, text=True, cwd=ROOT,
        )
        if proc.returncode != 0:
            problems.append("http_contract.ts 类型检查失败:\n" + proc.stdout[-3000:])
            print("  失败  http_contract.ts tsc --noEmit")
        else:
            print("  OK    http_contract.ts tsc --noEmit")
    else:
        print(f"  跳过  http_contract.ts tsc（未找到 {tsc}）")
    print()
    return problems


def check_migration_ratchet(contract: dict) -> list[str]:
    """迁移棘轮：未迁入 api/ 的路由是对照冻结基线**只减不增**的集合。

    背景：三端重写要把 ``handler.rs::legacy_protected_routes``（路径字面量）里的
    路由陆续搬进 ``api/router.rs::protected_routes``（``path::ROUTE_*`` 常量）。
    仅靠「契约里声明过该路由」就能通过门禁，于是新端点可以悄悄加进 legacy 组而
    无人察觉 —— 本检查堵住这一点。

    ``route_baseline legacy`` 冻结迁移开始时的未迁全集。规则是只能变小：

      1. 基线里的路由必须真的还在 ``legacy_protected_routes()`` 里。少了一条就是
         可疑删除（要迁就走迁移流程，不要从基线里删一行了事）。
      2. 源码里出现基线之外、又不在 api/ 组的路由 —— 新端点，必须迁入 api/。

    迁移一条后**必须**同步删除对应基线行，否则该路由同时命中上面两条（这正是
    刻意的摩擦：迁移动作要显式落在契约里）。

    只按 ``auth`` 分组的 ``check_routes`` 无法覆盖这一维度（legacy 与 api 两组的
    auth 都是 ``required``，互换也通过）。
    """
    problems: list[str] = []
    src = read(HANDLER_RS)
    api_router = read(API_ROUTER_RS)
    _, legacy_src, api_src, health_src = split_router_groups(src, api_router)
    if not legacy_src or not api_src:
        return ["未能在 handler.rs / api/router.rs 里切出路由组，迁移棘轮无法核对"]

    api_group = set()
    for segment in (api_src, health_src):
        consts = _resolve_path_consts(segment)
        for m in re.finditer(
            r"\.route\(\s*(path::\w+)\s*,\s*(get|post|put|delete)\s*\(\s*(\w+)\s*\)",
            segment,
        ):
            const_name = m.group(1).rsplit("::", 1)[-1]
            if const_name in consts:
                api_group.add((m.group(2).upper(), consts[const_name]))

    legacy_group = {
        (m.group(2).upper(), m.group(1)) for m in _ROUTE_RE.finditer(legacy_src)
    }
    baseline = {
        (e["method"].upper(), e["path"]) for e in contract.get("route_baseline", [])
    }
    if not baseline:
        return ["契约缺少 'route_baseline legacy' 块，迁移棘轮无基线可比"]

    for key in sorted(baseline - legacy_group):
        problems.append(
            f"迁移棘轮: 基线里的 {key[0]} {key[1]} 已不在 legacy 组 —— 若是迁移请"
            "同步删除该基线行；若是误删则改回"
        )
    for key in sorted(legacy_group - baseline - api_group):
        problems.append(
            f"迁移棘轮: {key[0]} {key[1]} 既不在冻结基线、也不在 api/ 组 —— "
            "新端点必须迁入 api/（契约 route 声明 + api/router.rs 登记）"
        )

    print(
        f"  迁移棘轮: 基线 {len(baseline)} 条 / legacy 组 {len(legacy_group)} 条 / "
        f"api 组 {len(api_group)} 条"
    )
    return problems


def main() -> int:
    if not os.path.isfile(LAYOUT_JSON):
        print("错误: 未找到生成物，请先运行 gen.py", file=sys.stderr)
        return 2
    with open(LAYOUT_JSON, encoding="utf-8") as fh:
        contract = json.load(fh)

    print("=== HTTP 契约 vs daemon + 前端 ===")
    failures: list[str] = []
    failures += check_routes(contract)
    print()
    failures += check_migration_ratchet(contract)
    print()
    failures += check_auth_constants(contract)
    print()
    failures += check_sse_limits(contract)
    print()
    failures += check_envelope(contract)
    print()
    failures += check_codes(contract)
    print()
    failures += check_errmodels(contract)
    print()
    failures += check_headers(contract)
    print()
    failures += check_sse_events(contract)
    print()
    failures += check_types_rust(contract)
    print()
    failures += check_types_frontend(contract)
    print()
    failures += check_routes_frontend(contract)
    print()
    failures += check_anchors(contract)
    print()
    failures += check_defect_claims(contract)
    print()
    failures += check_artifacts()

    print()
    if failures:
        print("HTTP 契约校验失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        "HTTP 契约校验通过：路由、认证、SSE、信封、业务码、错误形状、安全头与"
        "前后端字段均与实现一致"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
