#!/usr/bin/env python3
"""HTTP 契约一致性校验：契约 vs daemon 的 Go 路由/响应结构体 + 前端 TS 类型。

为什么需要这一步
----------------
``gen.py`` 只保证**契约自身自洽**（路由不重复、业务码都被引用、stream 路由
都有上限……），完全没有核对契约是不是在描述真实接口。HTTP 契约比前两种更
容易撒谎，因为它横跨三个表面：

* daemon 的 ``net/http.ServeMux`` 注册串（Go 1.22 的 ``"METHOD /path"`` 模式）
* daemon 的 Go 响应结构体与 ``WriteSuccess`` 载荷（JSON 字段与类型）
* 前端的 TS 类型与端点封装（同一批字段的另一个副本）

任何一处对不上，表现都是「页面某个字段永远是 undefined」或「请求 404」，
而不是编译错误——所以必须机械核对。

做法（全部为机械核对，不做语义推断）
------------------------------------
1. daemon 里的 ``X.HandleFunc("<METHOD> <路径>", <handler>)`` 集合必须与契约
   **逐条**相同：注册串、方法、以及它的鉴权包装（``RequireAuth`` = 需认证 /
   无包装 = 公开）。注册分散在 ``internal/http/routes.go``、``static.go`` 与
   ``cmd/firewall-daemon/main.go``，故扫整个 daemon 的 Go 源码而不是单个文件。
   注册串写成生成物常量（``httpcontract.RouteXxx``）时按生成物表解回字面量。
   契约的 ``handler`` 记的就是这一侧解析出的注册符号（``_handler_symbol``），逐条
   等值比较：契约与源码同一步改，差一字即报出。
   不带方法前缀的 ``Handle("<路径>", h)`` 在 ServeMux 里匹配任何动词：按路径回落到
   它核对存在性与鉴权组，另记一条「方法未收紧」的缺口（未声明的动词本该由框架回 405）。
2. 认证常量（失败阈值 / 锁定秒数）与两条 SSE 各自的连接上限必须与契约数值相同。
   值只认 **手写的 daemon 源码**：``src/daemon/internal/httpcontract/http_contract.go``
   是 gen.py 写进 module 的生成物，里面的数字由契约本身产生，拿它核对契约等于空转，
   故它从搜索根里显式排除；手写代码 ``httpcontract.<名>`` 引用它才算落地证据。
3. 信封（``envelope.go``）的 JSON key 必须恰为 code/data/message（顺序即契约顺序，
   Go 的 ``encoding/json`` 就按声明顺序输出）；成功 message 必须是空串；失败 data
   必须**以 null 出现**，不能靠 ``omitempty`` 省略。
4. 每个声明的业务码必须在 Go 源码里有构造点（``Code<码>`` 常量或裸数字字面量）。
5. 文本形状的错误体必须逐字出现在 Go 源码里（401 是纯文本、且不发
   ``WWW-Authenticate``）；框架默认形状把状态码分成两类——net/http 自产的
   404/405（源码里本就不该有）与必须由 daemon 自己写出的 400/415/422，
   后者必须有构造点。
6. 安全头的值（含 Web UI 分支的 CSP）必须逐字出现在 Go 侧的中间件里，
   且 webui 分支必须有判别条件。
7. SSE 事件的每个事件名必须在发布侧（``Publish("<事件>"`` 或 ``event: <事件>``
   字面量）与前端订阅侧都存在。Go 侧没有 Rust 那套「按域版本号」机制，
   故不再核对 ``Domain::X`` 的发布者，改为逐事件名找发布点。
8. 每个载荷类型的每个字段必须能在对应 Go 结构体里找到（``json:"<key>"`` 标签；
   无标签时 Go 用导出字段名，大小写是唯一差异），且该结构体在 ``internal/http``
   里**真有构造点**——「仓库里有这个 struct」不等于 handler 返回的是它。
9. **跨层**：同一字段必须同时出现在前端 ``types.ts``；契约里每条路由都必须在前端
   ``endpoints.ts`` 有消费者（前端已改为引用生成物的 ``ROUTES.<名>``，路径字面量
   只在 ``contract/generated/http_contract.ts`` 里存在），且前端不得调用契约外的路径。
10. 锚点按 ``status`` 分派：``fixed`` 要求 ``fix`` 证据锚点存在。HTTP 契约已不再
    承载 ``where`` 位置索引（``gen.py`` 会拒绝该字段——路由注册串与 handler 名
    就是锚点），``where`` 若重新出现仍按旧规则核对，向前兼容。
11. 缺陷的 ``status`` 被当成**对代码现状的可执行断言**：``open``/``retained`` 要求
    探针答「现场仍在」，``fixed`` 要求答「现场已消失」。探针答「Go 面还没有承载它的
    端点/类型」时只有 open/retained 可以接受——**未实现永远不等于已修**。
    没有探针的缺陷按名列出，不静默当成通过。
12. 缺口棘轮（``contract/http_gap_baseline.txt``）：daemon 从 Rust 迁到 Go 后还有
    一批契约要求没接线（缺路由、SSE 上限、安全头、载荷字段……）。把校验器指向 Go 却
    不做这层区分，CI 会长期全红、真漂移淹在噪音里。于是问题文本先归一化成稳定指纹，
    与冻结基线三向比对：基线里没有 = 新缺口（红）、基线里有而不再报出 = 已闭合未删行
    （红）、两边都有 = 计数打印（不红）。契约里的要求一条都不为此删减。

不做的事
--------
不推断「这两个名字其实是一个东西」。载荷类型名的核对因此不做契约名↔Go 名的映射，
只认同名（见第 8 条）；handler 一侧则反过来——契约直接记录 Go 的注册符号，由两侧
等值比较，不再猜「``handle_*`` 与 ``ListBans`` 是不是一个东西」。

用法::

    python3 contract/verify_http.py                     # 门禁（make contract-check 的一步）
    python3 contract/verify_http.py --write-gap-baseline  # 人为核对后重新冻结缺口基线

    生成物自检会调 ``go build`` 与 ``tsc --noEmit``；``GO`` / ``NODE`` / ``TSC`` 可显式
    指定路径，工具链缺了据实打印「跳过」，不算契约失败也不静默。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_DIR = os.path.join(ROOT, "contract", "generated")
LAYOUT_JSON = os.path.join(GEN_DIR, "http_layout.json")

DAEMON = os.path.join(ROOT, "src", "daemon")
# HTTP 契约的 Go 生成物住在 daemon 的 module 内（Go 以 module 根为界，界外目录不是
# 包，跨界 import 编不过），由 gen.py 的 `in_module` 落点写出来；TS 那份仍留在
# contract/generated，因为前端用相对路径跨界 import 是可行的。
GENERATED_HTTP_PKG = "httpcontract"
GEN_HTTP_GO = os.path.join(
    DAEMON, "internal", GENERATED_HTTP_PKG, "http_contract.go"
)
GEN_HTTP_TS = os.path.join(GEN_DIR, "http_contract.ts")

HTTP_DIR = os.path.join(DAEMON, "internal", "http")
ROUTES_GO = os.path.join(HTTP_DIR, "routes.go")
AUTH_GO = os.path.join(HTTP_DIR, "auth.go")
SSE_GO = os.path.join(HTTP_DIR, "sse.go")
LOGS_GO = os.path.join(HTTP_DIR, "logs.go")
ENVELOPE_GO = os.path.join(HTTP_DIR, "envelope.go")
SERVER_GO = os.path.join(HTTP_DIR, "server.go")
STATIC_GO = os.path.join(HTTP_DIR, "static.go")
BANS_GO = os.path.join(HTTP_DIR, "bans.go")
MAIN_GO = os.path.join(DAEMON, "cmd", "firewall-daemon", "main.go")
CONSUMER_GO = os.path.join(DAEMON, "internal", "kernel", "consumer.go")
# jail 配置快照的属主：jails 域的变更触发从这里出发（见 HTTP_SSE_JAILS_NO_PUBLISHER）。
EXECUTOR_GO = os.path.join(DAEMON, "internal", "runtime", "executor.go")
CACHE_GO = os.path.join(DAEMON, "internal", "bans", "cache.go")
# 复发率与阈值推荐的**产出点**：缺陷 HTTP_RECIDIVISM_RATE_UNIT / _ZERO_AMBIGUOUS 的
# 现场就在这两个文件里（HTTP 侧的 recidivism_rate 与 recommended_value 都由它们算出）。
PERSIST_BAN_EVENTS_GO = os.path.join(DAEMON, "internal", "persist", "ban_events.go")
ANALYSIS_RECOMMENDATIONS_GO = os.path.join(DAEMON, "internal", "analysis", "recommendations.go")

TS_TYPES = os.path.join(ROOT, "frontend", "src", "api", "types.ts")
TS_ENDPOINTS = os.path.join(ROOT, "frontend", "src", "api", "endpoints.ts")
TS_SSE = os.path.join(ROOT, "frontend", "src", "hooks", "useSse.ts")
TS_LOGS_PAGE = os.path.join(ROOT, "frontend", "src", "views", "Logs.tsx")

# Go 源码根目录：逐个文件读入（跳过 ``_test.go``），用于「字段是否存在于结构体」的
# 核对。``internal/http`` 排在最前——HTTP 载荷只该归属那里，其余目录是它引用的领域包
# （`analysis` 的检测/推荐载荷、`bans` 的封禁条目、`config` 的 jail 与配置）。
#
# **`internal/contract` 不在表内**：那是 netlink 线格式的报文结构体，与 HTTP 载荷撞名
# 的有两个（`StatsResponse`、`WhitelistEntry`）。把它们当 HTTP 响应核对，报出来的会是
# 内核统计字段的漂移，而不是前端真正取用的 JSON 字段。
GO_SRC_DIRS = [
    HTTP_DIR,
    os.path.join(DAEMON, "internal", "analysis"),
    os.path.join(DAEMON, "internal", "bans"),
    os.path.join(DAEMON, "internal", "config"),
    os.path.join(DAEMON, "internal", "persist"),
    os.path.join(DAEMON, "internal", "jail"),
    os.path.join(DAEMON, "internal", "detect"),
    os.path.join(DAEMON, "internal", "runtime"),
    os.path.join(DAEMON, "cmd", "firewall-daemon"),
]

# 认证常量名 -> 契约里的键。候选名以 ``http_contract.go`` 的生成名为准
# （``AuthFailureThreshold`` / ``AuthLockoutSeconds``），并收下全大写写法——
# Go 侧导出与非导出的取法都可能出现，但**只按名字取**，不按「哪个数长得像阈值」猜。
AUTH_CONSTS = {
    "failure_threshold": ("AuthFailureThreshold", "AUTH_FAILURE_THRESHOLD"),
    "lockout_seconds": ("AuthLockoutSeconds", "AUTH_LOCKOUT_SECONDS"),
}

# SSE 路径 -> 源码里该流的连接上限常量候选名
#
# 两条流各自一个常量（10 / 5）是契约里「两条流互不共享」的唯一机械证据：
# 若 Go 侧只留一个共用值，缺陷 HTTP_LOG_SSE_LIMIT_DOC_DRIFT 就换了个形态复发。
SSE_LIMIT_CONST = {
    "/api/v1/events": ("SSEMaxConnectionsApiV1Events", "MAX_SSE_CONNECTIONS"),
    "/api/v1/logs/stream": ("SSEMaxConnectionsApiV1LogsStream", "MAX_LOG_SSE_CONNECTIONS"),
}

# 框架默认错误（``shape = framework_default``）只应列出 net/http **自己**会产出的状态码：
# 404（无匹配模式）与 405（模式带方法而动词不符），源码里本就不该出现它们的构造点。
# STATUS_TOKENS 是残留的防线：若有人把 400/415/422 重新塞回 framework_default，这里
# 无论源码写不写得出该状态码都会报——net/http 没有请求体/query 的自动校验，「框架默认」
# 这个说法对它们永远不成立，正确的归属是 shape = envelope。
FRAMEWORK_SELF_PRODUCED = {404, 405}
STATUS_TOKENS = {
    400: (r"http\.StatusBadRequest\b", r"(?<!\d)400(?!\d)"),
    415: (r"http\.StatusUnsupportedMediaType\b", r"(?<!\d)415(?!\d)"),
    422: (r"http\.StatusUnprocessableEntity\b", r"(?<!\d)422(?!\d)"),
}

# 契约里的路径参数写法 -> Go ServeMux 的 ``{ip}`` / 前端模板串的 ``:ip``
PARAM_RE = re.compile(r":(\w+)")


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _fn_body(src: str, name: str) -> str | None:
    """取 ``func [<接收者>] <name>(...)`` 的函数体（按花括号配平），找不到返回 None。

    用于核对某个 handler **内部**用了什么、没用什么——全文 includes 会被别处的同名
    标识符干扰（例如 ``/health`` 的断言要求函数体内不得出现 ``WriteSuccess``，而文件里
    其它 handler 必然出现）。接收者那一层可有可无：Go 里 HTTP handler 既写成
    ``func Health(w, r)`` 也写成 ``func (h *APIHandlers) Health(w, r)``。
    """
    m = re.search(rf"\bfunc\s+(?:\([^)]*\)\s*)?{re.escape(name)}\s*\(", src)
    if not m:
        return None
    # 从参数表右括号之后找第一个 `{`：函数体起点
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


def _strip_go_comments(src: str) -> str:
    """去掉 Go 源码里的注释，字符串字面量原样保留（``//`` 常出现在 URL 里）。

    缺陷探针要核的是「代码里有没有这个调用」，而注释完全可以逐字解释它**没有**做的事：
    health.go 的 handler 里就写着「裸写出，不经 WriteSuccess/WriteError」，把注释留在
    待匹配文本里会让一条否定注释把「现场仍在」读成「现场已消失」。响应头那一侧已经有
    ``_header_is_constructed`` 用调用语法躲过这个问题，这里从文本层面解决它。
    """
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # 注释分支必须在字符串分支**之前**：注释里常有反引号（`time.Format` 这样的代码
        # 片段是这里的书面语），若先按字符串处理，一个反引号就把后半段注释连同它的 `//`
        # 一起当成字面量留下——于是散文里的 `00:00` 能被探针读成「自然日窗口已实现」。
        # 位置上是 `/` 就不可能是引号，所以这个顺序不会把 `"https://x"` 误判为注释：
        # 进入字符串分支后整段字面量一次吃完，中间的 `//` 走不到这里。
        if c == "/" and src.startswith("//", i):
            nl = src.find("\n", i)
            i = n if nl < 0 else nl
            continue
        if c == "/" and src.startswith("/*", i):
            end = src.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
            continue
        if c in ('"', "`"):
            j = i + 1
            if c == "`":
                end = src.find("`", j)
                j = n if end < 0 else end + 1
            else:
                while j < n:
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == '"':
                        j += 1
                        break
                    j += 1
            out.append(src[i:j])
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _is_test_file(name: str) -> bool:
    """Go 的测试住在 ``*_test.go``：它们不是生产代码，一律不参与核对。

    Rust 时期靠剥离 ``#[cfg(test)]`` 块把测试挡住（见旧版 `_strip_cfg_test_blocks`）；
    Go 的编译单元天然按文件名分离，按文件名排除即可，不需要文本级剥离。
    「某个 SSE 事件只出现在测试里」这种假通过在这里同样被挡住。
    """
    return name.endswith("_test.go")


def go_sources() -> dict:
    """返回 {仓库相对路径: 源码}，覆盖 `GO_SRC_DIRS` 各目录**顶层**的 .go。"""
    out = {}
    for d in GO_SRC_DIRS:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".go") or _is_test_file(f):
                continue
            p = os.path.join(d, f)
            out[os.path.relpath(p, ROOT)] = read(p)
    return out


def go_tree_sources() -> str:
    """递归读 `src/daemon/**/*.go`（跳过测试与生成物），拼成一份用于子串/正则扫描的文本。

    与 [`go_sources`] 的区别：后者只读各目录顶层文件、且**不含** `internal/contract`
    （供载荷字段核对）；本函数要的是「整个 daemon 树」，因为业务码的构造点、安全头
    中间件与 SSE 发布点都可能落在子目录里，漏掉会让「有没有生产者」的断言假报缺失。

    `internal/httpcontract` 是 gen.py 写进 module 的 HTTP 契约生成物，必须排除：
    「常量值只认手写 daemon 源码」这条规则靠扫描根取不到生成物才成立，生成物搬家
    不能把它变成空转——要认它，只能由 `_used_contract_const` 显式按「引用」解引。
    """
    chunks = []
    for dirpath, dirnames, filenames in os.walk(DAEMON):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", GENERATED_HTTP_PKG)]
        for f in sorted(filenames):
            if f.endswith(".go") and not _is_test_file(f):
                chunks.append(read(os.path.join(dirpath, f)))
    return "\n".join(chunks)


def go_tree_code() -> str:
    """整棵 daemon 树的**代码**：逐文件剥离注释后再拼接。

    必须在**文件内**剥注释。先把整棵树拼起来再剥，会让扫描器的状态跨过文件边界：一个
    未闭合的字面量（行尾反引号、`"\\"` 这类把配平打乱的写法）把它后面那些文件的注释
    整段当成字符串留在结果里，于是散文中的 `00:00` 就能冒充「自然日窗口已实现」，把
    defect 的 status 断言翻成假的「现场已消失」。注释与字符串都不跨文件，逐文件处理则
    不可能有这种串扰。
    """
    chunks = []
    for dirpath, dirnames, filenames in os.walk(DAEMON):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", GENERATED_HTTP_PKG)]
        for f in sorted(filenames):
            if f.endswith(".go") and not _is_test_file(f):
                chunks.append(_strip_go_comments(read(os.path.join(dirpath, f))))
    return "\n".join(chunks)


def http_sources() -> str:
    """`internal/http` 包全体（不含测试）——注册串、信封、鉴权、SSE 都住在这一层。"""
    if not os.path.isdir(HTTP_DIR):
        return ""
    return "".join(
        read(os.path.join(HTTP_DIR, f))
        for f in sorted(os.listdir(HTTP_DIR))
        if f.endswith(".go") and not _is_test_file(f)
    )


def _go_path_to_contract(path: str) -> str:
    """把 ServeMux 的参数槽 ``{ip}`` 解回契约写法 ``:ip``。

    规则与 `src/daemon/internal/httpcontract/http_contract.go` 里的 ``GoPath()`` 互逆（那张表本身
    由 ``http.fwidl`` 生成），所以这只是同一规则的两种拼写，不是「猜这两个路径等价」。
    多段通配同样互逆：契约的 ``*path`` 在 Go 侧必须是 ``{path...}``（带方法前缀时
    ``*path`` 是字面量而不是通配），故解回契约写法时要把 `{…...}` 换回去。
    """
    path = re.sub(r"\{(\w+)\.\.\.\}", r"*\1", path)
    return re.sub(r"\{(\w+)\}", r":\1", path)



# ---------------------------------------------------------------------------
# 1. 路由表
# ---------------------------------------------------------------------------

# Go 侧的注册点：`mux.HandleFunc("<注册串>", <handler>)`（`Handle` 同形，收 http.Handler）。
# 只定位「调用起点」，注册串与 handler 表达式由花/圆括号配平往下扫——handler 常写成
# 多行的 func 字面量（`static.go` 里的 `/`、`/sw.js`），单行正则会整条漏掉。
_REG_CALL_RE = re.compile(r"\.Handle(?:Func)?\(\s*")
_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")


def _route_const_table() -> dict:
    """生成物里的注册串常量表：``Route*`` 常量名 -> ``"METHOD /path"``。

    Go 侧把注册串写成常量标识符（``httpcontract.RouteGetApiV1Bans``）时，直接扫字符串
    会看到零条路由，故到 `src/daemon/internal/httpcontract/http_contract.go` 查表解回字面量——那张表
    本身就由 `http.fwidl` 生成，等价于回到契约。同理，`server.go` 里
    ``s.mux.Handle(pattern, handler)`` 这种**包装函数自己的定义**用的是一般变量名，
    不在 `Route*` 之列，因此不会被误当成一条注册。
    """
    gen = read(GEN_HTTP_GO)
    return dict(re.findall(r'\b(Route\w+)\s*=\s*"([^"]+)"', gen))


def _split_args(expr: str) -> list[str]:
    """按顶层逗号切开通用参数表（忽略圆括号/花括号/方括号与字符串字面量内部的逗号）。"""
    args, buf, depth, in_str = [], [], 0, None
    for ch in expr:
        if in_str:
            buf.append(ch)
            if ch == in_str:
                in_str = None
            continue
        if ch in "\"'`":
            in_str = ch
            buf.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if "".join(buf).strip():
        args.append("".join(buf).strip())
    return args


# 鉴权包装：这些函数的**最后一项实参**才是被注册的 handler，符号取它、不取被调者。
# 其余调用（`spaShell(fsys)`、`serviceWorker(fsys)` 这类工厂）注册的是调用的返回值，
# 符号取被调者名——两类必须分开，否则工厂会退化成裸变量名（`fsys`）。
_AUTH_WRAPPERS = {"RequireAuth", "OptionalAuth"}


def _handler_symbol(expr: str) -> str:
    """从注册的 handler 表达式里取「这条路由实际注册的那个符号」，用于对账与诊断输出。

    ``OptionalAuth(api.username, api.password, api.ListBans)`` -> ``ListBans``（鉴权包装取
    末项实参）；``spaShell(fsys)`` -> ``spaShell``（工厂取被调者名，不是被传进去的 ``fsys``）；
    不可命名的 func 字面量如实写作 ``<func 字面量>``——它本身也是「这条路由的实现没有具名
    入口」这一事实的证据。
    """
    expr = expr.strip()
    if expr.startswith("func(") or expr.startswith("func ("):
        return "<func 字面量>"
    if expr.endswith(")"):
        # 找到与末尾 `)` 配平的 `(`，按被调者是不是鉴权包装决定取谁
        depth = 0
        for i in range(len(expr) - 1, -1, -1):
            if expr[i] == ")":
                depth += 1
            elif expr[i] == "(":
                depth -= 1
                if depth == 0:
                    callee = expr[:i].strip()
                    names = re.findall(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", callee)
                    callee_name = names[-1].rsplit(".", 1)[-1] if names else ""
                    if callee_name in _AUTH_WRAPPERS:
                        inner = _split_args(expr[i + 1: -1])
                        return _handler_symbol(inner[-1]) if inner else callee_name
                    return callee_name or "<未知>"
        return "<未知>"
    tail = re.findall(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", expr)
    return tail[-1].rsplit(".", 1)[-1] if tail else "<未知>"


def _auth_group(expr: str) -> str:
    """注册表达式的鉴权包装 -> 契约语义的 auth 组。

    Go 侧有三种形态，只认**包装函数名**（这是 `routes.go` 的事实约定，不是猜测）：
    ``RequireAuth`` = 未带凭据必拒（契约的 `required`）、无包装 = 公开（契约的 `none`）、
    ``OptionalAuth`` = 带错才 401、不带放行——它既不是 `required` 也不是 `none`，
    所以单独成组并照报偏差，绝不并入任何一侧。
    """
    if "RequireAuth" in expr:
        return "required"
    if "OptionalAuth" in expr:
        return "optional"
    return "none"


def _match_call_args(src: str, start: int) -> tuple[str, str, int]:
    """从 ``Handle(Func)(`` 之后 `start` 处解析（注册串, handler 表达式, 结束下标）。

    解析不出来（不是字面量也不是 `Route*` 常量、括号不配平）就返回 None 注册串，
    由调用方决定是问题还是忽略——绝不静默当成「没有这条路由」。
    """
    consts = _route_const_table()
    if src[start] == '"':
        end = src.find('"', start + 1)
        if end < 0:
            return "", "", start
        pattern = src[start + 1: end]
        i = end + 1
    else:
        m = re.match(r"(?:\w+\.)*(Route\w+)", src[start:])
        if not m:
            return "", "", start
        # 只认常量名里不含点的裸标识符（`httpcontract.RouteGetApiV1Bans` 取末段）
        const_name = m.group(0).rsplit(".", 1)[-1]
        if const_name not in consts:
            return f"?{const_name}", "", start
        pattern = consts[const_name]
        i = start + m.end()
    # 跳过空白与逗号，扫到与之配平的右括号
    while i < len(src) and src[i] in " \t\r\n":
        i += 1
    if i >= len(src) or src[i] != ",":
        return pattern, "", i
    i += 1
    depth = 0
    begin = i
    in_str = None
    while i < len(src):
        ch = src[i]
        if in_str:
            if ch == in_str and src[i - 1] != "\\":
                in_str = None
            i += 1
            continue
        if ch in "\"`":
            in_str = ch
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                # 只有 `)` 能收尾整个注册；`]`/`}` 先出现说明这串参数不配平
                if ch == ")":
                    return pattern, src[begin:i].strip(), i
                return pattern, "", i
            depth -= 1
        i += 1
    return pattern, "", i


def go_registrations() -> tuple[dict, list[str]]:
    """扫整个 daemon 的 Go 源码，返回 {(方法, 契约写法路径): (符号, auth 组, 文件)}。

    注册分散在 `internal/http/routes.go`（绝大多数）、`static.go`（SPA 外壳与静态资源）
    与 `cmd/firewall-daemon/main.go`（SSE 与 /metrics），所以按目录树扫而不是按单文件读。
    """
    actual: dict = {}
    problems: list[str] = []
    for rel, src in go_tree_sources_by_file().items():
        for m in _REG_CALL_RE.finditer(src):
            pattern, expr, _ = _match_call_args(src, m.end())
            if not pattern:
                continue
            if pattern.startswith("?"):
                problems.append(
                    f"{rel}: 注册串引用了生成物里没有的常量 {pattern[1:]}"
                    "（契约需重新生成？）"
                )
                continue
            head, _, rest = pattern.partition(" ")
            if head in _HTTP_METHODS:
                method, path = head, _go_path_to_contract(rest.strip())
            else:
                # 无方法前缀 = 该方法下所有请求都命中，与契约的逐方法注册不等价，
                # 原样记成 ANY 并在双向核对里报出来（不去猜它想表达 GET）。
                method, path = "ANY", _go_path_to_contract(pattern)
            key = (method, path)
            if key in actual:
                problems.append(
                    f"{rel}: 注册串 {pattern!r} 重复登记（另一处在 "
                    f"{actual[key][2]}），ServeMux 只认其中一条"
                )
            actual[key] = (_handler_symbol(expr), _auth_group(expr), rel)
    return actual, problems


def go_tree_sources_by_file() -> dict:
    """{仓库相对路径: 源码}，覆盖 daemon 全部 .go（跳过测试与 HTTP 契约生成物）。

    排除 `internal/httpcontract` 的理由与 [`go_tree_sources`] 相同：它是 gen.py 的
    产物而不是实现面，留着会让「注册点在哪个文件」「常量有没有值」这类断言把生成物
    自己当成证据。
    """
    out = {}
    for dirpath, dirnames, filenames in os.walk(DAEMON):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", GENERATED_HTTP_PKG)]
        for f in sorted(filenames):
            if f.endswith(".go") and not _is_test_file(f):
                p = os.path.join(dirpath, f)
                out[os.path.relpath(p, ROOT)] = read(p)
    return out


# 从路由 note 里抽取「声明的响应载荷类型名」用的两个正则：
# 句式锚点（载荷／返回）与类型记号（含泛型实参）。
_PAYLOAD_RE = re.compile(r"(?:载荷(?:直接是)?|返回)\s*([A-Za-z_]\w*(?:<[^>]*>)?)")
_TYPE_TOKEN_RE = re.compile(r"[A-Za-z_]\w*")


def _payload_names(note: str) -> list[str]:
    """从路由 note 的散文里抽出它声明的响应载荷类型名。

    契约里响应形状写成两种句式（没有专门的字段承载类型名，只能从 note 里读）：

      * `载荷 AttackGeoResponse` / `载荷直接是 RuntimeSnapshot`（多数路由）
      * `一律返回 PaginatedResponse<BanResponse>`（分页信封那几条）

    泛型取外层与实参两侧的名字，故 `PaginatedResponse<BanResponse>` 会同时核对
    这两个类型是否都有定义。

    注意这是**尽力而为**的抽取：note 没写载荷名的路由（如 `DELETE /api/v1/bans/:ip`
    的 note 为空、`PUT /api/v1/config` 只写了请求体）不产生任何断言，故调用方会
    打印覆盖数，让「未被这条检查覆盖的路由有几条」始终可见。
    """
    names: list[str] = []
    for raw in _PAYLOAD_RE.findall(note):
        names.extend(_TYPE_TOKEN_RE.findall(raw))
    return names


def check_routes(contract: dict) -> list[str]:
    problems: list[str] = []
    actual, reg_problems = go_registrations()
    problems += reg_problems
    if not actual:
        # 「一条路由都没解析出来」绝不能当成通过：那只会是扫描器坏了或注册全没了。
        return problems + [
            "未能在 daemon 的 Go 源码里解析出任何 ServeMux 注册"
            f"（扫描根：{os.path.relpath(DAEMON, ROOT)}/**/*.go）"
        ]

    declared = {}
    for r in contract["routes"]:
        declared[(r["method"].upper(), r["path"])] = r

    # handler 维度：契约记录的是 Go 侧**实际注册的那个符号**（`ListBans`、`spaShell`，
    # 无具名入口的 func 字面量记 `<func 字面量>`，取值口径见 `_handler_symbol`），两侧
    # 按等值比较。契约与源码因此必须同一步改：改了注册符号就得改契约，差一字逐条报出。
    for key, r in sorted(declared.items()):
        if key in actual and r["handler"] != actual[key][0]:
            problems.append(
                f"路由 {key[0]} {key[1]}: 源码 handler {actual[key][0]} != 契约 {r['handler']}"
            )

    # ServeMux 里 `Handle("/p", h)`（不带方法前缀）匹配**任何**方法。契约按方法逐条
    # 声明，于是同一条实现在两侧核对里会同时报成「注册里不存在」和「契约未声明」——
    # 那是解析器的形状差异，不是漂移。这里按路径回落到 ANY：路由存在性、auth 组都
    # 按 ANY 那条核，另外单独记一条「方法未收紧」的缺口，因为契约要的 405 由框架产生，
    # 方法不收紧时未声明的动词也会进 handler。
    any_by_path = {path: val for (method, path), val in actual.items() if method == "ANY"}
    claimed_any: set[str] = set()

    for key, r in sorted(declared.items()):
        if key not in actual:
            via = any_by_path.get(key[1])
            if via is None:
                problems.append(
                    f"路由 {key[0]} {key[1]} 在 daemon 的 ServeMux 注册里不存在"
                    f"（契约声明 handler {r['handler']}）"
                )
                continue
            claimed_any.add(key[1])
            problems.append(
                f"路由 {key[0]} {key[1]} 只以无方法前缀的 Handle 注册"
                f"（{via[2]}，handler {via[0]}）——任何动词都会进 handler，"
                "契约要的 405 因此不会由框架产生"
            )
        handler, group, rel = actual.get(key) or any_by_path[key[1]]
        if r["auth"] != group:
            hint = (
                "；Go 侧用 OptionalAuth 包装：未带凭据也放行，不是契约要的 401"
                if group == "optional" else ""
            )
            problems.append(
                f"路由 {key[0]} {key[1]}: 契约 auth={r['auth']} 但源码落在 {group} 组"
                f"（{rel}，handler {handler}）{hint}"
            )
    for key in sorted(actual):
        if key not in declared and not (key[0] == "ANY" and key[1] in claimed_any):
            handler, group, rel = actual[key]
            problems.append(
                f"daemon 中存在契约未声明的路由 {key[0]} {key[1]}"
                f"（{rel}，handler {handler}，auth 组 {group}）"
            )
    # 路由声明的载荷类型必须真的有定义。
    #
    # 为什么单列一条：`returns = type` 的载荷名只写在 note 的散文里，而载荷字段
    # 核对（check_types_go）只遍历**已定义**的类型——于是「声明了一个不存在的
    # 载荷」既不会被字段核对覆盖，也不会被路由核对覆盖，等于该端点的响应形状
    # 完全没有机械约束（AttackGeoResponse / AnomalyResponse 曾长期如此）。
    payload_checked = 0
    for key, r in sorted(declared.items()):
        if r.get("returns") != "type":
            continue
        names = _payload_names(r.get("note", ""))
        payload_checked += len(names)
        for name in names:
            if name not in contract["types"]:
                problems.append(
                    f"路由 {key[0]} {key[1]}: note 声明的载荷类型 {name} 没有 type 定义"
                    "（响应形状因此不受任何核对）"
                )

    n_none = sum(1 for r in contract["routes"] if r["auth"] == "none")
    print(
        f"  契约 {len(declared)} 条路由 / 源码注册 {len(actual)} 条"
        f"（契约无认证 {n_none} 条；注册串按 ServeMux 逐条解析，含 Route* 常量解引）"
    )
    print(
        f"  载荷声明核对：{payload_checked} 个类型名有定义"
        f"（{len(declared)} 条路由中 note 未写载荷名的不在此列）"
    )
    return problems


# ---------------------------------------------------------------------------
# 2. 认证常量与 SSE 连接上限
# ---------------------------------------------------------------------------


def _const_value(src: str, name: str) -> int | None:
    """取 Go 里名为 `name` 的**声明**值：`const NAME = 表达式`、`var NAME = 表达式`，
    以及 const 块里的裸条目（`NAME <type>? = 表达式`）。

    刻意不认 struct 字段初值（写作 `NAME: 值,`，冒号）：配置的默认值
    （`MaxSSEConnections: 32`）不是「按流的上限常量」，认了就会把「上限来自配置」
    误报成「常量与契约一致」——那正是 HTTP_LOG_SSE_LIMIT_DOC_DRIFT 想防的口径混淆。
    取不到声明或表达式不是数字（`DefaultSSELimit()` 之类）时返回 None，由调用方报错。
    """
    m = re.search(
        rf"^(?:const|var)?\s*{re.escape(name)}\s+(?:[\w\[\]*.]+\s+)?=\s*([^\n]+)",
        src,
        re.M,
    )
    if not m:
        return None
    expr = m.group(1).split("//")[0].strip()
    if not re.fullmatch(r"[\d\s_+\-*/()]+", expr):
        return None
    try:
        return int(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - 上面已限定只含算术
    except Exception:
        return None


# 真实的响应头构造点：Go 里只有 `w.Header().Set("…")` / `Add` / 直接写 map。
# 全文 includes 会假阳性——auth.go 的注释同样可能逐字解释「有意不发它」。
#
# `()` 与 `Set` 之间那个点是 Go 的方法调用本身：`w.Header().Set(...)`。模板里少写它
# 就等于「没有任何 Go 代码构造过任何头」，正反两个方向的断言一起变成空转。
_HEADER_CTOR_TMPL = (
    r"""\.Header\(\)\s*\.\s*(?:Set|Add)\s*\(\s*["]{name}["]"""
    r"""|\.Header\(\)\s*\[\s*["]{name}["]\]"""
)


def _const_in_daemon(tree: str, name: str) -> tuple[int, str] | None:
    """取「实现侧用到的契约常量值」，返回 (值, 证据名)。

    两种形态都算实现侧真的用到了这个数：

      * daemon 自己声明 ``NAME = 数字``——值就地可核；
      * daemon 引用生成物 ``httpcontract.NAME``——值取自生成物，而生成物由
        ``http.fwidl`` 生成，等价于回到契约。

    生成物目录已被排除出 `tree`，所以第二种形态不会因为「扫描根里本来就写着这个
    名字」而空转：要它成立，必须有人在手写代码里点这个引用。取不到返回 None，
    由调用方按「没有这个常量」报缺口。
    """
    v = _const_value(tree, name)
    if v is not None:
        return v, name
    if re.search(rf"\bhttpcontract\.{re.escape(name)}\b", tree):
        gv = _const_value(read(GEN_HTTP_GO), name)
        if gv is not None:
            return gv, f"httpcontract.{name}"
    return None


def _header_ident(header_name: str) -> str:
    """头名 -> 生成物里的常量标识符（`X-Frame-Options` -> HeaderXFrameOptions）。

    复制的是 gen.py 的 **命名规则**（按非字母数字切块、逐块首字母大写），不是值：规则
    变了两边会同时红，因为值还得逐字对得上。
    """
    return "Header" + "".join(
        t[:1].upper() + t[1:] for t in re.split(r"[^A-Za-z0-9]+", header_name) if t
    )


def _header_is_constructed(src: str, header_name: str) -> bool:
    """「这个响应头真的被写出来了」：字面量形态与生成物常量形态都算。

    只认 ``w.Header().Set/Add`` 与 ``w.Header()["…"]`` 三种写法。头名走
    ``httpcontract.Header<Name>`` 引用时同样算写点——那张常量表由 http.fwidl 生成，
    等价于回到契约，而且比在实现里再手打一遍头名更不容易分叉。
    """
    pat = _HEADER_CTOR_TMPL.format(name=re.escape(header_name))
    if re.search(pat, src, re.I):
        return True
    ident = _header_ident(header_name)
    return (
        re.search(rf"\.Header\(\)\s*\.\s*(?:Set|Add)\s*\(\s*httpcontract\.{ident}\b", src)
        is not None
    )


def check_auth_constants(contract: dict) -> list[str]:
    problems: list[str] = []
    # 值只认手写的 daemon 源码：生成物里的 `AuthFailureThreshold = 10` 由契约自己
    # 产生，拿它核对契约是空转。它现在物理上就在 src/daemon 树内（Go 只认 module 内
    # 的包），故由扫描根显式排除，只允许 `_const_in_daemon` 按引用解引。
    tree = go_tree_sources()
    for key, candidates in AUTH_CONSTS.items():
        want = int(contract["auth"][key])
        found = None
        for const in candidates:
            hit = _const_in_daemon(tree, const)
            if hit is not None:
                found = (hit[1], hit[0])
                break
        if found is None:
            names = " / ".join(candidates)
            problems.append(
                f"auth.{key}: 契约 {want}，但 daemon 的 Go 源码里没有常量 {names}"
                "（鉴权中间件未实现失败计数与锁定窗口，契约的防暴力破解语义无处可核）"
            )
        elif found[1] != want:
            problems.append(f"auth.{key}: 契约 {want} != 源码 {found[0]}={found[1]}")
        else:
            print(f"  auth.{key}: {found[1]} == {found[0]}")

    # 未授权响应体（纯文本、不经信封）与「不发 WWW-Authenticate」两条断言
    auth_src = read(AUTH_GO)
    body = contract["errmodels"].get("AUTH_UNAUTHORIZED", {}).get("body")
    if body:
        token = body.strip()
        if token and token not in auth_src and token not in tree:
            problems.append(
                f"errmodel AUTH_UNAUTHORIZED: 响应体 {token!r} 未出现在 "
                f"{os.path.relpath(AUTH_GO, ROOT)}（或任何 Go 源码）"
            )
        else:
            print("  errmodel AUTH_UNAUTHORIZED: 响应体在 Go 源码中存在")
    if _header_is_constructed(auth_src, "WWW-Authenticate"):
        problems.append(
            "auth.go 里真的构造了 WWW-Authenticate 响应头 —— 契约声明有意不发送"
            "该头（会让浏览器弹原生对话框、fetch 挂起）"
        )
    elif _header_is_constructed(tree, "WWW-Authenticate"):
        problems.append(
            "daemon 的 Go 源码里构造了 WWW-Authenticate 响应头 —— 契约声明有意不发送该头"
        )
    else:
        print("  auth: Go 源码未构造 WWW-Authenticate（符合契约）")
    return problems


def check_sse_limits(contract: dict) -> list[str]:
    problems: list[str] = []
    # 两条流各自的上限常量：按**常量名**取，不按「路径里含不含 events」猜文件。
    # Go 侧若把两条流接到同一个 broker 上限上，这里必然报缺失——那正是契约要拦的。
    tree = go_tree_sources()
    for r in contract["routes"]:
        if r["returns"] != "stream":
            continue
        candidates = SSE_LIMIT_CONST.get(r["path"])
        if candidates is None:
            problems.append(f"SSE {r['path']}: 校验器不知道其上限常量名")
            continue
        found = None
        for const in candidates:
            hit = _const_in_daemon(tree, const)
            if hit is not None:
                found = (hit[1], hit[0])
                break
        if found is None:
            names = " / ".join(candidates)
            problems.append(
                f"SSE {r['path']}: 契约上限 {r['max_connections']}，但 Go 源码里没有常量 "
                f"{names}（两条流共用一个连接上限时，契约声明的 10 / 5 各自独立不成立）"
            )
        elif found[1] != r["max_connections"]:
            problems.append(
                f"SSE {r['path']}: 契约上限 {r['max_connections']} != 源码 {found[0]}={found[1]}"
            )
        else:
            print(f"  SSE {r['path']}: 上限 {found[1]} == {found[0]}")
    # 心跳间隔同为契约声明值（15 秒）。Go 侧只有 `time.NewTicker(30 * time.Second)`
    # 这一处形态，没有具名常量，故只核对「源码里出现过 keep-alive 的字面量」——
    # 找不到就报，不静默。
    for r in contract["routes"]:
        if r["returns"] != "stream" or not r.get("keepalive_secs"):
            continue
        if not re.search(r"keepalive|keep-alive", read(SSE_GO), re.I):
            problems.append(f"SSE {r['path']}: 找不到 keep-alive 心跳的实现")
    return problems


# ---------------------------------------------------------------------------
# 3. 信封
# ---------------------------------------------------------------------------


def _go_struct_body(src: str, name: str) -> str | None:
    """取 ``type <name> struct {…}`` 的体部（花括号配平），找不到返回 None。

    名字与 ``struct`` 之间允许一段类型参数列表：契约的 `PaginatedResponse<T>` 在 Go 里
    写成 `type PaginatedResponse[T any] struct`（`params` 由生成物给出，这里的正则要与它
    兼容）。只让**带参数**的形态通过会漏判，只让不带参数的通过会把泛型 struct 读成
    「没有同名 struct」——那一类缺失正是本门禁要抓的假阳性来源。
    """
    m = re.search(
        rf"\btype\s+{re.escape(name)}\s*(?:\[[^\]]*\]\s*)?struct\s*\{{", src
    )
    if not m:
        return None
    i, start, depth = m.end(), m.end(), 1
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i]
        i += 1
    return None


def _go_struct_json_fields(body: str) -> list[tuple[str, str, str]]:
    """结构体体部 -> ``[(线上 JSON key, Go 类型, tag 原文)]``，按声明顺序。

    ``encoding/json`` 按**声明顺序**输出 key，所以顺序差异在这一层是真问题。
    没写 ``json`` 标签时 Go 用导出字段名当 key（大小写是唯一的线上差异），这里按
    字段名报出并保留 tag 原文——契约的 key 是线上拼写，不是 Go 的字段名。
    """
    out: list[tuple[str, str, str]] = []
    for line in body.splitlines():
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        m = re.match(r"([A-Za-z_]\w*)\s+([^\s`]+)\s*(?:`([^`]*)`)?\s*$", s)
        if not m:
            continue
        name, go_type, tag = m.group(1), m.group(2), m.group(3) or ""
        tm = re.search(r'json:"([^"]*)"', tag)
        key = tm.group(1).split(",")[0] if tm else ""
        if key == "-":
            continue  # `json:"-"` 是被排除序列化的字段，线上不存在
        out.append((key or name, go_type, tag))
    return out


def check_envelope(contract: dict) -> list[str]:
    """信封：JSON key 与顺序、成功 message、失败 code/data 的机械断言。

    信封类型**不靠猜名字**——契约叫 ``ApiResponse``，Go 侧成功响应的构造函数
    ``SuccessEnvelope`` 的返回类型才是真正被写出去的那个 struct，按它取。
    """
    problems: list[str] = []
    src = read(ENVELOPE_GO)
    m = re.search(r"\bfunc\s+SuccessEnvelope\s*\([^)]*\)\s*([\w.]+)\s*\{", src)
    if not m:
        return ["envelope.go 里没有 `func SuccessEnvelope(...) <类型>`，"
                "无法确定 daemon 实际写出的信封类型"]
    env_type = m.group(1)
    body = _go_struct_body(src, env_type)
    if body is None:
        return [f"envelope.go 里找不到 `type {env_type} struct`"
                f"（SuccessEnvelope 的返回类型，即实际写出的信封）"]

    fields = _go_struct_json_fields(body)
    keys = [k for k, _t, _g in fields]
    declared = [f["key"] for f in contract["envelope"]["fields"]]
    if keys != declared:
        problems.append(
            f"信封 {env_type} 的 JSON key: 源码 {keys} != 契约 {declared}"
            "（顺序即 encoding/json 的输出顺序）"
        )
    else:
        print(f"  信封 {env_type}: key {keys} 与契约一致")

    # code 必须是整数（契约 i32）；Go 的 int/int32 都算，其余形态说明这不是业务码字段
    code_field = next((f for f in fields if f[0] == "code"), None)
    if code_field is None:
        problems.append(f"信封 {env_type} 没有 code 字段")
    elif not re.fullmatch(r"u?int(8|16|32|64)?", code_field[1]):
        problems.append(
            f"信封 {env_type}.code 的 Go 类型是 {code_field[1]}，契约声明 i32（整数）"
        )

    ok_body = _fn_body(src, "SuccessEnvelope") or ""
    mm = re.search(r'Message:\s*"([^"]*)"', ok_body)
    if mm and mm.group(1) == "":
        print("  成功信封: message 为空串")
    elif mm:
        problems.append(
            f"成功信封的 message 是 {mm.group(1)!r}，契约声明成功时为空串"
            "（`codes` 段 0 号写明「成功；message 为空串」）"
        )
    else:
        problems.append("SuccessEnvelope 未显式设置 Message 字段，无法确认它是空串")

    # 失败信封：data 必须以 null 出现（不能靠 omitempty 省略），code 必须是业务码
    data_field = next((f for f in fields if f[0] == "data"), None)
    if data_field is None:
        problems.append(f"信封 {env_type} 没有 data 字段")
    elif "omitempty" in data_field[2]:
        problems.append(
            f"信封 {env_type}.data 的 tag 是 `{data_field[2]}`：带 omitempty 时"
            "失败响应的 data 会被整个省略，契约要求它作为 null 存在"
        )
    err_body = _fn_body(src, "ErrorEnvelope")
    if err_body is None:
        problems.append("envelope.go 里找不到 func ErrorEnvelope，无法核对失败信封形状")
    else:
        if not re.search(r"\bData\s*:", err_body):
            problems.append(
                "ErrorEnvelope 未给 data 赋值——失败响应里 data 为空，"
                "契约声明失败时 data 必须存在且为 null"
            )
        neg = re.search(r"Code:\s*(-\s*\d+)", err_body)
        if neg:
            problems.append(
                f"ErrorEnvelope 把 code 恒置为 {neg.group(1).replace(' ', '')}，"
                "契约声明失败时 code 是业务码（见 codes 段）"
            )
    return problems


# ---------------------------------------------------------------------------
# 4. 业务码
# ---------------------------------------------------------------------------


def _code_const_names(code: int) -> list[str]:
    """业务码在生成物里的常量名（``Code40001 = 40001``），用于认 daemon 侧的引用。

    值→名取自 ``src/daemon/internal/httpcontract/http_contract.go``：这是**同一份契约**的另一种拼写，
    不是拿契约数值核对契约（那条禁令管的是「阈值/SSE 上限」这类要从 daemon 读回来的值，
    这里只是给常量起个可搜索的名字）。
    """
    src = read(GEN_HTTP_GO)
    return re.findall(rf"\b(Code\w*)\s*=\s*{code}\b", src)


def check_codes(contract: dict) -> list[str]:
    """每个非零业务码必须在 daemon 的 Go 源码里有构造点。

    构造点的两种合法形态（都是逐字匹配，不认「大概是个错误码」）：

      * 引用生成物常量：``httpcontract.Code40001`` 之类的标识符出现在 daemon 源码里
      * 字面量落在赋值位：``Code: 40001`` / ``code = 40001``（结构体字段或变量赋值）

    全都没有 = 契约声明了一个前端永远收不到的码。这里聚合成**一条**问题列出所有缺
    失码（并写出 envelope.go 的实际形态），而不是每个码各报一遍——同一原因的噪音会
    淹没别的漂移。
    """
    problems: list[str] = []
    tree = go_tree_sources()
    missing: list[str] = []
    hit_total = 0
    for value, meta in sorted(contract["codes"].items(), key=lambda kv: int(kv[0])):
        code = int(value)
        if code == 0:
            continue  # 0 是成功码，由 SuccessEnvelope 固定写出，不在此断言
        refs = [n for n in _code_const_names(code) if re.search(rf"\b{re.escape(n)}\b", tree)]
        literal = re.search(rf"\b\w*[Cc]ode\w*\s*(?:=|:=|:)\s*{code}\b", tree)
        if refs or literal:
            hit_total += 1
            print(f"  业务码 {code}（HTTP {meta['status']}）：构造点 "
                  f"{refs[0] if refs else literal.group(0)}")
        else:
            missing.append(f"{code}(HTTP {meta['status']})")
    if missing:
        problems.append(
            f"业务码在 Go 源码里没有构造点：{', '.join(missing)} —— "
            "internal/http/envelope.go 的 ErrorEnvelope 只写 Code: -1，"
            "错误标识用的是字符串（\"bad_request\"），契约声明的整数业务码从未被产出"
        )
    print(f"  业务码 {len(contract['codes'])} 个已核对（契约声明 {len(contract['codes']) - 1} "
          f"个非零码，有构造点 {hit_total} 个）")
    return problems


# ---------------------------------------------------------------------------
# 5. 错误形状
# ---------------------------------------------------------------------------


def _first_hit(srcs: dict, pattern: str) -> str | None:
    """daemon Go 源码里第一处匹配该正则的位置 ``相对路径:行号``；无匹配返回 None。

    问题清单要能直接点到现场，不然「找不到 X」这种断言没法复核。
    """
    rx = re.compile(pattern)
    for rel, src in sorted(srcs.items()):
        for i, line in enumerate(src.splitlines(), 1):
            if rx.search(line):
                return f"{rel}:{i}"
    return None


def check_errmodels(contract: dict) -> list[str]:
    """三种错误形状：text 逐字核对 body，framework_default 只认框架自产，envelope 认闭合性。

    ``net/http`` 的纯文本写点只有三种确切形态，body 由它们决定：

      * ``http.Error(w, msg, code)`` 写出 ``msg + "\\n"``
      * ``http.NotFound(w, r)`` 写出 ``"Not Found\\n"``（状态行才是 404 Not Found）
      * ServeMux 自己：未匹配写 ``"404 page not found\\n"``、方法不匹配写
        ``"Method Not Allowed\\n"``

    ``framework_default`` 只覆盖框架**真的会自产**的状态码：404（无匹配模式）与 405
    （模式带方法而动词不符）。源码里出现它们的构造点反而是问题——那说明有人绕过了
    ServeMux 的默认面。400/415/422 从没有离开过 daemon 的手：那是 axum 提取器的行为，
    ``net/http`` 不做请求体与 query 的自动校验，所以它们改记 ``shape = envelope``，本函数
    按「业务码是否映射到该状态码」核对信封面的闭合性。
    """
    problems: list[str] = []
    srcs = go_tree_sources_by_file()
    tree = "\n".join(srcs.values())
    regs, _ = go_registrations()

    for name, d in contract["errmodels"].items():
        if d["shape"] == "text":
            want = d["body"]
            stripped = want.rstrip("\n")
            if not stripped:
                problems.append(f"errmodel {name}: shape=text 但 body 为空，契约被破坏")
                continue
            literal = _first_hit(srcs, rf'"{re.escape(stripped)}"')
            if literal:
                print(f"  errmodel {name}: 文本 body {stripped!r} 见 {literal}")
                continue
            near = [
                p
                for p in (
                    _first_hit(srcs, r"http\.Error\("),
                    _first_hit(srcs, r"http\.NotFound\("),
                )
                if p
            ]
            detail = (
                "；就近的纯文本写点：" + "、".join(near) if near
                else "；Go 源码里没有任何纯文本错误写点"
            )
            problems.append(
                f"errmodel {name}: 契约声明 {d['statuses']} 的响应体是纯文本 {want!r}，"
                f"Go 源码里没有这段文本{detail}"
            )
        elif d["shape"] == "framework_default":
            for status in d["statuses"]:
                if status in FRAMEWORK_SELF_PRODUCED:
                    if status == 404 and any(
                        method == "ANY" and path == "/" for method, path in regs
                    ):
                        catch_all = _first_hit(srcs, r'HandleFunc\(\s*"/"\s*,')
                        problems.append(
                            f"errmodel {name}: 契约把 404 记成 ServeMux 自产"
                            "（body `404 page not found`），但 daemon 注册了 \"/\" "
                            f"兜底模式（{catch_all}），未匹配路径走的是它，"
                            "body 不再是框架文本"
                        )
                        continue
                    print(f"  errmodel {name}: {status} 由 net/http ServeMux 自产")
                    continue
                tokens = STATUS_TOKENS.get(status)
                if tokens is None:
                    problems.append(f"errmodel {name}: 校验器不认识状态码 {status}")
                    continue
                hit = _first_hit(srcs, "|".join(tokens))
                if hit is None:
                    problems.append(
                        f"errmodel {name}: 契约声明 {status} 为框架默认错误，但 "
                        f"net/http 不会自动产生 {status}，Go 源码里也没有它的写点"
                    )
                else:
                    problems.append(
                        f"errmodel {name}: 契约把 {status} 记成「框架默认错误」，"
                        f"实际是 daemon 自己写出的（{hit}）——"
                        "net/http 没有请求体/查询参数的自动校验，这个状态码不可能由框架产生"
                    )
        elif d["shape"] == "envelope":
            # 信封错误面：状态码能不能到达，由 `codes` 段的 status= 决定——那张映射就是
            # 生成物里的 CodeHTTPStatus。所以这里核对的是契约自身的闭合性：声明了信封上
            # 有 422，就必须有一个业务码映射到 422，否则前端只收到一个查不到语义的码。
            mapped: dict[int, list[int]] = {}
            for value, meta in contract["codes"].items():
                mapped.setdefault(int(meta["status"]), []).append(int(value))
            for status in d["statuses"]:
                codes = mapped.get(status)
                if not codes:
                    problems.append(
                        f"errmodel {name}: 声明了信封状态码 {status}，但 codes 段里"
                        "没有任何业务码映射到它——该状态码在信封面上不可达"
                    )
                else:
                    print(f"  errmodel {name}: {status} ← 业务码 "
                          f"{'/'.join(str(c) for c in sorted(codes))}")
            # 写出方必须是信封本体：ErrorEnvelope 得在 envelope.go 里有构造函数
            if "func ErrorEnvelope(" not in read(ENVELOPE_GO):
                problems.append(
                    f"errmodel {name}: 声明为信封形状，但 "
                    f"{os.path.relpath(ENVELOPE_GO, ROOT)} 里没有 func ErrorEnvelope"
                )
        else:
            problems.append(f"errmodel {name}: 校验器不认识 shape {d['shape']!r}")

    print(f"  错误形状 {len(contract['errmodels'])} 种已核对")
    return problems


# ---------------------------------------------------------------------------
# 6. 安全头
# ---------------------------------------------------------------------------


def check_headers(contract: dict) -> list[str]:
    """安全头：头名必须真有写点，值必须逐字出现或经生成物常量引用，webui 分支必须有判别条件。

    Go 侧写响应头只有 ``w.Header().Set/Add``（见 ``_HEADER_CTOR_TMPL``），只认这个
    形态——全文 includes 会假阳性，注释里同样可能逐字解释「有意不发某个头」。头名与值
    都允许走 ``httpcontract.Header*`` 常量：那张表由契约生成，比在实现里再抄一遍字符串
    更符合「字面量只有一份」。
    """
    problems: list[str] = []
    srcs = go_tree_sources_by_file()
    tree = "\n".join(srcs.values())
    middleware = _first_hit(srcs, r"func\s+\([^)]*\)\s*connectionLimiter\b")
    for name, d in contract["headers"].items():
        if not _header_is_constructed(tree, name):
            extra = (
                f"（internal/http 里唯一的中间件是 {middleware}）" if middleware else ""
            )
            problems.append(
                f'header {name}: Go 源码里没有该头的写点'
                f'（没有 w.Header().Set/Add("{name}", …)）'
                f"——契约声明的安全头未实现{extra}"
            )
            continue
        for label, value in (("value", d["value"]), ("value_webui", d["value_webui"])):
            if not value:
                continue
            if value in tree:
                continue
            # 值也可能只经由生成物常量落地：`httpcontract.HeaderXxxValue[WebUI]` 的取值
            # 来自 http.fwidl，逐字抄一份到实现里反而多一处会漂移的副本。
            ident = _header_ident(name) + ("ValueWebUI" if label == "value_webui" else "Value")
            if re.search(rf"\bhttpcontract\.{re.escape(ident)}\b", tree):
                print(f"  header {name}.{label}: 经生成物常量 {ident} 引用")
                continue
            problems.append(
                f'header {name}.{label}: 值 {value!r} 既未逐字出现在 Go 源码里，'
                f"也没有经 httpcontract.{ident} 引用"
            )
        if d["value_webui"] and not _first_hit(srcs, r"(?i)isWebUI|is_webui|webUIPath"):
            problems.append(
                f"header {name}: 契约声明了 webui 分支的值，"
                "但 Go 源码里找不到分支判别条件（isWebUI / is_webui）"
            )
    print(f"  安全头 {len(contract['headers'])} 条已核对")
    return problems


# ---------------------------------------------------------------------------
# 7. SSE 事件（推送侧 + 订阅侧）
# ---------------------------------------------------------------------------


def _sse_publish_points(srcs: dict, event: str) -> list[str]:
    """事件名在 Go 侧的发布点：凡是**逐字面量**写着这个事件名的发帧调用或手写帧都算。

    Go 侧写一帧有三种形态，事件名都必须是字面量：

      * ``…Publish("<事件>", …)``——broker 的域广播（``internal/http/sse.go``、
        ``kernel/consumer.go``、``http/publish.go``）；
      * ``…writeFrame("<事件>", …)``——单条连接自己的帧（握手帧与日志流的 log/error 帧
        都走它，日志流没有 broker 可广播）；
      * 手写的 ``event: <事件>`` 帧文本（直接 Fprintf 的写法）。

    只认这三种，事件名写成变量（``writeFrame(name, …)``）就扫不到——这正是刻意的：契约
    声明的每个事件名都要在 Go 侧有一个字面发布点，名字进变量等于宣布它没有生产者。
    测试文件已由 ``go_tree_sources_by_file`` 排除——只出现在测试里的发布点不算。
    """
    pats = (
        rf'\.Publish\(\s*"{re.escape(event)}"',
        rf'\.writeFrame\(\s*"{re.escape(event)}"',
        rf'\bsseFrame\(\s*"{re.escape(event)}"',
        rf'event:\s*{re.escape(event)}\b',
    )
    out: list[str] = []
    for rel, src in sorted(srcs.items()):
        for i, line in enumerate(src.splitlines(), 1):
            if any(re.search(p, line) for p in pats):
                out.append(f"{rel}:{i}")
    return out


def check_sse_events(contract: dict) -> list[str]:
    """每个事件名都要在发布侧（Go）与订阅侧（前端）各存在一处。"""
    problems: list[str] = []
    srcs = go_tree_sources_by_file()
    for r in contract["routes"]:
        if r["returns"] != "stream":
            continue
        if r["path"] == "/api/v1/events":
            consumer_path, consumer_name = TS_SSE, "useSse.ts"
        else:
            consumer_path, consumer_name = TS_LOGS_PAGE, "Logs.tsx"
        consumer = read(consumer_path)
        for ev in r["events"]:
            points = _sse_publish_points(srcs, ev)
            if not points:
                problems.append(
                    f'SSE {r["path"]}: 事件 {ev!r} 在 Go 源码里没有发布点'
                    f'（既无 .Publish("{ev}", …) / .writeFrame("{ev}", …)，'
                    f'也无 `event: {ev}` 帧）'
                )
            else:
                print(f"  SSE {r['path']}: 事件 {ev!r} 发布点 {', '.join(points[:3])}")
            if f"'{ev}'" not in consumer and f'"{ev}"' not in consumer:
                problems.append(
                    f"SSE {r['path']}: 事件 {ev!r} 在前端订阅侧找不到（{consumer_name}）"
                )
        print(f"  SSE {r['path']}: {len(r['events'])} 个事件已核对（发布 + 订阅）")
    return problems


# ---------------------------------------------------------------------------
# 8. 载荷类型（Go 侧）
# ---------------------------------------------------------------------------


def _find_go_struct(srcs: dict, name: str) -> tuple[str, list[tuple[str, str, str]]] | None:
    """在 Go 源码里按**类型名逐字**找 ``type <name> struct``，返回 (相对路径, 字段)。

    不做名字映射：契约的载荷名与 Go 的结构体名之间没有机械等价规则，找不到就是
    找不到（调用方会把这类情形聚合成一条问题报出来）。
    """
    for rel, src in srcs.items():
        body = _go_struct_body(src, name)
        if body is not None:
            return rel, _go_struct_json_fields(body)
    return None


def check_types_go(contract: dict) -> list[str]:
    """契约里每个载荷类型的字段都必须是 Go 结构体的 json key，且该结构体真被返回。

    Go 的导出字段名与线上 key 可以不同（靠 ``json:"…"`` 标签映射），所以这里只比
    标签解出来的**线上 key**；没写标签的字段其线上 key 就是字段名本身——那同样是
    一种形状，不能替契约打圆场。
    """
    problems: list[str] = []
    srcs = go_sources()
    http_src = http_sources()
    missing: list[str] = []
    checked = 0
    for name, decl in contract["types"].items():
        if decl.get("inline"):
            # 内联形状没有具名 struct：改为核对 JSON key 字面量出现在 internal/http 里
            for f in decl["fields"]:
                if f'"{f["key"]}"' not in http_src:
                    problems.append(
                        f"内联类型 {name}: JSON key {f['key']!r} 未出现在 internal/http"
                    )
            continue
        found = _find_go_struct(srcs, name)
        if found is None:
            missing.append(name)
            continue
        rel, fields = found
        checked += 1
        keys = [k for k, _t, _g in fields]
        declared = [f["key"] for f in decl["fields"]]
        for f in decl["fields"]:
            if f["key"] not in keys:
                problems.append(
                    f"类型 {name}（{rel}）: 契约字段 {f['key']!r} 不是该 struct 的 json key"
                    f"（实际 {keys}）"
                )
        for extra in keys:
            if extra not in declared:
                problems.append(
                    f"类型 {name}（{rel}）: struct 字段 {extra!r} 未在契约中声明"
                )
        # 「仓库里有这个 struct」不等于 handler 返回的是它：引用点必须在 internal/http
        if not re.search(rf"\b{re.escape(name)}\b", http_src):
            problems.append(
                f"类型 {name}（{rel}）: internal/http 里没有它的引用——"
                "handler 返回的不是这个 struct"
            )
    if missing:
        problems.append(
            f"{len(missing)}/{len(contract['types'])} 个载荷类型在 Go 源码里没有同名 "
            f"struct（本门禁不做契约名↔Go 名的映射推断）：{', '.join(sorted(missing))}。"
            "这些还多是**未接线**的分析/统计载荷：接线时请为它们补 internal/http 的具名 "
            "struct（照 payload.go 的规矩，一个 struct 对一个契约 type 块），不要退回 "
            "map[string]any 字面量——字段没有具名类型承载时，跨层字段核对在这一层失去锚点"
        )
    print(
        f"  载荷类型 {len(contract['types'])} 个：{checked} 个有同名 Go struct 并逐字段核对，"
        f"{len(missing)} 个无同名 struct"
    )
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
        # 前端 interface 名可与 Go 结构体名不同（契约用 ts_name 显式声明）
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


def _ts_route_table() -> dict:
    """生成物 ``http_contract.ts`` 的 ``ROUTES`` 表：{常量名: 契约路径}。

    前端的调用地址全部来自这张表（``ROUTES.<常量>``），所以「前端消费了哪些路径」
    是一道查表题，不再是文字扫描——旧版靠模板串里的 ``/api/v1`` 字面量匹配，
    字面量一旦消失（已消失）那条检查会退化成「前端什么都没调用」的假失败。
    """
    src = read(GEN_HTTP_TS)
    m = re.search(r"export const ROUTES = \{(?P<body>.*?)\n\} as const", src, re.S)
    if not m:
        return {}
    return dict(re.findall(r"^\s*([A-Za-z0-9_]+):\s*[\"']([^\"']+)[\"'],", m.group("body"), re.M))


def check_routes_frontend(contract: dict) -> list[str]:
    """契约的每条路由必须在前端有消费者；前端不得调用契约外的路径。"""
    problems: list[str] = []
    table = _ts_route_table()
    if not table:
        return [
            "未能从 contract/generated/http_contract.ts 解出 ROUTES 表，"
            "前端消费侧无法核对（请先跑 gen.py）"
        ]
    src = strip_ts_comments(read(TS_ENDPOINTS))
    used = set(re.findall(r"\bROUTES\.([A-Za-z0-9_]+)", src))
    if not used:
        problems.append(
            "前端 endpoints.ts 没有引用任何 ROUTES 常量 —— 要么全部路径改成了手写"
            "字面量（脱离单一真相源），要么这条检查的对象已变，不能算通过"
        )
    used_paths = {table[n] for n in used if n in table}

    # 正向：契约里每条 API 路由都要在前端出现（按**路径**逐字比对，不做名字推断）。
    # Web UI 页面路由（/dashboard 等）由前端自己的 hash 路由消费，不在 endpoints.ts 里。
    missing = [
        f'{r["method"]} {r["path"]}'
        for r in contract["routes"]
        if r["path"].startswith("/api/v1") and r["path"] not in used_paths
    ]
    for m in missing:
        problems.append(f"前端 endpoints.ts 未调用契约路由 {m}")

    # 引用了 ROUTES 表里没有的名字 = 前端在等一个契约里不存在（或已改名）的常量
    for n in sorted(used - set(table)):
        problems.append(f"前端 endpoints.ts 引用了生成物里没有的 ROUTES.{n}")
    # 反向：前端取用的路径必须都在契约里（路径逐字比对，含 :param 拼写）
    declared_paths = {r["path"] for r in contract["routes"]}
    for n in sorted(used & set(table)):
        if table[n] not in declared_paths:
            problems.append(f"前端 endpoints.ts 经 ROUTES.{n} 调用了契约外的路径 {table[n]}")
    # 兜底：前端若绕过生成物直接写 `/api/v1…` 字面量，就是脱离了单一真相源
    # （注释里出现的路径示例已由 strip_ts_comments 去掉）。
    for literal in sorted(set(re.findall(r"['\"`](/api/v1[^'\"`]*)['\"`]", src))):
        problems.append(f"前端 endpoints.ts 手写了契约路径字面量 {literal}（应引用 ROUTES 常量）")

    print(
        f"  前端 endpoints.ts: 引用 {len(used)} 个 ROUTES 常量，"
        f"与契约 {len(declared_paths)} 条路由双向核对（缺消费者 {len(missing)} 条）"
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
    """核对 defect 的 ``fix`` 证据锚点；``where`` 位置索引已不在 HTTP 契约里。

    ``gen.py`` 的 HTTP 解析器现在**拒绝** ``where``（「契约不维护源码位置锚点」——
    路由注册串与 handler 名本身就是锚点），errmodel 与 defect 都只剩 status/fix。
    于是这一项只剩一条硬规则：

      fixed —— ``fix`` 指向修复证据，必须逐字仍在仓库里

    ``open`` / ``retained`` 没有锚点可核：它们的说法是否还成立，全部压在
    ``check_defect_claims`` 的机械断言上；既无锚点又无断言的，这里聚合成一条
    显式问题报出来（不静默当成通过）。``where`` 若哪天重新出现（换了别的解析器），
    仍按旧规则核对，向前兼容。
    """
    problems: list[str] = []
    n_ok = 0
    no_evidence: list[str] = []

    for name, d in contract["errmodels"].items():
        where = d.get("where") or ""
        if not where:
            continue  # 无位置锚点：形状本身由 check_errmodels 核对
        if _anchor_ok(f"errmodel {name}", where, problems):
            n_ok += 1

    for d in contract["defects"]:
        kind, status = f"defect {d['name']}", d["status"]
        where = d.get("where") or ""
        if where and not _shape_ok(kind, where, problems):
            continue
        w_exists = _anchor_exists(where) if where else False
        if status in ("open", "retained"):
            if where:
                if w_exists:
                    n_ok += 1
                else:
                    problems.append(f"{kind}: status={status} 但 where 锚点 '{where}' 不存在")
            else:
                # 无锚点：这条缺陷的说法当前只能靠机械断言站住
                no_evidence.append(d["name"])
        elif status == "fixed":
            if where and w_exists:
                rel = where.partition(":")[0]
                problems.append(
                    f"{kind}: status=fixed 但旧现场 '{where}' 仍在 "
                    f"（{rel} 若属旧实现应删除；若实现已修则契约需改判）"
                )
            fix = d.get("fix") or ""
            if not _shape_ok(kind, fix, problems, field="fix"):
                continue
            if _anchor_exists(fix):
                n_ok += 1
            else:
                rel = fix.partition(":")[0]
                why = "文件不存在" if not os.path.isfile(os.path.join(ROOT, rel)) else "锚点文字已消失"
                problems.append(
                    f"{kind}: status=fixed 但修复证据锚点 '{fix}' 不成立（{why}）"
                )
        else:
            problems.append(f"{kind}: 未知 status {status!r}")

    print(f"  {n_ok} 个 where/fix 锚点核对通过（含形状与 status 分派）")
    if no_evidence:
        print(f"  无位置锚点的 open/retained 缺陷：{', '.join(sorted(no_evidence))}"
              "（是否仍成立由机械断言承担，无断言者由 check_defect_claims 报出）")
    return problems


# ---------------------------------------------------------------------------
# 11. 缺陷 status 的可执行断言（现场是否仍在）
# ---------------------------------------------------------------------------


def check_defect_claims(contract: dict) -> list[str]:
    """把 defect 的 ``status`` 当成**对代码现状的可执行断言**，用探针核对。

    分派规则只有一条，方向两边都堵：

      ``open`` / ``retained`` —— 探针必须回答「现场仍在」
      ``fixed`` —— 探针必须回答「现场已消失」

    探针返回 ``None`` 表示 Go 面还没有承载这条缺陷的端点或类型（未接线）。未接线
    **不等于已修**：``fixed`` 配 ``None`` 一律失败，只有 ``open``/``retained`` 可以
    挂在「还没实现」上（缺哪条路由由 check_routes 报告、并进缺口基线冻结）。

    于是改判 status 会自动反过来要求代码跟上，代码跟上也会自动要求契约改判——
    两边都不许悄悄漂。新增 defect 而没有探针的，函数末尾按名列出，不给假安全感。
    """
    problems: list[str] = []
    declared = {d["name"] for d in contract["defects"]}
    status_of = {d["name"]: d["status"] for d in contract["defects"]}
    covered: set[str] = set()

    def verdict(name: str, live: bool | None, detail: str) -> None:
        covered.add(name)
        status = status_of.get(name, "open")
        wants_live = status in ("open", "retained")
        if live is None:
            if wants_live:
                print(f"  defect {name}: 无 Go 现场（未接线），与 status={status} 相容")
            else:
                problems.append(
                    f"defect {name}: status=fixed 但 Go 面没有可核对的现场（{detail}）"
                    "——未实现不等于已修"
                )
            return
        if live == wants_live:
            print(f"  defect {name}: {detail}（与 status={status} 一致）")
            return
        if live:
            problems.append(
                f"defect {name} 已失效：契约记 status={status}（应为已修），但现场仍在"
                f"——{detail}"
            )
        else:
            problems.append(
                f"defect {name} 已失效：契约记 status={status}（现场应在），但已找不到现场"
                f"——{detail}，契约需同步"
            )

    for name in sorted(declared):
        if name == "HTTP_RECIDIVISM_RATE_UNIT":
            # 「同名不同单位」要两个产出点都在：只有一处有 recidivism_rate 时没有
            # 可比的第二单位，探针据实返回 None。
            stats_src = read(PERSIST_BAN_EVENTS_GO)
            rec_src = read(ANALYSIS_RECOMMENDATIONS_GO)
            stats_pct = bool(
                re.search(r"recidivismRate\s*=\s*[^\n]*\*\s*100\b", stats_src)
            )
            rec_pct = bool(re.search(r"\brate\s*:?=\s*[^\n]*\*\s*100\b", rec_src))
            stats_has = bool(re.search(r"recidivismRate\s*=", stats_src))
            rec_has = bool(re.search(r"\brate\s*:?=\s*float64", rec_src))
            if not (stats_has and rec_has):
                verdict(name, None, f"产出点不齐（persist={stats_has} analysis={rec_has}）")
            else:
                verdict(
                    name,
                    stats_pct != rec_pct,
                    f"persist/ban_events.go 百分数={stats_pct}，"
                    f"analysis/recommendations.go 百分数={rec_pct}",
                )
        elif name == "HTTP_THRESHOLD_RECOMMENDATION_ZERO_AMBIGUOUS":
            # 歧义仍成立的条件：前端注释宣称 0=无需调整，而 Go 的三个分支都给不出 0。
            src = read(ANALYSIS_RECOMMENDATIONS_GO)
            ts = strip_ts_comments(read(TS_TYPES))
            doc_claims_zero = "0 = 无需调整" in ts or "0=无需调整" in ts
            emits_zero = bool(re.search(r"recommended\s*(=|\?=)\s*0\b", src))
            maintain_current = bool(
                re.search(r'direction\s*=\s*"maintain"', src)
                and re.search(r"recommended\s*=\s*current\b", src)
            )
            if not doc_claims_zero and not emits_zero:
                verdict(name, None, "前后端都没有 0 语义的声明或产出点")
            else:
                verdict(
                    name,
                    doc_claims_zero and not emits_zero,
                    f"前端仍声明 0=无需调整={doc_claims_zero}，Go 能产出 0={emits_zero}"
                    f"（maintain 分支返回原阈值={maintain_current}）",
                )
        elif name == "HTTP_HEALTH_NOT_ENVELOPED":
            # retained 说的是「契约那两条探针端点有意不套信封」。Go 面注册的是
            # /api/v1/health（另一条端点，走信封），契约的 GET /health 与 /healthz
            # 还没接线——拿它冒充现场就是自欺，所以返回 None，缺路由由 check_routes 报。
            actual, _ = go_registrations()
            probe = [f"{m} {p}" for (m, p) in actual if p in ("/health", "/healthz")]
            if not probe:
                verdict(name, None, "契约的 GET /health 与 /healthz 均未注册")
            else:
                body = _fn_body(http_sources(), "Health") or ""
                # 只看真代码：health.go 的 handler 里有一句注释写着「不经 WriteSuccess/
                # WriteError」，那是**否定**，按文字匹配会把裸写读成已套信封。
                code = _strip_go_comments(body)
                bare = "WriteSuccess" not in code and "WriteError" not in code
                verdict(
                    name,
                    bare,
                    f"{', '.join(sorted(probe))} 的响应是否仍裸写信封外={bare}",
                )
        elif name == "HTTP_BANS_DUAL_SHAPE":
            src = strip_ts_comments(read(TS_ENDPOINTS))
            overloads = len(re.findall(r"export\s+function\s+getBans\s*\(", src))
            bare_ts = "Promise<BanResponse[]>" in src
            paged_ts = "Promise<PaginatedResponse<BanResponse>>" in src
            handler = _fn_body(http_sources(), "ListBans")
            if handler is None:
                verdict(name, None, "internal/http 里找不到 ListBans")
            else:
                server_paged = bool(
                    re.search(r"URL\.Query\(\)|Paginated|\"items\"", handler)
                )
                verdict(
                    name,
                    not (server_paged and overloads == 1 and paged_ts and not bare_ts),
                    f"服务端分页信封={server_paged}，前端 getBans 重载 {overloads} 处"
                    f"（裸数组返回={bare_ts}，分页返回={paged_ts}）",
                )
        elif name == "HTTP_BAN_SORT_DOC_INCOMPLETE":
            handler = _fn_body(http_sources(), "ListBans")
            ts = read(TS_TYPES)
            mts = re.search(r"export\s+type\s+BanSortKey\s*=(.*?)(?:\n\n|\Z)", ts, re.S)
            keys = set(re.findall(r"'([a-z_]+)'", mts.group(1))) if mts else set()
            if handler is None:
                verdict(name, None, "internal/http 里找不到 ListBans")
            else:
                server_has_sort = bool(
                    re.search(r"sort_by|SortBy|sort\.(Slice|Strings)", handler)
                )
                verdict(
                    name,
                    not server_has_sort,
                    f"服务端有排序分支={server_has_sort}，前端 BanSortKey 仍声明 {len(keys)} 个取值",
                )
        elif name == "HTTP_READ_PATH_WRITES_STATE":
            # 现场 = **读** handler 里有写操作。按 handler 函数体来扫，不能整文件扫：
            # bans.go 同时装着 CreateBan/DeleteBan，它们写镜像是本职。
            #
            # 名单不硬编：从注册表面前取所有 GET handler 的符号。硬编名单在 P4 里留了
            # 四条 Rust 时代的死名字（BanStats/JailStats/WhitelistStats/GetJail），扫描
            # 对取不到函数体的名字静默跳过，于是「名单已过期」被读成「现场已消失」；
            # 接线统计面（P5-b）又会让一批新读 handler 落在名单外。静态外壳（static.go）
            # 不在扫描范围：它不碰运行时状态，且它的 handler 是 fs 包装而不是 API handler。
            reg, _reg_problems = go_registrations()
            # 用**整棵树逐文件剥注释**的文本取函数体：注册在 routes.go，handler 定义却住在
            # bans.go / stats.go / snapshot.go，按注册所在文件找必然找不到；剥注释是为了
            # 让「清扫不在这里」这类散文里的词不被当成写点（必须在文件内剥，见 go_tree_code）。
            tree = go_tree_code()
            readers: list[str] = []
            writes: list[str] = []
            unparsable: list[str] = []
            for (method, path), (symbol, _auth, rel) in sorted(reg.items()):
                if method != "GET" or rel.endswith(os.path.join("http", "static.go")):
                    continue
                if not symbol.isidentifier():
                    continue  # 内联函数字面量：没有可命名核对的函数体
                body = _fn_body(tree, symbol)
                if body is None:
                    unparsable.append(f"{symbol} ({path})")
                    continue
                readers.append(symbol)
                writes += re.findall(
                    r"SweepExpired|\.Upsert\(|\.Remove\(|MarkPending|ClearPending|\.Add\(1\)",
                    body,
                )
            if unparsable:
                # 注册了却取不到函数体 = 这条读路径根本没被扫到，不能算已核对。
                verdict(
                    name,
                    True,
                    f"{len(unparsable)} 条 GET handler 取不到函数体"
                    f"（{', '.join(unparsable)}）",
                )
            elif len(readers) < 20:
                verdict(
                    name,
                    True,
                    f"只扫到 {len(readers)} 条读 handler，少于注册面的量级：扫描可能已失效",
                )
            else:
                verdict(
                    name,
                    bool(writes),
                    f"读路径写点 {len(writes)} 处（扫了 {len(readers)} 条 GET handler）"
                    + (f"（{', '.join(sorted(set(writes)))}）" if writes
                       else "，清扫在 kernel/consumer.go 的对账里"),
                )
        elif name == "HTTP_SSE_RESERIALIZES_EVERY_DOMAIN":
            # 现场 = 序列化按连接、按 tick 重复发生。判据两条，缺一即现场仍在：
            #   1) 一次 Publish 只序列化一次——唯一的 marshal 在 sseFrame 里，Publish
            #      经它拿帧（序列化点从「每条连接各一次」收回「每个事件一次」）；
            #   2) 扇出循环（run）只搬运已经成形的字节，自己不做任何序列化。
            src = _strip_go_comments(read(SSE_GO))
            publish = _fn_body(src, "Publish") or ""
            fan_out = _fn_body(src, "run") or ""
            once_per_event = (
                "sseFrame(" in publish and publish.count("json.Marshal") <= 1
            )
            no_per_conn_marshal = "json.Marshal" not in fan_out
            verdict(
                name,
                not (once_per_event and no_per_conn_marshal),
                f"Publish 每事件序列化一次={once_per_event}，"
                f"扇出循环内无序列化={no_per_conn_marshal}"
                if once_per_event and no_per_conn_marshal
                else f"Publish 每事件序列化一次={once_per_event}，"
                f"扇出循环内无序列化={no_per_conn_marshal}（序列化点数处仍待收回）",
            )
        elif name == "HTTP_WHITELIST_KEY_DIVERGENCE":
            # 现场 = 白名单键有多套归一规则。两处构造点（镜像与检测聚合）都归一到
            # Masked()，且 bans 包里只有一处拼键。
            glob = read(os.path.join(DAEMON, "internal", "bans", "global.go"))
            cidr = read(os.path.join(DAEMON, "internal", "detect", "cidr.go"))
            both_masked = "prefix.Masked().String()" in glob and ".Masked()" in cidr
            verdict(
                name,
                not both_masked,
                f"白名单镜像与检测键都经 Masked() 归一={both_masked}",
            )
        elif name == "HTTP_BATCH_BAN_BECOMES_PERMANENT":
            src = read(BANS_GO)
            verdict(
                name,
                "isPermanent := req.Duration == 0" in src,
                "BatchBan 仍把 duration 缺省/0 升格为永久封禁"
                if "isPermanent := req.Duration == 0" in src
                else "BatchBan 不再把缺省 duration 判为永久",
            )
        elif name == "HTTP_SSE_STATUS_INCOMPLETE":
            body = _fn_body(http_sources(), "SSEStatus")
            if body is None:
                verdict(name, None, "internal/http 里找不到 SSEStatus")
            else:
                # 现场 = 还在从 HTTP 服务器级取那**一份** active/max。两条流各自的读数
                # 必须由各自的流对象产生：载荷是不是 events/logs 两份不是判据（写两个
                # 同名 key 的服务器级读数也能骗过形状核对），骗不过的是这里有没有
                # streamStatus(<某条流>) 这种「按流入手」的调用。
                server_level = bool(
                    re.search(r"\bserver\.(ActiveConnections|MaxConnections)\b", body)
                    or re.search(r"\bh\.server\.(Active|Max)Connections\b", body)
                )
                per_stream = (
                    len(re.findall(r"streamStatus\(", body)) >= 2 and not server_level
                )
                verdict(
                    name,
                    not per_stream,
                    "sse-status 按两条流各取一份 current/max/limit_reached"
                    if per_stream
                    else "sse-status 仍报 HTTP 服务器级单一 active/max（或两条流没有各自取数）",
                )
        elif name == "HTTP_SSE_JAILS_NO_PUBLISHER":
            # 现场 = jails 域没有**变更触发**的生产者。发布点刻意不在事件泵里：jails 不
            # 随采样变化，把域名塞回泵的域常量等于每个 tick 无脑重发同一份载荷（那是
            # HTTP_SSE_RESERIALIZES_EVERY_DOMAIN 记过的病）。真正的形状是「快照属主在
            # 换形状的那一刻喊一声」，所以判据两端都要看：
            #   * 帧侧——Go 树里任意实现文件有 `.Publish("jails", …)` 这类字面发布点
            #     （与 check_sse_events 同一套形式判据，不绑文件名）；
            #   * 触发侧——执行体发布 jail 快照的函数里通知了监听器。
            # 只看前一半会漏掉「有个每 tick 重发的假生产者」，只看后一半会漏掉通知了
            # 但没人发帧。
            executor = read(EXECUTOR_GO)
            points = _sse_publish_points(go_tree_sources_by_file(), "jails")
            triggered = (
                "publishJailSnapshot" in executor and "OnJailSnapshotChanged" in executor
            )
            live = not points or not triggered
            verdict(
                name,
                live,
                f"jails 帧发布点 {', '.join(points[:2])}，执行体快照发布点通知监听器"
                if not live
                else (
                    "Go 面没有 jails 域的字面发布点"
                    if not points
                    else "执行体发布 jail 快照时没有通知 SSE 生产者"
                ),
            )
        elif name == "HTTP_TODAY_BANS_EQUALS_TOTAL":
            # 扫**代码**而不是整棵树原文：这条判据问的是「有没有自然日窗口的算法」，
            # 一段提到 `00:00` 或 `today_bans` 的注释不是算法（见 go_tree_code）。
            tree = go_tree_code()
            if "today_bans" not in tree and "TodayBans" not in tree:
                verdict(name, None, "Go 面还没有 today_bans 字段与 GET /api/v1/stats")
            else:
                # 接回来之后：现场仍在 = 找不到任何「自然日窗口」的算法（今日与总计同源）。
                day_window = bool(
                    re.search(r"StartOfDay|startOfToday|Midnight|00:00", tree)
                )
                verdict(
                    name,
                    not day_window,
                    f"today_bans 存在但是否按自然日窗口计算={day_window}",
                )
        elif name == "HTTP_SERVICE_PROBE_NO_TOTAL":
            tree = go_tree_sources()
            if not ("ServiceProbe" in tree or "service-probes" in tree):
                verdict(name, None, "Go 面还没有 service-probes 端点/载荷")
            else:
                verdict(
                    name,
                    "total_detected" not in tree,
                    "service-probes 与 port-scanners 的检出计数字段是否已对齐",
                )
        elif name == "HTTP_LOG_SSE_LIMIT_DOC_DRIFT":
            # 现场仍在 = 两条流没有一个「各自独立」的上限。三个条件缺一即算现场还在：
            #   1) 组合根两条流各建一个实例（一个共用 broker 就是旧形状）；
            #   2) 两条流各自引用自己的契约上限常量（合成一个值就换了个形态复发）；
            #   3) 日志流真的走名额账本——只建一个 SSEStream 而 handler 不经过它，
            #      等于日志流仍然没有计数。
            main_src = read(MAIN_GO)
            sse_src = read(SSE_GO)
            logs_body = _fn_body(read(LOGS_GO), "StreamLogs") or ""
            two_streams = "NewEventsBroker(" in main_src and "NewLogsStream(" in main_src
            per_stream_caps = (
                "httpcontract.SSEMaxConnectionsApiV1Events" in sse_src
                and "httpcontract.SSEMaxConnectionsApiV1LogsStream" in sse_src
            )
            logs_capped = "streamSSE(" in logs_body and "h.logStream" in logs_body
            verdict(
                name,
                not (two_streams and per_stream_caps and logs_capped),
                f"组合根两条流各建实例={two_streams}，两条流各自引用契约上限常量"
                f"={per_stream_caps}，日志流经名额账本={logs_capped}"
                "（契约的 events 10 / logs 5 必须同时独立成立）",
            )
        # 没有探针的（例如纯文档类缺陷）落到下面的 missing 清单，不静默当成通过。

    missing = sorted(declared - covered)
    if missing:
        print(f"  提示：以下 defect 没有机械探针，只有锚点核对：{', '.join(missing)}")
    return problems


def _tool(override: str | None, name: str) -> str | None:
    """取工具链可执行文件：显式给的必须是存在的文件，否则退回 PATH 上找。

    CI 里把 `GO=go` 这类**名字**写进 env 时，直接拿去 subprocess 会抛
    FileNotFoundError——那会被读成「契约有问题」。这里统一：名字要在 PATH 上解析，
    解析不到就当没这个工具，由调用方打印「跳过」。
    """
    if override:
        if os.path.isfile(override) and os.access(override, os.X_OK):
            return override
        return shutil.which(override)
    return shutil.which(name)


def check_artifacts() -> list[str]:
    """确认 HTTP 生成物本身可用：Go 契约能编译、TS 契约能过类型检查。

    工具链缺失时**跳过并说明**，不报假红也不静默通过：`tsc` 的 shebang 需要
    node，本机没有 node 时它会以 127 退出且 stdout 为空——那不是契约的问题，
    把它记成契约失败只会让人以为生成的 .ts 有类型错误。Rust 生成物已随 Rust
    daemon 一并退役，这里不再有 rustc 一步。
    """
    problems: list[str] = []
    print("=== 生成物自检（各自工具链）===")

    go_src = GEN_HTTP_GO
    go = _tool(os.environ.get("GO"), "go")
    if go and os.path.isfile(go_src):
        # 临时目录留在仓库内（.gitignore 的 /tmp/fw_* 覆盖），不往仓库外落文件。
        scratch = os.path.join(ROOT, "tmp")
        os.makedirs(scratch, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fw_", dir=scratch) as td:
            dst = os.path.join(td, "http_contract.go")
            shutil.copyfile(go_src, dst)
            proc = subprocess.run(
                [go, "build", "-o", os.path.join(td, "pkg.a"), dst],
                capture_output=True, text=True, cwd=td,
            )
            if proc.returncode != 0:
                problems.append(
                    "http_contract.go 编译失败:\n"
                    + (proc.stderr or proc.stdout)[-3000:]
                )
                print("  失败  http_contract.go go build")
            else:
                print("  OK    http_contract.go go build")
    else:
        print(f"  跳过  http_contract.go go build（未找到 go：{go!r}）")

    ts_src = os.path.join(GEN_DIR, "http_contract.ts")
    tsc = os.environ.get("TSC") or os.path.join(ROOT, "frontend", "node_modules", ".bin", "tsc")
    node = _tool(os.environ.get("NODE"), "node")
    if os.path.isfile(tsc) and not node and not os.environ.get("TSC"):
        # tsc 是带 shebang 的 JS 包装：没有 node 就跑不起来，据实跳过。
        print(f"  跳过  http_contract.ts tsc（仓库里有 tsc 但环境无 node 运行时）")
    elif os.path.isfile(tsc):
        argv = [tsc, "--noEmit", "--strict", "--skipLibCheck", "--target", "es2020",
                "--lib", "es2020,dom", ts_src]
        if node:
            # 显式经 node 调用，避开 shebang 与 PATH 的差异。
            argv = [node, tsc] + argv[1:]
        proc = subprocess.run(argv, capture_output=True, text=True, cwd=ROOT)
        if proc.returncode != 0:
            problems.append(
                "http_contract.ts 类型检查失败:\n"
                + ((proc.stdout or "") + (proc.stderr or ""))[-3000:]
            )
            print("  失败  http_contract.ts tsc --noEmit")
        else:
            print("  OK    http_contract.ts tsc --noEmit")
    else:
        print(f"  跳过  http_contract.ts tsc（未找到 {tsc}）")
    print()
    return problems


# ---------------------------------------------------------------------------
# 13. 缺口棘轮：把「Go 还没接线」与「实现与契约矛盾」分开
# ---------------------------------------------------------------------------

# 每条问题文本 → 稳定指纹的规则。指纹**不含计数与散文**，因此改文案不会让基线整片
# 失效；反过来，散文改了而规则没跟上，那条问题就落进「校验器不认识」里当新缺口报出，
# 不会静默通过。规则按顺序匹配，第一条命中即取。
_GAP_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("route-missing", re.compile(r"^路由 (\w+ .+?) 在 daemon 的 ServeMux 注册里不存在")),
    ("route-any-method", re.compile(r"^路由 (\w+ .+?) 只以无方法前缀的 Handle 注册")),
    ("route-undeclared", re.compile(r"^daemon 中存在契约未声明的路由 (\w+ .+?)（")),
    ("route-auth-group", re.compile(r"^路由 (\w+ .+?): 契约 auth=")),
    ("route-handler-mismatch", re.compile(r"^路由 (\w+ .+?): 源码 handler")),
    ("auth-constant", re.compile(r"^(auth\.\w+):")),
    ("sse-cap", re.compile(r"^SSE (/[\w/\-]*): 契约上限")),
    ("sse-publish-point", re.compile(r"^SSE (/[\w/\-]*): 事件 '(\w+)' 在 Go 源码里没有发布点")),
    ("sse-subscriber", re.compile(r"^SSE (/[\w/\-]*): 事件 '(\w+)' 在前端订阅侧找不到")),
    ("type-contract-field", re.compile(r"^类型 (\w+)（[^）]*）: 契约字段 '(\w+)'")),
    ("type-go-only-field", re.compile(r"^类型 (\w+)（[^）]*）: struct 字段 '(\w+)'")),
    ("type-unreferenced", re.compile(r"^类型 (\w+)（[^）]*）: internal/http 里没有它的引用")),
    ("type-unmapped", re.compile(r"^\d+/\d+ 个载荷类型在 Go 源码里没有同名 struct")),
    ("header-missing", re.compile(r"^header ([\w\-]+):")),
    ("errmodel-body", re.compile(r"^errmodel (\w+): 响应体 ")),
    ("errmodel-plain-text", re.compile(r"^errmodel (\w+): 契约声明 \[(\d+)\] 的响应体是纯文本")),
    ("errmodel-framework-claim", re.compile(r"^errmodel (\w+): 契约(?:声明|把) (\d+)")),
    ("errmodel-fallback", re.compile(r"^errmodel (\w+):")),
    ("envelope-key-order", re.compile(r"^信封 \w+ 的 JSON key")),
    ("envelope-success-message", re.compile(r"^成功信封的 message")),
    ("envelope-data-omitempty", re.compile(r"^信封 \w+\.data 的 tag")),
    ("envelope-error-data", re.compile(r"^ErrorEnvelope 未给 data")),
    ("envelope-error-code", re.compile(r"^ErrorEnvelope 把 code")),
    ("business-codes-unproduced", re.compile(r"^业务码在 Go 源码里没有构造点")),
)

GAP_BASELINE_FILE = os.path.join(ROOT, "contract", "http_gap_baseline.txt")


def _gap_fingerprint(msg: str) -> str:
    """问题文本 → 指纹；不认识的问题用全文当指纹（于是必然不在基线里，报成新缺口）。"""
    for kind, pat in _GAP_RULES:
        m = pat.match(msg)
        if m:
            return ":".join((kind, *m.groups()))
    return "unclassified:" + msg


def _read_gap_baseline() -> dict[str, str]:
    """基线文件 → {指纹: 注释}。`#` 开头与空行忽略，行内 ` #` 之后是备注。"""
    entries: dict[str, str] = {}
    if not os.path.isfile(GAP_BASELINE_FILE):
        return entries
    for line in read(GAP_BASELINE_FILE).splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        fp, _, note = text.partition(" #")
        entries[fp.strip()] = note.strip()
    return entries


def apply_gap_ratchet(failures: list[str]) -> list[str]:
    """把「Go 尚未接线」的已知缺口按**只减不增**的基线冻结，其余一律算红。

    为什么需要这一层：daemon 从 Rust 迁到 Go 后，契约里 57 条路由有 20 来条、两条 SSE
    的上限与安全头都还没接上。直接把校验器指向 Go 会让 CI 长期全红，真漂移就淹在噪音里。
    冻结基线把两侧分开：

      - 缺口在基线里且仍然报出 → 计入「待实现」，不红（但**逐条打印**，不静默）
      - 缺口不在基线里 → 红：新出现的缺口，必须显式加行才允许存在
      - 基线里的条目不再报出 → 红：那一格已经补上了，必须删行（刻意的摩擦，
        逼着补齐动作同步落进契约与本文件）

    规则本身不削弱契约：.fwidl 里的要求一条都没删，基线只是记录「daemon 当前还没做到」，
    并且只许缩小。`defect … 已失效` 与生成物自检失败没有指纹，永远直接算红。
    """
    baseline = _read_gap_baseline()
    live: dict[str, str] = {}
    unknown: list[str] = []
    for msg in failures:
        fp = _gap_fingerprint(msg)
        if fp.startswith("unclassified:"):
            # 不认识的问题文本一律直接算红（defect 改判冲突、生成物自检失败、扫描器
            # 本身失灵都属于这类），不给它伪装成可冻结的缺口。
            unknown.append(msg)
            continue
        live.setdefault(fp, msg)

    problems: list[str] = list(unknown)
    new_gaps = [fp for fp in sorted(live) if fp not in baseline]
    closed = [fp for fp in sorted(baseline) if fp not in live]
    for fp in new_gaps:
        problems.append(
            f"新增缺口（不在 contract/{os.path.basename(GAP_BASELINE_FILE)} 里）：{live[fp]}"
            "\n     确认属于「Go 尚未接线」才加行；实现与契约矛盾应当修实现而不是加行"
        )
    for fp in closed:
        problems.append(
            f"缺口已闭合但基线未同步：{fp}"
            f"{'（' + baseline[fp] + '）' if baseline[fp] else ''}"
            " —— 请把该行从基线里删掉"
        )
    print(
        f"  缺口棘轮：基线 {len(baseline)} 条 / 仍缺 {len(live) - len(new_gaps)} 条 / "
        f"新增 {len(new_gaps)} 条 / 已闭合未删行 {len(closed)} 条"
    )
    frozen = [fp for fp in sorted(live) if fp in baseline]
    if frozen:
        by_kind: dict[str, int] = {}
        for fp in frozen:
            by_kind[fp.split(":")[0]] = by_kind.get(fp.split(":")[0], 0) + 1
        print(
            "  待实现（已在基线冻结，逐条见 contract/http_gap_baseline.txt）："
            + "、".join(f"{k} {v} 条" for k, v in sorted(by_kind.items()))
        )
    if new_gaps:
        print("  新增缺口指纹：" + ", ".join(new_gaps))
    if closed:
        print("  待删行的已闭合指纹：" + ", ".join(closed))
    return problems


def dump_gap_baseline(failures: list[str]) -> None:
    """`--write-gap-baseline` 用：把当前所有缺口指纹写成基线（含原问题文本作注释）。

    只在人为核对后手工运行，不作为常规门禁路径——常规路径只读基线并做只减不增比对。
    """
    seen: dict[str, str] = {}
    for msg in failures:
        fp = _gap_fingerprint(msg)
        if fp.startswith("unclassified:"):
            continue
        seen.setdefault(fp, msg)
    header = (
        "# HTTP 契约缺口的冻结基线（由 contract/verify_http.py --write-gap-baseline 生成）\n"
        "#\n"
        "# 一行一个指纹，格式 `<kind>:<标识>[…]: <原问题文本>`（# 之后是备注）。\n"
        "# 规则是**只减不增**：\n"
        "#   * 门禁报出而这里没有的指纹 = 新缺口，必须显式加行才允许存在；\n"
        "#   * 这里有而门禁不再报出的 = 那一格已补上，必须删行；\n"
        "#   * 实现与契约矛盾的东西不该进这里——那是要修的实现，不是可冻结的缺口。\n"
        "# 契约（http.fwidl）因此保持完整：这里只登记 daemon 当前还没接线的部分。\n"
    )
    with open(GAP_BASELINE_FILE, "w", encoding="utf-8") as fh:
        fh.write(header)
        for fp in sorted(seen):
            fh.write(f"{fp} # {seen[fp]}\n")
    print(f"  已写出基线：{GAP_BASELINE_FILE}（{len(seen)} 条）")


def main() -> int:
    dump_mode = "--write-gap-baseline" in sys.argv
    if not os.path.isfile(LAYOUT_JSON):
        print("错误: 未找到生成物，请先运行 gen.py", file=sys.stderr)
        return 2
    with open(LAYOUT_JSON, encoding="utf-8") as fh:
        contract = json.load(fh)

    print("=== HTTP 契约 vs daemon + 前端 ===")
    failures: list[str] = []
    failures += check_routes(contract)
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
    failures += check_types_go(contract)
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

    # 棘轮之后只留「红」的那部分：基线里冻结的缺口已从列表里摘掉，
    # 剩下的必须是新增缺口、已闭合未删行、以及无法归类的问题。
    # 重新冻结基线时要看**归类前**的完整列表，否则刚跑完棘轮就只剩新增项了。
    unfrozen = list(failures)
    failures = apply_gap_ratchet(failures)
    if dump_mode:
        print()
        dump_gap_baseline(unfrozen)
        return 0

    print()
    if failures:
        print("HTTP 契约校验失败:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(
        "HTTP 契约校验通过：已接线的部分与契约一致，缺口未新增"
        "（仍缺的条目见上面「待实现」计数与 contract/http_gap_baseline.txt）"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
