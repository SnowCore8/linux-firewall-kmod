# Web 前端

面向运维与二次开发：界面由哪些页面构成、数据从哪里来、凭据放在哪里、
哪些能力受浏览器约束。

服务侧的路由分层、SSE 约束、信封与认证集中在
[用户态守护进程](daemon.md)，本文不复制那边的结论。

前端是**桌面优先、响应式**的单页控制台：侧边栏 + 顶栏 + 内容区，
UI 用 Ant Design，图表用 ECharts。它是全新重写，不沿用任何旧移动页面范式
（无底部 TabBar、无下拉刷新、无滑动操作、无 Popup 表单）。

## 口径

页面清单、事件名、连接上限这类会随代码变动的事实，本文一律不写数值，只给出处：

| 事实 | 权威出处 |
|------|---------|
| 服务侧契约 | `contract/http.fwidl`，核对看 `contract/verify_http.py` 输出 |
| 前端路由表 | `frontend/src/app/router.tsx` 的 `createHashRouter` |
| 信息架构（分组/路径/标题/图标） | `frontend/src/app/nav.ts` 的 `NAV_GROUPS` |
| 服务侧固定页面路径 | `contract/http.fwidl` 中 handler 为 `spaShell` 的条目 |
| 数据面与凭据行为 | `frontend/src/api/`、`frontend/src/hooks/`、`frontend/src/providers/` |

## 技术栈

| 项 | 内容 | 出处 |
|----|------|------|
| 框架 | React 19 + TypeScript | `frontend/package.json` |
| 组件库 | Ant Design 6（`antd` + `@ant-design/icons`） | 同上 |
| 图表 | ECharts 6 + `echarts-for-react` | 同上；封装在 `frontend/src/components/charts/BaseChart.tsx` |
| 路由 | `react-router-dom` 7 的 `createHashRouter` | `frontend/src/app/router.tsx` |
| 构建 | Vite 8 + `@vitejs/plugin-react` | `frontend/vite.config.ts` |
| 类型检查 | `tsc --noEmit` | `frontend/package.json` 的 `typecheck` 脚本 |
| 入口 | `frontend/index.html` + `frontend/src/main.tsx` | `index.html` 的 `<script type="module" src="/src/main.tsx">` |

依赖锁在 `frontend/package-lock.json`。CI 用 `npm ci`。

`tslib` 是**显式声明**的运行时依赖：`echarts-for-react` 以 `importHelpers` 编译却
没把 `tslib` 列进自己的依赖，缺它打包会报 `failed to resolve import "tslib"`。
它不是本项目代码直接用的库，纯粹补上游的打包缺口，别当多余依赖删掉。

数据层是**自研 hooks**（`useAsync` / `useLiveData` / `useSse`），没有引入
TanStack Query 之类的数据缓存库——REST 拉取、SSE 增量、轮询兜底与新鲜度仲裁
都在 `frontend/src/hooks/` 里，规模可控且与契约门禁贴合。

### 构建落点

`frontend/vite.config.ts` 的 `build.outDir` 是 `../build/obj/frontend`。
`make daemon` 在 `go build` 期间把这批文件临时拷进
`src/daemon/web_ui/static/`，由该目录的 `assets.go`（`//go:embed *`）
携带进守护进程二进制；`go build` 退出时 `trap` 删除临时文件，只留 `assets.go`。
产物文件名固定：

| 产物 | 配置项 |
|------|--------|
| `app.js` | `rollupOptions.output.entryFileNames` |
| `chunk-[name].js` | `chunkFileNames` |
| `style.css` | `assetFileNames` + `cssCodeSplit: false` |
| 平铺在输出根 | `assetsDir: ''` |
| 资源 URL 前缀 `/static/` | `base: '/static/'` |

三项与守护进程对齐的约束写在 `vite.config.ts` 顶部注释：

1. `base = "/static/"`：守护进程对外提供 `GET /static/*path`。
2. 资源平铺、文件名固定：便于 `go:embed` 按名查找。
3. 守护进程只对一组固定页面路径返回 HTML，没有 catch-all，所以用 hash 路由。

### JSX 运行时

统一到 React 的自动运行时，三处配置必须成对维护：

| 位置 | 值 |
|------|-----|
| `frontend/tsconfig.json` | `"jsx": "react-jsx"` |
| 同上 | `"jsxImportSource": "react"` |
| `frontend/vite.config.ts` | `plugins: [react()]`（`@vitejs/plugin-react`） |

不成对的后果写在 `vite.config.ts` 注释里：tsc 与打包器会各自解析一份 JSX 实现，
类型报不匹配，产物却跑另一套运行时。

`tsconfig.json` 还开了 `verbatimModuleSyntax`（类型导入必须写 `import type`）、
`allowImportingTsExtensions`（相对导入一律带 `.ts`/`.tsx` 后缀），
以及 `noUnusedLocals`/`noUnusedParameters`——这三条是 `tsc --noEmit` 会拦的硬约束。

### 中间产物与源码树隔离

Vite 输出目录 `build/obj/frontend/` 在源码树之外，因此 `emptyOutDir: true`：
每次构建清空的是构建目录。`src/daemon/web_ui/static/` 里只有已入库的
`assets.go`，面板文件仅在 `make daemon` 执行 `go build` 期间临时存在，
由 `trap cleanup EXIT` 在退出时删除，并保留 `assets.go`：

```
find src/daemon/web_ui/static -mindepth 1 ! -name assets.go -delete
```

`assets.go` 是 `//go:embed` 的持有文件，不能删，否则 `go build` 报
「包内无 .go 文件」。

> **改前端必须重新构建守护进程才可见**：面板产物落盘后要再跑 `make daemon`
> 才会重编二进制。只改前端不重编，守护进程提供的仍是旧包。
> 详见 [构建](../development/building.md)。

## 目录结构

`frontend/src/` 按职责分层：

| 目录 | 职责 |
|------|------|
| `api/` | 契约纪律层：`types.ts`（镜像契约类型）、`endpoints.ts`（`ROUTES.*` 解出的路径 + 调用函数 + SSE URL 构造）、`client.ts`（fetch + 信封解包 + 错误分类）、`auth.ts`（凭据存取与编码）、`contract.ts`（契约桥接常量） |
| `app/` | 组合根与外壳：`App.tsx`（Provider 树）、`router.tsx`（路由表）、`AppShell.tsx`（侧边栏布局）、`nav.ts`（信息架构单一真相源） |
| `providers/` | `ThemeProvider`、`AuthProvider`、`NotificationProvider`、`SseProvider`、`ErrorBoundary` |
| `hooks/` | `useAsync`（REST）、`useSse`（events 流连接管理）、`useLiveData`（SSE+REST 合流）、`useRefreshSignal`、`useHotkey`、`useMediaQuery`、`usePersistentState` |
| `components/` | 通用组件：`PageHeader`、`DataTable`、`DrawerForm`、`StatCard`、`ChartCard`、`CommandPalette`、`NotificationCenter`、`charts/BaseChart`、`state/{EmptyState,ErrorState,LoadingState,RealtimeBadge}` |
| `views/` | 页面组件，**平铺**为 `views/<Name>.tsx`（门禁按此路径核对，见下） |
| `theme/` | `tokens.ts`：品牌色、语义色、威胁等级色阶、字体、密度、`buildTheme` |
| `lib/` | 纯函数工具：`format`、`validation`、`freshness`、`charts`、`defaults`、`appEvents`、`visibility` |

> **`views/` 必须平铺**：`contract/verify_http.py` 硬编码了
> `frontend/src/views/Logs.tsx` 这条路径来核对日志流的事件名字面量
> （`TS_LOGS_PAGE`）。把 Logs 挪进子目录（如 `views/logs/index.tsx`）会让门禁找不到文件而失败。

## 页面与路由

### 为什么必须是 hash 路由

守护进程只对一组**固定的**页面路径返回 HTML 外壳，没有 catch-all。
用 history 路由时，用户在 `/bans` 按刷新会直接吃到服务侧 404。
hash 路由下地址是 `#/bans`，浏览器只请求 `/`，刷新与分享直达都安全。
代价是地址里带 `#`。

### 路由表

`frontend/src/app/router.tsx` 的 `createHashRouter`：`/login` 是公开闸门，
其余全部挂在 `RequireAuth` 保护的 `AppShell` 下，作为子路由渲染进 `<Outlet/>`。
页面组件一律 `React.lazy` 懒加载，切页时由外壳的 `LoadingBoundary`（Suspense）
兜底成表格骨架，避免首屏一次性下载所有页面代码。

| 路径 | 视图 | 说明 |
|------|------|------|
| `/login` | `Login` | 公开；已登录访问由 Login 自身跳回概览 |
| `/`（index） | 重定向到 `/dashboard` | — |
| `/dashboard` | `Dashboard` | 概览 |
| `/bans` | `Bans` | 封禁管理 |
| `/bans/:ip` | `Bans` | 深链：自动打开该 IP 的详情抽屉 |
| `/whitelist` | `Whitelist` | 白名单 |
| `/jails` | `Jails` | 越狱规则 |
| `/ddos` | `Ddos` | DDoS 监控 |
| `/risk` | `Risk` | 风险引擎（需 `risk_engine` flag） |
| `/threat-feeds` | `ThreatFeeds` | 威胁情报（需 `threat_feeds` flag） |
| `/analysis` | `Analysis` | 综合分析 |
| `/analysis/ip/:ip` | `Analysis` | 深链：自动打开该 IP 的综合分析抽屉 |
| `/logs` | `Logs` | 日志（历史 + SSE 实时流） |
| `/settings` | `Settings` | 设置 |
| `*` | `NotFound` | 软兜底 |

`NotFound` **不做硬 404**：已知路径的深链前缀交回对应页，其余重定向到 `/dashboard`
——控制台里硬 404 意义不大，错误链接被送回概览比白屏更可用。

深链（`/bans/:ip`、`/analysis/ip/:ip`）复用同一个页面组件，由页面读 `useParams`
决定是否自动打开详情抽屉，于是「实时告警点进来直达某 IP」与「手动浏览」走同一条渲染路径。

### 信息架构：nav.ts 是单一真相源

侧边栏分组、路由路径、页面标题与图标全部定义在 `frontend/src/app/nav.ts` 的
`NAV_GROUPS`，三处消费同一份配置以避免漂移：

1. `AppShell.tsx` 的侧边栏菜单（分组 + 图标 + 选中态）；
2. `CommandPalette.tsx` 的页面跳转项（模糊匹配 `label`/`keywords`）；
3. 路由表与 `PageHeader` 面包屑。

分组按运维心智模型：

| 分组 | 页面 |
|------|------|
| 总览 | 概览 |
| 防护 | 封禁管理、白名单、越狱规则、DDoS 监控 |
| 智能 | 风险引擎、威胁情报、综合分析 |
| 运维 | 日志、设置 |

「智能」组多为只读洞察，消费既有但旧界面未接的后端端点。
`risk`/`threat-feeds` 带 `featureFlag`：对应后端 flag 关闭时端点回 503，
页面显示 `disabled` 空态而非报错。旧版的 3D 地图页（three.js）已移除，
攻击源地理分布并入分析页的只读视图。

## 应用外壳（AppShell）

`frontend/src/app/AppShell.tsx` 是全站唯一的框架层：侧边栏 + 顶栏 + 内容区。

响应式策略（桌面优先，逐级降级）：

| 断点 | 侧边栏 |
|------|--------|
| ≥lg(1024) | 常驻，可手动折叠（折叠态持久化 + 跨标签同步） |
| md–lg(768–1023) | 自动折叠为图标条，把横向空间让给表格 |
| <md(768) | 收进抽屉，顶栏出现汉堡按钮；表格由各页自行降级为卡片/横滚 |

顶栏聚合跨页常驻能力：命令面板入口（`⌘K`/`Ctrl+K`）、实时状态灯（`RealtimeBadge`）、
主题切换（`⌘J`）、密度切换、通知中心、账户菜单（退出登录）。
全局快捷键由 `useHotkey` 注册：`mod+k` 开命令面板、`mod+j` 切主题、`r` 触发刷新
（`lib/appEvents.ts` 的 `emitRefresh`，各页用 `useRefreshSignal` 订阅）。

外壳订阅 SSE 连接态与威胁等级，在**状态跃迁**时推通知（连接降级/重连/恢复、
威胁等级升高），跃迁去抖保证只在真正变化时推一次——让运维盯着别的页面也不错过关键变化。

## Provider 组合与认证闸门

Provider 组合根在 `frontend/src/app/App.tsx`（**不在** `main.tsx`），
从外到内的嵌套顺序即依赖顺序：

```
ThemeProvider（AntD ConfigProvider：主题 token / 暗色算法 / 中文 locale）
  └ AntdApp（上下文感知的 notification/message/modal 实例，随主题走）
    └ ErrorBoundary（兜住下面任何一层渲染崩溃）
      └ AuthProvider（令牌生命周期；SSE 依赖它决定是否连接）
        └ NotificationProvider（用 AntdApp 的实例弹 toast；实时告警的落点）
          └ SseProvider（唯一一条 events 连接；useAuth 决定 enabled）
            └ RouterProvider（页面组件在此消费以上全部 context）
```

顺序不能乱的两条硬约束（写在 `App.tsx` 注释里）：

1. `NotificationProvider` 必须在 `AntdApp` 之内——它调 `App.useApp()` 拿主题感知的
   通知实例，用静态 `notification.xxx` 会在暗色下渲染成亮色；
2. `SseProvider` 必须在 `AuthProvider` 之内——它读 `isAuthenticated` 决定连不连实时流，
   未登录时连接会被守护进程 401 拒绝，白白触发退避重连、并喂大服务侧暴力破解计数。

`SseProvider` 仍包在 `RouterProvider` **之外**，所以 hash 路由切换不重建连接。

`main.tsx` 只做两件事：在 `StrictMode` 下挂载 `<App/>`，以及注册 `/sw.js`
（注册失败静默忽略，见 PWA 一节）。`StrictMode` 保留：开发期双调用 effect
能提前暴露「SSE 没在卸载时清干净」「订阅没退订」这类副作用泄漏，生产构建不受影响。

## 数据面：首帧 REST + SSE 增量 + 轮询兜底

| 通道 | 承担 | 入口 |
|------|------|------|
| REST `/api/v2/*` | 首帧取数、翻页、**全部写操作** | `api/client.ts` + `hooks/useAsync.ts` |
| SSE `/api/v2/events` | 实时增量（统计、封禁、jail、速率、白名单） | `hooks/useSse.ts` + `providers/SseProvider.tsx` |
| SSE `/api/v2/logs/stream` | 实时日志流 | `views/Logs.tsx`（该页自己接管，见下） |

### REST 侧

`api/client.ts` 收敛三件事：附加凭据、解包信封（HTTP 2xx **且** `code === 0`
才算业务成功）、把失败统一抛成 `ApiError`。`ApiError` 带 `.kind`
（`network`/`timeout`/`unauthorized`/`business`/`http`/`parse`/`aborted`）、
`.status`（无响应时为 `0`）、`.code`（业务码）。网络层失败时 `status` 为 `0`，
调用方据此区分「服务侧明确拒绝」与「根本连不上」。

> 特例：`/api/v2/health` **不经信封**（裸 `RuntimeSnapshot`，200=就绪 / 503=未就绪，
> 见 defect `HTTP_HEALTH_NOT_ENVELOPED`），走 `apiFetchRaw` 直接取 JSON。

视图侧统一用 `hooks/useAsync.ts`，它保证三点：

- 卸载或依赖变化后不再 `setState`；
- 用请求序号丢弃过期响应，避免竞态覆盖；
- 错误转成可展示文案，不吞掉。

路径常量与类型来自契约生成物 `api/endpoints.ts` 与 `api/types.ts`。
`frontend/src` 里**禁止**出现裸 `/api/v…` 字面量：路径一律由 `endpoints.ts`
从 `ROUTES.*` 解出，这条由 `verify_http.py` 机械核对。

### SSE 侧

`SseProvider` 全应用只挂一个，且在路由之外：hash 路由切换不重建连接。
连接管理在 `hooks/useSse.ts`：

| 策略 | 做法 | 出处 |
|------|------|------|
| 单例连接 | 只建一条 `EventSource` | `hooks/useSse.ts` |
| 受控重连 | 收到 `error` 时主动 `close`，按 `min(2**min(n,5),30)` 秒指数退避重连 | 同上 |
| 超限即停 | 重连前先探 `GET /api/v2/stats/sse-status`，`events.limit_reached` 为真就**停手**，状态置 `limit` | 同上 |
| 分域快照 | 每个域（stats/bans/jails/whitelist/rates）各存一份数据 + 新鲜度序号，独立更新 | 同上 |
| 单帧容错 | 解析失败只丢弃该帧，不影响整条连接 | 同上 |

继续重试只会持续打满服务侧日志且永远不会成功，所以超限改由界面提示用户
关闭其它控制台标签页后刷新，并降级到 REST 轮询。上限数值与事件集见
`contract/http.fwidl`，本文不复制。

> **门禁约束**：`verify_http.py` 的 `check_sse_events` 要求契约声明的每个事件名
> （events 流的 `connected`/`stats`/`bans`/`jails`/`whitelist`/`rates`）逐字出现在
> `hooks/useSse.ts` 里；日志流的 `connected`/`log`/`error` 逐字出现在 `views/Logs.tsx` 里。
> 所以两处都用逐个 `addEventListener('名字', …)` 的写法，而不是拿数组循环——
> 字面量必须落在源码里，这条检查才成立。日志流因此由 `Logs.tsx` 自己接管，不走 `useSse`。

### SSE 与 REST 合流：useLiveData

一个域的数据同时有两条来路：SSE 域帧（快、可能断）和 REST 拉取（慢、可靠）。
`hooks/useLiveData.ts` 用全局新鲜度序号（`lib/freshness.ts` 的 `nextSeq`/`pickFresher`）
仲裁「谁更新」，视图只消费一个值，不必关心它这次从哪条路来：

- SSE 断了（`limit`/重连中/未登录）时，REST 轮询是唯一兜底；
- SSE 活着时，REST 轮询退化为低频校准（服务端真值），SSE 负责秒级抖动；
- 两者按 seq 取胜，于是「慢 REST 晚到」不会盖掉「新 SSE 帧」，界面不来回跳。

`bans` 这类「SSE 是整表镜像、REST 是分页对象」形状不一致的域**不用** `useLiveData`，
由页面自行处理（它需要服务端分页/排序，无法用整表镜像替代）。

### 连接状态与实时灯

`components/state/RealtimeBadge.tsx` 把连接状态（`idle`/`connecting`/`open`/
`reconnecting`/`limit`/`closed`）渲染成顶栏状态灯，颜色 + 文案双通道，色盲用户也可分辨。
数据新鲜度由最近一帧到达时刻（`lastEventAt`）驱动。离线判定只监听浏览器的
`online`/`offline` 事件，不做轮询。

## 认证与令牌

凭据的**唯一来源**是 `api/auth.ts`。REST 与 SSE 都从它取，不允许各自维护一份。

| 载体 | 用于 | 原因 |
|------|------|------|
| `Authorization: Basic <base64(user:pass)>` | REST 读写 | 服务侧中间件的首选来源 |
| `?access_token=<base64>` | `EventSource` | 浏览器不给 `EventSource` 设自定义请求头 |
| `sessionStorage`，键 `firewall.access_token` | 刷新后沿用 | 同源隔离，关闭标签页即失效 |

### 令牌从哪来

令牌只在**交互式登录**时产生：登录页（`views/Login.tsx`）收集用户名/密码 →
`api/auth.ts` 的 `encodeBasic` 编成 `base64(user:pass)` → 一次真实探测通过后
`setAccessToken` 写进 `sessionStorage`。此后：

- REST 侧由 `client.ts` 经 `authorizationHeader()` 注入 `Authorization: Basic <token>`；
- SSE 侧由 `endpoints.ts` 的 `eventsStreamUrl()`/`logsStreamUrl()` 从 `getAccessToken()`
  取令牌、拼成 `?access_token=<token>`（`EventSource` 设不了请求头）。

> **不再支持 `?access_token=` 深链引导**：旧移动前端有一个从 URL query 读取令牌、
> 写进 `sessionStorage` 再从地址栏抹掉的入口（`initAccessToken`）。本次重写**没有**保留它——
> 前端不消费 URL 里的 `access_token`，访问任何页面都先过登录页。守护进程的 `GET /`
> 仍会原样保留 query string 跳到 `/dashboard`，但前端不读它。若外部系统依赖
> `http://<host>/?access_token=<令牌>` 免登录直达，这是一个行为回退，需要时再单独接回。

### 登录探测与锁定

`providers/AuthProvider.tsx` 是令牌生命周期 + 登录/登出 + 401 自动登出 +
锁定倒计时的单一真相源：

- 登录成功与否由一次**真实探测**决定：`probeAuth` 打 `GET /api/v2/bans`
  （不能用恒 303 的 `GET /`）；
- 任何 REST 调用收到 401 都经 `client.ts` 的 `onUnauthorized` 广播到这里 →
  自动清令牌并跳登录，不让某个视图停在「拿着废令牌反复失败」的状态；
- 连续失败达 `AUTH_FAILURE_THRESHOLD` 次后进入本地锁定倒计时（`AUTH_LOCKOUT_SECONDS`，
  镜像守护进程的锁定窗口），倒计时内禁用登录按钮，避免把账号越试越死。

`endpoints.ts` 拼 `access_token` 时做 `encodeURIComponent`，服务侧对应做
百分号解码（`internal/http/auth.go`）。这一对**必须成对修改**：只改一边的表现是
SSE 永久 401。

### 为什么不依赖浏览器原生认证弹窗

SPA 外壳是公开路由，返回不含数据的静态壳，顶层文档**不会**返回 401，
所以浏览器永远不会弹凭据对话框、也就不会缓存凭据。
页面自身发出的请求会全部 401，每个无凭据请求又累加服务侧的暴力破解计数，
最终把正确凭据一起锁死，表现为「越刷新越不可用」。

凭据因此由前端显式携带。服务侧也刻意不发 `WWW-Authenticate`：
那个头会让浏览器弹原生对话框并让 `fetch` 挂起。
代码里的这条断言见 `internal/http/routes_contract_test.go`。

### 失效与登出

`client.ts` 收到 401 时经 `onUnauthorized` 广播，`AuthProvider` 清除本地令牌、
把状态置回未认证，界面回到登录页（`views/Login.tsx`）。

**不做自动重登**：服务侧锁定期间连正确凭据也返回 401，
自动重试只会延长锁定，因此交由用户重新输入触发一次新凭据。

## 主题、密度与设计令牌

`providers/ThemeProvider.tsx` 是外观模式（跟随系统 / 暗 / 亮）+ 信息密度
（标准 / 紧凑）的单一真相源，集中做三件事：

1. 把 antd 6 的 `ThemeConfig` 经 `ConfigProvider` 注入整个组件树
   （暗色算法 / 紧凑算法 / token / `zhCN` locale）；
2. 把语义色、字体、威胁等级色阶写成 `:root` 上的 CSS 变量，供自绘元素与
   ECharts 之外的纯 CSS 组件消费（组件库主题管不到手写样式）；
3. 把 `<html data-theme>` 与 `index.html` 里的首屏内联防闪烁脚本对齐，切主题不闪白。

令牌定义在 `frontend/src/theme/tokens.ts`（`BRAND`、`SEMANTIC`、`THREAT_COLORS`、
`FONT_SANS`/`FONT_MONO`、`buildTheme`、`Density`）。偏好落 `localStorage` 并跨标签同步
（`usePersistentState`）：一个标签切暗色，其它标签跟随。等宽字体（`FONT_MONO`）
专用于 IP / 速率 / 计数这类需要按位对齐的读数。

## PWA

| 项 | 内容 | 出处 |
|----|------|------|
| 清单 | `frontend/public/manifest.webmanifest`，`index.html` 以 `/static/manifest.webmanifest` 引用 | `frontend/index.html` |
| 清单内容类型 | `application/manifest+json`；Go 的内建 MIME 表没有 `.webmanifest`，`internal/http/static.go` 的 `init` 注册该扩展名，否则按 `application/octet-stream` 发出，浏览器不会把它当清单 | `internal/http/static.go` |
| Service Worker | 手写 `frontend/public/sw.js`（零依赖） | 同上 |
| 注册路径 | 根作用域 `/sw.js`，不是 `/static/sw.js` | `main.tsx` + `internal/http/static.go` |
| 作用域抬升 | 响应带 `Service-Worker-Allowed: /` | `internal/http/static.go` |
| `/api/*` | 不缓存，保证封禁列表与统计新鲜 | `frontend/public/sw.js` |
| 缓存版本 | `sw.js` 的 `CACHE_VERSION`；改动本文件后加一，activate 阶段自动清旧缓存 | 同上 |

`sw.js` 对导航请求与 `/static/*` 都用**网络优先 + 离线回退缓存**：构建产物文件名固定
（`app.js`/`style.css`），缓存优先会在守护进程升级后把上一版 JS 喂给新版 index.html，
表现为界面停在旧样式或新旧不匹配的运行期错误。缓存只作断网兜底。

脚本作用域由脚本 URL 决定：`/static/sw.js` 只能接管 `/static/` 下的资源，
接管不了页面导航。Vite 只负责把 `sw.js` 输出到 `static/`，
路由由守护进程单独提供。

### 已知限制：安全上下文

浏览器只在 HTTPS 或 localhost 下暴露 `serviceWorker` API。
经 `http://<局域网IP>:9119` 访问时该 API 不存在，PWA 安装同样被拒。
这是浏览器的硬性约束，本应用绕不过。`main.tsx` 检测不到就静默跳过，
不打警告、不影响界面功能。

**这是已知限制，不是缺陷**，不要当 bug「修掉」，也不要塞 polyfill 或改注册路径。

机械证据在 `tests/e2e/pwa-context.spec.ts`：

```bash
sudo bash scripts/e2e-daemon.sh start
eval "$(bash scripts/e2e-daemon.sh env)"
# 不设 E2E_LAN_ORIGIN 时只跑安全上下文一侧，局域网一侧显式跳过（CI 即如此）
E2E_LAN_ORIGIN=http://<局域网IP>:<port> npm run test:e2e
sudo bash scripts/e2e-daemon.sh stop
```

> 控制台洁净度门槛的判定基准是**当前 baseURL 的源**，不是固定常量。
> 同一套用例会在多个源上跑，写死一个源会让另一侧的判定整体失效
> （`tests/e2e/support.ts`）。

上表的具体观察结果：未验证（本次重写未运行浏览器用例）。
用例本身是可执行断言，跑通即成立。

## 二次开发

hash 路由只解决客户端。服务侧还认一份固定路径清单，
漏一处就会 404，或以 `default-src 'none'` 加载外壳（页面白屏、样式全丢）。

**新增一个页面**要同时动四处：

| # | 位置 | 改什么 |
|---|------|--------|
| 1 | `frontend/src/views/<Name>.tsx` | 新建页面组件（默认导出，可被 `React.lazy` 加载） |
| 2 | `frontend/src/app/router.tsx` | 路由表加一条 `lazy` 导入 + 一个 `path` |
| 3 | `frontend/src/app/nav.ts` | `NAV_GROUPS` 里加一项（驱动侧边栏、命令面板、面包屑） |
| 4 | `contract/http.fwidl` | 加 `spaShell` 那条页面路由，再 `python3 contract/gen.py` 重新生成 |

改完重新构建：`make frontend` + `make daemon`，产物经 `//go:embed` 进二进制。

生成物在 `contract/generated/` 与
`src/daemon/internal/httpcontract/http_contract.go`。
`python3 contract/verify_http.py` 核对契约与 `routes.go` 的注册串。

**新增或修改接口**的顺序相反：先改契约，再改代码。
前端的类型与路径分别来自 `api/types.ts` 与 `api/endpoints.ts`，
两者都是生成物。

## 相关文档

- [用户态守护进程](daemon.md)：路由分层、SSE 约束、信封与认证
- [数据流](data-flow.md)
- [测试](../development/testing.md)：浏览器端到端的夹具与 CI 任务
