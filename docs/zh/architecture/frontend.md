# Web 前端

面向运维与二次开发：界面由哪些页面构成、数据从哪里来、凭据放在哪里、
哪些能力受浏览器约束。

服务侧的路由分层、SSE 约束、信封与认证集中在
[用户态守护进程](daemon.md)，本文不复制那边的结论。

## 口径

页面清单、事件名、连接上限这类会随代码变动的事实，本文一律不写数值，只给出处：

| 事实 | 权威出处 |
|------|---------|
| 服务侧契约 | `contract/http.fwidl`，核对看 `contract/verify_http.py` 输出 |
| 前端路由表 | `frontend/src/App.tsx` 的 `createHashRouter` |
| 服务侧固定页面路径 | `contract/http.fwidl` 中 handler 为 `spaShell` 的条目 |
| 数据面与凭据行为 | `frontend/src/api/` 与 `frontend/src/hooks/` |

## 技术栈

| 项 | 内容 | 出处 |
|----|------|------|
| 框架 | React 19 + TypeScript | `frontend/package.json` |
| 组件库 | antd-mobile 5 | 同上 |
| 路由 | `react-router-dom` 的 `createHashRouter` | `frontend/src/App.tsx` |
| 3D 地球 | three | `frontend/package.json`，`src/views/Globe.tsx` |
| 图表 | 手写 SVG，无图表库 | `frontend/src/charts/*.tsx`；`package.json` 无图表依赖 |
| 构建 | Vite + `@vitejs/plugin-react` | `frontend/vite.config.ts` |
| 类型检查 | `tsc --noEmit` | `frontend/package.json` 的 `typecheck` 脚本 |
| 入口 | `frontend/index.html` + `frontend/src/main.tsx` | `index.html` 的 `<script type="module" src="/src/main.tsx">` |

依赖锁在 `frontend/package-lock.json`。CI 用 `npm ci`。

### 构建落点

`frontend/vite.config.ts` 的 `build.outDir` 直接指向
`src/daemon/web_ui/static/`，由 `src/daemon/web_ui/static/assets.go` 的
`//go:embed *` 携带进守护进程二进制。产物文件名固定：

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

### `emptyOutDir: false` 的原因

输出目录 `src/daemon/web_ui/static/` 里住着一个已入库的文件
`assets.go`，它是 `//go:embed` 的持有文件。Vite 清空输出目录会连它一起删掉，
随后 `go build` 以「包内无 .go 文件」失败。

陈旧面板文件的清理由根 `Makefile` 的 `$(WEBUI_STATIC_DIR)` 目标完成，
那条命令保留了 `assets.go`：

```
find $(WEBUI_STATIC_DIR) -mindepth 1 ! -name assets.go -delete
```

> **改前端必须重新构建守护进程才可见**：产物落盘后要再跑 `make daemon`
> 才会重编二进制。只改前端不重编，守护进程提供的仍是旧包。
> 详见 [构建](../development/building.md)。

## 页面与路由

### 为什么必须是 hash 路由

守护进程只对一组**固定的**页面路径返回 HTML 外壳，没有 catch-all。
用 history 路由时，用户在 `/bans` 按刷新会直接吃到服务侧 404。
hash 路由下地址是 `#/bans`，浏览器只请求 `/`，刷新与分享直达都安全。
代价是地址里带 `#`。

### 路由表

`frontend/src/App.tsx` 的 `createHashRouter`，全部挂在 `AppShell` 下：

| 路径 | 视图 | 层级 |
|------|------|------|
| `/`（index） | 重定向到 `/dashboard` | — |
| `/dashboard` | `Dashboard` | 一级 |
| `/bans` | `Bans` | 一级 |
| `/whitelist` | `Whitelist` | 一级 |
| `/ddos` | `Ddos` | 一级 |
| `/more` | `More` | 一级 |
| `/jails` | `Jails` | 二级 |
| `/globe` | `Globe` | 二级 |
| `/logs` | `Logs` | 二级 |
| `/settings` | `Settings` | 二级 |
| `*` | `RouteNotFound` | 兜底 |

三层结构的定义位置：

| 层 | 出处 |
|----|------|
| 一级页（底部 TabBar） | `components/AppShell.tsx` 的 `TABS` |
| 二级页（收纳在「更多」下） | 同文件的 `MORE_CHILD_PATHS` 与 `views/More.tsx` 的 `ENTRIES` |
| 兜底页 | `App.tsx` 的 `RouteNotFound` |

命中二级页时底部仍高亮「更多」，用户不丢位置感。
`PAGE_TITLES` 提供顶栏标题，未知路径回退到应用名。
兜底页**不静默重定向**，错误链接能被发现而不是被掩盖。

`views/More.tsx` 不发请求、不写数据，只做页内跳转。

## Provider 组合与认证闸门

`frontend/src/main.tsx` 的 Provider 顺序固定，注释也写明不要调整：

```
ErrorBoundary → ThemeProvider → ToastProvider → AuthProvider → App
```

| 顺序约束 | 原因 |
|---------|------|
| Theme 在很外层 | 主题令牌要覆盖 Toast / Popup 这类 portal 内容 |
| Toast 在 Auth 外 | 登录失败提示才有地方出 |
| ErrorBoundary 最外 | Provider 自身抛错时也能看到信息，而不是白屏 |

`SseProvider` **不在** `main.tsx`，在 `App.tsx` 的 `AuthGate` 内部。
未认证时不挂载，就不会建立无令牌的 `EventSource`：那种连接会持续 401，
并喂大服务侧的暴力破解计数。它仍包在 `RouterProvider` 之外，
所以路由切换不重建连接。

antd-mobile 的 `Toast` / `Dialog` 用命令式渲染，`main.tsx` 在模块顶层、
Provider 挂载之前把它们切到 `react-dom/client` 的 `createRoot`。
这一步必须早于任何 `Toast` / `Dialog` 调用。

## 数据面：首帧 REST + SSE 增量

| 通道 | 承担 | 入口 |
|------|------|------|
| REST `/api/v1/*` | 首帧取数、翻页、**全部写操作** | `api/client.ts` + `hooks/useAsync.ts` |
| SSE `/api/v1/events` | 实时增量（统计、封禁、jail、速率、白名单） | `hooks/useSse.ts` |

### REST 侧

`api/client.ts` 收敛三件事：附加凭据、解包信封（HTTP 2xx **且** `code === 0`
才算业务成功）、把失败统一抛成 `ApiError`。网络层失败时 `status` 为 `0`，
调用方据此区分「服务侧明确拒绝」与「根本连不上」。

视图侧统一用 `hooks/useAsync.ts`，它保证三点：

- 卸载或依赖变化后不再 `setState`；
- 用请求序号丢弃过期响应，避免竞态覆盖；
- 错误转成可展示文案，不吞掉。

路径常量与类型来自契约生成物 `api/endpoints.ts` 与 `api/types.ts`。

### SSE 侧

`SseProvider` 全应用只挂一个，且在路由之外：hash 路由切换不重建连接。

| 策略 | 做法 | 出处 |
|------|------|------|
| 单例连接 | 只建一条 `EventSource` | `hooks/useSse.ts` |
| 受控重连 | 收到 `error` 时主动 `close`，由本模块按指数退避（有上限）调度下一次 | 同上 |
| 超限即停 | 重连前先探测服务侧上限，已达则置 `connection_limit` 并**停止**重连 | 同上 |
| 防重入 | 每个连接周期一个 error 标志；用「当前连接对象 === 触发者」丢弃旧连接的迟到回调 | 同上 |
| 速率趋势 | `rates` 事件在客户端聚合成环形缓冲（有长度上限） | `state/realtime.ts` 的 `RATE_HISTORY_LIMIT` |
| 单帧容错 | 解析失败只 `console.debug` 丢弃该帧，不影响整条连接 | 同上 |

继续重试只会持续打满服务侧日志且永远不会成功，
所以超限改由界面提示用户关闭其它控制台标签页后刷新。

上限数值与事件集见 `contract/http.fwidl`，本文不复制。

### 连接状态与横幅

`components/AppShell.tsx` 把连接状态渲染成顶栏状态灯，颜色 + 文案双通道，
色盲用户也可分辨。横幅按影响程度从高到低：

```
真离线 > 服务侧连接超限 > 断开重连 > 重连中
```

离线判定只监听浏览器的 `online` / `offline` 事件，不做轮询。

## 认证与令牌

凭据的**唯一来源**是 `api/auth.ts`。REST 与 SSE 都从它取，不允许各自维护一份。

| 载体 | 用于 | 原因 |
|------|------|------|
| `Authorization: Basic <base64(user:pass)>` | REST 读写 | 服务侧中间件的首选来源 |
| `?access_token=<base64>` | `EventSource` | 浏览器不给 `EventSource` 设自定义请求头 |
| `sessionStorage`，键 `firewall.access_token` | 刷新后沿用 | 同源隔离，关闭标签页即失效 |

### 令牌来源优先级

顺序是「URL query → `sessionStorage`」（`api/auth.ts` 的 `initAccessToken`）。
两种 query 位置都支持：

```
http://<host>/?access_token=<令牌>#/dashboard
http://<host>/#/dashboard?access_token=<令牌>
```

第二种是 hash 路由下更常见的形态。读取后**立即从地址栏移除**并写入
`sessionStorage`，避免令牌出现在截图、历史记录或分享出去的地址里。
`main.tsx` 在任何请求发生前完成这一步。

### 写操作与实时推送各走哪条

`withAccessToken()` 拼 `access_token` 时做 `encodeURIComponent`，
服务侧对应做百分号解码（`internal/http/auth.go`）。
这一对**必须成对修改**：只改一边的表现是 SSE 永久 401。

### 为什么不依赖浏览器原生认证弹窗

SPA 外壳是公开路由，返回不含数据的静态壳，顶层文档**不会**返回 401，
所以浏览器永远不会弹凭据对话框、也就不会缓存凭据。
页面自身发出的请求会全部 401，每个无凭据请求又累加服务侧的暴力破解计数，
最终把正确凭据一起锁死，表现为「越刷新越不可用」。

凭据因此由前端显式携带。服务侧也刻意不发 `WWW-Authenticate`：
那个头会让浏览器弹原生对话框并让 `fetch` 挂起。
代码里的这条断言见 `internal/http/routes_contract_test.go`。

### 失效与登出

`client.ts` 收到 401 时清除本地令牌，`hooks/useAuth.tsx` 经
`api/auth.ts` 的 `onAuthChange` 广播，界面回到登录页（`views/Login.tsx`）。

**不做自动重登**：服务侧锁定期间连正确凭据也返回 401，
自动重试只会延长锁定，因此交由用户重新输入触发一次新凭据。

## PWA

| 项 | 内容 | 出处 |
|----|------|------|
| 清单 | `frontend/public/manifest.webmanifest`，`index.html` 以 `/static/manifest.webmanifest` 引用 | `frontend/index.html` |
| Service Worker | 手写 `frontend/public/sw.js` | 同上 |
| 注册路径 | 根作用域 `/sw.js`，不是 `/static/sw.js` | `internal/http/static.go` |
| 作用域抬升 | 响应带 `Service-Worker-Allowed: /` | 同文件 |
| `/api/*` | 不缓存，保证封禁列表与统计新鲜 | `frontend/public/sw.js` |

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
| 1 | `frontend/src/App.tsx` | 路由表加一条 |
| 2 | `frontend/src/components/AppShell.tsx` | `PAGE_TITLES` 加标题；一级页还要进 `TABS` 或 `MORE_CHILD_PATHS` |
| 3 | `contract/http.fwidl` | 加 `spaShell` 那条页面路由，再 `python3 contract/gen.py` 重新生成 |
| 4 | 重新构建 | `make frontend` + `make daemon`，产物经 `//go:embed` 进二进制 |

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
