# Web 前端

面向运维与二次开发：说清界面由哪些页面构成、数据从哪里来、凭据放在哪里、哪些能力受浏览器
约束。**服务端**契约（路由分层、SSE 约束、信封与认证）集中在
[用户态守护进程](daemon.md)，本文只从消费方角度说明怎么用，不复制那边的结论。

## 本文档的口径

页面清单、事件名、连接上限这类会随代码变动的事实，本文一律不写数值，只给权威来源：

- **服务端契约**以 `contract/http.fwidl` 为准，核对以 `contract/verify_http.py` 的输出为准；
- **前端路由表**读 `frontend/src/App.tsx` 的 `createHashRouter`；
- **返回 HTML 的服务端路径清单**读 `src/daemon/http_exporter/handler.rs`；
- 数据面与凭据行为以 `frontend/src/api/` 与 `frontend/src/hooks/` 的源码为准。

## 技术栈与构建落点

| 项 | 内容 |
|----|------|
| 框架 | React 19 + TypeScript |
| 组件库 | antd-mobile v5 |
| 路由 | react-router 的 `createHashRouter`（**hash 路由**，理由见下） |
| 构建 | vite，产物直接输出到 `src/daemon/web_ui/static/`，由 `rust-embed` 编进守护进程二进制 |

`frontend/vite.config.ts` 固定了三项与守护进程对齐的约束：`base = "/static/"`（资源经
`GET /static/*path` 提供）、资源平铺且文件名固定（`app.js` / `style.css`，便于 rust-embed
按名查找）、单 CSS 文件。

> **前端改动必须重新构建守护进程才可见**：`make daemon` 依赖前端构建，把 vite 产物写进
> rust-embed 目录。只改前端而不重新编译，守护进程提供的仍是旧包。

## 页面与路由映射

### 为什么必须是 hash 路由

守护进程只对一组**固定的**页面路径返回 HTML 外壳，没有 catch-all。若用 history 路由，
用户在 `/bans` 上按刷新会直接吃到服务端 404。hash 路由下地址是 `#/bans`，浏览器永远只请求
`/`，因此**刷新与分享直达都安全**，代价只是地址里带 `#`。

### 三层结构

| 层 | 说明 | 权威位置 |
|----|------|----------|
| 一级页 | 底部 TabBar 的入口 | `AppShell.tsx` 的 `TABS` |
| 二级页 | 收纳在「更多」页里的页面 | `AppShell.tsx` 的 `MORE_CHILD_PATHS` 与 `views/More.tsx` 的 `ENTRIES` |
| 兜底页 | 未匹配路径时的提示页 | `App.tsx` 的 `RouteNotFound` |

命中二级页时底部仍高亮「更多」，用户不会丢失位置感；`AppShell.tsx` 的 `PAGE_TITLES` 提供
顶栏标题，未知路径回退到应用名。兜底页**不静默重定向**，这样错误链接能被发现而不是被掩盖。

`views/More.tsx` **不发起任何请求、不产生写操作**，只做页内跳转；真实数据与写操作都在被跳转
到的二级页里完成。

## Provider 组合与认证边界

`main.tsx` 的 Provider 顺序是固定的：`ErrorBoundary → Theme → Toast → Auth → App`。
Theme 在最外层，主题令牌才能覆盖 Toast / Popup 这类 portal 内容；Toast 在 Auth 之外，
登录失败提示才有地方出。

**`SseProvider` 刻意不在这里**，而在 `App.tsx` 的 `AuthGate` 内部：未认证时不挂载，就不会
建立无令牌的 `EventSource`——那种连接会持续 401 并喂大服务端的暴力破解计数。它仍包在
`RouterProvider` 之外，因此路由切换不会重建连接。

## 数据面：首帧 REST + SSE 增量

两条通道分工明确，不要混用：

| 通道 | 承担 | 入口 |
|------|------|------|
| REST（`/api/v1/*`） | 首帧取数、翻页，以及**全部写操作** | `api/client.ts` + `hooks/useAsync.ts` |
| SSE（`/api/v1/events`） | 实时增量（统计、封禁、jail、速率、白名单） | `hooks/useSse.ts` |

### REST 侧

`api/client.ts` 把三件事收敛到一处：附加凭据、解包信封（HTTP 2xx **且** `code === 0` 才算
业务成功）、把失败统一抛成 `ApiError`——网络层失败时 `status` 为 `0`，调用方据此区分
「服务端明确拒绝」与「根本连不上」。

视图侧统一用 `useAsync`，它保证三件事：卸载或依赖变化后不再 `setState`、用请求序号丢弃过期
响应（避免竞态覆盖）、错误转成可展示文案且绝不吞掉。信封形状与业务码语义见
[用户态守护进程](daemon.md) 的「信封与认证」，此处不复述。

### SSE 侧

`SseProvider` 全应用只挂一个，且**在路由之外**，因此 hash 路由切换不会重建连接（否则每次
切页都要重新握手、错过增量推送）。连接与重试策略：

- **单例连接**：只建一条 `EventSource`；订阅了哪些事件名以 `hooks/useSse.ts` 与
  `contract/http.fwidl` 里该 route 声明的字段为准；
- **受控重连**：`EventSource` 自带的重连节奏不受控，因此收到 `error` 时主动 `close`，
  由本模块按**指数退避**（有上限）调度下一次连接；
- **超限即停**：重连时先探测服务端连接上限，已达上限则置 `connection_limit` 并
  **停止**重连——继续重试只会持续打满服务端日志且永远不会成功，改由界面提示用户关闭其它
  控制台标签页后刷新；
- **防重入**：每个连接周期一个 error 标志（`onerror` 只处理一次），并用「当前连接对象 ===
  触发者」丢弃旧连接的迟到回调；
- **速率趋势**：`rates` 事件在客户端聚合成环形缓冲（有长度上限）供趋势图使用；
- 单帧解析失败只 `console.debug` 丢弃该帧，不影响整条连接，也不污染面向用户的控制台。

服务端侧的连接上限、事件集与 keepalive 见 [用户态守护进程](daemon.md) 的「SSE 约束（契约）」，
**上限数值一律不在本文复制**。

### 连接状态与横幅

`AppShell.tsx` 把连接状态渲染成顶栏状态灯（颜色 + 文案双通道，色盲用户也可分辨），并按影响
程度从高到低排出一条横幅：真离线 > 服务端连接超限 > 断开重连 > 重连中。离线判定只监听浏览器
的 `online` / `offline` 事件，不做轮询。

## 认证与令牌载体

凭据的**唯一来源**是 `api/auth.ts`，REST 与 SSE 都从它取，不允许各自维护一份。

| 载体 | 用于 | 原因 |
|------|------|------|
| `Authorization: Basic <base64(user:pass)>` | REST 读写 | 服务端中间件的首选来源 |
| `?access_token=<base64>` | `EventSource` | 浏览器不允许给 `EventSource` 设自定义请求头 |
| `sessionStorage` | 刷新后沿用 | 同源隔离，关闭标签页即失效 |

令牌来源优先级是「URL query → `sessionStorage`」。URL 便于书签直达与外部跳转，读取后
**立即用 `history.replaceState` 从地址栏移除**，避免它出现在截图、历史记录或分享出去的地址里。

`withAccessToken()` 拼接时做 `encodeURIComponent`，服务端对应做百分号解码——这一对必须
**成对修改**：只改一边的表现是 SSE 永久 401（两个方向的细节都在 `api/auth.ts` 与服务端
`http_exporter/auth.rs` 的注释里）。

### 为什么不依赖浏览器原生认证弹窗

SPA 外壳是公开路由、返回不含数据的静态壳，顶层文档**不会**返回 401，因此浏览器永远不会弹出
凭据对话框、也就不会缓存凭据；而页面自身发出的请求会全部 401，每个无凭据请求又在累加服务端
的暴力破解计数，最终把正确凭据一起锁死——表现为「越刷新越不可用」。所以凭据由前端显式携带。
服务端也刻意不发 `WWW-Authenticate`（理由见 [用户态守护进程](daemon.md) 的「信封与认证」）。

### 失效与登出

`client.ts` 收到 401 时清除本地令牌，`useAuth` 通过 `auth.ts` 的 `onAuthChange` 广播，界面
据此回到登录页。**不做自动重登**：服务端锁定期间连正确凭据也返回 401，自动重试只会延长锁定，
因此交由用户重新输入触发一次新凭据。

## PWA 边界

- **作用域**：Service Worker 注册在根路径 `/sw.js`，而不是 `/static/sw.js`——脚本作用域由
  脚本 URL 决定，`/static/sw.js` 只能接管 `/static/` 下的资源，无法接管页面导航。守护进程
  为此单独提供 `/sw.js` 路由（带 `Service-Worker-Allowed: /`），vite 只负责把它输出到
  `static/` 下。
- **安全上下文**：浏览器只在 HTTPS 或 localhost 下暴露 `serviceWorker` API。经
  `http://<局域网IP>:<port>` 访问时该 API 不存在，**PWA 安装同样被拒**。这是浏览器的硬性
  约束，本应用无法绕过；`main.tsx` 检测不到就静默跳过，不影响界面功能。
  **这是已知限制，不是缺陷**，不要当作 bug「修掉」。

### 验收记录：安全上下文边界（2026-09-21）

两侧对照的机械证据在 `tests/e2e/pwa-context.spec.ts`，复现方式：

```bash
# 夹具默认绑 0.0.0.0，因此局域网地址可直接访问，无需额外配置
sudo bash scripts/e2e-daemon.sh start
eval "$(bash scripts/e2e-daemon.sh env)"
# 不设置 E2E_LAN_ORIGIN 时只跑安全上下文一侧，局域网一侧显式跳过（CI 即如此）
E2E_LAN_ORIGIN=http://<局域网IP>:<port> npm run test:e2e
sudo bash scripts/e2e-daemon.sh stop
```

观察结果（本机 2026-09-21，Chromium）：

| 上下文 | `'serviceWorker' in navigator` | 注册 / 安装 | 页面功能 | 控制台 |
|--------|-------------------------------|-------------|----------|--------|
| `http://127.0.0.1:9119`（安全） | `true` | `/sw.js` 注册成功，manifest 可取 | 正常 | 洁净 |
| `http://192.168.8.5:9119`（非安全） | `false`（`navigator.serviceWorker` 为 `undefined`） | 不可能，PWA 安装被拒 | 正常（仪表盘 / 封禁页均可渲染） | 洁净 |

结论：该限制只剥夺 PWA 能力，不影响应用本体——数据面、路由与写操作全部照常，非安全上下文下
控制台同样洁净（`main.tsx` 静默跳过而不打警告）。**不把限制当缺陷修**，故本记录以「期望行为」
落成用例固化，防止后人塞 polyfill 或改注册路径。

> 控制台洁净度门槛的判定基准是**当前 baseURL 的源**而非固定常量：同一套用例会在多个源上跑
> （如上表的局域网地址），写死一个源会让另一侧的判定整体失效（`tests/e2e/support.ts`）。

## 二次开发：改动面清单

hash 路由只解决客户端；服务端还认一份固定路径清单，漏一处就会 404，或以 `default-src 'none'`
加载外壳（页面白屏、样式全丢）。**新增一个页面**要同时动四处：

1. `frontend/src/App.tsx` —— 路由表加一条；
2. `frontend/src/components/AppShell.tsx` —— `PAGE_TITLES` 加标题；一级页还要加进 `TABS`
   或 `MORE_CHILD_PATHS`；
3. `src/daemon/http_exporter/handler.rs` —— 注册返回外壳的路由，并把它加进
   `security_headers_middleware` 的 `is_webui` 判定；
4. `contract/http.fwidl` —— 改契约，再 `python3 contract/gen.py contract/http.fwidl` 重新生成
   工件，最后 `python3 contract/verify_http.py` 核对。

**新增或修改接口**的顺序相反：先改契约再改代码。前端的类型与路径分别来自契约生成的
`frontend/src/api/types.ts` 与 `frontend/src/api/endpoints.ts`。

## 相关文档

- [用户态守护进程](daemon.md) —— 路由分层、SSE 约束、信封与认证
- [数据流](data-flow.md)
- [前端重写设计](../development/frontend-rewrite-design.md) —— 批次划分与验收门槛
- [测试](../development/testing.md) —— 浏览器端到端测试的夹具与 CI 作业
