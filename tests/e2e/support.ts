/**
 * E2E 公共支撑：鉴权、路由断言锚点、控制台洁净度守卫
 *
 * 为什么需要鉴权：SPA 外壳（`/`、`/dashboard`…）是**公开**路由，返回的是不含
 * 运行时数据的静态壳，因此顶层文档不会返回 401，浏览器也就不会弹出、不会缓存
 * 原生 Basic 认证凭据。数据一律取自受保护的 `/api/v2/*`，未带令牌只会拿到 401。
 * 更麻烦的是每个无凭据请求都会累加服务端的暴力破解计数（10 次后半分钟内连正确
 * 凭据一起拒绝），所以用例**绝不能**先裸访问再补凭据。
 *
 * 采用的注入方式：在页面脚本执行前用 `addInitScript` 把令牌写进
 * `sessionStorage['firewall.access_token']`。AuthProvider 挂载时同步读
 * `hasAccessToken()`（见 frontend/src/providers/AuthProvider.tsx 的 useState 初值），
 * 读到即判为已认证、放行受保护路由，后续 fetch 与 EventSource 都自动携带该令牌。
 *
 * 为什么不再走 `?access_token=` 直达：旧前端有 `auth.ts::initAccessToken` 在启动时把
 * URL 里的令牌搬进 sessionStorage，本次全新重写**没有保留**这条引导路径（已在
 * docs/zh/architecture/frontend.md 记为行为回退）。因此夹具改为直接预置 sessionStorage，
 * 而不是依赖一个产品已不再提供的能力去「顺便验证书签直达」。
 */

import { expect, test as base } from '@playwright/test'
import type { Page } from '@playwright/test'

/** 目标地址：与 playwright.config.ts 的 baseURL 同源 */
export const BASE_URL = process.env.BASE_URL ?? 'http://127.0.0.1:9119'

/** 守护进程 Web UI 凭据；默认值与 scripts/e2e-daemon.sh 生成的临时配置一致 */
export const CREDENTIALS = {
  user: process.env.E2E_METRICS_USER ?? 'e2e',
  password: process.env.E2E_METRICS_PASSWORD ?? 'e2e-password',
}

/**
 * 把凭据编码成 Basic 令牌。
 * 先按 UTF-8 编码再 base64，与前端 `api/auth.ts::encodeBasic` 保持一致，
 * 避免用户名/密码含非 Latin-1 字符时 `btoa` 抛错。
 */
export function encodeCredentials(user: string, password: string): string {
  return Buffer.from(`${user}:${password}`, 'utf8').toString('base64')
}

/** 已编码的访问令牌 */
export const ACCESS_TOKEN = encodeCredentials(CREDENTIALS.user, CREDENTIALS.password)

/** 令牌在 sessionStorage 里的键（与 api/auth.ts::ACCESS_TOKEN_KEY 一致） */
export const ACCESS_TOKEN_KEY = 'firewall.access_token'

/**
 * 客户端路由断言锚点。
 *
 * 每个页面的区块标题由 `PageHeader` 渲染成 `h4`（`Typography.Title level={4}`），
 * 且**在加载/空/错误/未启用各分支都存在**——PageHeader 恒在视图顶部渲染，先于任何
 * 条件分支（如 Risk/ThreatFeeds 的 503→disabled 空态），因此用 `h4` 文本即可判定
 * 「这个页面真的渲染了」，与后端 flag 是否开启无关。
 *
 * 标题取自各视图 PageHeader 的 `title`，**不是** nav.ts 的 label——两者对 /analysis 就
 * 不同（菜单叫「综合分析」，页面标题是「智能分析」）。
 *
 * 未知路径命中路由表的 `*`（router.tsx::NotFound），新版**软重定向**到默认页而非硬 404。
 */
export interface RouteCase {
  /** hash 路由（`#` 之后的部分） */
  hash: string
  /** 该页面必须出现的区块标题（h4） */
  heading: string
}

export const ROUTE_CASES: RouteCase[] = [
  { hash: '/dashboard', heading: '概览' },
  { hash: '/bans', heading: '封禁管理' },
  { hash: '/whitelist', heading: '白名单' },
  { hash: '/jails', heading: '越狱规则' },
  { hash: '/ddos', heading: 'DDoS 监控' },
  { hash: '/risk', heading: '风险引擎' },
  { hash: '/threat-feeds', heading: '威胁情报' },
  { hash: '/analysis', heading: '智能分析' },
  { hash: '/logs', heading: '日志' },
  { hash: '/settings', heading: '设置' },
]

/**
 * 服务端返回 SPA 外壳的页面路径（static.go 的 spaShell 注册项，逐条对应契约 RouteGet*）。
 *
 * 与 ROUTE_CASES **刻意解耦**：/risk、/threat-feeds、/analysis 是仅前端的 hash 路由，
 * 服务端没有为它们注册壳（GET /risk 落到 `/` 子树模式 → 404），只能经「已知壳路径 +
 * `#/risk`」直达（openRoute 正是这么做的）。SHELL_PATHS 因此就是服务端逐条注册的全部页面壳
 * （与 static.go 的 spaShell 注册项、契约 RouteGet* 一一对应），不多也不少。
 */
export const SHELL_PATHS: string[] = [
  '/dashboard',
  '/bans',
  '/whitelist',
  '/jails',
  '/ddos',
  '/logs',
  '/settings',
]

/** 未知路径（不在 nav.ts 的 NAV_ITEMS 里）：命中路由表 `*` → 软重定向到默认页。 */
export const NOT_FOUND_HASH = '/no-such-page'
/** 默认落地页（DEFAULT_PATH）与其区块标题：根 hash 与未知路径都重定向到这里。 */
export const DEFAULT_HASH = '/dashboard'
export const DEFAULT_HEADING = '概览'

/** 控制台问题（按来源区分，便于过滤规则只作用于浏览器自身的噪音） */
export interface ConsoleIssue {
  kind: 'console' | 'pageerror'
  /** console 事件的类型（error / warning / …）或 pageerror 的异常名 */
  type: string
  text: string
  /** 归一化后的来源（`console` 事件才有） */
  url: string
}

/**
 * 浏览器自身产生、与应用代码无关的控制台噪音。
 * 只对**没有来源 URL**的消息生效；带 URL 的同类消息仍按应用问题处理。
 */
const BROWSER_NOISE: RegExp[] = [
  /\[Violation\]/, // 长任务/强制重排等性能提示
  /net::ERR_/, // 网络层失败详情行（如不可达的 Google Fonts）
  /Download the React DevTools/, // React 开发构建的提示（生产构建不会出现）
]

/** 是否为可忽略的浏览器噪音 */
function isIgnorable(issue: ConsoleIssue, origin: string): boolean {
  if (issue.kind === 'pageerror') return false // 未捕获异常一律视为缺陷
  // 跨源资源（如 Google Fonts）不可达只影响字体外观，不是应用缺陷。
  // 判据用**当前 baseURL 的源**而不是固定常量：同一套用例会在不同源上跑
  // （如非安全上下文的验收用局域网 IP），写死一个源会让另一侧的判定整体失效。
  if (issue.url !== '' && !issue.url.startsWith(origin)) return true
  if (issue.url === '' && BROWSER_NOISE.some((re) => re.test(issue.text))) return true
  return false
}

/**
 * 附加到 context 的鉴权初始化：在页面脚本执行前把令牌预置进 sessionStorage。
 *
 * addInitScript 对每次导航、每个同源文档都在页面脚本之前运行，因此首屏 React 挂载时
 * AuthProvider 就能读到令牌。about:blank 等无源文档写 sessionStorage 会抛 SecurityError，
 * 忽略即可——真正的首次导航是同源 URL，那时写入必然成功。
 */
async function seedToken(page: Page, token: string): Promise<void> {
  await page.addInitScript(
    ([key, value]: [string, string]) => {
      try {
        window.sessionStorage.setItem(key, value)
      } catch {
        // 无源文档（about:blank）会抛 SecurityError：忽略，同源导航时会再次运行
      }
    },
    [ACCESS_TOKEN_KEY, token] as [string, string],
  )
}

/**
 * 外壳就绪锚点：顶栏「打开命令面板」按钮由 AppShell 的 Header 渲染。
 *
 * 用它判定「认证闸门已放行 + 外壳已挂载」：未认证时 RequireAuth 会重定向到 /login
 * （Login 视图没有这个按钮）；且它不随视口宽度消失（移动端也在顶栏），比旧的
 * `h1.fw-topbar-title`（全新外壳已无此元素）更稳。页面区块标题在懒加载的 Outlet 内，
 * 由各自的 expectHeading 自动重试等待，不必在这里等。
 */
export function shellReady(page: Page) {
  return page.getByRole('button', { name: '打开命令面板', exact: true })
}

/**
 * 打开某个 hash 路由并等待应用外壳渲染完成。
 *
 * HTTP 路径固定走已知壳路径 `/dashboard`（服务端为它返回 SPA 外壳），客户端路由由 `#`
 * 承载——这样连 /risk、/analysis 等「仅前端」路由也能直达，无需服务端为每条前端路由
 * 单独注册壳。令牌由 `app` 夹具的 seedToken 预置，URL 里不再出现 access_token。
 */
export async function openRoute(page: Page, hash: string): Promise<void> {
  const separator = hash.startsWith('/') ? hash : `/${hash}`
  await page.goto(`/dashboard#${separator}`)
  await expect(shellReady(page)).toBeVisible()
}

/**
 * 切换到某个 hash 路由，复用已建立的会话（同源、仅改 hash → 同文档导航，不重载外壳）。
 * 用于同一用例内连续访问多个路由。
 */
export async function gotoHash(page: Page, hash: string): Promise<void> {
  const separator = hash.startsWith('/') ? hash : `/${hash}`
  await page.goto(`/dashboard#${separator}`)
}

/** 断言当前页面的区块标题（PageHeader 的 h4）为期望值 */
export async function expectHeading(page: Page, heading: string): Promise<void> {
  await expect(page.getByRole('heading', { level: 4, name: heading, exact: true })).toBeVisible()
}

/**
 * 测试夹具：`issues` 收集控制台问题，`app` 在用例结束后断言「一条都没有」。
 *
 * 为什么在夹具里断言而不是每个用例各写一遍：这是本套件的**统一门槛**——
 * 任何 console.error / console.warn / 未捕获异常都算失败。写在夹具里，
 * 新加的用例默认受保护，不会因为忘记断言而漏检。
 *
 * 注意：`app` 与 Playwright 内建 `page` 是同一个 Page 对象（夹具 seed 令牌后原样 yield），
 * 但只有解构出 `app` 才会触发「预置令牌 + 结束时校验控制台洁净」这套逻辑；用例应统一用 `app`。
 */
export const test = base.extend<{ issues: ConsoleIssue[]; app: Page }>({
  issues: async ({ page }, use) => {
    const issues: ConsoleIssue[] = []

    page.on('console', (msg) => {
      const type = msg.type()
      if (type !== 'error' && type !== 'warning') return
      issues.push({
        kind: 'console',
        type,
        text: msg.text(),
        url: msg.location().url ?? '',
      })
    })

    // 未捕获异常（含 React 渲染期抛错）不会经过 console：单独收集，
    // 否则 ErrorBoundary 之外的错误会被静默放过。
    page.on('pageerror', (err) => {
      issues.push({ kind: 'pageerror', type: err.name, text: err.message, url: '' })
    })

    await use(issues)
  },

  app: async ({ page, issues, baseURL }, use) => {
    await seedToken(page, ACCESS_TOKEN)
    await use(page)

    const offending = issues.filter((issue) => !isIgnorable(issue, baseURL ?? BASE_URL))
    expect(
      offending.map((i) => `[${i.kind}/${i.type}] ${i.text}${i.url ? ` @ ${i.url}` : ''}`),
      '用例期间出现了控制台错误/警告或未捕获异常',
    ).toEqual([])
  },
})

export { expect }
