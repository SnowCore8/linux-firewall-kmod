/**
 * E2E 公共支撑：鉴权、路由断言锚点、控制台洁净度守卫
 *
 * 为什么需要鉴权：SPA 外壳（`/`、`/dashboard`…）是**公开**路由，返回的是不含
 * 运行时数据的静态壳，因此顶层文档不会返回 401，浏览器也就不会弹出、不会缓存
 * 原生 Basic 认证凭据。数据一律取自受保护的 `/api/v1/*`，未带令牌只会拿到 401。
 * 更麻烦的是每个无凭据请求都会累加服务端的暴力破解计数（10 次后半分钟内连正确
 * 凭据一起拒绝），所以用例**绝不能**先裸访问再补凭据。
 *
 * 采用的注入方式：`?access_token=<base64(user:pass)>`。这是产品本身支持的能力
 * （见 `frontend/src/api/auth.ts::initAccessToken`，`http_exporter/handler.rs::handle_redirect`
 * 还会把 query 原样带到 `/dashboard`），装载后从地址栏清除并写入 sessionStorage，
 * 后续 fetch 与 EventSource 都自动携带。相当于顺便验证了「书签直达」这条路径，
 * 而不是绕过产品逻辑去塞 storage。
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
 * 先按 UTF-8 编码再 base64，与前端 `encodeCredentials` 保持一致，
 * 避免用户名/密码含非 Latin-1 字符时 `btoa` 抛错。
 */
export function encodeCredentials(user: string, password: string): string {
  return Buffer.from(`${user}:${password}`, 'utf8').toString('base64')
}

/** 已编码的访问令牌 */
export const ACCESS_TOKEN = encodeCredentials(CREDENTIALS.user, CREDENTIALS.password)

/**
 * 路由断言锚点。
 *
 * 每个页面的区块标题由 `PageHeader` 渲染成 `h2`，且**在加载/错误/空数据各分支
 * 都存在**（顶栏的 `h1.fw-topbar-title` 同样稳定，但顶栏标题与页面标题并非一一
 * 对应，例如 `/settings` 的顶栏是「设置」而区块标题是「Web UI 配置」），
 * 因此用 `h2` 文本判定「这个页面真的渲染了」。
 *
 * 未知路径命中路由表的 `*` 兜底（`App.tsx::RouteNotFound`），不是重定向。
 */
export interface RouteCase {
  /** hash 路由（`#` 之后的部分） */
  hash: string
  /** 该页面必须出现的区块标题（h2） */
  heading: string
}

export const ROUTE_CASES: RouteCase[] = [
  { hash: '/dashboard', heading: '总览' },
  { hash: '/bans', heading: '封禁管理' },
  { hash: '/whitelist', heading: '白名单' },
  { hash: '/ddos', heading: 'DDoS 监控' },
  { hash: '/more', heading: '更多' },
  { hash: '/jails', heading: 'Jail 列表' },
  { hash: '/logs', heading: '实时日志' },
  { hash: '/settings', heading: 'Web UI 配置' },
]

/** 兜底路由：不存在的路径应给出「页面不存在」而不是静默重定向 */
export const NOT_FOUND_HASH = '/no-such-page'
export const NOT_FOUND_HEADING = '页面不存在'

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
  /net::ERR_/, // 网络层失败详情行
  /Download the React DevTools/, // React 开发构建的提示（生产构建不会出现）
]

/** 是否为可忽略的浏览器噪音 */
function isIgnorable(issue: ConsoleIssue): boolean {
  if (issue.kind === 'pageerror') return false // 未捕获异常一律视为缺陷
  // 跨源资源（如 Google Fonts）不可达只影响字体外观，不是应用缺陷
  if (issue.url !== '' && !issue.url.startsWith(BASE_URL)) return true
  if (issue.url === '' && BROWSER_NOISE.some((re) => re.test(issue.text))) return true
  return false
}

/** 附加到 context 的鉴权初始化：在页面脚本执行前预置令牌，覆盖「刷新后沿用」路径 */
async function seedToken(page: Page, token: string): Promise<void> {
  await page.addInitScript((value: string) => {
    try {
      window.sessionStorage.setItem('firewall.access_token', value)
    } catch {
      // about:blank 等无源页面会抛 SecurityError：忽略，导航后再由 URL query 注入
    }
  }, token)
}

/**
 * 打开某个 hash 路由并等待应用外壳渲染完成。
 *
 * 首次导航把令牌放进 URL query（验证书签直达能力，`initAccessToken` 会把它从
 * 地址栏清掉并落进 sessionStorage）；此后同源导航直接沿用 sessionStorage。
 */
export async function openRoute(page: Page, hash: string, token = ACCESS_TOKEN): Promise<void> {
  const separator = hash.startsWith('/') ? hash : `/${hash}`
  await page.goto(`/dashboard?access_token=${encodeURIComponent(token)}#${separator}`)
  // 外壳就绪的判据：顶栏标题出现，说明 AuthGate 已放行、RouterProvider 已渲染
  await expect(page.locator('h1.fw-topbar-title')).toBeVisible()
}

/**
 * 打开某个 hash 路由，复用已建立的会话（不重复注入 URL 令牌）。
 * 用于同一用例内连续访问多个路由。
 */
export async function gotoHash(page: Page, hash: string): Promise<void> {
  const separator = hash.startsWith('/') ? hash : `/${hash}`
  await page.goto(`/dashboard#${separator}`)
}

/** 断言当前页面的区块标题为期望值 */
export async function expectHeading(page: Page, heading: string): Promise<void> {
  await expect(page.getByRole('heading', { level: 2, name: heading, exact: true })).toBeVisible()
}

/**
 * 测试夹具：`issues` 收集控制台问题，`app` 在用例结束后断言「一条都没有」。
 *
 * 为什么在夹具里断言而不是每个用例各写一遍：这是本套件的**统一门槛**——
 * 任何 console.error / console.warn / 未捕获异常都算失败。写在夹具里，
 * 新加的用例默认受保护，不会因为忘记断言而漏检。
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

  app: async ({ page, issues }, use) => {
    await seedToken(page, ACCESS_TOKEN)
    await use(page)

    const offending = issues.filter((issue) => !isIgnorable(issue))
    expect(
      offending.map((i) => `[${i.kind}/${i.type}] ${i.text}${i.url ? ` @ ${i.url}` : ''}`),
      '用例期间出现了控制台错误/警告或未捕获异常',
    ).toEqual([])
  },
})

export { expect }
