/**
 * 全量 hash 路由访问 —— 每个页面都必须能渲染出自身的区块标题。
 *
 * 前置条件：守护进程已在运行（见 scripts/e2e-daemon.sh start）。
 *
 * 覆盖范围（与 App.tsx 的路由表逐条对应）：
 *   - 每条页面路由（`support.ts` 的 `ROUTE_CASES`，清单与该文件同源）
 *   - 根 hash（`#/`）的重定向到 /dashboard
 *   - 未知路径命中的 `*` 兜底页
 *   - 服务端 `/` → `/dashboard` 的 HTTP 重定向（并保留 query）
 *
 * 为什么同时断言「顶栏标题」与「区块标题」：两者来源不同（`AppShell::PAGE_TITLES`
 * 与各视图的 `PageHeader`），任一侧写错都会让用户看到错位的上下文；
 * 未知路径则要求**不静默重定向**（`RouteNotFound` 明确提示「页面不存在」）。
 *
 * 控制台洁净度由 support.ts 的 `app` 夹具统一断言（无 console.error / console.warn）。
 */

import { expect, ROUTE_CASES, NOT_FOUND_HASH, NOT_FOUND_HEADING, expectHeading, gotoHash, openRoute, test } from './support'

/** hash 路由 → 顶栏标题（AppShell::PAGE_TITLES，去除尾部斜杠后精确匹配） */
const TOPBAR_TITLES: Record<string, string> = {
  '/dashboard': '仪表盘',
  '/bans': '封禁管理',
  '/whitelist': '白名单',
  '/ddos': 'DDoS 监控',
  '/more': '更多',
  '/jails': 'Jail 管理',
  '/logs': '日志',
  '/settings': '设置',
}

test.describe('全量 hash 路由', () => {
  // 逐条参数化：失败时报告直接指名是哪个路由，不必翻日志定位
  for (const route of ROUTE_CASES) {
    test(`${route.hash} 渲染「${route.heading}」`, async ({ app }) => {
      await openRoute(app, route.hash)

      await expectHeading(app, route.heading)
      await expect(app.locator('h1.fw-topbar-title')).toHaveText(TOPBAR_TITLES[route.hash])
    })
  }

  test('根 hash 重定向到 /dashboard', async ({ app }) => {
    await openRoute(app, '/')

    // index 路由是 <Navigate to="/dashboard" replace />，地址栏应被改写
    await expect(app).toHaveURL(/#\/dashboard$/)
    await expectHeading(app, '总览')
  })

  test('未知路径落到兜底页而非静默重定向', async ({ app }) => {
    await openRoute(app, NOT_FOUND_HASH)

    // 兜底页用 EmptyState 渲染标题（普通 div，没有 heading 角色），
    // 与各视图的 PageHeader（h2）不同，故这里按文本断言而非 expectHeading。
    await expect(app.getByText(NOT_FOUND_HEADING, { exact: true })).toBeVisible()
    // 兜底页仍在外壳内：底部导航可用，用户能自行走回正常页面
    await expect(app.locator('.fw-tabbar')).toBeVisible()
    // 明确不重定向：地址栏保留用户输入的路径（便于发现失效链接）
    await expect(app).toHaveURL(new RegExp(`#${NOT_FOUND_HASH}$`))
  })

  test('同一会话内连续切换路由不重建外壳', async ({ app }) => {
    // 先建立会话（URL 令牌会被清除并落进 sessionStorage）
    await openRoute(app, '/dashboard')
    await expect(app).not.toHaveURL(/access_token/)

    // 之后逐页切换：令牌改由 sessionStorage 提供，任一页 401 都会在界面上表现为
    // 弹回登录页，故这里同时锁住「刷新/续访后令牌仍然有效」
    for (const route of ROUTE_CASES.slice(1)) {
      await gotoHash(app, route.hash)
      await expectHeading(app, route.heading)
    }
  })
})

test.describe('服务端页面路由', () => {
  test('/ -> /dashboard 重定向保留 query', async ({ request }) => {
    // 服务端用 axum 的 Redirect::to，其状态码固定为 303 See Other
    // （axum 未公开自定义状态码的构造器；303 对纯 GET 重定向与 302 行为一致）。
    // 不带 query：303 到干净的 /dashboard
    const plain = await request.get('/', { maxRedirects: 0 })
    expect(plain.status()).toBe(303)
    expect(plain.headers()['location']).toBe('/dashboard')

    // 带 query：必须原样带到目标地址，否则 ?access_token= 直达会在进入应用前丢掉
    const withQuery = await request.get('/?access_token=abc', { maxRedirects: 0 })
    expect(withQuery.status()).toBe(303)
    expect(withQuery.headers()['location']).toBe('/dashboard?access_token=abc')
  })

  test('每个页面路径都返回 SPA 外壳', async ({ request }) => {
    // 服务端只认固定的页面路径（handler.rs），全部返回同一份不含数据的静态壳；
    // hash 路由因此刷新与直达都安全（history 路由会 404）。
    for (const route of ROUTE_CASES) {
      const response = await request.get(route.hash)
      expect(response.status(), `${route.hash} 应返回 200`).toBe(200)
      const body = await response.text()
      expect(body, `${route.hash} 应返回 SPA 外壳`).toContain('id="root"')
    }
  })
})
