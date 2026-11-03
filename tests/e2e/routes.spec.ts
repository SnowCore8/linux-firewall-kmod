/**
 * 全量 hash 路由访问 —— 每个页面都必须能渲染出自身的区块标题。
 *
 * 前置条件：守护进程已在运行（见 scripts/e2e-daemon.sh start）。
 *
 * 覆盖范围（与 app/router.tsx 的路由表逐条对应）：
 *   - 每条客户端页面路由（`support.ts` 的 `ROUTE_CASES`，标题取自各视图 PageHeader）
 *   - 根 hash（`#/`）重定向到 /dashboard
 *   - 未知路径命中 `*` 的**软重定向**（NotFound → /dashboard，不做硬 404）
 *   - 服务端 `/` → `/dashboard` 的 HTTP 重定向（并保留 query）
 *   - 服务端已注册的每条页面路径都返回同一份 SPA 外壳（`SHELL_PATHS`）
 *
 * 为什么区块标题用 h4：全新外壳的页面标题由 `PageHeader`（`Typography.Title level={4}`）
 * 渲染，且恒在视图顶部、先于加载/空/错误/未启用各分支，故它出现即「这页真的渲染了」。
 * 旧外壳的顶栏标题元素（`h1.fw-topbar-title`）已不存在，不再断言。
 *
 * 客户端路由与服务端壳路径是两回事：/risk、/threat-feeds、/analysis 只有 hash 路由、
 * 服务端没有对应壳路径（GET 它们会 404），故壳路径断言只跑 `SHELL_PATHS`。
 *
 * 控制台洁净度由 support.ts 的 `app` 夹具统一断言（无 console.error / console.warn）。
 */

import {
  expect,
  ROUTE_CASES,
  SHELL_PATHS,
  NOT_FOUND_HASH,
  DEFAULT_HASH,
  DEFAULT_HEADING,
  ACCESS_TOKEN_KEY,
  expectHeading,
  gotoHash,
  openRoute,
  shellReady,
  test,
} from './support'

test.describe('全量 hash 路由', () => {
  // 逐条参数化：失败时报告直接指名是哪个路由，不必翻日志定位
  for (const route of ROUTE_CASES) {
    test(`${route.hash} 渲染「${route.heading}」`, async ({ app }) => {
      await openRoute(app, route.hash)
      await expectHeading(app, route.heading)
    })
  }

  test('根 hash 重定向到 /dashboard', async ({ app }) => {
    await openRoute(app, '/')

    // index 路由是 <Navigate to="/dashboard" replace />，地址栏应被改写
    await expect(app).toHaveURL(new RegExp(`#${DEFAULT_HASH}$`))
    await expectHeading(app, DEFAULT_HEADING)
  })

  test('未知路径软重定向到默认页而非硬 404', async ({ app }) => {
    await openRoute(app, NOT_FOUND_HASH)

    // 路由表 `*` → NotFound：非已知前缀一律 <Navigate to={DEFAULT_PATH} replace />。
    // 控制台里硬 404 意义不大，故重设计为软重定向；地址栏应被改写到 /dashboard。
    await expect(app).toHaveURL(new RegExp(`#${DEFAULT_HASH}$`))
    await expectHeading(app, DEFAULT_HEADING)
    // 外壳仍在：顶栏命令面板可用，用户能继续导航到别处
    await expect(shellReady(app)).toBeVisible()
  })

  test('同一会话内连续切换路由不重建外壳', async ({ app }) => {
    // 先建立会话：令牌由 seedToken 预置进 sessionStorage，URL 里不应残留 access_token
    await openRoute(app, '/dashboard')
    await expect(app, 'URL 不应残留 access_token').not.toHaveURL(/access_token/)
    const seeded = await app.evaluate((key) => window.sessionStorage.getItem(key), ACCESS_TOKEN_KEY)
    expect(seeded, 'sessionStorage 应持有访问令牌').toBeTruthy()

    // 之后逐页切换：仅改 hash → 同文档导航，令牌改由 sessionStorage 提供，
    // 任一页 401 都会表现为弹回登录页，故这里同时锁住「续访后令牌仍然有效」
    for (const route of ROUTE_CASES.slice(1)) {
      await gotoHash(app, route.hash)
      await expectHeading(app, route.heading)
    }
  })
})

test.describe('服务端页面路由', () => {
  test('/ -> /dashboard 重定向保留 query', async ({ request }) => {
    // 服务端用 Go 的 http.StatusSeeOther 写响应，状态码固定 303 See Other
    // （303 明确表达「响应是另一个资源、原请求无副作用」；对纯 GET 重定向与 302 行为一致）。
    // 不带 query：303 到干净的 /dashboard
    const plain = await request.get('/', { maxRedirects: 0 })
    expect(plain.status()).toBe(303)
    expect(plain.headers()['location']).toBe('/dashboard')

    // 带 query：redirectRoot 原样把 query 带到目标地址（服务端契约行为，与前端是否消费无关）
    const withQuery = await request.get('/?access_token=abc', { maxRedirects: 0 })
    expect(withQuery.status()).toBe(303)
    expect(withQuery.headers()['location']).toBe('/dashboard?access_token=abc')
  })

  test('每条已注册页面路径都返回 SPA 外壳', async ({ request }) => {
    // 服务端只认 static.go 里逐条注册的页面路径，全部返回同一份不含数据的静态壳；
    // hash 路由因此刷新与直达都安全（history 路由会 404）。仅前端路由（/risk 等）不在此列。
    for (const path of SHELL_PATHS) {
      const response = await request.get(path)
      expect(response.status(), `${path} 应返回 200`).toBe(200)
      const body = await response.text()
      expect(body, `${path} 应返回 SPA 外壳`).toContain('id="root"')
    }
  })
})
