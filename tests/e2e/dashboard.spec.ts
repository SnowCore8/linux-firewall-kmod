/**
 * 健康检查 —— 守护进程与 Web UI 的基本可达性。
 *
 * 前置条件：守护进程已在运行（`scripts/e2e-daemon.sh start`，或 CI 里的等价步骤），
 * 目标地址可通过 `BASE_URL` 环境变量覆盖。
 *
 * 与其它规格的分工：本文件只回答「服务是不是活着」，不访问页面、不依赖凭据；
 * 路由覆盖在 `routes.spec.ts`，写操作回环在 `write-flow.spec.ts`。
 * `/health` 是**无认证**端点（见 http_exporter/handler.rs 的分层），
 * 未就绪时返回 503，因此「200」就是 netlink 链路与内核 procfs 同时就绪的判据。
 */

import { expect, test } from './support'

test.describe('守护进程健康检查', () => {
  test('health 端点返回健康状态', async ({ request }) => {
    const response = await request.get('/health')
    expect(response.status(), '/health 应在就绪时返回 200').toBe(200)

    // 只断言「200」是不够的：响应体是 RuntimeSnapshot，必须真的自报 ok
    const snapshot = (await response.json()) as {
      status?: string
      netlink_ready?: boolean
      kmod_proc_present?: boolean
    }
    expect(snapshot.status).toBe('ok')
    expect(snapshot.netlink_ready).toBe(true)
    expect(snapshot.kmod_proc_present).toBe(true)
  })

  test('dashboard 外壳可加载', async ({ page }) => {
    const response = await page.goto('/dashboard')
    expect(response?.ok(), 'dashboard 应返回 2xx').toBeTruthy()
    await expect(page).toHaveTitle(/firewall/i)
  })
})
