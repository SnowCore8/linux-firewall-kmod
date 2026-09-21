/**
 * PWA 的「安全上下文」边界验收。
 *
 * 浏览器只在**安全上下文**（HTTPS 或 localhost / 127.0.0.1）下暴露 `serviceWorker` API。
 * 本项目部署后常被以 `http://<局域网IP>:<port>` 访问，此时该 API 根本不存在，
 * Service Worker 无法注册、PWA 安装被浏览器拒绝。这是浏览器硬性约束，**不是缺陷**，
 * 因此本用例把它固化为「期望行为」而不是去「修掉」——文档与代码注释里都写了这条限制，
 * 这里补上可复现的机械证据，防止后人误当 bug 处理（如塞 polyfill、改注册路径）。
 *
 * 两侧对照：
 *   - 安全上下文（baseURL 默认 127.0.0.1）：SW 可用且注册成功、manifest 可取；
 *   - 非安全上下文（`E2E_LAN_ORIGIN`，如 http://192.168.8.5:9119）：SW 不可用，
 *     但各页面功能正常，且**控制台保持洁净**（main.tsx 检测不到就静默跳过，
 *     不会打警告——这正是不该「修」的另一个理由）。
 *
 * 局域网侧的地址由环境变量给出：CI runner 的网段不可预知，取不到就跳过这一侧
 * （与内核模块可加载性的门禁同一约定：环境不具备则显式跳过并说明原因）。
 */

import { expect, gotoHash, openRoute, test } from './support'

/** 局域网（非安全上下文）地址，形如 http://192.168.8.5:9119；未设置则不跑这一侧 */
const LAN_ORIGIN = process.env.E2E_LAN_ORIGIN

/** 是否为安全上下文（浏览器判定，不由本项目决定） */
async function serviceWorkerAvailable(page: import('@playwright/test').Page): Promise<boolean> {
  return page.evaluate(() => 'serviceWorker' in navigator)
}

test.describe('PWA：安全上下文下可用', () => {
  test('Service Worker 可注册，manifest 可取', async ({ app, request }) => {
    await openRoute(app, '/dashboard')
    expect(await serviceWorkerAvailable(app), 'localhost/127.0.0.1 应为安全上下文').toBe(true)

    // 注册发生在 window load 之后（main.tsx 的 load 监听），因此用轮询等待而不是立即断言
    await expect
      .poll(async () => app.evaluate(() => navigator.serviceWorker.getRegistration().then((r) => r !== undefined)), {
        message: '安全上下文下 /sw.js 应注册成功',
      })
      .toBe(true)

    // manifest 由守护进程提供；安装 PWA 需要它可取且是合法 JSON
    const manifest = await request.get('/static/manifest.webmanifest')
    expect(manifest.status(), 'manifest 应可访问').toBe(200)
    expect(manifest.headers()['content-type'] ?? '', '应为 JSON 类型').toContain('json')
  })
})

test.describe('PWA：非安全上下文下的已知限制', () => {
  // 该 describe 内所有请求改走局域网地址（非安全上下文）
  test.use({ baseURL: LAN_ORIGIN })

  test.skip(!LAN_ORIGIN, '未设置 E2E_LAN_ORIGIN（局域网地址），跳过非安全上下文验收')

  test('Service Worker 不可用，但界面功能不受影响', async ({ app }) => {
    await openRoute(app, '/dashboard')

    expect(
      await serviceWorkerAvailable(app),
      'http://<局域网IP> 不是安全上下文：浏览器不暴露 serviceWorker，这是硬性约束',
    ).toBe(false)
    expect(
      await app.evaluate(() => typeof navigator.serviceWorker === 'undefined'),
      '非安全上下文下 navigator.serviceWorker 应为 undefined',
    ).toBe(true)

    // 关键：SW 缺席不影响应用本体——离线能力降级为「普通网页」，数据面照常工作
    await expect(app.getByRole('heading', { level: 2, name: '总览', exact: true })).toBeVisible()
    await gotoHash(app, '/bans')
    await expect(app.getByRole('heading', { level: 2, name: '封禁管理', exact: true })).toBeVisible()

    // 控制台洁净度由 app 夹具统一断言：此处不额外断言，避免重复
  })
})
