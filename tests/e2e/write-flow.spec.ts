/**
 * 写操作回环。
 *
 * 前置条件：守护进程已在运行（见 `scripts/e2e-daemon.sh start`）。封禁回环额外需要
 * **加载内核模块**（否则写路径无处下发，用例视为环境不满足而跳过，而不是误报产品缺陷）；
 * Jail 开关只改守护进程配置，不需要内核。
 *
 * 为什么必须覆盖写操作：读路径全绿只能证明界面能把数据画出来；本项目真正的风险在
 * 写路径——封禁/解封要经 daemon → netlink → 内核并等内核确认，Jail 开关要落到运行
 * 时配置，这些链路（含二次确认、错误信封、**写后列表刷新**）才是「改了配置却对系统
 * 没有影响」的事故高发区。
 *
 * 两个回环断言三层，逐层收紧：
 *   1. 界面层：卡片/开关就地变化、成功提示文案；
 *   2. 接口层：`GET /api/v1/bans` 或 `GET /api/v1/jails` 的可见性随之翻转
 *      （证明 UI 不是自己骗自己）；
 *   3. 干净层：整个用例期间无 console.error / console.warn（由 support.ts 夹具断言）。
 *
 * 封禁回环的目标 IP 取 RFC 5737 的 TEST-NET-3（203.0.113.0/24，文档专用），
 * 不会与真实局域网地址冲突。
 */

import { expect, ACCESS_TOKEN, openRoute, test } from './support'

/** 文档专用地址，避免与真实主机冲突 */
const TEST_IP = '203.0.113.7'
/** 写入审计与封禁详情的原因文案 */
const TEST_REASON = 'e2e 自动化回归'
/** 封禁时长（秒） */
const TEST_DURATION = 300

/** 带 Basic 凭据的请求头：`request` 夹具不共享页面的 sessionStorage，需显式携带 */
const AUTH_HEADERS = { Authorization: `Basic ${ACCESS_TOKEN}` }

/** 从分页信封里取出封禁条目（`GET /api/v1/bans` 恒为 { code, data: { items } }） */
async function listBanIps(
  request: import('@playwright/test').APIRequestContext,
): Promise<string[]> {
  const response = await request.get('/api/v1/bans', { headers: AUTH_HEADERS })
  expect(response.status(), 'GET /api/v1/bans 应返回 200').toBe(200)
  const body = (await response.json()) as { code: number; data: { items: { ip: string }[] } }
  expect(body.code, '业务码应为 0').toBe(0)
  return body.data.items.map((item) => item.ip)
}

test.describe('写操作回环：封禁后解封', () => {
  test.skip(
    () => !process.env.E2E_KERNEL_MODULE,
    '未声明内核模块可用（E2E_KERNEL_MODULE=1）：写操作需要真实内核链路',
  )

  test.beforeEach(async ({ request }) => {
    // 前置清理：上一条用例异常中断时可能留下同一 IP 的封禁
    await request.delete(`/api/v1/bans/${TEST_IP}`, { headers: AUTH_HEADERS })
  })

  test('封禁写入内核，再解封恢复原状', async ({ app, page, request }) => {
    // 前置状态：该 IP 不在封禁表中
    expect(await listBanIps(request)).not.toContain(TEST_IP)

    await openRoute(app, '/bans')
    await expect(page.getByRole('heading', { level: 2, name: '封禁管理', exact: true })).toBeVisible()

    // ---- 1. 新建封禁 ----
    await page.getByRole('button', { name: '新建封禁', exact: true }).click()

    // 弹层表单以 label 关联控件（antd-mobile 的 Form.Item 会生成 <label for>）
    await page.getByLabel('IP 地址', { exact: true }).fill(TEST_IP)
    await page.getByLabel('时长(秒)', { exact: true }).fill(String(TEST_DURATION))
    await page.getByLabel('原因', { exact: true }).fill(TEST_REASON)
    await page.getByRole('button', { name: '提交封禁', exact: true }).click()

    // 成功提示：文案由 Bans.tsx 按后端返回的 permanent/duration_seconds 组装
    await expect(page.getByText(`已封禁 ${TEST_IP} ${TEST_DURATION} 秒`)).toBeVisible()

    // 该行出现，且带本次写入的原因（证明数据来自后端而非本地乐观更新）。
    // 锚定滑动容器（.adm-swipe-action）而非行本身（.fw-row）：行内的「解封」按钮由
    // SwipeAction 渲染在滑动轨道之外，只有外层容器同时包住「行 + 解封按钮」。
    const row = page.locator('.adm-swipe-action').filter({ hasText: TEST_IP })
    await expect(row).toBeVisible()
    await expect(row).toContainText(TEST_REASON)

    // ---- 2. 接口层确认：写操作真的落到了封禁表 ----
    await expect
      .poll(async () => listBanIps(request), { message: '封禁应出现在活跃封禁列表中' })
      .toContain(TEST_IP)

    // ---- 3. 解封（二次确认）----
    await row.getByRole('button', { name: '解封', exact: true }).click()

    // Dialog.confirm 渲染成 ARIA role=dialog 的节点（内容含 confirmText='解封'）。
    // 不用 .adm-dialog 外层容器做可见性锚点：它是无尺寸的定位壳（子元素绝对定位），
    // Playwright 会把它判为 hidden；按 role 定位既稳定又能与列表行上的按钮区分开。
    const dialog = page.getByRole('dialog')
    await expect(dialog).toBeVisible()
    await expect(dialog).toContainText(`确定解封 ${TEST_IP}`)
    await dialog.getByRole('button', { name: '解封', exact: true }).click()

    await expect(page.getByText(`已解封 ${TEST_IP}`)).toBeVisible()

    // ---- 4. 两端同时恢复原状 ----
    await expect(row).toHaveCount(0)
    await expect
      .poll(async () => listBanIps(request).then((ips) => !ips.includes(TEST_IP)), {
        message: '解封后该 IP 应从活跃封禁列表中消失',
      })
      .toBe(true)
  })
})

/**
 * 单个 Jail 的实时状态（`GET /api/v1/jails` 返回裸数组）。
 *
 * 按名字取 `enabled`：列表里通常只有 `sshd` 一个 Jail，但按名字定位不依赖顺序，
 * 后续新增 Jail 也不会让断言错位。
 */
async function getJailEnabled(
  request: import('@playwright/test').APIRequestContext,
  name: string,
): Promise<boolean> {
  const response = await request.get('/api/v1/jails', { headers: AUTH_HEADERS })
  expect(response.status(), 'GET /api/v1/jails 应返回 200').toBe(200)
  const body = (await response.json()) as {
    code: number
    data: { name: string; enabled: boolean }[]
  }
  expect(body.code, '业务码应为 0').toBe(0)
  const jail = body.data.find((j) => j.name === name)
  expect(jail, `Jail ${name} 应存在于列表中`).toBeTruthy()
  return jail!.enabled
}

test.describe('写操作回环：Jail 开关就地生效', () => {
  /**
   * 回归缺陷 HTTP_SSE_JAILS_NO_PUBLISHER。
   *
   * 该缺陷下：服务端 `jails` 这个 SSE 域没有生产者（收完首帧永不重发），前端又写
   * `jails = sseJails ?? restJails.data`——SSE 一旦有过首帧，REST 那份永远取不到。
   * 于是切开关后界面弹「已启用」，开关却弹回原位，**只有整页刷新**（重连 SSE、
   * 重收首帧）才看得到新值，页内刷新按钮也是死代码。
   *
   * 本用例**不刷新页面**，直接断言开关就地翻转——这正是原缺陷做不到的事。
   */
  test('切换 Jail 开关后开关就地翻转（无需刷新页面）', async ({ app, page, request }) => {
    await openRoute(app, '/jails')
    await expect(page.getByRole('heading', { level: 2, name: 'Jail 列表', exact: true })).toBeVisible()

    // 取第一个 Jail 及其初始状态：不硬编码 `sshd`，避免依赖默认配置的 Jail 名。
    // 名字取自开关所在面板的标题（.fw-panel-title）——Jail 名是面板标题、开关在面板体
    // 内，两者不在同一行，只能沿面板容器回溯。不限定标签：面板根节点是 <section>，
    // 写死 `ancestor::div` 会永远匹配不到。
    const firstSwitch = page.getByRole('switch').first()
    await expect(firstSwitch).toBeVisible()
    const name = (
      await firstSwitch
        .locator('xpath=ancestor::*[contains(@class,"fw-panel")][1]')
        .locator('.fw-panel-title')
        .first()
        .innerText()
    ).trim()
    const before = await getJailEnabled(request, name)

    // 切换（开启 → 关闭，或反之）
    await firstSwitch.click()

    // 成功提示出现即证明后端写成功（提示文案由 toggleJail 在 PUT 返回后组装）
    await expect(page.getByText(new RegExp(`${name} 已(启用|禁用)`))).toBeVisible()

    // ---- 1. 界面层：开关就地翻转，**没有整页刷新** ----
    await expect(firstSwitch).toHaveAttribute('aria-checked', String(!before))

    // ---- 2. 接口层：后端状态确实翻转（证明不是本地乐观更新） ----
    await expect.poll(async () => getJailEnabled(request, name), {
      message: `切换后 Jail ${name} 的 enabled 应变为 ${!before}`,
    }).toBe(!before)

    // ---- 3. 恢复原状，避免影响其它用例与后续人工查看 ----
    await firstSwitch.click()
    await expect(firstSwitch).toHaveAttribute('aria-checked', String(before))
    await expect.poll(async () => getJailEnabled(request, name), {
      message: `恢复后 Jail ${name} 的 enabled 应回到 ${before}`,
    }).toBe(before)
  })
})
