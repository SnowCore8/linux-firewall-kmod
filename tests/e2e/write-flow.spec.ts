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
 *   1. 界面层：表格行/开关就地变化、成功提示文案；
 *   2. 接口层：`GET /api/v2/bans` 或 `GET /api/v2/jails` 的可见性随之翻转
 *      （证明 UI 不是自己骗自己）；
 *   3. 干净层：整个用例期间无 console.error / console.warn（由 support.ts 夹具断言）。
 *
 * 桌面范式下的控件（与旧移动版完全不同，选择器按 frontend/src/views 的真实标记取）：
 *   - 列表是 AntD Table（行 `.ant-table-row`），不是滑动删除；
 *   - 新建封禁是右侧 Drawer 表单（DrawerForm），字段用 Form.Item 的 `<label for>` 关联；
 *   - 解封是 Popconfirm 二次确认（`.ant-popover` 弹层），不是 Dialog.confirm；
 *   - Jail 开关是 AntD Switch（`role="switch"`，带 `aria-label="启用/停用规则 <name>"`）。
 *
 * 封禁回环的目标 IP 取 RFC 5737 的 TEST-NET-3（203.0.113.0/24，文档专用），
 * 不会与真实局域网地址冲突。
 */

import { expect, ACCESS_TOKEN, expectHeading, openRoute, test } from './support'

/** 文档专用地址，避免与真实主机冲突 */
const TEST_IP = '203.0.113.7'
/** 写入审计与封禁详情的原因文案 */
const TEST_REASON = 'e2e 自动化回归'
/** 封禁时长（秒） */
const TEST_DURATION = 300

/** 带 Basic 凭据的请求头：`request` 夹具不共享页面的 sessionStorage，需显式携带 */
const AUTH_HEADERS = { Authorization: `Basic ${ACCESS_TOKEN}` }

/** 从分页信封里取出封禁条目（`GET /api/v2/bans` 恒为 { code, data: { items } }） */
async function listBanIps(
  request: import('@playwright/test').APIRequestContext,
): Promise<string[]> {
  const response = await request.get('/api/v2/bans', { headers: AUTH_HEADERS })
  expect(response.status(), 'GET /api/v2/bans 应返回 200').toBe(200)
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
    // 前置清理：上一条用例异常中断时可能留下同一 IP 的封禁（不存在时后端回 4xx，忽略）
    await request.delete(`/api/v2/bans/${TEST_IP}`, { headers: AUTH_HEADERS })
  })

  test('封禁写入内核，再解封恢复原状', async ({ app, request }) => {
    // 前置状态：该 IP 不在封禁表中
    expect(await listBanIps(request)).not.toContain(TEST_IP)

    await openRoute(app, '/bans')
    await expectHeading(app, '封禁管理')

    // ---- 1. 新建封禁（右侧 Drawer 表单）----
    // 工具条与空表引导各有一个「新建封禁」按钮：工具条那个带图标，可访问名是「plus 新建封禁」，
    // 空表引导那个是纯文本「新建封禁」。用正则同时匹配两者、取 DOM 中靠前的工具条按钮
    // （工具条在表格之前渲染），空表/非空表都稳定命中同一入口，也不触发 strict 冲突。
    await app.getByRole('button', { name: /新建封禁/ }).first().click()

    // 抽屉用 ARIA role=dialog + 可访问名「新建封禁」锚定：AntD Drawer 渲染 role="dialog"，
    // 名称取自标题。这比依赖私有类名 .ant-drawer-content 稳——AntD 6 已把面板语义从
    // content 迁到 section，类名随大版本会变，role 不会。批量/详情抽屉此刻未打开、不在 DOM，
    // 故该 dialog 唯一。
    const drawer = app.getByRole('dialog', { name: '新建封禁' })
    await expect(drawer).toBeVisible()
    // 必填项「IP 地址」的可访问名带 AntD 必填星号（实为 "* IP 地址"），故三处均用非精确
    // 子串匹配；标签是全角括号：「时长（秒）」「原因（可选）」（与旧版半角写法不同）。
    await drawer.getByLabel('IP 地址').fill(TEST_IP)
    await drawer.getByLabel('时长（秒）').fill(String(TEST_DURATION))
    await drawer.getByLabel('原因（可选）').fill(TEST_REASON)
    // 提交按钮 = DrawerForm 的 submitText「封禁」（primary 危险色）。AntD 给「恰好两个汉字
    // 且非 link/text 型」的按钮自动插入空格，可访问名实为「封 禁」，故用 \s* 容错。
    await drawer.getByRole('button', { name: /封\s*禁/ }).click()

    // 成功提示：Bans.tsx 用 message.success(`已封禁 ${ip}（时长 ${formatDuration(...)}）`)
    // 或 `（永久）`；时长文案随格式化变化，故只锚定「已封禁 + IP」这段稳定前缀。
    await expect(app.getByText(new RegExp(`已封禁 ${TEST_IP.replace(/\./g, '\\.')}`))).toBeVisible()

    // 该行出现，且带本次写入的原因（证明数据来自后端而非本地乐观更新）。
    // AntD Table 行是 `.ant-table-row`；按 IP 文本过滤定位到目标行。
    const row = app.locator('.ant-table-row').filter({ hasText: TEST_IP })
    await expect(row).toBeVisible()
    await expect(row).toContainText(TEST_REASON)

    // ---- 2. 接口层确认：写操作真的落到了封禁表 ----
    await expect
      .poll(async () => listBanIps(request), { message: '封禁应出现在活跃封禁列表中' })
      .toContain(TEST_IP)

    // ---- 3. 解封（Popconfirm 二次确认）----
    await row.getByRole('button', { name: '解封', exact: true }).click()

    // Popconfirm 弹层：用其唯一的确认文案过滤定位（`.ant-popover` 是 Popconfirm/Tooltip
    // 的共同基类，按描述文本过滤即可锁定本弹层，不依赖 `.ant-popconfirm*` 具体类名）。
    const popconfirm = app
      .locator('.ant-popover')
      .filter({ hasText: `将立即解除对 ${TEST_IP} 的封禁。` })
    await expect(popconfirm).toBeVisible()
    // 确认按钮 okText=「解封」（primary 危险色 → 同样被 AntD 插入空格成「解 封」，用 \s* 容错）；
    // 行内触发按钮是 link 型（不插空格，可访问名仍是「解封」）且在弹层之外，不会与之混淆。
    await popconfirm.getByRole('button', { name: /解\s*封/ }).click()

    await expect(app.getByText(`已解封 ${TEST_IP}`)).toBeVisible()

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
 * 单个 Jail 的实时状态（`GET /api/v2/jails` 返回裸数组）。
 *
 * 按名字取 `enabled`：列表里通常只有 `sshd` 一个 Jail，但按名字定位不依赖顺序，
 * 后续新增 Jail 也不会让断言错位。
 */
async function getJailEnabled(
  request: import('@playwright/test').APIRequestContext,
  name: string,
): Promise<boolean> {
  const response = await request.get('/api/v2/jails', { headers: AUTH_HEADERS })
  expect(response.status(), 'GET /api/v2/jails 应返回 200').toBe(200)
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
   * 全新前端的 Jails.tsx 明确规避了它：PUT /jails 异步生效且不推 SSE 帧，故切换成功后
   * 直接 `refetch()` 重读权威状态（见该文件 handleToggle 注释）。本用例**不刷新页面**，
   * 直接断言开关就地翻转——这正是原缺陷做不到的事。
   */
  test('切换 Jail 开关后开关就地翻转（无需刷新页面）', async ({ app, request }) => {
    await openRoute(app, '/jails')
    await expectHeading(app, '越狱规则')

    // 取第一个 Jail 及其初始状态：不硬编码 `sshd`，避免依赖默认配置的 Jail 名。
    // 名字直接取自 Switch 的 aria-label「启用/停用规则 <name>」——它由 Jails.tsx 显式设置，
    // 不依赖列顺序，也绕开了 expandable 展开列对「第一格」的干扰。
    const firstSwitch = app.getByRole('switch').first()
    await expect(firstSwitch).toBeVisible()
    const ariaLabel = await firstSwitch.getAttribute('aria-label')
    expect(ariaLabel, 'Switch 应带 aria-label「启用/停用规则 <name>」').toBeTruthy()
    const name = (ariaLabel ?? '').replace(/^启用\/停用规则\s*/, '').trim()
    expect(name, '应从 aria-label 解析出 Jail 名').not.toBe('')
    const before = await getJailEnabled(request, name)

    // 切换（开启 → 关闭，或反之）
    await firstSwitch.click()

    // 停用方向有二次确认弹窗（Jails.tsx handleToggle：modal.confirm），需点击「停用」才真正执行
    if (before) {
      const confirmBtn = app.getByRole('button', { name: '停用' })
      await expect(confirmBtn).toBeVisible()
      await confirmBtn.click()
    }

    // 成功提示出现即证明后端写成功（Jails.tsx：`规则 <name> 已<启用|停用>（<status>）`）
    await expect(app.getByText(new RegExp(`规则 ${name} 已(启用|停用)`))).toBeVisible()

    // ---- 1. 界面层：开关就地翻转，**没有整页刷新** ----
    await expect(firstSwitch).toHaveAttribute('aria-checked', String(!before))

    // ---- 2. 接口层：后端状态确实翻转（证明不是本地乐观更新） ----
    await expect
      .poll(async () => getJailEnabled(request, name), {
        message: `切换后 Jail ${name} 的 enabled 应变为 ${!before}`,
      })
      .toBe(!before)

    // ---- 3. 恢复原状，避免影响其它用例与后续人工查看 ----
    await firstSwitch.click()

    // 恢复时如果又是停用方向（即 before=false → 当前 enabled=true → 再切回 enabled=false），
    // 同样需要处理二次确认弹窗
    if (!before) {
      const confirmBtn = app.getByRole('button', { name: '停用' })
      await expect(confirmBtn).toBeVisible()
      await confirmBtn.click()
    }

    await expect(firstSwitch).toHaveAttribute('aria-checked', String(before))
    await expect
      .poll(async () => getJailEnabled(request, name), {
        message: `恢复后 Jail ${name} 的 enabled 应回到 ${before}`,
      })
      .toBe(before)
  })
})
