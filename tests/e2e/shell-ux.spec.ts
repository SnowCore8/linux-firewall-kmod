/**
 * 应用外壳交互 UX —— 主题/密度切换、命令面板（按钮 + 快捷键）、侧边栏折叠。
 *
 * 这条 spec 是「全新重写方案」Phase 6 手动验收项的**自动化替身**：把原本要靠人点一遍的
 * 外壳级体验（切主题、切密度、⌘K 命令面板、折叠侧栏）固化成可回归的浏览器断言，
 * 每次改动外壳都能立刻发现回归，而不必依赖人工走查。
 *
 * 前置条件：守护进程已在运行（见 scripts/e2e-daemon.sh start）。
 *
 * 断言锚点全部取自外壳源码，避免猜选择器：
 *   - 顶栏按钮 aria-label：AppShell.tsx（切换主题 / 切换密度 / 打开命令面板 / 折叠侧边栏·展开侧边栏）
 *   - `<html data-theme|data-density>`：ThemeProvider.tsx 的 useEffect 写入
 *   - 偏好落 localStorage（JSON 序列化）：usePersistentState.ts
 *   - 命令面板：CommandPalette.tsx（搜索框 aria-label「命令面板搜索」+ role=listbox/option）
 *   - 快捷键 mod+k：useHotkey.ts —— Linux 上 mod 解析为 Control（非 macOS 平台走 ctrl）
 *
 * 设备固定 Desktop Chrome（视口 ≥ lg 断点），故外壳走桌面布局：常驻侧边栏、顶栏命令面板入口可见。
 * 每个用例都是全新浏览器上下文（localStorage 起始为空），所以「默认密度=标准」是确定的初值。
 *
 * 控制台洁净度由 support.ts 的 `app` 夹具统一断言（无 console.error / console.warn）。
 */

import type { Page } from '@playwright/test'
import { expect, openRoute, shellReady, test } from './support'

/** 偏好持久化键（与 ThemeProvider.tsx / AppShell.tsx 中的常量逐字一致） */
const THEME_KEY = 'firewall.theme.preference'
const DENSITY_KEY = 'firewall.theme.density'
const SIDER_KEY = 'firewall.sider.collapsed'

/** 读回 usePersistentState 写入的值：它在 localStorage 里是 JSON 字符串，需 parse。 */
async function readStored<T>(page: Page, key: string): Promise<T | null> {
  return page.evaluate((k) => {
    const raw = window.localStorage.getItem(k)
    return raw === null ? null : (JSON.parse(raw) as T)
  }, key)
}

test.describe('外观：主题与密度', () => {
  test('切换主题即时生效、落盘并在刷新后保持', async ({ app }) => {
    await openRoute(app, '/dashboard')

    // data-theme 在首屏由 index.html 内联脚本预设、再由 ThemeProvider 对齐，
    // 先等它收敛成确定值（dark/light），据此算出点击后的对立面——不假设系统配色初值。
    const html = app.locator('html')
    await expect(html).toHaveAttribute('data-theme', /^(dark|light)$/)
    const before = await html.getAttribute('data-theme')
    const after = before === 'dark' ? 'light' : 'dark'

    await app.getByRole('button', { name: '切换主题', exact: true }).click()

    // 切换后：显式偏好覆盖了 system，data-theme 与新偏好应一致
    await expect(html).toHaveAttribute('data-theme', after)
    expect(await readStored<string>(app, THEME_KEY), '主题偏好应落 localStorage').toBe(after)

    // 刷新后保持：内联脚本按 localStorage 复位，不应闪回系统默认
    await app.reload()
    await expect(shellReady(app)).toBeVisible()
    await expect(app.locator('html')).toHaveAttribute('data-theme', after)
  })

  test('切换密度在标准/紧凑间往返', async ({ app }) => {
    await openRoute(app, '/dashboard')

    // 全新上下文 → 默认标准密度（这是新用户拿到的初值，作为断言基线）
    const html = app.locator('html')
    await expect(html).toHaveAttribute('data-density', 'standard')

    const densityBtn = app.getByRole('button', { name: '切换密度', exact: true })
    await densityBtn.click()
    await expect(html).toHaveAttribute('data-density', 'compact')
    expect(await readStored<string>(app, DENSITY_KEY), '密度偏好应落 localStorage').toBe('compact')

    await densityBtn.click()
    await expect(html).toHaveAttribute('data-density', 'standard')
    expect(await readStored<string>(app, DENSITY_KEY)).toBe('standard')
  })
})

test.describe('命令面板', () => {
  test('按钮打开面板、搜索过滤、Esc 关闭', async ({ app }) => {
    await openRoute(app, '/dashboard')

    // destroyOnHidden：面板关闭时搜索框不在 DOM 里
    const search = app.getByLabel('命令面板搜索')
    await expect(search).toHaveCount(0)

    await app.getByRole('button', { name: '打开命令面板', exact: true }).click()

    // 打开即聚焦搜索框（键盘全可达的前提），并渲染候选列表
    await expect(search).toBeVisible()
    await expect(search).toBeFocused()
    const options = app.getByRole('option')
    await expect(app.getByRole('listbox')).toBeVisible()
    expect(await options.count(), '默认应列出全部命令').toBeGreaterThan(0)

    // 模糊搜索：输入「封禁」应能命中「新建封禁」快捷动作
    await search.fill('封禁')
    await expect(app.getByRole('option', { name: /新建封禁/ }).first()).toBeVisible()

    // Esc 关闭（Modal onCancel）→ destroyOnHidden 卸载搜索框
    await search.press('Escape')
    await expect(search).toBeHidden()
  })

  test('快捷键 Control+K 打开面板', async ({ app }) => {
    await openRoute(app, '/dashboard')

    const search = app.getByLabel('命令面板搜索')
    await expect(search).toHaveCount(0)

    // useHotkey('mod+k') 挂在 window 上；Linux 下 mod=Control。
    // 用真实按键序列验证「手不离键盘即可唤出面板」这条核心效率项。
    await app.keyboard.press('Control+k')
    await expect(search).toBeVisible()
    await expect(search).toBeFocused()

    await app.keyboard.press('Escape')
    await expect(search).toBeHidden()
  })
})

test.describe('侧边栏', () => {
  test('折叠隐藏品牌文字、落盘并在刷新后保持', async ({ app }) => {
    await openRoute(app, '/dashboard')

    // 桌面布局默认展开：品牌文字「Firewall」可见，折叠按钮 aria-label 为「折叠侧边栏」
    const brand = app.getByText('Firewall', { exact: true })
    await expect(brand).toBeVisible()

    await app.getByRole('button', { name: '折叠侧边栏', exact: true }).click()

    // 折叠后：图标条态，品牌文字被条件渲染移除；aria-label 翻转为「展开侧边栏」
    await expect(app.getByRole('button', { name: '展开侧边栏', exact: true })).toBeVisible()
    await expect(brand).toBeHidden()
    expect(await readStored<boolean>(app, SIDER_KEY), '折叠态应落 localStorage').toBe(true)

    // 刷新后保持折叠（偏好从 localStorage 复位）
    await app.reload()
    await expect(shellReady(app)).toBeVisible()
    await expect(app.getByRole('button', { name: '展开侧边栏', exact: true })).toBeVisible()
    await expect(app.getByText('Firewall', { exact: true })).toBeHidden()
  })
})
