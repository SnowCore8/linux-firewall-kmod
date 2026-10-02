/**
 * 深/浅主题状态。
 *
 * - 主题写在 `<html data-theme="dark|light">` 上，样式令牌由 `styles/global.css` 按该
 *   属性切换；`index.html` 已预置 `data-theme="dark"`，保证首屏不闪白。
 * - 持久化到 localStorage，刷新后沿用上次选择；**默认 dark**。
 * - 多标签页同步：其他标签页切换主题时本页跟随（同一台手机上开两个标签的情形）。
 */

import { effect, signal } from '../lib/signals'

/** 可用主题 */
export type Theme = 'dark' | 'light'

/** localStorage 键名（带项目前缀，避免与同源其他页面冲突） */
const THEME_STORAGE_KEY = 'firewall-theme'

/** 读取持久化主题；无记录或存储不可用时回退 dark */
function readStoredTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch (err) {
    // 隐私模式 / 存储被禁用：读不到就按默认值走，不阻断应用启动
    console.debug('[theme] 读取主题偏好失败，使用默认 dark', err)
  }
  return 'dark'
}

/** 写入持久化主题；失败时仅记录，不影响当前会话已生效的主题 */
function persistTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch (err) {
    console.debug('[theme] 保存主题偏好失败（当前会话仍然生效）', err)
  }
}

/** 当前主题。视图可读它取渲染分支，但不要在渲染函数里写它。 */
export const theme = signal<Theme>(readStoredTheme())

/** 在深/浅之间切换，并持久化 */
export function toggleTheme(): void {
  theme.update((current) => (current === 'dark' ? 'light' : 'dark'))
}

/**
 * 建立主题副作用：把主题同步到 `<html data-theme>` 并落盘，同时监听其他标签页的变更。
 *
 * @returns 停止函数（应用根卸载时调用）
 */
export function initTheme(): () => void {
  const stopSync = effect(() => {
    const current = theme.get()
    // 属性挂在 <html> 上：CSS 变量按该选择器生效
    document.documentElement.dataset.theme = current
    persistTheme(current)
  })

  // storage 事件不会在触发页自身触发，因此只有其他标签页的切换会走到这里
  const onStorage = (event: StorageEvent): void => {
    if (event.key !== THEME_STORAGE_KEY) return
    if (event.newValue === 'light' || event.newValue === 'dark') {
      theme.set(event.newValue)
    }
  }
  window.addEventListener('storage', onStorage)

  return () => {
    window.removeEventListener('storage', onStorage)
    stopSync()
  }
}
