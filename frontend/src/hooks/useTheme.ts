/**
 * 深/浅主题 Hook
 *
 * 行为：
 * - 主题写在 `<html data-theme="dark|light">` 上，样式令牌由 `styles/global.css` 按该属性切换；
 *   index.html 里已预置 `data-theme="dark"`，保证首屏不闪白。
 * - 持久化到 localStorage，刷新后沿用上次选择；**默认 dark**。
 * - 多标签页同步：其他标签页切换主题时本页跟随（同一台手机上开了两个标签的情况）。
 *
 * 本文件是 `.ts` 而非 `.tsx`（契约指定的路径），因此用 createElement 而非 JSX。
 */

import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { JSX, ReactNode } from 'react'

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
    console.debug('[useTheme] 读取主题偏好失败，使用默认 dark', err)
  }
  return 'dark'
}

/** 写入持久化主题；失败时仅记录，不影响当前会话已生效的主题 */
function persistTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme)
  } catch (err) {
    console.debug('[useTheme] 保存主题偏好失败（当前会话仍然生效）', err)
  }
}

interface ThemeValue {
  theme: Theme
  toggle: () => void
}

const ThemeContext = createContext<ThemeValue | null>(null)

/** 主题 Provider：包裹整个应用，供全局读取当前主题 */
export function ThemeProvider(props: { children: ReactNode }): JSX.Element {
  const [theme, setTheme] = useState<Theme>(readStoredTheme)

  useEffect(() => {
    // 属性挂在 <html> 上：CSS 变量与 antd-mobile 的暗色变量都能按此选择器生效
    document.documentElement.dataset.theme = theme
    persistTheme(theme)
  }, [theme])

  useEffect(() => {
    // 监听其他标签页的主题变更（storage 事件不会在触发页自身触发）
    const onStorage = (event: StorageEvent): void => {
      if (event.key !== THEME_STORAGE_KEY) return
      if (event.newValue === 'light' || event.newValue === 'dark') {
        setTheme(event.newValue)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const toggle = useCallback(() => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }, [])

  const value = useMemo<ThemeValue>(() => ({ theme, toggle }), [theme, toggle])

  return createElement(ThemeContext.Provider, { value }, props.children)
}

/**
 * 读取当前主题与切换函数。
 * @throws Error 在 `<ThemeProvider>` 之外调用时
 */
export function useTheme(): { theme: Theme; toggle: () => void } {
  const ctx = useContext(ThemeContext)
  if (!ctx) {
    throw new Error('useTheme 必须在 <ThemeProvider> 内使用（请检查应用根部的 Provider 组合）')
  }
  return ctx
}
