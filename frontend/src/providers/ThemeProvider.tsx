import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  type ReactNode,
} from 'react'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'
import { usePersistentState } from '../hooks/usePersistentState.ts'
import { useMediaQuery } from '../hooks/useMediaQuery.ts'
import {
  BRAND,
  FONT_MONO,
  FONT_SANS,
  SEMANTIC,
  THREAT_COLORS,
  buildTheme,
  type Density,
  type ThemeMode,
} from '../theme/tokens.ts'

/**
 * 主题 Provider —— 外观模式（跟随系统 / 暗 / 亮）+ 信息密度（标准 / 紧凑）的单一真相源。
 *
 * 三件事集中在这里，避免各处各调各的：
 *   1. 把 antd 6 的 ThemeConfig 经 ConfigProvider 注入整个组件树（暗色算法 / 紧凑算法 / token）；
 *   2. 把语义色、字体、威胁等级色阶写成 `:root` 上的 CSS 变量，供自绘元素与 ECharts 之外的
 *      纯 CSS 组件消费（组件库主题管不到手写样式）；
 *   3. 把 `<html data-theme>` 与首屏内联脚本（index.html 里防闪烁）对齐，切换主题不闪白。
 *
 * 偏好落 localStorage 并跨标签同步（usePersistentState）：一个标签切暗色，其它标签跟随。
 */

/** 外观偏好：system=跟随操作系统，dark/light=强制。 */
export type ThemePreference = 'system' | ThemeMode

export interface ThemeContextValue {
  /** 用户设定的偏好。 */
  preference: ThemePreference
  /** 实际生效的模式（preference=system 时按 prefers-color-scheme 解析）。 */
  mode: ThemeMode
  isDark: boolean
  density: Density
  setPreference: (p: ThemePreference) => void
  setDensity: (d: Density) => void
  /** 在暗/亮之间切换（把 system 解析成对立的显式值）。 */
  toggleMode: () => void
  toggleDensity: () => void
}

const ThemeContext = createContext<ThemeContextValue | null>(null)

const PREF_KEY = 'firewall.theme.preference'
const DENSITY_KEY = 'firewall.theme.density'

/** 首屏防闪烁：index.html 的内联脚本已按 localStorage 预设了 data-theme，这里读初值对齐。 */
function initialPreference(): ThemePreference {
  try {
    const raw = window.localStorage.getItem(PREF_KEY)
    if (raw) {
      const parsed = JSON.parse(raw) as ThemePreference
      if (parsed === 'system' || parsed === 'dark' || parsed === 'light') return parsed
    }
  } catch {
    // 忽略脏值，走默认
  }
  return 'system'
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreference] = usePersistentState<ThemePreference>(
    PREF_KEY,
    initialPreference(),
  )
  const [density, setDensity] = usePersistentState<Density>(DENSITY_KEY, 'standard')

  // 跟随系统时用媒体查询解析；强制模式时忽略系统值
  const systemDark = useMediaQuery('(prefers-color-scheme: dark)')
  const mode: ThemeMode =
    preference === 'system' ? (systemDark ? 'dark' : 'light') : preference
  const isDark = mode === 'dark'

  // data-theme 属性：与 CSS 变量、index.html 内联脚本同一约定
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', mode)
    document.documentElement.setAttribute('data-density', density)
  }, [mode, density])

  // CSS 变量：把设计令牌暴露给纯 CSS / 自绘元素
  useEffect(() => {
    const root = document.documentElement.style
    root.setProperty('--fw-brand', BRAND)
    root.setProperty('--fw-font-sans', FONT_SANS)
    root.setProperty('--fw-font-mono', FONT_MONO)
    root.setProperty('--fw-success', SEMANTIC.success)
    root.setProperty('--fw-warning', SEMANTIC.warning)
    root.setProperty('--fw-danger', SEMANTIC.danger)
    root.setProperty('--fw-info', SEMANTIC.info)
    for (const [level, color] of Object.entries(THREAT_COLORS)) {
      root.setProperty(`--fw-threat-${level}`, color)
    }
    // 明暗两套表面色（与 tokens.buildTheme 的 Layout 底色保持一致）
    if (isDark) {
      root.setProperty('--fw-bg-body', '#05080d')
      root.setProperty('--fw-bg-sider', '#0a0f16')
      root.setProperty('--fw-bg-header', '#0b1119')
      root.setProperty('--fw-bg-elevated', '#0e1621')
      root.setProperty('--fw-text-primary', '#e6edf3')
      root.setProperty('--fw-text-secondary', '#93a7b6')
      root.setProperty('--fw-border', '#1c2836')
    } else {
      root.setProperty('--fw-bg-body', '#f4f6f8')
      root.setProperty('--fw-bg-sider', '#ffffff')
      root.setProperty('--fw-bg-header', '#ffffff')
      root.setProperty('--fw-bg-elevated', '#ffffff')
      root.setProperty('--fw-text-primary', '#1f2733')
      root.setProperty('--fw-text-secondary', '#5a6b7b')
      root.setProperty('--fw-border', '#e3e8ee')
    }
  }, [isDark])

  // AntD 的日期组件走 dayjs；统一设成中文，避免日期选择器出现英文月份
  useEffect(() => {
    dayjs.locale('zh-cn')
  }, [])

  const toggleMode = useCallback(() => {
    setPreference(isDark ? 'light' : 'dark')
  }, [isDark, setPreference])

  const toggleDensity = useCallback(() => {
    setDensity((prev) => (prev === 'standard' ? 'compact' : 'standard'))
  }, [setDensity])

  const value = useMemo<ThemeContextValue>(
    () => ({
      preference,
      mode,
      isDark,
      density,
      setPreference,
      setDensity,
      toggleMode,
      toggleDensity,
    }),
    [preference, mode, isDark, density, setPreference, setDensity, toggleMode, toggleDensity],
  )

  const themeConfig = useMemo(() => buildTheme(mode, density), [mode, density])

  return (
    <ThemeContext.Provider value={value}>
      <ConfigProvider theme={themeConfig} locale={zhCN}>
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  )
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme 必须在 <ThemeProvider> 内使用')
  return ctx
}

/** 只订阅「是否暗色」的轻量选择器（图表配色等只需这一个维度时用，减少无谓重渲染面）。 */
export function useIsDark(): boolean {
  return useTheme().isDark
}
