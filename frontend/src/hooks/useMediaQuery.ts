import { useEffect, useState } from 'react'

/**
 * CSS 媒体查询订阅：响应式外壳据此在断点处折叠侧边栏 / 切换表格降级。
 * 断点常量与设计系统一致（见 theme/tokens.ts 的说明），集中在这里避免各组件各写一遍 matchMedia。
 */

/** 断点（px），桌面优先：≥xl 宽屏，lg 常规桌面，md 平板，<md 手机（抽屉导航）。 */
export const BREAKPOINTS = {
  sm: 576,
  md: 768,
  lg: 1024,
  xl: 1440,
} as const

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState<boolean>(() =>
    typeof window !== 'undefined' ? window.matchMedia(query).matches : false,
  )

  useEffect(() => {
    if (typeof window === 'undefined') return
    const mql = window.matchMedia(query)
    const onChange = (e: MediaQueryListEvent) => setMatches(e.matches)
    setMatches(mql.matches)
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [query])

  return matches
}

/** 视口是否窄于给定断点（默认 md=768，即手机）。 */
export function useIsBelow(breakpoint: keyof typeof BREAKPOINTS = 'md'): boolean {
  return useMediaQuery(`(max-width: ${BREAKPOINTS[breakpoint] - 1}px)`)
}

/** 视口是否宽于等于给定断点（默认 lg=1024，即常规桌面）。 */
export function useIsAtLeast(breakpoint: keyof typeof BREAKPOINTS = 'lg'): boolean {
  return useMediaQuery(`(min-width: ${BREAKPOINTS[breakpoint]}px)`)
}
