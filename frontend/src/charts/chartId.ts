/**
 * 图表共享工具 —— 实例唯一 ID 与统一调色板
 *
 * # 为什么必须用 `useChartId`
 * SVG 里 `url(#xxx)` 的引用是**文档全局**的：`linearGradient` / `filter` / `clipPath`
 * 一旦重名，浏览器只会取文档中第一个匹配项。仪表盘一屏内会同时渲染多个同类图表
 * （例如两条趋势线图），若所有实例都写死 `id="line-grad"`，B 图就会用上 A 图的渐变
 * ——表现为「不同图表串色」。
 *
 * 本 hook 用 React 的 `useId()` 拿到**每个组件实例**都不同的后缀（同一组件渲染两次
 * 会得到两个不同值），拼上调用方给的语义前缀，再把非 `[A-Za-z0-9_-]` 的字符统一
 * 归一化成 `-`：React 生成的 id 形如 `:r0:`，其中的冒号虽然合法，但放进
 * `url(#...)` 与 CSS 选择器容易被误解析，故一律抹平。
 *
 * # 影响范围
 * 只影响本目录 4 个图表组件内部的 SVG id 引用。不产生全局状态、不触碰 DOM 之外的资源。
 * 组件内所有 defs（渐变等）都必须基于返回值的字符串拼接 id。
 */
import { useId, useMemo } from 'react'

/**
 * 图表默认调色板（8 色循环）
 *
 * 取中间明度、中高饱和度的色相：既能落在深色主题的深底上，也能落在浅色主题的白底上，
 * 因此不需要跟随主题切换，避免图表在主题变化时重排颜色。
 */
export const CHART_COLORS: readonly string[] = [
  '#3d8b9a', // 青 —— 主色，与顶栏品牌色一致
  '#e0a458', // 琥珀
  '#c85a54', // 砖红
  '#6ea97f', // 苔绿
  '#8b7ec8', // 紫
  '#4a90c2', // 蓝
  '#d4789a', // 玫红
  '#8a949e', // 中性灰（兜底，用于「其他」类目）
]

/**
 * 按序号取调色板颜色，越界自动回绕
 *
 * @param index 序列下标（负数、小数、NaN 都会被安全归一化）
 * @returns 十六进制颜色字符串，保证是 `CHART_COLORS` 中的一项
 */
export function chartColor(index: number): string {
  if (!Number.isFinite(index)) return CHART_COLORS[0]
  const count = CHART_COLORS.length
  return CHART_COLORS[((Math.trunc(index) % count) + count) % count]
}

/**
 * 生成当前图表实例唯一的 id 前缀
 *
 * @param prefix 语义前缀，如 `'line'` / `'pie'`；会被归一化，可传任意字符串
 * @returns 可直接用于 `id={...}` 与 `url(#...)` 的字符串，形如 `chart-line-r0`
 *
 * @example
 * const uid = useChartId('line')
 * // 同一页面渲染两个 LineChart，分别得到 chart-line-r0 / chart-line-r7，互不串色
 * <linearGradient id={`${uid}-area-0`} … />
 * <path fill={`url(#${uid}-area-0)`} … />
 */
export function useChartId(prefix: string): string {
  const instanceId = useId()

  return useMemo(() => {
    // 只保留 HTML id 与 CSS 选择器都安全的字符
    const safePrefix = prefix.replace(/[^A-Za-z0-9_-]/g, '-')
    const safeInstance = instanceId.replace(/[^A-Za-z0-9_-]/g, '-')
    return `chart-${safePrefix}-${safeInstance}`
  }, [prefix, instanceId])
}
