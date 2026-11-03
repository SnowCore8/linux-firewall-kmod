/**
 * 设计令牌 —— 桌面控制台的视觉单一真相源。
 *
 * 两处消费：
 * 1. `buildTheme()` 产出 antd 6 的 `ThemeConfig`，经 ConfigProvider 注入组件库；
 * 2. 语义色常量（威胁等级、图表调色板、状态色）供 ECharts 与自绘元素直接引用，
 *    保证「组件库主题」与「图表/徽标用色」同源，不会各调各的。
 *
 * 基调：安全运维控制台——暗色优先、高密度、可信。品牌色沿用旧版青色系（teal），
 * 保持产品识别连续性；语义色 success/warning/danger/info 与后端威胁等级一一对应。
 */

import { theme as antdTheme } from 'antd'
import type { ThemeConfig } from 'antd'

/** 外观模式：暗色（默认）/ 亮色 */
export type ThemeMode = 'dark' | 'light'

/** 信息密度：标准 / 紧凑（安全运维常需一屏看更多） */
export type Density = 'standard' | 'compact'

/** 字体族：正文用 IBM Plex Sans，等宽用于 IP / 速率 / 计数（表格数字对齐） */
export const FONT_SANS =
  "'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif"
export const FONT_MONO =
  "'JetBrains Mono', 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace"

/** 品牌主色（teal）——与旧版 --fw-primary-strong 同源，保持识别连续性 */
export const BRAND = '#13aebf'

/** 语义色：与后端威胁等级 / 运行状态对应，全站统一 */
export const SEMANTIC = {
  success: '#2fbf71',
  warning: '#f5a524',
  danger: '#ff5561',
  info: '#4a9eff',
} as const

/**
 * 威胁等级色阶（后端 ThreatLevel.level 的 5 个取值）。
 * safe→critical 由绿到红，中间过渡用黄/橙，便于仪表盘一眼分级。
 */
export const THREAT_COLORS: Record<string, string> = {
  safe: '#3ad98d',
  low: '#9ccc3d',
  medium: '#f5a524',
  high: '#ff8a3d',
  critical: '#ff5561',
}

/** 威胁等级中文标签 */
export const THREAT_LABELS: Record<string, string> = {
  safe: '安全',
  low: '低风险',
  medium: '中风险',
  high: '高风险',
  critical: '严重',
}

/**
 * 威胁等级序：safe < low < medium < high < critical。
 * 用于「等级是否升高」的比较（实时告警、仪表盘箭头方向），避免各处各写一份字符串数组。
 */
export const THREAT_RANK: Record<string, number> = {
  safe: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

/** 取等级序（未知等级按 safe=0 处理，不因脏值误报升级）。 */
export function threatRank(level: string): number {
  return THREAT_RANK[level] ?? 0
}

/** 取等级中文标签（未知等级原样回显，便于发现后端新增了未映射的取值）。 */
export function threatLabel(level: string): string {
  return THREAT_LABELS[level] ?? level
}

/**
 * 图表调色板（8 色，中等明度，暗/亮背景都可读）。
 * ECharts 系列默认按此顺序取色；需要固定语义时用 `chartColor(index)`。
 */
export const CHART_COLORS = [
  '#13aebf',
  '#4a9eff',
  '#3ad98d',
  '#f5a524',
  '#ff8a3d',
  '#b07cff',
  '#ff6b9d',
  '#5ad1c0',
] as const

/** 按序号取图表色（超出长度回绕，保证任意条数都有稳定配色） */
export function chartColor(index: number): string {
  return CHART_COLORS[((index % CHART_COLORS.length) + CHART_COLORS.length) % CHART_COLORS.length]
}

/** 密度对应的控件高度 / 内边距（紧凑模式整体收窄，一屏容纳更多行） */
const DENSITY_METRICS: Record<Density, { controlHeight: number; borderRadius: number }> = {
  standard: { controlHeight: 34, borderRadius: 6 },
  compact: { controlHeight: 28, borderRadius: 5 },
}

/**
 * 构建 antd 6 主题配置。
 *
 * @param mode    暗/亮：选择 antd 的 darkAlgorithm / defaultAlgorithm
 * @param density 标准/紧凑：叠加 compactAlgorithm 并收窄控件高度
 */
export function buildTheme(mode: ThemeMode, density: Density): ThemeConfig {
  const metrics = DENSITY_METRICS[density]
  const algorithms = [mode === 'dark' ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm]
  if (density === 'compact') algorithms.push(antdTheme.compactAlgorithm)

  return {
    algorithm: algorithms,
    token: {
      colorPrimary: BRAND,
      colorSuccess: SEMANTIC.success,
      colorWarning: SEMANTIC.warning,
      colorError: SEMANTIC.danger,
      colorInfo: SEMANTIC.info,
      colorLink: BRAND,
      borderRadius: metrics.borderRadius,
      controlHeight: metrics.controlHeight,
      fontFamily: FONT_SANS,
      fontSize: density === 'compact' ? 13 : 14,
      wireframe: false,
    },
    components: {
      Layout: {
        // 侧边栏与顶栏用比内容区更深的底色，形成层次（暗色下尤为明显）
        siderBg: mode === 'dark' ? '#0a0f16' : '#ffffff',
        headerBg: mode === 'dark' ? '#0b1119' : '#ffffff',
        bodyBg: mode === 'dark' ? '#05080d' : '#f4f6f8',
        headerHeight: 56,
        headerPadding: '0 20px',
      },
      Menu: {
        // 侧边栏菜单：紧凑行高，选中项用品牌色左边条 + 半透明底
        itemHeight: density === 'compact' ? 36 : 42,
        darkItemBg: 'transparent',
        darkSubMenuItemBg: 'transparent',
      },
      Table: {
        headerBg: mode === 'dark' ? '#0e1621' : '#fafafa',
        rowHoverBg: mode === 'dark' ? 'rgba(19,174,191,0.08)' : 'rgba(19,174,191,0.06)',
        cellPaddingBlock: density === 'compact' ? 6 : 12,
        cellPaddingInline: density === 'compact' ? 8 : 16,
      },
      Card: {
        paddingLG: density === 'compact' ? 14 : 20,
      },
    },
  }
}

/**
 * 供 ECharts 使用的主题化基础配置（文字色 / 轴线色 / 背景）。
 * 与 antd token 分开：ECharts 不走 ConfigProvider，需要显式喂色。
 */
export function chartBaseTheme(mode: ThemeMode): {
  textColor: string
  axisLineColor: string
  splitLineColor: string
  backgroundColor: string
} {
  return mode === 'dark'
    ? {
        textColor: '#93a7b6',
        axisLineColor: '#22303f',
        splitLineColor: '#16202c',
        backgroundColor: 'transparent',
      }
    : {
        textColor: '#5a6b7b',
        axisLineColor: '#dfe4e9',
        splitLineColor: '#eef1f4',
        backgroundColor: 'transparent',
      }
}
