import { useMemo } from 'react'
import ReactECharts from 'echarts-for-react'
import type { EChartsOption } from 'echarts-for-react'
import { EmptyState } from '../state/EmptyState.tsx'
import { useTheme } from '../../providers/ThemeProvider.tsx'
import { CHART_COLORS, chartBaseTheme } from '../../theme/tokens.ts'

/**
 * 图表基座 —— 全站 ECharts 的唯一渲染入口。
 *
 * 集中三件事，保证「所有图看起来是一套的」：
 *   1. 主题：调色板（CHART_COLORS）、文字色、透明背景随明暗主题切换，不散落到各图各配；
 *   2. 空态：无数据时渲染设计系统的 EmptyState 而不是画一张空坐标轴（空轴会误导成「值为 0」）；
 *   3. 加载/尺寸：统一的 loading 遮罩、autoResize、canvas 渲染器与默认高度。
 *
 * option 由调用方用 `useChartBase()` 拿到的轴色/文字色自行拼装——基座只负责「主题外壳」，
 * 具体图形（line/bar/pie/radar/heatmap/gauge）的形状知识留在各页的 option 构造里。
 */

export interface ChartBase {
  textColor: string
  axisLineColor: string
  splitLineColor: string
  palette: readonly string[]
  isDark: boolean
}

/** 供各页构造 option 时取用的主题化基色（轴线/文字/调色板）。 */
export function useChartBase(): ChartBase {
  const { mode } = useTheme()
  return useMemo(() => {
    const base = chartBaseTheme(mode)
    return {
      textColor: base.textColor,
      axisLineColor: base.axisLineColor,
      splitLineColor: base.splitLineColor,
      palette: CHART_COLORS,
      isDark: mode === 'dark',
    }
  }, [mode])
}

export interface BaseChartProps {
  option: EChartsOption
  /** 图表高度（px 或 CSS 长度）。 */
  height?: number | string
  /** 无数据时展示空态而非空坐标轴。 */
  empty?: boolean
  emptyText?: string
  loading?: boolean
  /** ECharts 事件绑定（如点击柱子弹详情）。 */
  onEvents?: Record<string, (params: unknown) => void>
}

export function BaseChart({
  option,
  height = 260,
  empty = false,
  emptyText = '暂无图表数据',
  loading = false,
  onEvents,
}: BaseChartProps) {
  const { mode } = useTheme()

  // 主题对象按 mode memo：identity 稳定，避免每次渲染都触发 ECharts 重新初始化
  const theme = useMemo(() => {
    const base = chartBaseTheme(mode)
    return {
      color: [...CHART_COLORS],
      backgroundColor: base.backgroundColor,
      textStyle: { color: base.textColor, fontFamily: 'var(--fw-font-sans)' },
    }
  }, [mode])

  if (empty && !loading) {
    return (
      <div style={{ height: typeof height === 'number' ? height : undefined, minHeight: 160 }}>
        <EmptyState scenario="no-data" title={emptyText} />
      </div>
    )
  }

  return (
    <ReactECharts
      option={option}
      theme={theme}
      notMerge
      lazyUpdate
      showLoading={loading}
      autoResize
      opts={{ renderer: 'canvas' }}
      onEvents={onEvents}
      style={{ height: typeof height === 'number' ? `${height}px` : height, width: '100%' }}
    />
  )
}
