import type { EChartsOption } from 'echarts-for-react'
import type { ChartData } from '../api/types.ts'
import type { ChartBase } from '../components/charts/BaseChart.tsx'

/**
 * ECharts option 构造器 —— 把「主题化轴/网格/提示」的重复样式收在一处。
 *
 * 各页只传数据与少量语义参数（名称、颜色、是否面积图），轴线色/文字色/网格边距/tooltip
 * 外观由这里按 ChartBase 统一注入，于是全站折线/柱状/饼/仪表盘的观感一致，改主题只改一处。
 *
 * 返回类型是 EChartsOption（其定义为 any）：ECharts 的 option 结构过于庞大且高度联合，
 * 精确建模收益低、维护成本高，这里刻意保持宽松，形状正确性由渲染结果与手动验收保证。
 */

function grid(defaults = {}) {
  return { left: 8, right: 16, top: 24, bottom: 8, containLabel: true, ...defaults }
}

function tooltip(base: ChartBase, extra = {}) {
  return {
    trigger: 'axis',
    backgroundColor: base.isDark ? '#0e1621' : '#ffffff',
    borderColor: base.axisLineColor,
    borderWidth: 1,
    textStyle: { color: base.textColor, fontSize: 12 },
    axisPointer: { type: 'line', lineStyle: { color: base.axisLineColor } },
    ...extra,
  }
}

function categoryAxis(base: ChartBase, labels: string[], extra = {}) {
  return {
    type: 'category',
    data: labels,
    boundaryGap: false,
    axisLine: { lineStyle: { color: base.axisLineColor } },
    axisTick: { show: false },
    axisLabel: { color: base.textColor, fontSize: 11, hideOverlap: true },
    ...extra,
  }
}

function valueAxis(base: ChartBase, extra = {}) {
  return {
    type: 'value',
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: { color: base.textColor, fontSize: 11 },
    splitLine: { lineStyle: { color: base.splitLineColor } },
    ...extra,
  }
}

/** 折线/面积图（时间序列：封禁趋势、速率历史、失败尝试趋势）。 */
export function lineOption(
  base: ChartBase,
  data: ChartData,
  opts: { name?: string; color?: string; area?: boolean; smooth?: boolean; yName?: string } = {},
): EChartsOption {
  const color = opts.color ?? base.palette[0]
  return {
    grid: grid(),
    tooltip: tooltip(base),
    xAxis: categoryAxis(base, data.labels),
    yAxis: valueAxis(base, opts.yName ? { name: opts.yName, nameTextStyle: { color: base.textColor } } : {}),
    series: [
      {
        name: opts.name ?? '',
        type: 'line',
        smooth: opts.smooth ?? true,
        showSymbol: data.labels.length <= 40,
        symbolSize: 5,
        lineStyle: { color, width: 2 },
        itemStyle: { color },
        areaStyle: opts.area
          ? {
              color: {
                type: 'linear',
                x: 0,
                y: 0,
                x2: 0,
                y2: 1,
                colorStops: [
                  { offset: 0, color: `${color}55` },
                  { offset: 1, color: `${color}00` },
                ],
              },
            }
          : undefined,
        data: data.values,
      },
    ],
  }
}

/** 柱状图（Top 攻击源、jail 分布、端口分布）；horizontal=true 时条形横向。 */
export function barOption(
  base: ChartBase,
  data: ChartData,
  opts: { name?: string; color?: string; horizontal?: boolean; stack?: string } = {},
): EChartsOption {
  const color = opts.color ?? base.palette[1]
  const cat = {
    type: 'category' as const,
    data: data.labels,
    axisLine: { lineStyle: { color: base.axisLineColor } },
    axisTick: { show: false },
    axisLabel: { color: base.textColor, fontSize: 11, hideOverlap: true },
  }
  const val = {
    type: 'value' as const,
    axisLine: { show: false },
    axisTick: { show: false },
    axisLabel: { color: base.textColor, fontSize: 11 },
    splitLine: { lineStyle: { color: base.splitLineColor } },
  }
  return {
    grid: grid(),
    tooltip: tooltip(base, opts.horizontal ? { trigger: 'axis' } : {}),
    xAxis: opts.horizontal ? val : cat,
    yAxis: opts.horizontal ? { ...cat, boundaryGap: true } : val,
    series: [
      {
        name: opts.name ?? '',
        type: 'bar',
        stack: opts.stack,
        barMaxWidth: 28,
        itemStyle: { color, borderRadius: opts.horizontal ? [0, 3, 3, 0] : [3, 3, 0, 0] },
        data: data.values,
      },
    ],
  }
}

/** 饼/环图（jail 占比、失败原因占比）。 */
export function pieOption(
  base: ChartBase,
  items: { name: string; value: number }[],
  opts: { donut?: boolean; legend?: boolean } = {},
): EChartsOption {
  const donut = opts.donut ?? true
  return {
    tooltip: tooltip(base, { trigger: 'item' }),
    legend: opts.legend
      ? { bottom: 0, textStyle: { color: base.textColor, fontSize: 11 }, type: 'scroll' }
      : undefined,
    series: [
      {
        type: 'pie',
        radius: donut ? ['48%', '72%'] : '70%',
        center: ['50%', opts.legend ? '44%' : '50%'],
        avoidLabelOverlap: true,
        itemStyle: { borderColor: base.isDark ? '#0e1621' : '#fff', borderWidth: 2 },
        label: { color: base.textColor, fontSize: 11, formatter: '{b}: {d}%' },
        labelLine: { length: 8, length2: 8 },
        data: items.map((it, i) => ({ ...it, itemStyle: { color: base.palette[i % base.palette.length] } })),
      },
    ],
  }
}

/** 仪表盘（威胁分数 0-100）。value 超 max 时夹到 max。 */
export function gaugeOption(
  base: ChartBase,
  value: number,
  opts: { max?: number; color?: string; label?: string } = {},
): EChartsOption {
  const max = opts.max ?? 100
  const color = opts.color ?? base.palette[0]
  return {
    series: [
      {
        type: 'gauge',
        startAngle: 210,
        endAngle: -30,
        min: 0,
        max,
        radius: '92%',
        progress: { show: true, width: 12, itemStyle: { color } },
        axisLine: { lineStyle: { width: 12, color: [[1, base.splitLineColor]] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        pointer: { show: false },
        anchor: { show: false },
        title: { show: !!opts.label, offsetCenter: [0, '28%'], color: base.textColor, fontSize: 12 },
        detail: {
          valueAnimation: true,
          offsetCenter: [0, 0],
          fontSize: 30,
          fontWeight: 700,
          fontFamily: 'var(--fw-font-mono)',
          color,
          formatter: (v: number) => String(Math.round(v)),
        },
        data: [{ value: Math.min(value, max), name: opts.label ?? '' }],
      },
    ],
  }
}

/** 热力图（24 小时 × 星期 的封禁分布）。 */
export function heatmapOption(
  base: ChartBase,
  opts: { xLabels: string[]; yLabels: string[]; points: [number, number, number][]; max?: number },
): EChartsOption {
  const max = opts.max ?? Math.max(1, ...opts.points.map((p) => p[2]))
  return {
    grid: grid({ top: 12, bottom: 40 }),
    tooltip: tooltip(base, { trigger: 'item' }),
    xAxis: {
      type: 'category',
      data: opts.xLabels,
      splitArea: { show: true },
      axisLabel: { color: base.textColor, fontSize: 10 },
      axisLine: { lineStyle: { color: base.axisLineColor } },
    },
    yAxis: {
      type: 'category',
      data: opts.yLabels,
      splitArea: { show: true },
      axisLabel: { color: base.textColor, fontSize: 10 },
      axisLine: { lineStyle: { color: base.axisLineColor } },
    },
    visualMap: {
      min: 0,
      max,
      calculable: false,
      orient: 'horizontal',
      left: 'center',
      bottom: 0,
      itemWidth: 10,
      itemHeight: 80,
      textStyle: { color: base.textColor, fontSize: 10 },
      inRange: { color: base.isDark ? ['#0e2a30', '#13aebf', '#ff5561'] : ['#e6f7f9', '#13aebf', '#ff5561'] },
    },
    series: [
      {
        type: 'heatmap',
        data: opts.points,
        progressive: 0,
        itemStyle: { borderColor: base.isDark ? '#0b1119' : '#fff', borderWidth: 1 },
      },
    ],
  }
}

/** 雷达图（多维风险向量：7 个维度各归一到 0-1）。 */
export function radarOption(
  base: ChartBase,
  opts: { indicators: { name: string; max?: number }[]; values: number[]; name?: string },
): EChartsOption {
  return {
    tooltip: tooltip(base, { trigger: 'item' }),
    radar: {
      indicator: opts.indicators.map((i) => ({ name: i.name, max: i.max ?? 1 })),
      radius: '66%',
      axisName: { color: base.textColor, fontSize: 11 },
      splitLine: { lineStyle: { color: base.splitLineColor } },
      splitArea: { areaStyle: { color: ['transparent'] } },
      axisLine: { lineStyle: { color: base.axisLineColor } },
    },
    series: [
      {
        type: 'radar',
        data: [
          {
            name: opts.name ?? '',
            value: opts.values,
            areaStyle: { color: `${base.palette[0]}33` },
            lineStyle: { color: base.palette[0], width: 2 },
            itemStyle: { color: base.palette[0] },
          },
        ],
      },
    ],
  }
}
