// 控制台原语：设计系统在代码侧的落点
//
// 做什么：把「面板 / 数据行 / 徽标 / 细条计量 / 指标瓦片 / 行内迷你图 / 判决条」
//        这几个排版单位做成组件。视图层只拼装它们，不各写一套内联样式。
// 影响什么：纯展示组件——不取数、不发请求、不写状态；样式全部来自 styles/global.css
//          的 fw-* 类，因此主题切换与密度调整只需改一处。
//
// 为什么单独一个文件而不是七个：这些原语总是一起用（面板里放行、行里放徽标），
// 放一起便于一眼看出整套排版语言的形状；它们之间没有依赖方向问题。

import { Skeleton } from 'antd-mobile'
import { LeftOutline } from 'antd-mobile-icons'
import type { CSSProperties, ReactNode } from 'react'

/** 语义色调：所有原语共用（对应 --fw-* 语义色） */
export type Tone = 'default' | 'primary' | 'success' | 'warning' | 'danger'

/** 色调 → CSS 颜色值；default 走普通正文色 */
export function toneColor(tone: Tone = 'default'): string {
  switch (tone) {
    case 'primary':
      return 'var(--fw-primary-strong)'
    case 'success':
      return 'var(--fw-success)'
    case 'warning':
      return 'var(--fw-warning)'
    case 'danger':
      return 'var(--fw-danger)'
    default:
      return 'var(--fw-text)'
  }
}

// ---------------------------------------------------------------------------
// 面板
// ---------------------------------------------------------------------------

export interface PanelProps {
  /** 面板标题（11px 大写感的短标签） */
  title: ReactNode
  /** 标题右侧的元信息（等宽小字，如计数、时间范围） */
  meta?: ReactNode
  /** 标题右侧的自定义内容（优先级高于 meta；用于放按钮） */
  extra?: ReactNode
  /** 是否给内容套默认内边距；表格/瓦片类内容应传 false 自行控制 */
  padded?: boolean
  children: ReactNode
  style?: CSSProperties
}

/**
 * 控制台面板：发丝边框 + 22px 细条标题栏（左侧强调色方块）。
 *
 * 与 antd-mobile Card 的区别：无内边距假设、无圆角、标题是细条而非大标题——
 * 一屏能放下更多面板，且面板之间靠边框分组而不是空白。
 */
export function Panel({ title, meta, extra, padded = true, children, style }: PanelProps) {
  return (
    <section className="fw-panel" style={style}>
      <header className="fw-panel-head">
        <span className="fw-panel-title">{title}</span>
        {extra ?? (meta !== undefined && meta !== null ? <span className="fw-panel-meta">{meta}</span> : null)}
      </header>
      {padded ? <div className="fw-panel-body">{children}</div> : children}
    </section>
  )
}

// ---------------------------------------------------------------------------
// 数据行
// ---------------------------------------------------------------------------

export interface RowProps {
  /** 左侧标签（dim、固定列宽，保证多行数值对齐） */
  label: ReactNode
  /** 右侧数值；不传则标签占满整行（用于纯说明行） */
  value?: ReactNode
  /** 数值后的单位（比数值更暗一档） */
  unit?: ReactNode
  /** 数值色调 */
  tone?: Tone
  /** 行尾附加内容（如迷你图、徽标） */
  tail?: ReactNode
  /** 标签列加宽（长标签用） */
  wide?: boolean
  style?: CSSProperties
}

/**
 * 数据行：本设计系统最核心的排版单位。
 *
 * 结构是「标签 dim + 数值亮（等宽、右对齐）」——多行叠起来数值列自然对齐，
 * 这正是控制台「可扫读」的来源。
 */
export function Row({ label, value, unit, tone = 'default', tail, wide, style }: RowProps) {
  return (
    <div className="fw-row" style={style}>
      <span className={`fw-row-label${wide ? ' fw-row-label-wide' : ''}`}>{label}</span>
      {value !== undefined && value !== null ? (
        <>
          <span className="fw-row-value" style={{ color: toneColor(tone) }}>
            {value}
          </span>
          {unit !== undefined && unit !== null ? <span className="fw-row-unit">{unit}</span> : null}
        </>
      ) : null}
      {tail ? <span className="fw-row-spark">{tail}</span> : null}
    </div>
  )
}

/** 数据行容器：负责去掉末行的分隔线与裁掉溢出 */
export function Rows({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return (
    <div className="fw-rows" style={style}>
      {children}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 徽标 / 细条计量
// ---------------------------------------------------------------------------

export interface BadgeProps {
  children: ReactNode
  tone?: Tone
  /** 弱化显示（用于次要标） */
  dim?: boolean
}

/** 终端风格状态标：`[ TEXT ]`，边框与文字同色 */
export function Badge({ children, tone = 'default', dim }: BadgeProps) {
  return (
    <span className={`fw-badge${dim ? ' fw-badge-dim' : ''}`} style={{ color: toneColor(tone) }}>
      {children}
    </span>
  )
}

export interface MeterProps {
  /** 填充比例（0~1，超出会被截到 1） */
  ratio: number
  tone?: Tone
}

/**
 * 细条计量（3px）：比进度条更薄，在密集列表里不抢视线。
 * 文本数值必须另行给出——只靠条长判断数量是不可读的。
 */
export function Meter({ ratio, tone = 'primary' }: MeterProps) {
  const clamped = Number.isFinite(ratio) ? Math.min(Math.max(ratio, 0), 1) : 0
  return (
    <div className="fw-meter">
      <div
        className="fw-meter-fill"
        style={{ width: `${clamped * 100}%`, background: toneColor(tone) }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// 指标瓦片
// ---------------------------------------------------------------------------

export interface TileProps {
  label: ReactNode
  value: ReactNode
  unit?: ReactNode
  tone?: Tone
}

/** 指标瓦片：label 小字 + value 等宽大字（可带单位） */
export function Tile({ label, value, unit, tone = 'default' }: TileProps) {
  return (
    <div className="fw-tile">
      <span className="fw-tile-label">{label}</span>
      <span className="fw-tile-value" style={{ color: toneColor(tone) }}>
        {value}
        {unit !== undefined && unit !== null ? <span className="fw-tile-unit"> {unit}</span> : null}
      </span>
    </div>
  )
}

/** 瓦片网格容器：列数固定为 2 或 3（1px 缝充当分隔线） */
export function Tiles({
  columns = 2,
  children,
  style,
}: {
  columns?: 2 | 3
  children: ReactNode
  style?: CSSProperties
}) {
  return (
    <div className={`fw-tiles fw-tiles-${columns}`} style={style}>
      {children}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 行内迷你图
// ---------------------------------------------------------------------------

export interface SparkProps {
  /** 数值序列（旧的在前）；少于 2 个点时不画，返回占位 */
  values: number[]
  width?: number
  height?: number
  tone?: Tone
  /** 是否填充面积（默认填，控制台的迷你趋势常用面积表示量级） */
  area?: boolean
}

/**
 * 行内迷你图（sparkline）：贴在数据行里表示「最近的走势」。
 *
 * 与 charts/LineChart 的分工：LineChart 是有坐标轴、可交互的主图；
 * Spark 是 12×32px 的无轴缩略图，只表达形状，不表达精确数值——
 * 因为它旁边永远紧挨着精确数字，重复坐标系反而挤占密度。
 */
export function Spark({ values, width = 46, height = 14, tone = 'primary', area = true }: SparkProps) {
  if (values.length < 2) return null

  const max = Math.max(...values)
  const min = Math.min(...values)
  // 全平序列（max == min）画在中线，否则会除以 0
  const span = max - min
  const stepX = width / (values.length - 1)
  const y = (v: number): number =>
    span === 0 ? height / 2 : height - ((v - min) / span) * (height - 2) - 1

  const line = values.map((v, i) => `${(i * stepX).toFixed(1)},${y(v).toFixed(1)}`).join(' ')
  const color = toneColor(tone)

  return (
    <svg
      className="fw-row-spark"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
      focusable="false"
    >
      {area ? (
        <polygon
          points={`0,${height} ${line} ${width},${height}`}
          fill={color}
          opacity={0.16}
        />
      ) : null}
      <polyline points={line} fill="none" stroke={color} strokeWidth={1.2} strokeLinejoin="round" />
    </svg>
  )
}

// ---------------------------------------------------------------------------
// 判决条
// ---------------------------------------------------------------------------

export interface VerdictProps {
  /** 一句结论（等宽大字，如 NOMINAL / ALERT） */
  text: string
  tone?: Tone
  /** 结论下方的补充说明 */
  sub?: ReactNode
  /** 右侧内容（通常是关键数字） */
  right?: ReactNode
}

/**
 * 判决条：整页唯一允许放大字号的地方（22px）。
 *
 * 控制台的信息密度很高，但「现在到底有没有事」必须一眼可得——
 * 这条把结论从密集数据里单独提出来，其余面板只作为它的证据。
 */
export function Verdict({ text, tone = 'default', sub, right }: VerdictProps) {
  return (
    <div className="fw-verdict">
      <span className="fw-dot" style={{ color: toneColor(tone) }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="fw-verdict-text" style={{ color: toneColor(tone) }}>
          {text}
        </div>
        {sub ? <div className="fw-verdict-sub">{sub}</div> : null}
      </div>
      {right ? <div style={{ flexShrink: 0, textAlign: 'right' }}>{right}</div> : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 分节小标题
// ---------------------------------------------------------------------------

/** 面板内部的次级分组标题（比面板头更轻，只用字距与颜色区分） */
export function SubHead({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="fw-subhead">
      <span style={{ flex: 1, minWidth: 0 }}>{children}</span>
      {right ? <span className="fw-panel-meta">{right}</span> : null}
    </div>
  )
}

// ---------------------------------------------------------------------------
// 分区切换 / 说明行 / 行内错误 / 返回入口
//
// 这四件原本在 Ddos 与 Logs 各写一份（同一样式两份代码），现收进原语层：
// 页面之间的「同一个控件长得不一样」正是从这类复制开始的。
// ---------------------------------------------------------------------------

/** 当页数值转可展示文案：client 抛出的 ApiError 是 Error 子类，其余原样转换 */
export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

export interface SegTabsProps<T extends string> {
  /** 无障碍分组名（读屏器读出「×× 选项卡」） */
  label: string
  items: ReadonlyArray<{ label: string; value: T }>
  value: T
  onChange: (next: T) => void
}

/**
 * 分区切换（选项卡条）：等分、发丝边、激活项用底部 2px 强调色。
 *
 * 为什么不用 antd-mobile 的 Selector：全局样式把 Selector 每格压到 ~24px 高，
 * 低于触摸目标下限。本组件保持「11px 字、方角、发丝边」的密度，同时把每格
 * 高度固定到 --fw-tap，让密度与触摸目标互不妥协。
 */
export function SegTabs<T extends string>({ label, items, value, onChange }: SegTabsProps<T>) {
  return (
    <div
      role="tablist"
      aria-label={label}
      style={{
        display: 'flex',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-radius)',
        background: 'var(--fw-surface)',
        overflow: 'hidden',
      }}
    >
      {items.map((item) => {
        const active = item.value === value
        return (
          <button
            key={item.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(item.value)}
            style={{
              flex: '1 1 0',
              minWidth: 0,
              minHeight: 'var(--fw-tap)', // 触摸目标下限，不随密度压缩
              padding: '0 2px',
              border: 0,
              // 底部 2px 强调色：激活态的主要视觉信号，比整块反色更省注意力
              borderBottom: `2px solid ${active ? 'var(--fw-primary-strong)' : 'transparent'}`,
              background: active ? 'var(--fw-primary-soft)' : 'transparent',
              color: active ? 'var(--fw-primary-strong)' : 'var(--fw-text-3)',
              fontFamily: 'var(--fw-font-mono)',
              fontSize: 11,
              fontWeight: active ? 700 : 400,
              letterSpacing: '0.02em',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              cursor: 'pointer',
            }}
          >
            {item.label}
          </button>
        )
      })}
    </div>
  )
}

/** 面板内的 dim 说明行（口径、阈值、操作提示），比正文弱一档 */
export function Note({ children, tone = 'default' }: { children: ReactNode; tone?: Tone }) {
  return (
    <div
      style={{
        padding: '3px 6px 4px',
        fontSize: 10,
        lineHeight: 1.45,
        color: tone === 'default' ? 'var(--fw-text-3)' : toneColor(tone),
      }}
    >
      {children}
    </div>
  )
}

/**
 * 面板内的加载占位：骨架条。
 *
 * 全站统一用骨架而不是「读取中…」一行字：骨架的灰块位置与随后出现的内容一致，
 * 数据到达时不会跳版；一行文字则会让面板先矮后高。行数由调用方按该面板的实际
 * 行数量给，避免所有面板都撑成同一高度。
 */
export function PanelLoading({ lines = 4 }: { lines?: number }) {
  return (
    <div style={{ padding: 6 }}>
      <Skeleton.Paragraph lineCount={lines} animated />
    </div>
  )
}

/**
 * 行内错误：如实暴露失败原因并给出重试，禁止用空态掩盖数据错误。
 *
 * 与 NoticeBar 的分工：NoticeBar 用于「流内提示」（如写操作结果），本组件是
 * 「这一格取数失败」的专用形态——红色横幅 + 44px 重试按钮，且不依赖组件库。
 */
export function InlineError({ message, onRetry }: { message: ReactNode; onRetry?: () => void }) {
  return (
    <div className="fw-banner fw-banner-danger" role="alert" style={{ alignItems: 'center', gap: 6 }}>
      <span style={{ flex: 1, minWidth: 0 }}>{message}</span>
      {onRetry ? (
        <button type="button" className="fw-cmd" onClick={onRetry}>
          重试
        </button>
      ) : null}
    </div>
  )
}

/**
 * 返回入口：二级页（Jail / 日志 / 设置）回到收纳它们的「更多」。
 *
 * 全站统一样式与位置——页面头部左上角、.fw-cmd 方角按钮、文案「← 更多」。
 * 不用 antd-mobile 的 NavBar：那是一条 45px 高的独立标题栏，会让二级页与
 * 一级页的头部结构完全不同（二级页多出一整条），这正是「不像一家」的来源。
 */
export function BackLink({ onClick }: { onClick: () => void }) {
  return (
    <button type="button" className="fw-cmd" aria-label="返回更多页面" onClick={onClick}>
      <LeftOutline /> 更多
    </button>
  )
}

/**
 * 页面工具条：横向一行，左端可放返回入口，右端放本页动作。
 *
 * 位置统一在 PageHeader 之上（页面最顶部）、不随下拉刷新移动；一级页不渲染它，
 * 二级页渲染且左端固定是 BackLink。
 */
export function Toolbar({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 5,
        marginBottom: 'var(--fw-gap)',
        minHeight: 'var(--fw-tap)',
      }}
    >
      {children}
    </div>
  )
}
