// 页内区块标题：视图内部的分组标题 + 说明 + 右侧操作
//
// 与 AppShell 顶栏的分工：顶栏（h1）只放「当前页面名称」，本组件（h2）承载
// 页面内部的分区标题 —— 二者不同级，也不会出现两个并列的一级标题。
//
// 控制台形态：11px 字距加宽的小标题 + 左侧 2px 强调色方块（与面板头同一套语言，
// 见 global.css 的 .fw-panel-head::before），副标题降一档到 10px 弱化色。
// 字号刻意小于顶栏标题：一屏要放下的信息更多，层级靠颜色与字距区分而不是靠放大。
//
// 无障碍与 E2E：标题必须是 h2 且文本就是 title 本身（装饰方块放在 h2 之外，
// 不会混进可访问名），否则按标题检索的用例会失配。
import type { CSSProperties, ReactNode } from 'react'

export interface PageHeaderProps {
  /** 区块标题（必填） */
  title: ReactNode
  /** 副标题：放统计口径、时间范围等限定信息 */
  subtitle?: ReactNode
  /** 右侧操作区（切换器、状态标等窄元素；不放刷新按钮——刷新只走顶栏与下拉手势） */
  extra?: ReactNode
  /** 标题下方的补充内容（说明文字、图例） */
  children?: ReactNode
  /**
   * 标题与顶栏（h1）文字相同时置为 true：视觉上不再重复显示同名标题。
   *
   * 为什么不能直接删掉：读屏器需要标题层级、e2e 按 h2 文本断言（两者都要求
   * 它存在于 DOM）。因此改为只读屏可见（.fw-sr-only），副标题与操作区照常显示——
   * 顶栏已经告诉用户「这是哪一页」，再重复一行同名标题纯属噪音。
   */
  srOnly?: boolean
  style?: CSSProperties
}

export function PageHeader({ title, subtitle, extra, children, srOnly = false, style }: PageHeaderProps) {
  return (
    <div style={{ marginBottom: 5, ...style }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 5,
          // 标题只读屏可见时不占位，操作区独自靠右，避免左边留一段空白
          justifyContent: srOnly ? 'flex-end' : undefined,
        }}
      >
        {/* 强调色方块：与面板头对齐的视觉锚点，纯装饰，不进可访问名 */}
        {srOnly ? null : (
          <span
            aria-hidden="true"
            style={{
              width: 2,
              height: 10,
              flexShrink: 0,
              background: 'var(--fw-primary-strong)',
            }}
          />
        )}
        <h2
          className={srOnly ? 'fw-sr-only' : undefined}
          style={
            srOnly
              ? { margin: 0 }
              : {
                  flex: 1,
                  minWidth: 0,
                  margin: 0,
                  fontSize: 11,
                  fontWeight: 600,
                  letterSpacing: '0.06em',
                  color: 'var(--fw-text-2)',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }
          }
        >
          {title}
        </h2>
        {extra ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
            {extra}
          </div>
        ) : null}
      </div>
      {subtitle ? (
        <p
          style={{
            margin: '1px 0 0',
            marginLeft: srOnly ? 0 : 7,
            fontSize: 10,
            lineHeight: 1.4,
            color: 'var(--fw-text-3)',
          }}
        >
          {subtitle}
        </p>
      ) : null}
      {children}
    </div>
  )
}

export default PageHeader
