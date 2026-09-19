// 页内区块标题：用于视图内部的分组标题 + 说明 + 右侧操作
//
// 与 AppShell 顶栏的分工：顶栏（h1）只放「当前页面名称」，本组件（h2）承载
// 页面内部的分区标题，从而避免同一页出现两个同级的标题、也不与 antd-mobile
// NavBar 争抢返回按钮。
import type { CSSProperties, ReactNode } from 'react'

export interface PageHeaderProps {
  /** 区块标题（必填） */
  title: ReactNode
  /** 副标题：放统计口径、时间范围等限定信息 */
  subtitle?: ReactNode
  /** 右侧操作区（刷新按钮、切换器等窄元素） */
  extra?: ReactNode
  /** 标题下方的补充内容（说明文字、图例） */
  children?: ReactNode
  style?: CSSProperties
}

export function PageHeader({ title, subtitle, extra, children, style }: PageHeaderProps) {
  return (
    <div style={{ marginBottom: 7, ...style }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
        <h2
          style={{
            flex: 1,
            minWidth: 0,
            margin: 0,
            fontSize: 15,
            fontWeight: 600,
            color: 'var(--fw-text)',
          }}
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
        <p style={{ margin: '2px 0 0', fontSize: 12, lineHeight: 1.5, color: 'var(--fw-text-3)' }}>
          {subtitle}
        </p>
      ) : null}
      {children}
    </div>
  )
}

export default PageHeader
