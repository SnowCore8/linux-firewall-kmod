import type { ReactNode } from 'react'
import { Breadcrumb, Flex, Space, Typography } from 'antd'
import { Link } from 'react-router-dom'
import { RealtimeBadge } from './state/RealtimeBadge.tsx'
import type { SseConnectionState } from '../hooks/useSse.ts'

/**
 * 页面标题区 —— 每页统一的顶部：面包屑 + 标题 + 说明 + 上下文操作 + 实时徽标。
 *
 * 统一的理由：运维在多页之间来回切，标题区的**结构**固定（左标题右操作），眼睛不用每页重新
 * 找「刷新在哪、新建在哪、数据新不新」。实时徽标放在标题右侧，让「这页数据是不是活的」一眼可见。
 *
 * 面包屑用 react-router 的 hash 路由链接；最后一项是当前页（不可点）。
 */

export interface BreadcrumbItem {
  title: string
  /** 提供 path 则可点击跳转；省略表示当前页（末项）。 */
  path?: string
}

export interface PageHeaderProps {
  title: ReactNode
  /** 一句话说明这页是干什么的（次要文字色）。 */
  description?: ReactNode
  breadcrumb?: BreadcrumbItem[]
  /** 右侧操作区（刷新、新建、筛选等按钮）。 */
  extra?: ReactNode
  /** 传入则渲染实时徽标。 */
  realtimeState?: SseConnectionState
  realtimeLastEventAt?: number
  realtimeDisconnectedAt?: number
  /** 标题下方的一整行自定义内容（如全局筛选工具条）。 */
  footer?: ReactNode
}

export function PageHeader({
  title,
  description,
  breadcrumb,
  extra,
  realtimeState,
  realtimeLastEventAt,
  realtimeDisconnectedAt,
  footer,
}: PageHeaderProps) {
  return (
    <div className="fw-page-header">
      {breadcrumb && breadcrumb.length > 0 && (
        <Breadcrumb
          style={{ marginBottom: 8, fontSize: 12 }}
          items={breadcrumb.map((item) => ({
            title: item.path ? <Link to={item.path}>{item.title}</Link> : item.title,
          }))}
        />
      )}
      <Flex justify="space-between" align="flex-start" gap={16} wrap="wrap">
        <Space direction="vertical" size={2} style={{ minWidth: 0 }}>
          <Flex align="center" gap={12} wrap="wrap">
            <Typography.Title level={4} style={{ margin: 0 }}>
              {title}
            </Typography.Title>
            {realtimeState && (
              <RealtimeBadge state={realtimeState} lastEventAt={realtimeLastEventAt} disconnectedAt={realtimeDisconnectedAt} />
            )}
          </Flex>
          {description && (
            <Typography.Text type="secondary" style={{ fontSize: 13 }}>
              {description}
            </Typography.Text>
          )}
        </Space>
        {extra && <Space size={8} wrap>{extra}</Space>}
      </Flex>
      {footer && <div style={{ marginTop: 12 }}>{footer}</div>}
    </div>
  )
}
