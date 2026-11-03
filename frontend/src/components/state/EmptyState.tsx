import type { ReactNode } from 'react'
import { Button, Empty, Space, Typography } from 'antd'
import {
  InboxOutlined,
  SearchOutlined,
  StopOutlined,
  SettingOutlined,
} from '@ant-design/icons'

/**
 * 空态 —— 分场景，而不是千篇一律的「暂无数据」。
 *
 * 四种语义：
 *   * no-data   正常但当前没有记录（如白名单为空）——给一个「新建」引导动作；
 *   * no-results 有数据但被筛选/搜索滤空——给「清除筛选」动作；
 *   * disabled  功能被后端 flag 关闭（如风险引擎未启用）——说明如何开启，不给无效动作；
 *   * needs-config 需要先在配置里开启/填写——引导去设置页。
 * 分场景的意义：同一个「空」在不同语境下用户该做的下一步完全不同，空态要把那一步递到手边。
 */

export type EmptyScenario = 'no-data' | 'no-results' | 'disabled' | 'needs-config'

const SCENARIO_META: Record<EmptyScenario, { icon: ReactNode; defaultTitle: string }> = {
  'no-data': { icon: <InboxOutlined />, defaultTitle: '暂无数据' },
  'no-results': { icon: <SearchOutlined />, defaultTitle: '没有匹配的结果' },
  disabled: { icon: <StopOutlined />, defaultTitle: '功能未启用' },
  'needs-config': { icon: <SettingOutlined />, defaultTitle: '需要先完成配置' },
}

export interface EmptyStateProps {
  scenario?: EmptyScenario
  title?: string
  description?: ReactNode
  /** 引导动作（如「新建封禁」「清除筛选」「去设置」）。 */
  actionLabel?: string
  onAction?: () => void
  /** 额外自定义底部内容（优先于 actionLabel/onAction）。 */
  extra?: ReactNode
}

export function EmptyState({
  scenario = 'no-data',
  title,
  description,
  actionLabel,
  onAction,
  extra,
}: EmptyStateProps) {
  const meta = SCENARIO_META[scenario]

  return (
    <div style={{ padding: '32px 16px', textAlign: 'center' }}>
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        imageStyle={{ height: 48, color: 'var(--fw-text-secondary)' }}
        description={
          <Space direction="vertical" size={4}>
            <Typography.Text strong style={{ fontSize: 14 }}>
              <Space size={6}>
                {meta.icon}
                {title ?? meta.defaultTitle}
              </Space>
            </Typography.Text>
            {description && (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {description}
              </Typography.Text>
            )}
          </Space>
        }
      >
        {extra ??
          (actionLabel && onAction ? (
            <Button type="primary" onClick={onAction}>
              {actionLabel}
            </Button>
          ) : null)}
      </Empty>
    </div>
  )
}
