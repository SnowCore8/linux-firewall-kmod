import { useMemo } from 'react'
import { Badge, Button, Empty, Flex, List, Popover, Space, Tag, Tooltip, Typography } from 'antd'
import { BellOutlined, CheckOutlined, DeleteOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { useNotify, type NoticeItem, type NoticeType } from '../providers/NotificationProvider.tsx'
import { formatClock } from '../lib/format.ts'

/**
 * 通知中心 —— 顶栏铃铛 + 可回溯列表。
 *
 * 铃铛上的红点数 = 未读条数；点开是最近 50 条（FIFO）。每条可标记已读、全部已读、清空。
 * 带 link 的条目点击即跳转（如「某 IP 威胁升级」跳到它的分析页），把「看到告警」与「去处理」
 * 连成一步，而不是让运维自己去找那个 IP。
 */

const TYPE_META: Record<NoticeType, { color: string; label: string }> = {
  info: { color: 'blue', label: '信息' },
  success: { color: 'green', label: '成功' },
  warning: { color: 'orange', label: '警告' },
  error: { color: 'red', label: '错误' },
}

function NoticeRow({ item, onOpen }: { item: NoticeItem; onOpen: (item: NoticeItem) => void }) {
  const meta = TYPE_META[item.type]
  const clickable = !!item.link
  return (
    <List.Item
      style={{
        padding: '10px 12px',
        cursor: clickable ? 'pointer' : 'default',
        background: item.read ? 'transparent' : 'color-mix(in srgb, var(--fw-brand) 6%, transparent)',
        borderInlineStart: `2px solid ${item.read ? 'transparent' : 'var(--fw-brand)'}`,
      }}
      onClick={() => clickable && onOpen(item)}
      actions={[
        <Typography.Text
          key="time"
          type="secondary"
          style={{ fontSize: 11, fontFamily: 'var(--fw-font-mono)' }}
        >
          {formatClock(item.at)}
        </Typography.Text>,
      ]}
    >
      <List.Item.Meta
        title={
          <Space size={6}>
            <Tag color={meta.color} style={{ marginInlineEnd: 0 }}>
              {meta.label}
            </Tag>
            <Typography.Text strong={!item.read} style={{ fontSize: 13 }}>
              {item.title}
            </Typography.Text>
            {item.source && (
              <Typography.Text type="secondary" style={{ fontSize: 11 }}>
                · {item.source}
              </Typography.Text>
            )}
          </Space>
        }
        description={
          item.message ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {item.message}
            </Typography.Text>
          ) : undefined
        }
      />
    </List.Item>
  )
}

export function NotificationCenter() {
  const { items, unreadCount, markAllRead, markRead, clear } = useNotify()
  const navigate = useNavigate()

  const openItem = useMemo(
    () => (item: NoticeItem) => {
      markRead(item.id)
      if (item.link) navigate(item.link)
    },
    [markRead, navigate],
  )

  const content = (
    <div style={{ width: 360 }}>
      <Flex justify="space-between" align="center" style={{ marginBottom: 8 }}>
        <Typography.Text strong>通知</Typography.Text>
        <Space size={4}>
          <Tooltip title="全部标为已读">
            <Button
              size="small"
              type="text"
              icon={<CheckOutlined />}
              onClick={markAllRead}
              disabled={unreadCount === 0}
            />
          </Tooltip>
          <Tooltip title="清空">
            <Button
              size="small"
              type="text"
              icon={<DeleteOutlined />}
              onClick={clear}
              disabled={items.length === 0}
            />
          </Tooltip>
        </Space>
      </Flex>
      <div style={{ maxHeight: 420, overflowY: 'auto' }}>
        {items.length === 0 ? (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无通知" style={{ padding: 24 }} />
        ) : (
          <List
            dataSource={items}
            split
            renderItem={(item) => <NoticeRow item={item} onOpen={openItem} />}
          />
        )}
      </div>
    </div>
  )

  return (
    <Popover
      content={content}
      trigger="click"
      placement="bottomRight"
      arrow={false}
      onOpenChange={(open) => {
        // 打开面板即视为已读全部（运维看到了就不该再挂红点）
        if (open && unreadCount > 0) markAllRead()
      }}
    >
      <Tooltip title="通知中心">
        <Badge count={unreadCount} size="small" offset={[-2, 2]}>
          <Button type="text" icon={<BellOutlined style={{ fontSize: 16 }} />} aria-label="通知中心" />
        </Badge>
      </Tooltip>
    </Popover>
  )
}
