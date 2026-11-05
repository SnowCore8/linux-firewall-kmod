import type { CSSProperties } from 'react'
import { Alert, Button } from 'antd'

/**
 * 页级陈旧数据提示 —— 持有旧数据但最近一次刷新失败时，明确告诉用户「当前展示的可能不是
 * 最新状态」，避免把过期数据静默当成实时数据。
 *
 * 与 useLiveData 配合：调用方自行判断 `isStale && source !== 'sse'`——SSE 还在推帧时
 * REST 校准失败并不代表数据过期，不该打扰用户；两条来路都断了才是真的陈旧。
 */

export interface StaleNoticeProps {
  visible: boolean
  /** 手动重试（通常接 refetch）。 */
  onRetry?: () => void
  /** 提示正文，默认面向「实时数据」页面。 */
  description?: string
  /** 透传给 Alert 的样式（外边距由调用方按所在布局决定；隐藏时整体不渲染）。 */
  style?: CSSProperties
}

export function StaleNotice({ visible, onRetry, description, style }: StaleNoticeProps) {
  if (!visible) return null
  return (
    <Alert
      type="warning"
      showIcon
      message="数据可能已过期"
      description={
        description ?? '实时推送与后台刷新均未成功，页面展示的是最近一次成功获取的数据。'
      }
      style={style}
      action={
        onRetry ? (
          <Button size="small" type="link" onClick={onRetry}>
            重试
          </Button>
        ) : undefined
      }
    />
  )
}
