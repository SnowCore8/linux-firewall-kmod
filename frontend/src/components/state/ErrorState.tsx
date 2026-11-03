import { Button, Result, Space, Typography } from 'antd'
import type { ApiError, ApiErrorKind } from '../../api/client.ts'

/**
 * 错误态 —— 按错误种类给可读文案 + 恰当的重试动作，而不是把原始堆栈甩给用户。
 *
 * 分类（与 client.ts 的 ApiErrorKind 对齐）：
 *   * network/timeout  连不上或超时 → 「检查守护进程/网络」+ 重试（值得重试）；
 *   * unauthorized     401 → 提示会跳登录（重试无意义，交给 AuthProvider 自动登出）；
 *   * business         服务端业务码 → 原样透出后端 message（如「IP 非法」「不在表中」）；
 *   * http/parse       其它非 2xx / 响应体损坏 → 通用文案 + 重试。
 * 401 时不显示重试按钮：令牌已废，重试只会再吃一次 401，正确动作是重新登录。
 */

const KIND_META: Record<
  ApiErrorKind,
  { status: 'warning' | 'error' | 'info'; title: string; fallback: string; retryable: boolean }
> = {
  network: { status: 'warning', title: '无法连接', fallback: '连不上守护进程，请确认服务在运行、网络可达', retryable: true },
  timeout: { status: 'warning', title: '请求超时', fallback: '守护进程响应超时，可能负载过高', retryable: true },
  unauthorized: { status: 'info', title: '需要重新登录', fallback: '登录状态已失效，请重新认证', retryable: false },
  business: { status: 'error', title: '操作未成功', fallback: '服务端拒绝了该请求', retryable: false },
  http: { status: 'error', title: '服务异常', fallback: '服务端返回了错误状态', retryable: true },
  parse: { status: 'error', title: '数据损坏', fallback: '响应体不是合法数据，可能是版本不匹配', retryable: true },
  aborted: { status: 'info', title: '已取消', fallback: '请求被取消', retryable: false },
}

export interface ErrorStateProps {
  error: ApiError | null
  /** 重试回调；错误可重试时显示按钮。 */
  onRetry?: () => void
  /** 紧凑模式（表格内联错误条，而非整块 Result）。 */
  compact?: boolean
}

export function ErrorState({ error, onRetry, compact = false }: ErrorStateProps) {
  if (!error) return null
  const meta = KIND_META[error.kind]
  const message = error.message || meta.fallback
  const showRetry = meta.retryable && !!onRetry

  if (compact) {
    return (
      <Space
        style={{
          width: '100%',
          padding: '10px 12px',
          border: '1px solid var(--fw-border)',
          borderRadius: 6,
          background: 'color-mix(in srgb, var(--fw-danger) 8%, transparent)',
        }}
      >
        <Typography.Text type="danger" style={{ fontSize: 13 }}>
          {meta.title}：{message}
        </Typography.Text>
        {showRetry && (
          <Button size="small" type="link" onClick={onRetry}>
            重试
          </Button>
        )}
      </Space>
    )
  }

  return (
    <Result
      status={meta.status}
      title={meta.title}
      subTitle={message}
      extra={
        showRetry ? (
          <Button type="primary" onClick={onRetry}>
            重试
          </Button>
        ) : undefined
      }
    />
  )
}
