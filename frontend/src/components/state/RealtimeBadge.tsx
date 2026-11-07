import { useEffect, useState } from 'react'
import { Tooltip } from 'antd'
import type { SseConnectionState } from '../../hooks/useSse.ts'

/**
 * 实时状态徽标 —— 把 SSE 连接生命周期翻译成一个「灯 + 文案」，全站统一。
 *
 * 六种连接态对应六种视觉：open=绿(实时)、connecting/reconnecting=青闪(连接中)、
 * limit=橙(已达上限、已降级轮询)、idle=灰(未启用)、closed=灰(已关闭)。
 * 传入 `lastEventAt` 时附一个「x 秒前」的新鲜度尾标，让运维知道数据有多新——
 * 一个静止的绿色灯并不能证明数据还在动。
 */

const STATE_META: Record<
  SseConnectionState,
  { color: string; label: string; pulse: boolean; tip: string }
> = {
  open: { color: 'var(--fw-success)', label: '实时', pulse: true, tip: '实时流已连接，数据随事件更新' },
  connecting: {
    color: 'var(--fw-brand)',
    label: '连接中',
    pulse: true,
    tip: '正在建立实时连接',
  },
  reconnecting: {
    color: 'var(--fw-brand)',
    label: '重连中',
    pulse: true,
    tip: '实时连接断开，正在按退避重连',
  },
  limit: {
    color: 'var(--fw-warning)',
    label: '已降级',
    pulse: false,
    tip: '实时连接数已达上限，改用 REST 轮询刷新',
  },
  exhausted: {
    color: 'var(--fw-danger)',
    label: '已断开',
    pulse: false,
    tip: '实时连接已断开，自动重连次数耗尽，请点击重试按钮手动重连',
  },
  idle: { color: 'var(--fw-text-secondary)', label: '未连接', pulse: false, tip: '实时流未启用（未登录或已关闭）' },
  closed: { color: 'var(--fw-text-secondary)', label: '已关闭', pulse: false, tip: '实时流已关闭' },
}

/** 把毫秒时刻转成「x 秒前 / x 分钟前」；0 或未来时刻回空串。 */
function freshnessText(at: number, now: number): string {
  if (at <= 0) return ''
  const secs = Math.max(0, Math.round((now - at) / 1000))
  if (secs < 5) return '刚刚'
  if (secs < 60) return `${secs} 秒前`
  const mins = Math.round(secs / 60)
  if (mins < 60) return `${mins} 分钟前`
  return `${Math.round(mins / 60)} 小时前`
}

export interface RealtimeBadgeProps {
  state: SseConnectionState
  /** 最近一帧到达时刻（ms epoch）；缺省则不显示新鲜度尾标。 */
  lastEventAt?: number
  /** 进入断开态的时刻（ms epoch）；exhausted 态时显示「已断开 X 分钟」。 */
  disconnectedAt?: number
  /** 是否显示文案（false 时只剩一个灯，用于空间紧凑处）。 */
  showLabel?: boolean
  /** 是否显示新鲜度尾标。 */
  showFreshness?: boolean
}

export function RealtimeBadge({
  state,
  lastEventAt = 0,
  disconnectedAt = 0,
  showLabel = true,
  showFreshness = true,
}: RealtimeBadgeProps) {
  const meta = STATE_META[state]
  // 每秒重算新鲜度文案（否则「x 秒前」会冻在渲染那一刻）
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!showFreshness || lastEventAt <= 0) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [showFreshness, lastEventAt])

  const fresh = showFreshness && lastEventAt > 0 ? freshnessText(lastEventAt, now) : ''
  const disconnectedText =
    state === 'exhausted' && disconnectedAt > 0 ? freshnessText(disconnectedAt, now) : ''

  return (
    <Tooltip title={meta.tip}>
      <span
        className="fw-realtime-badge"
        role="status"
        aria-label={`实时连接状态：${meta.label}`}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
      >
        <span
          className={meta.pulse ? 'fw-dot fw-dot--pulse' : 'fw-dot'}
          style={{ background: meta.color }}
          aria-hidden
        />
        {showLabel && <span style={{ fontSize: 12, color: 'var(--fw-text-secondary)' }}>{meta.label}</span>}
        {fresh && <span style={{ fontSize: 12, color: 'var(--fw-text-secondary)', opacity: 0.7 }}>{fresh}</span>}
        {disconnectedText && (
          <span style={{ fontSize: 12, color: 'var(--fw-danger)', opacity: 0.9 }}>{disconnectedText}</span>
        )}
      </span>
    </Tooltip>
  )
}
