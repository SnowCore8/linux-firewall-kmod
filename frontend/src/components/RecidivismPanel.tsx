// 封禁复发分析面板：复发率 + 复发 IP TOP 列表
//
// 数据来源：`GET /api/v1/stats/recidivism`（后端 src/daemon/web_ui/stats.rs 的
// `get_ban_recidivism()`）。响应类型直接复用 api/types.ts 中由 Rust 推导的模型，
// 不在本文件重复声明，避免同一份服务端契约出现两套字段定义。
// 与「当前封禁列表」不同，这里是**历史**维度：只有被解封后再次被封的 IP 才算复发
// （ban_count >= 2），因此必须走 REST 而不是 SSE 实时推送，且需要手动刷新才更新。
//
// 无 props 也能用（数据自取），调用方直接 <RecidivismPanel /> 即可。
import { Button, SpinLoading, Tag } from 'antd-mobile'
import { ExclamationTriangleOutline } from 'antd-mobile-icons'
import type { CSSProperties } from 'react'

import { getJson } from '../api/client'
import type { RecidivismResponse } from '../api/types'
import { useAsync } from '../hooks/useAsync'
import { EmptyState } from './EmptyState'
import { PageHeader } from './PageHeader'
import { StatCard } from './StatCard'

/** 端点：复发率统计（见 handler.rs 的 `/api/v1/stats/recidivism`） */
const RECIDIVISM_ENDPOINT = '/api/v1/stats/recidivism'

export interface RecidivismPanelProps {
  /** TOP 列表展示条数，默认 10（后端最多也只返回 10 条） */
  limit?: number
}

/** 把 Unix 秒格式化成移动端易读的时间；无意义值返回「—」 */
function formatBannedAt(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '—'

  const date = new Date(seconds * 1000)
  const now = new Date()
  const hhmm = `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`
  const sameDay =
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate()

  return sameDay ? `今天 ${hhmm}` : `${date.getMonth() + 1}-${date.getDate()} ${hhmm}`
}

/** 复发率 → 结论与配色（阈值口径在这里集中定义，便于与后端策略对齐） */
function describeRate(rate: number): { color: string; verdict: string } {
  if (rate >= 30) {
    return { color: 'var(--fw-danger)', verdict: '复发率偏高，建议延长基础封禁时长或缩短检测窗口' }
  }
  if (rate >= 10) {
    return { color: 'var(--fw-warning)', verdict: '复发率处于可接受范围，渐进式封禁策略运行正常' }
  }
  return { color: 'var(--fw-success)', verdict: '复发率很低，当前封禁策略有效' }
}

/** 封禁次数 → 配色（次数越高越危险） */
function banCountColor(count: number): string {
  if (count >= 4) return 'var(--fw-danger)'
  if (count >= 3) return 'var(--fw-warning)'
  return 'var(--fw-text)'
}

const MINI_LABEL_STYLE: CSSProperties = { fontSize: 12, color: 'var(--fw-text-3)' }
const MINI_VALUE_STYLE: CSSProperties = { fontSize: 16, fontWeight: 600, lineHeight: 1.2 }

/** 面板内的紧凑指标（比 StatCard 更小，适合三列并排） */
function MiniMetric({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
        padding: '6px 5px',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-radius)',
        background: 'var(--fw-surface)',
        textAlign: 'center',
      }}
    >
      <span style={MINI_LABEL_STYLE}>{label}</span>
      <span className="fw-num" style={{ ...MINI_VALUE_STYLE, color: color ?? 'var(--fw-text)' }}>
        {value}
      </span>
    </div>
  )
}

export function RecidivismPanel({ limit = 10 }: RecidivismPanelProps) {
  const { data, loading, error, reload } = useAsync<RecidivismResponse>(
    () => getJson<RecidivismResponse>(RECIDIVISM_ENDPOINT),
    [],
  )

  const header = (
    <PageHeader
      title="封禁复发分析"
      subtitle="历史封禁记录中，被解封后再次被封的 IP 占比（数据来自服务端历史统计，需手动刷新）"
      extra={
        <Button size="mini" fill="outline" color="primary" loading={loading} onClick={reload}>
          刷新
        </Button>
      }
    />
  )

  // 首次加载（尚无任何数据）时才占位，避免手动刷新时内容闪烁
  if (loading && !data) {
    return (
      <div>
        {header}
        <div style={{ display: 'flex', justifyContent: 'center', padding: '19px 0' }}>
          <SpinLoading />
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div>
        {header}
        <EmptyState
          title="复发统计加载失败"
          description={error}
          action={
            <Button color="primary" fill="outline" onClick={reload}>
              重试
            </Button>
          }
        />
      </div>
    )
  }

  if (!data || data.total_ips === 0) {
    return (
      <div>
        {header}
        <EmptyState
          title="暂无封禁历史"
          description="还没有累积到封禁历史记录，无法计算复发率。发生封禁后回来查看即可。"
        />
      </div>
    )
  }

  const rate = data.recidivism_rate
  const { color: rateColor, verdict } = describeRate(rate)
  const topList = data.top_recidivists.slice(0, limit)

  return (
    <div>
      {header}

      {/* 主指标：复发率（0~100，后端口径） */}
      <StatCard
        label="总体复发率"
        value={rate.toFixed(1)}
        unit="%"
        tone={rate >= 30 ? 'danger' : rate >= 10 ? 'warning' : 'success'}
        hint={verdict}
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 5, marginTop: 7 }}>
        <MiniMetric label="历史封禁 IP" value={data.total_ips} />
        <MiniMetric label="复发 IP" value={data.recidivist_ips} color={rateColor} />
        <MiniMetric label="永久封禁" value={data.permanent_bans} />
      </div>

      <PageHeader title="复发 TOP" subtitle={`按累计封禁次数排序，共 ${topList.length} 条`} style={{ marginTop: 12 }} />

      {topList.length === 0 ? (
        <EmptyState compact title="没有复发 IP" description="所有 IP 都只被封禁过一次。" />
      ) : (
        <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 5 }}>
          {topList.map((entry, index) => (
            <li
              key={entry.ip}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                minHeight: 'var(--fw-tap)',
                padding: '5px 6px',
                border: '1px solid var(--fw-border)',
                borderRadius: 'var(--fw-radius)',
                background: 'var(--fw-surface)',
              }}
            >
              <span
                className="fw-num"
                aria-hidden="true"
                style={{
                  width: 20,
                  height: 20,
                  flexShrink: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  borderRadius: '50%',
                  fontSize: 12,
                  fontWeight: 600,
                  color: index < 3 ? 'var(--fw-danger)' : 'var(--fw-text-3)',
                  background: 'var(--fw-surface-hi)',
                }}
              >
                {index + 1}
              </span>

              <span style={{ flex: 1, minWidth: 0 }}>
                <span
                  className="fw-mono"
                  style={{
                    display: 'block',
                    fontSize: 13,
                    color: 'var(--fw-text)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {entry.ip}
                </span>
                <span style={{ display: 'block', fontSize: 12, color: 'var(--fw-text-3)' }}>
                  最近封禁：{formatBannedAt(entry.last_banned_at)}
                </span>
              </span>

              {entry.was_permanent ? (
                <Tag color="danger" fill="outline">
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 1 }}>
                    <ExclamationTriangleOutline />
                    永久
                  </span>
                </Tag>
              ) : null}

              <span
                className="fw-num"
                style={{ fontSize: 14, fontWeight: 600, color: banCountColor(entry.ban_count), flexShrink: 0 }}
                title={`累计封禁 ${entry.ban_count} 次`}
              >
                ×{entry.ban_count}
              </span>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

export default RecidivismPanel
