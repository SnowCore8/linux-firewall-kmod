// 异常检测面板：全局流量偏离 + per-IP 行为离群
//
// 数据来源：`GET /api/v1/stats/anomalies`（后端 `src/daemon/anomaly/` + `web_ui/anomaly.rs`）。
// 与 RecidivismPanel 同模式：自取数据、按 poll 间隔自动刷新、后台标签页暂停。

import { CheckCircleOutline } from 'antd-mobile-icons'

import { getJson } from '../api/client'
import type { AnomalyResponse } from '../api/types'
import { useAsync } from '../hooks/useAsync'
import { usePollInterval } from '../hooks/usePollInterval'
import {
  Badge,
  InlineError,
  Panel,
  PanelLoading,
  Row,
  Rows,
  Verdict,
  type Tone,
} from './console'
import { EmptyState } from './EmptyState'

const ANOMALY_ENDPOINT = '/api/v1/stats/anomalies'

/** 评分 → 展示等级 */
function scoreTone(score: number): Tone {
  if (score >= 60) return 'danger'
  if (score >= 30) return 'warning'
  return 'success'
}

/** 评分 → 文字标签 */
function scoreLabel(score: number): string {
  if (score >= 60) return '显著偏离'
  if (score >= 30) return '轻度偏离'
  return '正常'
}

/** 维度偏差分 → 条颜色 */
function dimColor(score: number): string {
  if (score >= 0.7) return 'var(--adm-color-danger)'
  if (score >= 0.3) return 'var(--adm-color-warning)'
  return 'var(--adm-color-success)'
}

/** 维度名中文映射 */
const DIM_LABELS: Record<string, string> = {
  syn_ratio: 'SYN 占比',
  udp_ratio: 'UDP 占比',
  icmp_ratio: 'ICMP 占比',
  ack_ratio: 'ACK 占比',
  rst_ratio: 'RST 占比',
  fin_ratio: 'FIN 占比',
  volume_ratio: '流量体量',
  active_ips: '活跃 IP 数',
}

export function AnomalyPanel() {
  const pollMs = usePollInterval()
  const { data, error, loading, reload } = useAsync<AnomalyResponse>(
    () => getJson<AnomalyResponse>(ANOMALY_ENDPOINT),
    [],
    { pollMs },
  )

  if (loading && !data) {
    return (
      <Panel title="异常检测">
        <PanelLoading lines={4} />
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel title="异常检测">
        <InlineError message={`异常检测加载失败：${error}`} onRetry={reload} />
      </Panel>
    )
  }

  if (!data) return null

  const tone = scoreTone(data.global_score)
  const label = scoreLabel(data.global_score)

  return (
    <Panel title="异常检测" meta={`${data.global_sample_count} 样本`}>
      <Rows>
        {/* 判决条：全局异常评分 */}
        <Verdict
          text={label}
          tone={tone}
          sub={`全局评分 ${data.global_score.toFixed(1)} / 100`}
          right={<Badge tone={tone}>{data.global_score.toFixed(0)}</Badge>}
        />

        {/* 维度分解：各维度偏差分水平条 */}
        <Row
          label="维度偏离"
          value={
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, width: '100%' }}>
              {data.global_dimensions.map((dim) => (
                <div
                  key={dim.name}
                  style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}
                >
                  <span style={{ width: 72, flexShrink: 0, color: 'var(--adm-color-text)' }}>
                    {DIM_LABELS[dim.name] ?? dim.name}
                  </span>
                  <div
                    style={{
                      flex: 1,
                      height: 6,
                      background: 'var(--adm-color-fill-content)',
                      borderRadius: 3,
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${Math.min(dim.score * 100, 100)}%`,
                        height: '100%',
                        background: dimColor(dim.score),
                        borderRadius: 3,
                        transition: 'width 0.3s',
                      }}
                    />
                  </div>
                  <span
                    style={{
                      width: 32,
                      textAlign: 'right',
                      fontVariantNumeric: 'tabular-nums',
                      color: dim.score >= 0.3 ? dimColor(dim.score) : 'var(--adm-color-weak)',
                    }}
                  >
                    {(dim.score * 100).toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
          }
        />

        {/* per-IP 异常 TOP 列表 */}
        {data.ip_anomalies.length > 0 ? (
          <Row
            label="异常 IP"
            value={
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, width: '100%' }}>
                {data.ip_anomalies.slice(0, 10).map((entry) => {
                  const ipTone: Tone =
                    entry.score >= 50 ? 'danger' : entry.score >= 20 ? 'warning' : 'default'
                  const topDim = entry.dimensions.reduce(
                    (best, d) => (d.score > best.score ? d : best),
                    entry.dimensions[0],
                  )
                  return (
                    <div
                      key={entry.ip}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: 12,
                      }}
                    >
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{entry.ip}</span>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 11, color: 'var(--adm-color-weak)' }}>
                          {DIM_LABELS[topDim?.name] ?? topDim?.name ?? ''}
                        </span>
                        <Badge tone={ipTone}>{entry.score.toFixed(0)}</Badge>
                      </span>
                    </div>
                  )
                })}
              </div>
            }
          />
        ) : (
          <Row
            label="异常 IP"
            value={
              <EmptyState
                compact
                icon={<CheckCircleOutline fontSize={20} />}
                title="未检测到行为异常 IP"
              />
            }
          />
        )}
      </Rows>
    </Panel>
  )
}
