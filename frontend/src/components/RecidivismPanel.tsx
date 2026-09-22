// 封禁复发分析面板：复发率 + 复发 IP TOP 列表（控制台风格）
//
// 数据来源：`GET /api/v1/stats/recidivism`（后端 `src/daemon/web_ui/stats.rs` 的
// `get_ban_recidivism()`）。响应类型直接复用 api/types.ts 中由 Rust 推导的模型，
// 不在本文件重复声明，避免同一份服务端契约出现两套字段定义。
//
// 与「当前封禁列表」不同，这里是**历史**维度：只有被解封后再次被封的 IP 才算复发
// （ban_count >= 2），因此必须走 REST 而不是 SSE 实时推送，但会按与 SSE 同源的间隔
// 自动刷新（`usePollInterval`），后台标签页自动暂停。面板内**不设刷新按钮**：
// 全站刷新入口只有顶栏「刷新」与下拉手势（见 console.tsx 的工具条说明）。
//
// 排版：本组件**不渲染 h2**。它是仪表盘内的一个内容块，页面的 h2 由 `PageHeader`
// 独占——否则同一屏会出现两层同级标题，读屏器与 e2e 的 exact 断言都会被干扰。
// 分组改用 `Panel`（自带 11px 细条标题），层级仍然清楚。
//
// 无 props 也能用（数据自取），调用方直接 <RecidivismPanel /> 即可。
import { ExclamationTriangleOutline } from 'antd-mobile-icons'

import { getJson } from '../api/client'
import type { RecidivismResponse } from '../api/types'
import { useAsync } from '../hooks/useAsync'
import { usePollInterval } from '../hooks/usePollInterval'
import {
  Badge,
  InlineError,
  Meter,
  Panel,
  PanelLoading,
  Row,
  Rows,
  Tile,
  Tiles,
  Verdict,
  toneColor,
  type Tone,
} from './console'
import { EmptyState } from './EmptyState'

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

/**
 * 复发率 → 结论与色调。
 * 阈值口径集中在这里，便于与后端策略对齐；改阈值只改这一处。
 */
function describeRate(rate: number): { tone: Tone; verdict: string; advice: string } {
  if (rate >= 30) {
    return { tone: 'danger', verdict: '复发率偏高', advice: '建议延长基础封禁时长，或缩短检测窗口' }
  }
  if (rate >= 10) {
    return { tone: 'warning', verdict: '复发率可接受', advice: '渐进式封禁策略运行正常' }
  }
  return { tone: 'success', verdict: '复发率很低', advice: '当前封禁策略有效' }
}

/** 封禁次数 → 色调（次数越高越危险） */
function banCountTone(count: number): Tone {
  if (count >= 4) return 'danger'
  if (count >= 3) return 'warning'
  return 'default'
}

export function RecidivismPanel({ limit = 10 }: RecidivismPanelProps) {
  const pollMs = usePollInterval()
  const { data, loading, error, reload } = useAsync<RecidivismResponse>(
    () => getJson<RecidivismResponse>(RECIDIVISM_ENDPOINT),
    [],
    { pollMs },
  )

  // 首次加载（尚无任何数据）时才占位，避免自动刷新时内容闪烁
  if (loading && !data) {
    return (
      <Panel title="封禁复发分析">
        <PanelLoading lines={4} />
      </Panel>
    )
  }

  if (error) {
    return (
      <Panel title="封禁复发分析">
        <InlineError message={`复发统计加载失败：${error}`} onRetry={reload} />
      </Panel>
    )
  }

  if (!data || data.total_ips === 0) {
    return (
      <Panel title="封禁复发分析">
        <EmptyState
          title="暂无封禁历史"
          description="还没有累积到封禁历史记录，无法计算复发率。发生封禁后回来查看即可。"
        />
      </Panel>
    )
  }

  const rate = data.recidivism_rate
  const { tone, verdict, advice } = describeRate(rate)
  const topList = data.top_recidivists.slice(0, limit)
  // 复发占比：分母是历史封禁 IP 总数，与后端的 recidivism_rate 同一份口径
  const ratio = data.total_ips > 0 ? data.recidivist_ips / data.total_ips : 0

  return (
    <>
      <Panel title="封禁复发分析">
        {/* 结论条：一眼看出「策略有没有效」；右侧是大号比例 + 同比例细条 */}
        <Verdict
          text={verdict}
          tone={tone}
          sub={advice}
          right={
            <>
              <div className="fw-tile-value" style={{ color: toneColor(tone) }}>
                {rate.toFixed(1)}
                <span className="fw-tile-unit">%</span>
              </div>
              <div style={{ width: 62, marginTop: 3 }}>
                <Meter ratio={rate / 100} tone={tone} />
              </div>
            </>
          }
        />

        <Tiles columns={3} style={{ marginTop: 5 }}>
          <Tile label="历史封禁 IP" value={data.total_ips} />
          <Tile label="复发 IP" value={data.recidivist_ips} tone={tone} />
          <Tile label="永久封禁" value={data.permanent_bans} />
        </Tiles>

        {/* 绝对数看规模，比例才是策略有效性的判据——两者并排给出 */}
        <Rows style={{ marginTop: 5 }}>
          <Row
            label="复发占比"
            value={`${(ratio * 100).toFixed(1)}%`}
            unit={`${data.recidivist_ips}/${data.total_ips}`}
            tone={tone}
          />
        </Rows>
      </Panel>

      <Panel title="复发 TOP" meta={`共 ${topList.length} 条`} padded={false}>
        {topList.length === 0 ? (
          <div style={{ padding: 5 }}>
            <EmptyState compact title="没有复发 IP" description="所有 IP 都只被封禁过一次。" />
          </div>
        ) : (
          <Rows>
            {topList.map((entry, index) => (
              /* 不用通用 Row：名次列很窄、IP 必须左对齐（右对齐会让不同长度的 IP
                 失去公共起点，反而难扫读），这是列表型数据的既定例外。 */
              <div className="fw-row" key={entry.ip}>
                <span className="fw-row-label" style={{ width: 20, color: index < 3 ? 'var(--fw-danger)' : undefined }}>
                  #{index + 1}
                </span>
                {/* IP 占满剩余宽度：它左对齐（不同长度的 IP 有公共起点），
                    并把时间/标记/次数推到右侧形成对齐的数值列 */}
                <span
                  className="fw-mono"
                  style={{
                    flex: 1,
                    minWidth: 0,
                    fontSize: 12,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {entry.ip}
                </span>
                <span style={{ flexShrink: 0, fontSize: 10, color: 'var(--fw-text-3)' }}>
                  {formatBannedAt(entry.last_banned_at)}
                </span>
                {entry.was_permanent ? (
                  <Badge tone="danger" dim>
                    永久
                  </Badge>
                ) : null}
                <span
                  className="fw-num"
                  style={{ fontWeight: 600, color: toneColor(banCountTone(entry.ban_count)) }}
                  title={`累计封禁 ${entry.ban_count} 次`}
                >
                  ×{entry.ban_count}
                </span>
              </div>
            ))}
          </Rows>
        )}

        {/* 永久封禁是唯一需要额外解释的量：说明它的含义，避免用户误以为可以自动解封 */}
        <div className="fw-kv-inline" style={{ padding: '3px 6px' }}>
          <ExclamationTriangleOutline />
          <span>标记「永久」的 IP 曾进入永久封禁，需手工解封</span>
        </div>
      </Panel>
    </>
  )
}

export default RecidivismPanel
