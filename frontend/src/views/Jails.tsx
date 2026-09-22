// Jail 管理页（控制台风格，二级页位于「更多」之下）
//
// 做什么：每个 Jail 一个面板——面板头 = 名称（等宽）+ 当前封禁数；面板体 = 运行状态开关行
//        （整行 44px 触摸目标）+ 配置数据行（失败阈值 / 检测窗口 / 封禁时长 / 内网倍数 /
//        高峰倍数）+ 解析与命中统计瓦片（本次运行累计）；页面末尾是「封禁时长推荐」面板——
//        按累犯回归间隔判断当前时长是否偏短。
// 影响什么：切换开关是**写操作**，会下发到 Jail 运行状态并持久化到运行时配置；
//          其余内容为只读展示。开关是受控组件（checked 直接来自后端数据），
//          保存失败时界面自动回到真实状态，不会出现「界面已切换但实际没生效」。
//
// 数据来源：
//   1) 全局 SSE 的 jails 事件（useSse().jails）——实时且变更后立即推送；
//   2) GET /api/v1/jails —— 实时通道未就绪时的回退（两者按共享新鲜度戳取较新一份）；
//   3) GET /api/v1/stats/ban-duration-recommendations —— 推荐为按需计算，走 REST。

import { useState } from 'react'
import type { CSSProperties } from 'react'
import { NoticeBar, PullToRefresh, Skeleton, Switch } from 'antd-mobile'
import { useNavigate } from 'react-router-dom'
import type { BanDurationRecommendationResponse, JailResponse } from '../api/types'
import { getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { pickLiveData } from '../hooks/useLiveData'
import { useSse } from '../hooks/useSse'
import { useToast } from '../hooks/useToast'
import { BackLink, Badge, Panel, Row, Rows, SubHead, Tile, Tiles, Toolbar, errorText } from '../components/console'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { formatDuration, formatNumber } from '../lib/format'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const JAILS_URL = '/api/v1/jails'
const DURATION_RECOMMENDATIONS_URL = '/api/v1/stats/ban-duration-recommendations'

/** 空列表常量：避免 `?? []` 每次渲染产生新数组 */
const EMPTY_JAILS: JailResponse[] = []

/** 失败阈值行里的补充说明（等宽小字） */
const THRESHOLD_NOTE = (effective: number): string => `（生效 ${formatNumber(effective, false)}）`

/** 次要说明文本：小字、弱化、允许换行（配置口径说明与推荐理由用） */
const NOTE_TEXT: CSSProperties = {
  fontSize: 10,
  lineHeight: 1.45,
  color: 'var(--fw-text-3)',
  wordBreak: 'break-all',
}

/** 推荐条目的容器：条目之间用发丝线分界，不靠间距分组 */
const REC_ITEM: CSSProperties = {
  padding: '4px 6px',
  borderBottom: '1px solid var(--fw-border)',
}

/** Jail 面板内的开关行：整行作为触摸目标，开关靠右 */
const SWITCH_ROW: CSSProperties = { minHeight: 'var(--fw-tap)', alignItems: 'center' }

/** 解析统计瓦片网格的占位格：3 列网格 5 个瓦片会空出第 6 格，
 *  不补满的话会露出网格缝隙底色（--fw-border），形成一块假色斑 */
function TilePlaceholder() {
  return <div className="fw-tile" aria-hidden="true" />
}

/** 把任意抛出物转成可展示文案 */
/** 封禁时长文案：后端用 -1 表示永久，formatDuration 会渲染成「永久」 */
function banTimeText(seconds: number): string {
  return seconds < 0 ? '永久封禁' : formatDuration(seconds)
}

export default function Jails() {
  const navigate = useNavigate()
  const toast = useToast()
  const { jails: sseJails, payloadSeq } = useSse()

  // SSE 未就绪时的回退：GET /api/v1/jails
  const restJails = useAsync(() => getJson<JailResponse[]>(JAILS_URL), [])
  // 取较新的一份而非「SSE 优先」：写操作后 restJails.reload() 必须真正反映到界面。
  // `liveJails === null` 表示**两条来源都还没有数据**，用于骨架/错误提示的判据。
  const liveJails = pickLiveData(sseJails, payloadSeq.jails, restJails)
  const jails = liveJails ?? EMPTY_JAILS

  // 封禁时长推荐：与列表解耦，失败不影响开关操作
  const recommendations = useAsync(
    () => getJson<BanDurationRecommendationResponse>(DURATION_RECOMMENDATIONS_URL),
    [],
  )

  /** 正在提交的 Jail 名：用于开关 loading，避免同一 Jail 重复提交 */
  const [busyName, setBusyName] = useState<string | null>(null)

  /**
   * 切换 Jail 启用状态。
   * PUT /api/v1/jails/:name 的语义是「整体设置 enabled」，因此直接传目标值而不是取反，
   * 避免与实时推送回来的最新状态产生竞态。
   */
  const toggleJail = async (jail: JailResponse, nextEnabled: boolean) => {
    setBusyName(jail.name)
    try {
      const updated = await sendJson<{ enabled: boolean }, JailResponse>(
        `${JAILS_URL}/${encodeURIComponent(jail.name)}`,
        'PUT',
        { enabled: nextEnabled },
      )
      toast.success(`${updated.name} 已${updated.enabled ? '启用' : '禁用'}`)
      restJails.reload()
    } catch (e) {
      // 失败后不修改本地状态：开关受控于后端数据，会自动回到真实值
      toast.error(`切换失败：${errorText(e)}`)
    } finally {
      setBusyName(null)
    }
  }

  const recData = recommendations.data
  const needsAdjust = (recData?.recommendations ?? []).filter((rec) => rec.needs_adjustment)

  return (
    <>
      {/* 二级页头部：统一工具条（左端返回更多；刷新走全局下拉手势，不设页内刷新按钮） */}
      <Toolbar>
        <BackLink onClick={() => navigate('/more')} />
      </Toolbar>

      <PageHeader
        title="Jail 列表"
        srOnly
        subtitle={`共 ${formatNumber(jails.length, false)} 个 Jail；统计值为本次运行的累计口径`}
      />

      <PullToRefresh
        onRefresh={async () => {
          await Promise.all([restJails.reload(), recommendations.reload()])
        }}
      >
        <div className="fw-page">
        {/* 回退取数失败且两条来源都无数据：错误可见并提供重试 */}
        {liveJails === null && restJails.error !== null && (
          <NoticeBar
            color="error"
            wrap
            content={`Jail 列表加载失败：${restJails.error}`}
            extra={
              <a onClick={() => restJails.reload()} style={{ color: 'inherit', textDecoration: 'underline' }}>
                重试
              </a>
            }
          />
        )}

        {/* 首屏加载骨架：避免误显示「没有 Jail」 */}
        {liveJails === null && restJails.loading && (
          <Panel title="Jail 列表" padded>
            <Skeleton.Title animated />
            <Skeleton.Paragraph lineCount={6} animated />
          </Panel>
        )}

        {liveJails !== null && jails.length === 0 && (
          <Panel title="Jail 列表" padded={false}>
            <EmptyState
              title="没有可用 Jail"
              description="Jail 由守护进程按配置加载；若配置中已定义却仍为空，请检查守护进程日志"
            />
          </Panel>
        )}

        {jails.map((jail) => (
          <Panel
            key={jail.name}
            title={<span className="fw-mono">{jail.name}</span>}
            meta={`${formatNumber(jail.ban_count, false)} 个封禁中`}
            padded={false}
          >
            {/* 开关行：antd Switch 自身小于触摸目标，靠整行 44px 补齐 */}
            <div className="fw-row" style={SWITCH_ROW}>
              <span className="fw-row-label">运行状态</span>
              <span
                style={{
                  flex: 1,
                  minWidth: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'flex-end',
                  gap: 6,
                }}
              >
                <Badge tone={jail.enabled ? 'success' : 'default'} dim={!jail.enabled}>
                  {jail.enabled ? '已启用' : '已禁用'}
                </Badge>
                {/* 开关套 .fw-tap：antd Switch 默认尺寸小于触摸目标下限，容器补齐 44px */}
                <span className="fw-tap">
                  <Switch
                    checked={jail.enabled}
                    loading={busyName === jail.name}
                    style={{ '--width': '42px', '--height': '26px' }}
                    onChange={(checked) => {
                      void toggleJail(jail, checked)
                    }}
                  />
                </span>
              </span>
            </div>

            <Rows>
              <Row
                label="失败次数阈值"
                value={formatNumber(jail.max_retries, false)}
                unit={THRESHOLD_NOTE(jail.effective_max_retries)}
              />
              <Row label="检测窗口" value={formatDuration(jail.findtime)} />
              <Row
                label="封禁时长"
                value={banTimeText(jail.ban_time)}
                tone={jail.ban_time < 0 ? 'danger' : 'default'}
              />
              <Row label="内网阈值倍数" value={`×${jail.internal_ip_multiplier}`} />
              <Row
                label="业务高峰期"
                value={jail.is_peak_hours ? `是（阈值 ×${jail.peak_hours_multiplier}）` : '否'}
                tone={jail.is_peak_hours ? 'warning' : 'default'}
              />
            </Rows>

            {/* 统计瓦片：5 个计数用 3 列网格压成两行，比 5 行数据行更省首屏 */}
            <SubHead right="本次运行累计">解析与命中</SubHead>
            <Tiles columns={3}>
              <Tile label="解析行" value={formatNumber(jail.lines_parsed, true)} />
              <Tile label="正则命中" value={formatNumber(jail.regex_matches, true)} />
              <Tile label="提取 IP" value={formatNumber(jail.ips_extracted, true)} />
              <Tile label="失败尝试" value={formatNumber(jail.failed_attempts, true)} />
              <Tile label="触发封禁" value={formatNumber(jail.bans_triggered, true)} />
              <TilePlaceholder />
            </Tiles>
          </Panel>
        ))}

        {/* 封禁时长推荐：只读建议，采纳需要人工到配置页修改（本页不隐式改配置） */}
        <Panel
          title="封禁时长推荐"
          meta={
            recommendations.data === null
              ? undefined
              : `${formatNumber(recommendations.data.recommendations.length, false)} 条建议`
          }
          padded={false}
        >
          {recommendations.error !== null ? (
            <div style={{ padding: 6 }}>
              <NoticeBar
                color="error"
                wrap
                content={`推荐加载失败：${recommendations.error}`}
                extra={
                  <a onClick={() => recommendations.reload()} style={{ color: 'inherit', textDecoration: 'underline' }}>
                    重试
                  </a>
                }
              />
            </div>
          ) : recData === null ? (
            <div style={{ padding: 6 }}>
              <Skeleton.Paragraph lineCount={3} animated />
            </div>
          ) : recData.recommendations.length === 0 ? (
            <EmptyState
              compact
              title="暂无推荐"
              description="需要足够的历史封禁样本才能推断回归间隔；样本不足时不给出建议"
            />
          ) : (
            <>
              {/* 汇总说明与「无需调整」提示：都由后端给出，界面不改写结论 */}
              {recData.summary !== '' && (
                <div style={{ ...NOTE_TEXT, padding: '4px 6px', borderBottom: '1px solid var(--fw-border)' }}>
                  {recData.summary}
                </div>
              )}
              {needsAdjust.length === 0 && (
                <div style={{ ...NOTE_TEXT, padding: '4px 6px', borderBottom: '1px solid var(--fw-border)' }}>
                  当前所有 Jail 的封禁时长均处于合理区间，无需调整。
                </div>
              )}

              {recData.recommendations.map((rec, index) => (
                <div
                  key={rec.jail_name}
                  style={{
                    ...REC_ITEM,
                    borderBottom:
                      index === recData.recommendations.length - 1
                        ? 'none'
                        : '1px solid var(--fw-border)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span className="fw-mono" style={{ ...NOTE_TEXT, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {rec.jail_name}
                    </span>
                    <Badge tone={rec.needs_adjustment ? 'warning' : 'success'} dim={!rec.needs_adjustment}>
                      {rec.needs_adjustment ? '建议调整' : '保持现状'}
                    </Badge>
                  </div>

                  <Rows>
                    <Row label="当前时长" value={banTimeText(rec.current_ban_time)} />
                    <Row
                      label="建议时长"
                      value={banTimeText(rec.recommended_ban_time)}
                      tone={rec.needs_adjustment ? 'warning' : 'default'}
                    />
                    <Row label="累犯" value={formatNumber(rec.recidivist_count, false)} unit="个" />
                    <Row
                      label="回归中位数"
                      value={rec.median_return_secs > 0 ? formatDuration(rec.median_return_secs) : '样本不足'}
                    />
                  </Rows>

                  {rec.reason !== '' && (
                    <div style={{ ...NOTE_TEXT, marginTop: 2 }}>{rec.reason}</div>
                  )}
                </div>
              ))}
            </>
          )}
        </Panel>
        </div>
      </PullToRefresh>
    </>
  )
}
