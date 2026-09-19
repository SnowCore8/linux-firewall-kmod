// Jail 管理页（二级页，位于「更多」之下）
//
// 做什么：卡片式列出所有 Jail 的配置与运行时统计（阈值、检测窗口、封禁时长、峰值倍数、
//        解析行数/正则命中/提取 IP 等），并提供启用 / 禁用开关；下方展示后端给出的
//        「封禁时长推荐」——按累犯回归间隔判断当前时长是否偏短。
// 影响什么：切换开关是**写操作**，会下发到 Jail 运行状态并持久化到运行时配置；
//          其它内容为只读展示。开关是受控组件（checked 直接来自后端数据），
//          因此保存失败时界面会自动回到真实状态，不会出现「界面已切换但实际没生效」。
//
// 数据来源：
//   1) 全局 SSE 的 jails 事件（useSse().jails）——实时且变更后立即推送；
//   2) GET /api/v1/jails —— 实时通道未就绪时的回退；
//   3) GET /api/v1/stats/ban-duration-recommendations —— 推荐为按需计算，走 REST。

import { useState } from 'react'
import { Button, Card, List, NavBar, NoticeBar, Skeleton, Switch, Tag } from 'antd-mobile'
import { ClockCircleOutline, LoopOutline } from 'antd-mobile-icons'
import { useNavigate } from 'react-router-dom'
import type { BanDurationRecommendationResponse, JailResponse } from '../api/types'
import { getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { useSse } from '../hooks/useSse'
import { useToast } from '../hooks/useToast'
import { PageHeader } from '../components/PageHeader'
import { EmptyState } from '../components/EmptyState'
import { formatDuration, formatNumber } from '../lib/format'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const JAILS_URL = '/api/v1/jails'
const DURATION_RECOMMENDATIONS_URL = '/api/v1/stats/ban-duration-recommendations'

/** 空列表常量：避免 `?? []` 每次渲染产生新数组 */
const EMPTY_JAILS: JailResponse[] = []

/** 次要说明文字样式 */
const MUTED = { color: 'var(--adm-color-text-secondary)', fontSize: 12 } as const

/** 把任意抛出物转成可展示文案 */
function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** 封禁时长文案：后端用 -1 表示永久，formatDuration 会渲染成「永久」 */
function banTimeText(seconds: number): string {
  return seconds < 0 ? '永久封禁' : formatDuration(seconds)
}

export default function Jails() {
  const navigate = useNavigate()
  const toast = useToast()
  const { jails: sseJails } = useSse()

  // SSE 未就绪时的回退：GET /api/v1/jails
  const restJails = useAsync(() => getJson<JailResponse[]>(JAILS_URL), [])
  const jails = sseJails ?? restJails.data ?? EMPTY_JAILS

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
      {/* 二级页返回入口：回到收纳本页的「更多」 */}
      <NavBar onBack={() => navigate('/more')}>Jail 管理</NavBar>

      <PageHeader
        title="Jail 列表"
        subtitle={`共 ${formatNumber(jails.length, false)} 个 Jail；统计值为本次运行的累计口径`}
        extra={
          <Button
            size="small"
            fill="none"
            style={{ minHeight: 44 }}
            aria-label="刷新 Jail 列表与推荐"
            onClick={() => {
              restJails.reload()
              recommendations.reload()
            }}
          >
            <LoopOutline fontSize={18} />
          </Button>
        }
      />

      <div style={{ paddingBottom: 7 }}>
        {/* 回退取数失败且 SSE 无数据：错误可见并提供重试 */}
        {sseJails === null && restJails.error !== null && (
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
        {sseJails === null && restJails.loading && (
          <div style={{ marginTop: 7 }}>
            <Skeleton.Title animated />
            <Skeleton.Paragraph lineCount={6} animated />
          </div>
        )}

        {jails.length === 0 && !restJails.loading && (
          <EmptyState
            title="没有可用 Jail"
            description="Jail 由守护进程按配置加载；若配置中已定义却仍为空，请检查守护进程日志"
          />
        )}

        {jails.map((jail) => (
          <Card key={jail.name} style={{ marginTop: 5 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ flex: 1, minWidth: 0, fontSize: 15, fontWeight: 600, wordBreak: 'break-all' }}>
                {jail.name}
              </span>
              {/* 开关外面套 44px 高的容器：antd-mobile 默认尺寸小于触摸目标下限 */}
              <div className="fw-tap">
                <Switch
                  checked={jail.enabled}
                  loading={busyName === jail.name}
                  style={{ '--width': '42px', '--height': '26px' }}
                  onChange={(checked) => {
                    void toggleJail(jail, checked)
                  }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
              <Tag color={jail.enabled ? 'success' : 'default'} fill="outline">
                {jail.enabled ? '已启用' : '已禁用'}
              </Tag>
              {jail.is_peak_hours && (
                <Tag color="warning" fill="outline">
                  业务高峰期（阈值 ×{jail.peak_hours_multiplier}）
                </Tag>
              )}
              <Tag color="primary" fill="outline">
                当前封禁 {formatNumber(jail.ban_count, false)} 个 IP
              </Tag>
            </div>

            <List style={{ marginTop: 5 }}>
              <List.Item
                extra={`${formatNumber(jail.max_retries, false)}（生效 ${formatNumber(jail.effective_max_retries, false)}）`}
              >
                失败次数阈值
              </List.Item>
              <List.Item extra={formatDuration(jail.findtime)}>检测窗口</List.Item>
              <List.Item extra={banTimeText(jail.ban_time)}>封禁时长</List.Item>
              <List.Item extra={`×${jail.internal_ip_multiplier}`}>内网 IP 阈值倍数</List.Item>
            </List>

            <div style={{ ...MUTED, marginTop: 5 }}>解析与命中统计</div>
            <List>
              <List.Item extra={formatNumber(jail.lines_parsed, true)}>已解析日志行</List.Item>
              <List.Item extra={formatNumber(jail.regex_matches, true)}>正则命中次数</List.Item>
              <List.Item extra={formatNumber(jail.ips_extracted, true)}>提取到的 IP</List.Item>
              <List.Item extra={formatNumber(jail.failed_attempts, true)}>失败尝试累计</List.Item>
              <List.Item extra={formatNumber(jail.bans_triggered, true)}>触发封禁次数</List.Item>
            </List>
          </Card>
        ))}

        {/* 封禁时长推荐：只读建议，采纳需要人工到配置页修改（本页不隐式改配置） */}
        <Card
          title={
            <span>
              <ClockCircleOutline /> 封禁时长推荐
            </span>
          }
          style={{ marginTop: 10 }}
        >
          {recommendations.error !== null ? (
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
          ) : recData === null ? (
            <Skeleton.Paragraph lineCount={3} animated />
          ) : recData.recommendations.length === 0 ? (
            <EmptyState
              compact
              title="暂无推荐"
              description="需要足够的历史封禁样本才能推断回归间隔；样本不足时不给出建议"
            />
          ) : (
            <>
              {recData.summary !== '' && <NoticeBar color="info" wrap content={recData.summary} />}

              {needsAdjust.length === 0 && (
                <div style={{ ...MUTED, marginTop: 5 }}>
                  当前所有 Jail 的封禁时长均处于合理区间，无需调整。
                </div>
              )}

              {recData.recommendations.map((rec) => (
                <div
                  key={rec.jail_name}
                  style={{ padding: '6px 0', borderBottom: '1px solid var(--fw-border)' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ flex: 1, minWidth: 0, fontWeight: 600, wordBreak: 'break-all' }}>
                      {rec.jail_name}
                    </span>
                    <Tag color={rec.needs_adjustment ? 'warning' : 'success'} fill="outline">
                      {rec.needs_adjustment ? '建议调整' : '保持现状'}
                    </Tag>
                  </div>

                  <div style={{ ...MUTED, marginTop: 2 }}>
                    当前 {banTimeText(rec.current_ban_time)} → 建议{' '}
                    {banTimeText(rec.recommended_ban_time)}
                  </div>
                  <div style={{ ...MUTED, marginTop: 1 }}>
                    累犯 {formatNumber(rec.recidivist_count, false)} 个 · 回归间隔中位数{' '}
                    {rec.median_return_secs > 0 ? formatDuration(rec.median_return_secs) : '样本不足'}
                  </div>
                  {rec.reason !== '' && <div style={{ ...MUTED, marginTop: 1 }}>{rec.reason}</div>}
                </div>
              ))}
            </>
          )}
        </Card>
      </div>
    </>
  )
}
