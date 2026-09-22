// 白名单管理页（控制台风格）
//
// 做什么：白名单条目压成单行——CIDR（等宽）+ 绑定设备 + 行尾「复制」提示，
//        整行点击即复制 CIDR，左滑露出「移出」；上方是搜索框与「新增」入口；
//        「智能推荐」面板展示后端按历史封禁统计给出的建议条目（网段 / 单 IP，
//        带置信度徽标与细条），逐条二次确认后采纳。
// 影响什么：新增 / 移出 / 采纳推荐都是**写操作**，会真实改写内核白名单表并持久化配置，
//          全部需要二次确认；关键词过滤与复制只在浏览器内完成，不产生请求。
//
// 数据来源（任何一级都是真实端点，无占位假数据）：
//   1) 全局 SSE 的 whitelist 事件（useSse().whitelist）—— 状态变更后服务端会立即推送；
//   2) GET /api/v1/whitelist —— 实时通道未就绪时的回退（两者按共享新鲜度戳取较新一份）；
//   3) 推荐列表走 REST GET /api/v1/whitelist/recommendations（后端按需计算，非推送项）。

import { useMemo, useState } from 'react'
import type { CSSProperties } from 'react'
import {
  Button,
  Dialog,
  Form,
  Input,
  NoticeBar,
  Popup,
  PullToRefresh,
  SearchBar,
  Skeleton,
  SwipeAction,
} from 'antd-mobile'
import { AddOutline } from 'antd-mobile-icons'
import type { WhitelistEntry, WhitelistRecommendation } from '../api/types'
import { delJson, getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { pickLiveData } from '../hooks/useLiveData'
import { useSse } from '../hooks/useSse'
import { useToast } from '../hooks/useToast'
import { Badge, Meter, Panel, errorText } from '../components/console'
import type { Tone } from '../components/console'
import { EmptyState } from '../components/EmptyState'
import { HighlightText } from '../components/HighlightText'
import { PageHeader } from '../components/PageHeader'
import { copyToClipboard, formatNumber } from '../lib/format'
import { isValidCidr } from '../lib/validation'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const WHITELIST_URL = '/api/v1/whitelist'
const WHITELIST_RECOMMENDATIONS_URL = '/api/v1/whitelist/recommendations'

/** 空列表常量：避免 `?? []` 每次渲染都产生新数组，导致 useMemo 失效 */
const EMPTY_ENTRIES: WhitelistEntry[] = []

// ---------------------------------------------------------------------------
// 布局常量（只引用 global.css 的 fw-* 令牌，不引入新颜色）
// ---------------------------------------------------------------------------

/** 次要说明文本：小字、弱化、允许换行（推荐理由与口径说明用） */
const NOTE_TEXT: CSSProperties = {
  fontSize: 10,
  lineHeight: 1.45,
  color: 'var(--fw-text-3)',
  wordBreak: 'break-all',
}

/** 列表项：整行可点（≥44px 触摸目标），单行结构（CIDR + 设备 + 复制提示） */
const LIST_ROW: CSSProperties = { minHeight: 'var(--fw-tap)', alignItems: 'center', cursor: 'pointer' }

/** 面板内的交互提示行（列表可点 / 可滑的说明） */
const HINT_ROW: CSSProperties = {
  padding: '3px 6px',
  fontSize: 10,
  color: 'var(--fw-text-3)',
  borderBottom: '1px solid var(--fw-border)',
}

/** 推荐条目的容器：条目之间用发丝线分界，不靠间距分组 */
const REC_ITEM: CSSProperties = {
  padding: '5px 6px',
  borderBottom: '1px solid var(--fw-border)',
}

// ---------------------------------------------------------------------------
// 纯函数工具
// ---------------------------------------------------------------------------

/**
 * CIDR 表单校验：直接复用共享校验（与后端 `IpAddr`/`Ipv4Addr` 解析规则一致）。
 * 后端 create_whitelist 仍会独立校验，前端这一层只为减少无效请求。
 */
function cidrValidator(_rule: unknown, value: unknown): Promise<void> {
  const raw = String(value ?? '').trim()
  if (raw === '') return Promise.reject(new Error('请输入 CIDR 或单个 IP'))
  return isValidCidr(raw)
    ? Promise.resolve()
    : Promise.reject(new Error('格式不合法：需形如 10.0.0.0/8、192.168.1.1 或 2001:db8::/32'))
}

/** 推荐类型 → 中文标签（后端 rec_type 取值 "subnet" / "ip"） */
function recTypeLabel(recType: string): string {
  if (recType === 'subnet') return '网段'
  if (recType === 'ip') return '单个 IP'
  return recType === '' ? '未知类型' : recType
}

/** 置信度 → 色调（三档，便于一眼区分采纳优先级） */
function confidenceTone(confidence: number): Tone {
  if (confidence >= 80) return 'success'
  if (confidence >= 50) return 'primary'
  return 'default'
}

/** 把任意抛出物转成可展示文案（client 抛出的 ApiError 就是 Error 子类） */
// ---------------------------------------------------------------------------
// 页面
// ---------------------------------------------------------------------------

export default function Whitelist() {
  const toast = useToast()
  const { whitelist: sseWhitelist, payloadSeq } = useSse()

  // SSE 未就绪时的回退：GET /api/v1/whitelist（后端直接返回数组）
  const restEntries = useAsync(() => getJson<WhitelistEntry[]>(WHITELIST_URL), [])
  // 取较新的一份而非「SSE 优先」：增删白名单后的 restEntries.reload() 必须真正生效
  const liveEntries = pickLiveData(sseWhitelist, payloadSeq.whitelist, restEntries)
  const entries = liveEntries ?? EMPTY_ENTRIES

  // 智能推荐：与实时列表解耦，失败不影响主列表展示
  const recommendations = useAsync(
    () => getJson<WhitelistRecommendation[]>(WHITELIST_RECOMMENDATIONS_URL),
    [],
  )

  const [keyword, setKeyword] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  /** 正在被删除 / 采纳的 CIDR：用于按钮 loading，防止重复提交 */
  const [busyCidr, setBusyCidr] = useState<string | null>(null)

  const filtered = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    if (kw === '') return entries
    return entries.filter(
      (entry) =>
        entry.cidr.toLowerCase().includes(kw) || entry.device.toLowerCase().includes(kw),
    )
  }, [entries, keyword])

  const recList = recommendations.data ?? []

  /**
   * 列表变化后统一刷新「白名单 + 推荐」（推荐会随白名单变化而变化）。
   * 返回 Promise 供下拉刷新等待：转圈要转到两份数据都落定再收起。
   */
  const refreshAll = async (): Promise<void> => {
    await Promise.all([restEntries.reload(), recommendations.reload()])
  }

  /** 复制 CIDR：helper 会在不安全上下文里自动降级，失败也静默，故提示留出回退办法 */
  const handleCopy = (cidr: string) => {
    copyToClipboard(cidr)
    toast.info(`已复制 ${cidr}（若剪贴板未更新，请长按手动复制）`)
  }

  /** 新增白名单：写操作，成功后关闭弹层并刷新 */
  const submitCreate = async (values: Record<string, unknown>) => {
    const cidr = String(values.cidr ?? '').trim()
    setSubmitting(true)
    try {
      await sendJson<{ cidr: string }, unknown>(WHITELIST_URL, 'POST', { cidr })
      toast.success(`已加入白名单：${cidr}`)
      setCreateOpen(false)
      refreshAll()
    } catch (e) {
      // 后端会返回 40003 等错误码与原因，这里原样呈现给用户
      toast.error(`新增失败：${errorText(e)}`)
    } finally {
      setSubmitting(false)
    }
  }

  /** 删除白名单：写操作，必须先二次确认 */
  const removeEntry = async (cidr: string) => {
    const confirmed = await Dialog.confirm({
      content: `确定将 ${cidr} 移出白名单？移出后该来源将重新受封禁策略约束。`,
      confirmText: '移出',
    })
    if (!confirmed) return
    setBusyCidr(cidr)
    try {
      await delJson<unknown>(`${WHITELIST_URL}/${encodeURIComponent(cidr)}`)
      toast.success(`已移出白名单：${cidr}`)
      refreshAll()
    } catch (e) {
      toast.error(`移除失败：${errorText(e)}`)
    } finally {
      setBusyCidr(null)
    }
  }

  /** 采纳推荐：等价于新增同一条 CIDR，同样需要确认（推荐是建议，不是自动动作） */
  const acceptRecommendation = async (rec: WhitelistRecommendation) => {
    const confirmed = await Dialog.confirm({
      content: `确定将推荐条目 ${rec.cidr} 加入白名单？共影响 ${formatNumber(rec.affected_ips, false)} 个 IP。`,
      confirmText: '加入',
    })
    if (!confirmed) return
    setBusyCidr(rec.cidr)
    try {
      await sendJson<{ cidr: string }, unknown>(WHITELIST_URL, 'POST', { cidr: rec.cidr })
      toast.success(`已采纳推荐：${rec.cidr}`)
      refreshAll()
    } catch (e) {
      toast.error(`采纳失败：${errorText(e)}`)
    } finally {
      setBusyCidr(null)
    }
  }

  return (
    <>
      <PageHeader
        title="白名单"
        srOnly
        subtitle={`共 ${formatNumber(entries.length, false)} 条；白名单内来源不参与封禁判定`}
      />

      <PullToRefresh onRefresh={refreshAll}>
        <div className="fw-page">
        {/* 回退取数失败且两条来源都无数据：错误必须对用户可见，并提供重试入口 */}
        {liveEntries === null && restEntries.error !== null && (
          <NoticeBar
            color="error"
            wrap
            content={`白名单加载失败：${restEntries.error}`}
            extra={
              <a onClick={() => restEntries.reload()} style={{ color: 'inherit', textDecoration: 'underline' }}>
                重试
              </a>
            }
          />
        )}

        {/* 搜索与新增：搜索只过滤本地列表；新增打开表单弹层 */}
        <Panel title="筛选与新增" padded={false}>
          <div style={{ padding: '4px 6px', display: 'flex', alignItems: 'stretch', gap: 5 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <SearchBar
                placeholder="搜索 CIDR / 设备名"
                value={keyword}
                onChange={setKeyword}
                // antd-mobile 默认高度偏小，显式抬到 44px 触摸目标
                style={{ '--height': '44px' }}
              />
            </div>
            <Button
              color="primary"
              style={{ minHeight: 44, flexShrink: 0 }}
              onClick={() => setCreateOpen(true)}
            >
              <AddOutline /> 新增
            </Button>
          </div>
        </Panel>

        {/* 智能推荐：按置信度展示后端建议，逐条确认后采纳 */}
        <Panel
          title="智能推荐"
          meta={`${formatNumber(recList.length, false)} 条建议`}
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
          ) : recommendations.data === null ? (
            <div style={{ padding: 6 }}>
              <Skeleton.Paragraph lineCount={3} animated />
            </div>
          ) : recList.length === 0 ? (
            <EmptyState
              compact
              title="暂无推荐"
              description="后端按历史封禁统计给出建议；样本不足或当前无需放行时为空"
            />
          ) : (
            recList.map((rec, index) => (
              <div
                key={`${rec.rec_type}:${rec.cidr}`}
                style={{
                  ...REC_ITEM,
                  borderBottom:
                    index === recList.length - 1 ? 'none' : '1px solid var(--fw-border)',
                }}
              >
                {/* 主行：建议网段（等宽）+ 类型与置信度徽标 */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span
                    className="fw-mono"
                    style={{
                      flex: 1,
                      minWidth: 0,
                      fontSize: 12,
                      fontWeight: 600,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {rec.cidr}
                  </span>
                  <Badge tone="primary" dim>
                    {recTypeLabel(rec.rec_type)}
                  </Badge>
                  <Badge tone={confidenceTone(rec.confidence)}>置信 {Math.round(rec.confidence)}</Badge>
                </div>

                {/* 置信度细条：数值已在上行给出，这里只表达量级 */}
                <div style={{ marginTop: 3 }}>
                  <Meter ratio={rec.confidence / 100} tone={confidenceTone(rec.confidence)} />
                </div>

                {rec.reason !== '' && <div style={{ ...NOTE_TEXT, marginTop: 3 }}>{rec.reason}</div>}

                <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginTop: 2 }}>
                  <span style={{ ...NOTE_TEXT, flex: 1, minWidth: 0 }}>
                    影响 {formatNumber(rec.affected_ips, false)} 个 IP · 历史封禁{' '}
                    {formatNumber(rec.total_bans, false)} 次
                  </span>
                  <Button
                    size="mini"
                    color="primary"
                    fill="outline"
                    style={{ minHeight: 44, minWidth: 72, flexShrink: 0 }}
                    loading={busyCidr === rec.cidr}
                    onClick={() => {
                      void acceptRecommendation(rec)
                    }}
                  >
                    采纳
                  </Button>
                </div>
              </div>
            ))
          )}
        </Panel>

        {/* 首屏加载：SSE 与 REST 都还没有结果时给骨架屏，避免误显示「白名单为空」 */}
        {liveEntries === null && restEntries.loading ? (
          <Panel title="已放行" padded>
            <Skeleton.Title animated />
            <Skeleton.Paragraph lineCount={5} animated />
          </Panel>
        ) : (
          <Panel
            title="已放行"
            meta={`${formatNumber(filtered.length, false)} / ${formatNumber(entries.length, false)}`}
            padded={false}
          >
            {/* 交互提示：点击复制与左滑移出的动作在列表上方一句话讲清 */}
            {filtered.length > 0 && <div style={HINT_ROW}>点击行复制 CIDR · 左滑移出</div>}

            {filtered.length === 0 ? (
              <EmptyState
                title={keyword.trim() === '' ? '白名单为空' : '没有匹配的白名单条目'}
                description={
                  keyword.trim() === ''
                    ? '白名单为空时所有来源都受封禁策略约束；可点击「新增」放行可信来源'
                    : `关键词「${keyword.trim()}」未命中任何 CIDR 或设备名`
                }
              />
            ) : (
              filtered.map((entry, index) => {
                const isLast = index === filtered.length - 1
                return (
                  <SwipeAction
                    key={entry.cidr}
                    rightActions={[
                      {
                        key: 'remove',
                        text: busyCidr === entry.cidr ? '移出中' : '移出',
                        color: 'danger',
                        onClick: () => {
                          void removeEntry(entry.cidr)
                        },
                      },
                    ]}
                  >
                    {/* SwipeAction 会把子元素包进滑动轨道，`:last-child` 去线规则会命中每一行，
                        因此分隔线在行内显式控制 */}
                    <div
                      className="fw-row"
                      style={{ ...LIST_ROW, borderBottom: isLast ? 'none' : '1px solid var(--fw-border)' }}
                      onClick={() => handleCopy(entry.cidr)}
                    >
                      <span className="fw-mono" style={{ fontSize: 12, fontWeight: 600 }}>
                        <HighlightText text={entry.cidr} query={keyword} />
                      </span>
                      <span style={{ flex: 1 }} />
                      <span
                        style={{
                          fontSize: 10,
                          color: 'var(--fw-text-3)',
                          maxWidth: '38%',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                      >
                        {entry.device === '' ? (
                          '未绑定设备'
                        ) : (
                          <HighlightText text={entry.device} query={keyword} />
                        )}
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--fw-primary-strong)', flexShrink: 0 }}>
                        复制
                      </span>
                    </div>
                  </SwipeAction>
                )
              })
            )}
          </Panel>
        )}

        {/* 口径说明：让用户知道列表字段来自哪里 */}
        <Panel title="口径" padded={false}>
          <div style={{ padding: '4px 6px', display: 'flex', flexDirection: 'column', gap: 3 }}>
            <div style={NOTE_TEXT}>· 白名单按 CIDR 或单个 IP 匹配，命中后跳过该来源的失败计数与封禁</div>
            <div style={NOTE_TEXT}>· 「绑定设备」由后端按 IP 反查本机网络设备，未识别时为空</div>
          </div>
        </Panel>
        </div>
      </PullToRefresh>

      {/* 新增白名单：destroyOnClose 保证每次打开都是干净表单 */}
      <Popup
        visible={createOpen}
        position="bottom"
        destroyOnClose
        closeOnMaskClick
        onMaskClick={() => setCreateOpen(false)}
      >
        <Form
          layout="horizontal"
          onFinish={(values) => {
            void submitCreate(values as Record<string, unknown>)
          }}
          footer={
            <Button block type="submit" color="primary" size="large" loading={submitting} style={{ minHeight: 44 }}>
              提交
            </Button>
          }
        >
          <Form.Header>新增白名单（写操作：直接改写内核白名单表）</Form.Header>
          <Form.Item name="cidr" label="CIDR / IP" rules={[{ validator: cidrValidator }]}>
            <Input placeholder="例如 10.0.0.0/8、192.168.1.1、2001:db8::/32" clearable />
          </Form.Item>
        </Form>
      </Popup>
    </>
  )
}
