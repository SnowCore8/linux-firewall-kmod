// 白名单管理页（移动优先）
//
// 做什么：卡片式展示白名单条目（CIDR + 绑定设备），支持关键词过滤、CIDR 校验后新增、
//        二次确认删除、复制 CIDR；并展示「智能推荐」——后端按历史封禁统计给出的
//        建议白名单（网段 / 单 IP，带置信度），可一键采纳。
// 影响什么：新增 / 删除 / 采纳推荐都是**写操作**，会真实改写内核白名单表并持久化配置，
//          全部需要二次确认；关键词过滤与复制只在浏览器内完成，不产生请求。
//
// 数据来源（任何一级都是真实端点，无占位假数据）：
//   1) 全局 SSE 的 whitelist 事件（useSse().whitelist）—— 状态变更后服务端会立即推送；
//   2) GET /api/v1/whitelist —— 实时通道未就绪时的回退；
//   3) 推荐列表走 REST GET /api/v1/whitelist/recommendations（后端按需计算，非推送项）。

import { useMemo, useState } from 'react'
import {
  Button,
  Card,
  Dialog,
  Form,
  Input,
  List,
  NoticeBar,
  Popup,
  ProgressBar,
  SearchBar,
  Skeleton,
  Space,
  Tag,
} from 'antd-mobile'
import { AddOutline, DeleteOutline, LoopOutline } from 'antd-mobile-icons'
import type { WhitelistEntry, WhitelistRecommendation } from '../api/types'
import { delJson, getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { useSse } from '../hooks/useSse'
import { useToast } from '../hooks/useToast'
import { PageHeader } from '../components/PageHeader'
import { EmptyState } from '../components/EmptyState'
import { HighlightText } from '../components/HighlightText'
import { copyToClipboard, formatNumber } from '../lib/format'
import { isValidCidr } from '../lib/validation'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const WHITELIST_URL = '/api/v1/whitelist'
const WHITELIST_RECOMMENDATIONS_URL = '/api/v1/whitelist/recommendations'

/** 空列表常量：避免 `?? []` 每次渲染都产生新数组，导致 useMemo 失效 */
const EMPTY_ENTRIES: WhitelistEntry[] = []

/** 次要说明文字样式 */
const MUTED = { color: 'var(--adm-color-text-secondary)', fontSize: 12 } as const
/** 等宽字体：IP / CIDR 用等宽更易逐字符核对 */
const MONO = { fontFamily: 'var(--fw-font-mono)', wordBreak: 'break-all' } as const

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

/** 置信度 → Tag 颜色（三档，便于一眼区分采纳优先级） */
function confidenceTone(confidence: number): 'success' | 'primary' | 'default' {
  if (confidence >= 80) return 'success'
  if (confidence >= 50) return 'primary'
  return 'default'
}

/** 把任意抛出物转成可展示文案（client 抛出的 ApiError 就是 Error 子类） */
function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

export default function Whitelist() {
  const toast = useToast()
  const { whitelist: sseWhitelist } = useSse()

  // SSE 未就绪时的回退：GET /api/v1/whitelist（后端直接返回数组）
  const restEntries = useAsync(() => getJson<WhitelistEntry[]>(WHITELIST_URL), [])
  const entries = sseWhitelist ?? restEntries.data ?? EMPTY_ENTRIES

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

  /** 卸载或列表变化后统一刷新「白名单 + 推荐」（推荐会随白名单变化而变化） */
  const refreshAll = () => {
    restEntries.reload()
    recommendations.reload()
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
        subtitle={`共 ${formatNumber(entries.length, false)} 条；白名单内来源不参与封禁判定`}
        extra={
          <Button
            size="small"
            fill="none"
            style={{ minHeight: 44 }}
            aria-label="刷新白名单与推荐"
            onClick={refreshAll}
          >
            <LoopOutline fontSize={18} />
          </Button>
        }
      />

      <div style={{ paddingBottom: 7 }}>
        {/* 回退取数失败且 SSE 无数据：错误必须对用户可见，并提供重试入口 */}
        {sseWhitelist === null && restEntries.error !== null && (
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

        <SearchBar
          placeholder="搜索 CIDR / 设备名"
          value={keyword}
          onChange={setKeyword}
          // antd-mobile 默认高度偏小，显式抬到 44px 触摸目标
          style={{ '--height': '44px' }}
        />

        <Space block style={{ marginTop: 7 }}>
          <Button color="primary" style={{ minHeight: 44 }} onClick={() => setCreateOpen(true)}>
            <AddOutline /> 新增白名单
          </Button>
        </Space>

        {/* 智能推荐：按置信度展示后端建议，逐条确认后采纳 */}
        <Card title="智能推荐" style={{ marginTop: 7 }}>
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
          ) : recommendations.data === null ? (
            <Skeleton.Paragraph lineCount={3} animated />
          ) : recList.length === 0 ? (
            <EmptyState
              compact
              title="暂无推荐"
              description="后端按历史封禁统计给出建议；样本不足或当前无需放行时为空"
            />
          ) : (
            recList.map((rec) => (
              <div
                key={`${rec.rec_type}:${rec.cidr}`}
                style={{
                  padding: '6px 0',
                  borderBottom: '1px solid var(--fw-border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ ...MONO, flex: 1, minWidth: 0, fontSize: 14 }}>{rec.cidr}</span>
                  <Tag color="primary" fill="outline">
                    {recTypeLabel(rec.rec_type)}
                  </Tag>
                  <Tag color={confidenceTone(rec.confidence)} fill="outline">
                    置信度 {Math.round(rec.confidence)}
                  </Tag>
                </div>

                <div style={{ ...MUTED, marginTop: 2 }}>{rec.reason}</div>
                <div style={{ ...MUTED, marginTop: 1 }}>
                  影响 {formatNumber(rec.affected_ips, false)} 个 IP · 历史封禁{' '}
                  {formatNumber(rec.total_bans, false)} 次
                </div>

                {/* 置信度进度条：文本另给真实数值，避免只靠长度判断 */}
                <ProgressBar percent={Math.min(Math.max(rec.confidence, 0), 100)} text={false} />

                <Button
                  block
                  size="small"
                  color="primary"
                  fill="outline"
                  style={{ marginTop: 5, minHeight: 44 }}
                  loading={busyCidr === rec.cidr}
                  onClick={() => {
                    void acceptRecommendation(rec)
                  }}
                >
                  采纳并加入白名单
                </Button>
              </div>
            ))
          )}
        </Card>

        {/* 首屏加载：SSE 与 REST 都还没有结果时给骨架屏，避免误显示「白名单为空」 */}
        {sseWhitelist === null && restEntries.loading && (
          <div style={{ marginTop: 7 }}>
            <Skeleton.Title animated />
            <Skeleton.Paragraph lineCount={5} animated />
          </div>
        )}

        {filtered.length === 0 && !restEntries.loading && (
          <EmptyState
            title={keyword.trim() === '' ? '白名单为空' : '没有匹配的白名单条目'}
            description={
              keyword.trim() === ''
                ? '白名单为空时所有来源都受封禁策略约束；可点击「新增白名单」放行可信来源'
                : `关键词「${keyword.trim()}」未命中任何 CIDR 或设备名`
            }
          />
        )}

        {filtered.map((entry) => (
          <Card key={entry.cidr} style={{ marginTop: 5 }}>
            <div style={{ ...MONO, fontSize: 14 }}>
              <HighlightText text={entry.cidr} query={keyword} />
            </div>

            <div style={{ marginTop: 4 }}>
              {entry.device === '' ? (
                <Tag fill="outline">未绑定设备</Tag>
              ) : (
                <Tag color="success" fill="outline">
                  <HighlightText text={entry.device} query={keyword} />
                </Tag>
              )}
            </div>

            <div style={{ display: 'flex', gap: 5, marginTop: 6 }}>
              <Button style={{ flex: 1, minHeight: 44 }} onClick={() => handleCopy(entry.cidr)}>
                复制
              </Button>
              <Button
                color="danger"
                fill="outline"
                style={{ flex: 1, minHeight: 44 }}
                loading={busyCidr === entry.cidr}
                onClick={() => {
                  void removeEntry(entry.cidr)
                }}
              >
                <DeleteOutline /> 移出
              </Button>
            </div>
          </Card>
        ))}

        {/* 统计口径说明：让用户知道列表字段来自哪里 */}
        <List header="说明" style={{ marginTop: 7 }}>
          <List.Item>白名单按 CIDR 或单个 IP 匹配，命中后跳过该来源的失败计数与封禁</List.Item>
          <List.Item>「绑定设备」由后端按 IP 反查本机网络设备，未识别时为空</List.Item>
        </List>
      </div>

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
