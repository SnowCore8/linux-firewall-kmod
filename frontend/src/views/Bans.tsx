// 封禁管理页（移动优先）
//
// 做什么：卡片式列出当前活跃封禁，支持关键词搜索、多维排序、新建封禁、单条解封、
//        批量封禁多个 IP、一键解封全部临时封禁，以及单 IP 的封禁详情（信誉分 / 渐进式等级 / 下次时长）。
// 影响什么：新建与解封都会真实下发 netlink 命令改写内核封禁表，属**写操作**且全部需要二次确认；
//          搜索、排序、渐进展示只在浏览器内进行，不产生额外请求。
//
// 数据来源：优先全局 SSE 的 bans 事件（后端推的就是全量活跃封禁列表）；
//          SSE 未就绪时回退 GET /api/v1/bans（不带分页参数时后端同样返回全量）。
// 排序语义与后端 api.rs::get_active_bans_paginated 的 sort_by 取值逐一对应，
// 其中 remaining_asc/remaining_desc 把永久封禁（后端用 -1 表示）分别排到末位/首位。

import { useEffect, useMemo, useState } from 'react'
import {
  Button,
  Card,
  Checkbox,
  Dialog,
  Form,
  InfiniteScroll,
  Input,
  List,
  NoticeBar,
  Popup,
  ProgressBar,
  SearchBar,
  Selector,
  Skeleton,
  Space,
  Tag,
} from 'antd-mobile'
import type { SelectorOption } from 'antd-mobile'
import { DeleteOutline, LoopOutline } from 'antd-mobile-icons'
import type { BanResponse } from '../api/types'
import { delJson, getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { useSse } from '../hooks/useSse'
import { useToast } from '../hooks/useToast'
import { PageHeader } from '../components/PageHeader'
import { EmptyState } from '../components/EmptyState'
import { HighlightText } from '../components/HighlightText'
import { formatDatetime, formatDuration, formatNumber } from '../lib/format'
import { isValidDuration, isValidIp } from '../lib/validation'

/** 端点常量与 handler.rs 路由一一对应 */
const BANS_URL = '/api/v1/bans'
const BAN_BATCH_URL = '/api/v1/bans/batch'
const BAN_UNBAN_TEMPORARY_URL = '/api/v1/bans/unban-temporary'

/** 空列表常量：避免 `?? []` 每次渲染产生新数组导致 useMemo 失效 */
const EMPTY_BANS: BanResponse[] = []

/** 每次渐进展示的条数：控制 DOM 规模，长列表不一次性渲染 */
const PAGE_STEP = 30

/** 新建封禁 / 后端 api.rs::CreateBanRequest —— duration 省略或 0 表示永久封禁 */
interface CreateBanBody {
  ip: string
  duration?: number
  reason?: string
}

/** 后端 ban_ops.rs::BanOperationResponse */
interface BanOperationResponse {
  ip: string
  action: string
  permanent: boolean
  duration_seconds: number | null
}

/** 后端 ban_ops.rs::BatchOperationResponse */
interface BatchOperationResponse {
  total: number
  succeeded: number
  failed_count: number
  details: string[]
}

/** 后端 ban_ops.rs::BanDetailResponse */
interface BanDetailResponse {
  ip: string
  is_banned: boolean
  jail_name: string
  reason: string
  banned_at: number
  expires_at: number
  is_permanent: boolean
  fail_count: number
  ban_count: number
  last_unbanned_at: number
  was_permanent: boolean
  progressive_level: string
  next_ban_duration: string
  reputation_score: number
  reputation_multiplier: number
}

/** 排序选项：value 直接使用后端 sort_by 的取值字符串，避免前后端语义漂移 */
const SORT_OPTIONS: SelectorOption<string>[] = [
  { label: '最新封禁', value: 'banned_at_desc' },
  { label: '最早封禁', value: 'banned_at_asc' },
  { label: '剩余时间少', value: 'remaining_asc' },
  { label: '剩余时间多', value: 'remaining_desc' },
  { label: 'IP 升序', value: 'ip_asc' },
  { label: 'IP 降序', value: 'ip_desc' },
  { label: 'Jail 升序', value: 'jail_asc' },
]

/** 永久封禁在「剩余时间」排序中的键：与后端一致地推到另一端 */
function remainingKey(seconds: number): number {
  return seconds < 0 ? Number.MAX_SAFE_INTEGER : seconds
}

/** 与后端一致的排序实现（升序/降序语义逐一对应 sort_by 取值） */
function sortBans(list: BanResponse[], sortBy: string): BanResponse[] {
  const copy = [...list]
  switch (sortBy) {
    case 'banned_at_asc':
      return copy.sort((a, b) => a.banned_at - b.banned_at)
    case 'remaining_asc':
      return copy.sort((a, b) => remainingKey(a.remaining_seconds) - remainingKey(b.remaining_seconds))
    case 'remaining_desc':
      return copy.sort((a, b) => remainingKey(b.remaining_seconds) - remainingKey(a.remaining_seconds))
    case 'ip_asc':
      return copy.sort((a, b) => a.ip.localeCompare(b.ip))
    case 'ip_desc':
      return copy.sort((a, b) => b.ip.localeCompare(a.ip))
    case 'jail_asc':
      return copy.sort((a, b) => a.jail.localeCompare(b.jail))
    default:
      // banned_at_desc（后端默认）
      return copy.sort((a, b) => b.banned_at - a.banned_at)
  }
}

/** 统一把任意异常转为可展示文本；client 抛出的 ApiError 也是 Error 子类 */
function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** IP 表单校验：调用共享校验，与后端「必须是合法 IP 字面量」的约束一致 */
function ipValidator(_rule: unknown, value: unknown): Promise<void> {
  const raw = String(value ?? '').trim()
  if (raw === '') return Promise.reject(new Error('请输入 IP 地址'))
  return isValidIp(raw) ? Promise.resolve() : Promise.reject(new Error('IP 地址格式不合法（需 IPv4 或 IPv6）'))
}

/** 时长校验：留空＝永久封禁，其余必须是合法秒数 */
function durationValidator(_rule: unknown, value: unknown): Promise<void> {
  const raw = String(value ?? '').trim()
  return isValidDuration(raw)
    ? Promise.resolve()
    : Promise.reject(new Error('时长需为 0~86400 的整数秒，留空表示永久封禁'))
}

/** 详情行的左右布局 */
const DETAIL_ROW = { display: 'flex', justifyContent: 'space-between', gap: 7 } as const
const MUTED = { color: 'var(--adm-color-text-secondary)', fontSize: 12 } as const

export default function Bans() {
  const toast = useToast()
  const { bans: sseBans } = useSse()

  // SSE 未就绪时的回退：不带分页参数 → 后端返回全量活跃封禁
  const restBans = useAsync(() => getJson<BanResponse[]>(BANS_URL), [])
  const list = sseBans ?? restBans.data ?? EMPTY_BANS

  const [keyword, setKeyword] = useState('')
  const [sortBy, setSortBy] = useState('banned_at_desc')
  const [visibleCount, setVisibleCount] = useState(PAGE_STEP)

  // 选择模式与批量操作
  const [selectMode, setSelectMode] = useState(false)
  const [selected, setSelected] = useState<string[]>([])

  // 新建封禁弹层
  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)

  // 详情弹层
  const [detailIp, setDetailIp] = useState<string | null>(null)
  // 单条解封 / 批量操作的进行中标记，用于按钮 loading
  const [busyIp, setBusyIp] = useState<string | null>(null)
  const [batching, setBatching] = useState(false)

  // 关键词或排序变化后回到首屏，避免用户看到「已滚到一半」的旧视图
  useEffect(() => {
    setVisibleCount(PAGE_STEP)
  }, [keyword, sortBy])

  const filtered = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    const matched =
      kw === ''
        ? list
        : list.filter(
            (b) =>
              b.ip.toLowerCase().includes(kw) ||
              b.jail.toLowerCase().includes(kw) ||
              b.reason.toLowerCase().includes(kw),
          )
    return sortBans(matched, sortBy)
  }, [list, keyword, sortBy])

  const shown = filtered.slice(0, visibleCount)
  const hasMore = visibleCount < filtered.length

  // 详情按需取数：未选中 IP 时直接返回 null，不产生请求
  const detail = useAsync(
    () =>
      detailIp === null
        ? Promise.resolve<BanDetailResponse | null>(null)
        : getJson<BanDetailResponse>(`${BANS_URL}/${encodeURIComponent(detailIp)}/detail`),
    [detailIp],
  )

  const loadMore = async (): Promise<void> => {
    setVisibleCount((v) => v + PAGE_STEP)
  }

  const toggleSelect = (ip: string) => {
    setSelected((prev) => (prev.includes(ip) ? prev.filter((x) => x !== ip) : [...prev, ip]))
  }

  /** 单条解封：先确认，再调用真实 DELETE，失败时把后端消息原样呈现给用户 */
  const unban = async (ip: string): Promise<boolean> => {
    const confirmed = await Dialog.confirm({
      content: `确定解封 ${ip}？该操作会立即下发内核解封命令。`,
      confirmText: '解封',
    })
    if (!confirmed) return false
    setBusyIp(ip)
    try {
      const resp = await delJson<BanOperationResponse>(`${BANS_URL}/${encodeURIComponent(ip)}`)
      toast.success(`已解封 ${resp.ip}`)
      restBans.reload()
      return true
    } catch (e) {
      toast.error(`解封失败：${errorText(e)}`)
      return false
    } finally {
      setBusyIp(null)
    }
  }

  /** 新建封禁：提交后按后端校验结果反馈，成功则清空表单并关闭弹层 */
  const submitCreate = async (values: Record<string, unknown>) => {
    const ip = String(values.ip ?? '').trim()
    const durationRaw = String(values.duration ?? '').trim()
    const reason = String(values.reason ?? '').trim()
    setCreating(true)
    try {
      const body: CreateBanBody = { ip }
      // 留空 → 不发送 duration，后端按永久封禁处理
      if (durationRaw !== '') body.duration = Number(durationRaw)
      if (reason !== '') body.reason = reason
      const resp = await sendJson<CreateBanBody, BanOperationResponse>(BANS_URL, 'POST', body)
      toast.success(resp.permanent ? `已永久封禁 ${resp.ip}` : `已封禁 ${resp.ip} ${resp.duration_seconds ?? 0} 秒`)
      setCreateOpen(false)
      restBans.reload()
    } catch (e) {
      toast.error(`封禁失败：${errorText(e)}`)
    } finally {
      setCreating(false)
    }
  }

  /** 批量封禁选中 IP：后端单次上限 100 个，这里预先拦截避免无谓请求 */
  const batchBan = async () => {
    if (selected.length === 0) return
    if (selected.length > 100) {
      toast.error(`单次最多封禁 100 个 IP，当前已选 ${selected.length} 个`)
      return
    }
    const confirmed = await Dialog.confirm({
      content: `确定批量封禁选中的 ${selected.length} 个 IP？后端将统一使用 3600 秒封禁时长。`,
      confirmText: '批量封禁',
    })
    if (!confirmed) return
    setBatching(true)
    try {
      const resp = await sendJson<string[], BatchOperationResponse>(BAN_BATCH_URL, 'POST', selected)
      if (resp.failed_count > 0) {
        toast.error(`成功 ${resp.succeeded} 个，失败 ${resp.failed_count} 个：${resp.details.slice(0, 2).join('；')}`)
      } else {
        toast.success(`已封禁 ${resp.succeeded} 个 IP`)
      }
      setSelected([])
      restBans.reload()
    } catch (e) {
      toast.error(`批量封禁失败：${errorText(e)}`)
    } finally {
      setBatching(false)
    }
  }

  /** 一键解封所有临时封禁：永久封禁保留 */
  const unbanAllTemporary = async () => {
    const confirmed = await Dialog.confirm({
      content: '确定解封所有临时封禁？永久封禁不受影响。',
      confirmText: '全部解封',
    })
    if (!confirmed) return
    setBatching(true)
    try {
      const resp = await sendJson<Record<string, never>, BatchOperationResponse>(
        BAN_UNBAN_TEMPORARY_URL,
        'POST',
        {},
      )
      if (resp.failed_count > 0) {
        toast.error(`成功 ${resp.succeeded} 个，失败 ${resp.failed_count} 个，详情见守护进程日志`)
      } else {
        toast.success(`已解封 ${resp.succeeded} 个临时封禁`)
      }
      restBans.reload()
    } catch (e) {
      toast.error(`批量解封失败：${errorText(e)}`)
    } finally {
      setBatching(false)
    }
  }

  const detailData = detail.data

  return (
    <>
      <PageHeader
        title="封禁管理"
        subtitle={`显示 ${formatNumber(filtered.length, false)} / 共 ${formatNumber(list.length, false)} 条活跃封禁`}
        extra={
          <Button
            size="small"
            fill="none"
            style={{ minHeight: 44 }}
            onClick={() => {
              restBans.reload()
            }}
          >
            <LoopOutline fontSize={18} />
          </Button>
        }
      />

      {/* 外层 .fw-main 已提供 12px 内边距，这里只补底部留白 */}
      <div style={{ paddingBottom: 7 }}>
        {/* REST 回退失败且 SSE 无数据时，错误对用户可见 */}
        {sseBans === null && restBans.error !== null && (
          <NoticeBar
            color="error"
            wrap
            content={`封禁列表加载失败：${restBans.error}`}
            extra={
              <a onClick={() => restBans.reload()} style={{ color: 'inherit', textDecoration: 'underline' }}>
                重试
              </a>
            }
          />
        )}

        <SearchBar
          placeholder="搜索 IP / Jail / 原因"
          value={keyword}
          onChange={setKeyword}
          style={{ '--height': '44px' }}
        />

        <div style={{ marginTop: 5 }}>
          <Selector options={SORT_OPTIONS} value={[sortBy]} onChange={(v) => setSortBy(v[0] ?? 'banned_at_desc')} />
        </div>

        <Space wrap block style={{ marginTop: 7 }}>
          <Button color="primary" style={{ minHeight: 44 }} onClick={() => setCreateOpen(true)}>
            新建封禁
          </Button>
          <Button
            style={{ minHeight: 44 }}
            onClick={() => {
              setSelectMode((v) => !v)
              setSelected([])
            }}
          >
            {selectMode ? '退出多选' : '多选'}
          </Button>
          <Button
            style={{ minHeight: 44 }}
            loading={batching}
            onClick={() => {
              void unbanAllTemporary()
            }}
          >
            解封全部临时封禁
          </Button>
          {selectMode && (
            <>
              <Button
                color="danger"
                fill="outline"
                style={{ minHeight: 44 }}
                disabled={selected.length === 0}
                loading={batching}
                onClick={() => {
                  void batchBan()
                }}
              >
                批量封禁（{selected.length}）
              </Button>
              <Button
                size="small"
                fill="none"
                style={{ minHeight: 44 }}
                onClick={() => setSelected(filtered.map((b) => b.ip))}
              >
                全选筛选结果
              </Button>
              <Button
                size="small"
                fill="none"
                style={{ minHeight: 44 }}
                disabled={selected.length === 0}
                onClick={() => setSelected([])}
              >
                清空选择
              </Button>
            </>
          )}
        </Space>

        {/* 首屏加载：SSE 与 REST 都还没有结果时给骨架屏，避免误显示「无封禁」 */}
        {sseBans === null && restBans.loading && (
          <div style={{ marginTop: 7 }}>
            <Skeleton.Title animated />
            <Skeleton.Paragraph lineCount={6} animated />
          </div>
        )}

        {filtered.length === 0 && !restBans.loading && (
          <EmptyState
            title={keyword.trim() === '' ? '当前没有活跃封禁' : '没有匹配的封禁记录'}
            description={keyword.trim() === '' ? '内核封禁表为空，系统处于平静状态' : `关键词「${keyword.trim()}」未命中任何 IP / Jail / 原因`}
          />
        )}

        <div style={{ marginTop: 7 }}>
          {shown.map((ban) => {
            const isSelected = selected.includes(ban.ip)
            return (
              <Card
                key={ban.ip}
                style={{ marginBottom: 5 }}
                onClick={selectMode ? () => toggleSelect(ban.ip) : undefined}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 5 }}>
                  <span style={{ fontFamily: 'var(--adm-font-family-mono, monospace)', fontSize: 14, wordBreak: 'break-all' }}>
                    <HighlightText text={ban.ip} query={keyword} />
                  </span>
                  {selectMode ? (
                    <Checkbox checked={isSelected} />
                  ) : (
                    <Tag color={ban.is_permanent ? 'danger' : 'warning'} fill="outline">
                      {ban.is_permanent ? '永久' : formatDuration(ban.remaining_seconds)}
                    </Tag>
                  )}
                </div>

                <div style={{ ...MUTED, marginTop: 4 }}>
                  Jail <HighlightText text={ban.jail} query={keyword} /> · 第 {formatNumber(ban.ban_count, false)} 次封禁
                </div>
                <div style={{ ...MUTED, marginTop: 1 }}>
                  原因 <HighlightText text={ban.reason} query={keyword} />
                </div>
                <div style={{ ...MUTED, marginTop: 1 }}>封禁时间 {formatDatetime(ban.banned_at)}</div>

                {!selectMode && (
                  <div style={{ display: 'flex', gap: 5, marginTop: 6 }}>
                    <Button style={{ flex: 1, minHeight: 44 }} onClick={() => setDetailIp(ban.ip)}>
                      详情
                    </Button>
                    <Button
                      color="danger"
                      fill="outline"
                      style={{ flex: 1, minHeight: 44 }}
                      loading={busyIp === ban.ip}
                      onClick={() => {
                        void unban(ban.ip)
                      }}
                    >
                      解封
                    </Button>
                  </div>
                )}
              </Card>
            )
          })}
        </div>

        {/* 客户端渐进展示：控制长列表的 DOM 规模，数据本身已在内存中 */}
        <InfiniteScroll loadMore={loadMore} hasMore={hasMore} />
      </div>

      {/* 新建封禁：destroyOnClose 保证每次打开都是干净表单 */}
      <Popup visible={createOpen} position="bottom" destroyOnClose closeOnMaskClick onMaskClick={() => setCreateOpen(false)}>
        <Form
          layout="horizontal"
          onFinish={(values) => {
            void submitCreate(values as Record<string, unknown>)
          }}
          footer={
            <Button block type="submit" color="primary" size="large" loading={creating} style={{ minHeight: 44 }}>
              提交封禁
            </Button>
          }
        >
          <Form.Header>新建封禁（写操作：直接下发内核）</Form.Header>
          <Form.Item name="ip" label="IP 地址" rules={[{ validator: ipValidator }]}>
            <Input placeholder="例如 203.0.113.7 或 2001:db8::1" />
          </Form.Item>
          <Form.Item name="duration" label="时长(秒)" rules={[{ validator: durationValidator }]}>
            <Input placeholder="留空或 0 表示永久封禁" inputMode="numeric" />
          </Form.Item>
          <Form.Item name="reason" label="原因">
            <Input placeholder="可选，写入审计与封禁详情" />
          </Form.Item>
        </Form>
      </Popup>

      {/* 封禁详情：信誉分 / 渐进式等级 / 下次封禁时长 */}
      <Popup visible={detailIp !== null} position="bottom" destroyOnClose closeOnMaskClick onMaskClick={() => setDetailIp(null)}>
        <div style={{ padding: 10, maxHeight: '80vh', overflowY: 'auto' }}>
          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 7, wordBreak: 'break-all' }}>
            {detailIp}
          </div>

          {detail.error !== null && <NoticeBar color="error" wrap content={`详情加载失败：${detail.error}`} />}
          {detailData === null && detail.error === null && <Skeleton.Paragraph lineCount={6} animated />}

          {detailData !== null && (
            <>
              <Space wrap style={{ marginBottom: 7 }}>
                <Tag color={detailData.is_banned ? 'danger' : 'default'} fill="solid">
                  {detailData.is_banned ? '封禁中' : '未处于封禁状态'}
                </Tag>
                <Tag fill="outline">{detailData.progressive_level}</Tag>
                {detailData.was_permanent && (
                  <Tag color="danger" fill="outline">
                    曾被永久封禁
                  </Tag>
                )}
              </Space>

              <div style={{ marginBottom: 7 }}>
                <div style={DETAIL_ROW}>
                  <span style={MUTED}>IP 信誉分（100 = 完全信任）</span>
                  <span>{detailData.reputation_score}</span>
                </div>
                <ProgressBar percent={detailData.reputation_score} text={false} />
                <div style={MUTED}>当前阈值乘数 {detailData.reputation_multiplier}</div>
              </div>

              <List>
                <List.Item extra={detailData.jail_name === '' ? 'N/A' : detailData.jail_name}>Jail</List.Item>
                <List.Item extra={detailData.reason === '' ? 'N/A' : detailData.reason}>原因</List.Item>
                <List.Item extra={formatDatetime(detailData.banned_at)}>封禁时间</List.Item>
                <List.Item extra={detailData.is_permanent ? '永久' : formatDatetime(detailData.expires_at)}>
                  过期时间
                </List.Item>
                <List.Item extra={formatNumber(detailData.fail_count, false)}>触发前失败次数</List.Item>
                <List.Item extra={formatNumber(detailData.ban_count, false)}>累计封禁次数</List.Item>
                <List.Item extra={detailData.last_unbanned_at > 0 ? formatDatetime(detailData.last_unbanned_at) : '仍在封禁中'}>
                  上次解封时间
                </List.Item>
                <List.Item extra={detailData.next_ban_duration}>下次封禁时长</List.Item>
              </List>

              {detailData.is_banned && (
                <Button
                  block
                  color="danger"
                  style={{ marginTop: 7, minHeight: 44 }}
                  loading={busyIp === detailData.ip}
                  onClick={() => {
                    void unban(detailData.ip).then((ok) => {
                      // 仅在真正解封成功后才关闭详情，失败时保留上下文供用户重试
                      if (ok) setDetailIp(null)
                    })
                  }}
                >
                  <DeleteOutline /> 解封该 IP
                </Button>
              )}
            </>
          )}
        </div>
      </Popup>
    </>
  )
}
