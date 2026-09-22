// 封禁管理页（控制台风格）
//
// 做什么：以控制台式高密度列表呈现当前活跃封禁。每条封禁压成两行——
//        主行 = IP（等宽）+ 右侧状态标（永久 / 剩余时长），
//        次行 = 封禁时间 · Jail · 累计次数 · 原因（单行省略，详情里看全）；
//        整行点击打开详情，左滑露出解封。另支持关键词搜索、状态筛选（全部 / 永久 / 临时）、
//        排序、新建封禁、批量选择与批量封禁、一键解封全部临时封禁。
// 影响什么：新建 / 解封 / 批量封禁 / 批量解封都是**写操作**，会真实下发 netlink 命令改写
//          内核封禁表，全部经过二次确认；搜索、筛选、排序、渐进展示只在浏览器内进行，
//          不产生额外请求。
//
// 数据来源：优先全局 SSE 的 bans 事件（后端推的就是全量活跃封禁列表）；
//          SSE 未就绪时回退 GET /api/v1/bans（分页信封，取第一页 items），
//          两者按共享新鲜度戳取较新一份（见 hooks/useLiveData.ts）——写操作后的
//          reload() 必须真正反映到界面，不能写回「SSE 优先」。
// 排序语义与后端 api.rs::get_active_bans_paginated 的 sort_by 取值逐一对应，
// 其中 remaining_asc/remaining_desc 把永久封禁（后端用 -1 表示）分别排到末位/首位。

import { useEffect, useMemo, useState } from 'react'
import type { CSSProperties } from 'react'
import {
  Button,
  Checkbox,
  Dialog,
  Form,
  InfiniteScroll,
  Input,
  NoticeBar,
  Picker,
  Popup,
  PullToRefresh,
  SearchBar,
  Skeleton,
  SwipeAction,
} from 'antd-mobile'
import { DeleteOutline } from 'antd-mobile-icons'
import type {
  BanDetailResponse,
  BanOperationResponse,
  BanResponse,
  BanSortKey,
  BatchOperationResponse,
  CreateBanRequest,
} from '../api/types'
import { delJson, getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { pickLiveData } from '../hooks/useLiveData'
import { useSse } from '../hooks/useSse'
import { useToast } from '../hooks/useToast'
import { Badge, Meter, Panel, Row, Rows, errorText } from '../components/console'
import type { Tone } from '../components/console'
import { EmptyState } from '../components/EmptyState'
import { HighlightText } from '../components/HighlightText'
import { PageHeader } from '../components/PageHeader'
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

/** 状态筛选：全部 / 仅永久 / 仅临时（纯本地过滤） */
type StatusFilter = 'all' | 'permanent' | 'temporary'

const STATUS_FILTERS: { value: StatusFilter; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'permanent', label: '永久' },
  { value: 'temporary', label: '临时' },
]

/** 排序选项：value 直接使用后端 sort_by 的取值字符串，避免前后端语义漂移 */
const SORT_OPTIONS: { label: string; value: BanSortKey }[] = [
  { label: '最新封禁', value: 'banned_at_desc' },
  { label: '最早封禁', value: 'banned_at_asc' },
  { label: '剩余时间少', value: 'remaining_asc' },
  { label: '剩余时间多', value: 'remaining_desc' },
  { label: 'IP 升序', value: 'ip_asc' },
  { label: 'IP 降序', value: 'ip_desc' },
  { label: 'Jail 升序', value: 'jail_asc' },
]

// ---------------------------------------------------------------------------
// 布局常量（只引用 global.css 的 fw-* 令牌，不引入新颜色）
// ---------------------------------------------------------------------------

/** 控制台按钮选中态：主色描边 + 主色软底（叠加在 .fw-cmd 上） */
const CMD_ON: CSSProperties = {
  borderColor: 'var(--fw-primary-strong)',
  background: 'var(--fw-primary-soft)',
  color: 'var(--fw-primary-strong)',
}

/** 工具按钮：保证 ≥44px 的触摸目标（两字标签下仍成立） */
const CMD_WIDE: CSSProperties = { minWidth: 48, padding: '0 10px' }

/** 页内工具条：控件横排，窄屏自动换行 */
const TOOLBAR: CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  alignItems: 'stretch',
  gap: 5,
  padding: '4px 6px',
}

/** 列表项：整行可点（≥44px 触摸目标），两行堆叠（主行标识 + 次行元信息） */
const LIST_ROW: CSSProperties = {
  minHeight: 'var(--fw-tap)',
  flexDirection: 'column',
  alignItems: 'stretch',
  justifyContent: 'center',
  gap: 2,
  cursor: 'pointer',
}

/** 列表项主行：关键标识 + 右侧状态标 */
const LIST_ROW_TOP: CSSProperties = { display: 'flex', alignItems: 'center', gap: 5 }

/** 列表项次行：元信息小字，单行、超长省略 */
const LIST_ROW_SUB: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 4,
  minWidth: 0,
  fontSize: 10,
  color: 'var(--fw-text-3)',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
}

/** 面板内的交互提示行（列表可点 / 可滑的说明） */
const HINT_ROW: CSSProperties = {
  padding: '3px 6px',
  fontSize: 10,
  color: 'var(--fw-text-3)',
  borderBottom: '1px solid var(--fw-border)',
}

/** 明细弹层里的横向徽标组 */
const BADGE_ROW: CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: 4,
  padding: '5px 6px 3px',
}

/** Popup 顶部的标题条：标识 + 关闭入口 */
const POPUP_HEAD: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 6,
  padding: '4px 6px',
  borderBottom: '1px solid var(--fw-border)',
}

/** IP 标题（可能很长：IPv6 不换行截断，详情正文里有完整重复） */
const POPUP_HEAD_TITLE: CSSProperties = {
  flex: 1,
  minWidth: 0,
  fontWeight: 600,
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
}

/** 平台侧带内边距的明细块（用于面板内嵌的非 Row 内容） */
const DETAIL_PAD: CSSProperties = { padding: '4px 6px' }

// ---------------------------------------------------------------------------
// 纯函数工具
// ---------------------------------------------------------------------------

/** 永久封禁在「剩余时间」排序中的键：与后端一致地推到另一端 */
function remainingKey(seconds: number): number {
  return seconds < 0 ? Number.MAX_SAFE_INTEGER : seconds
}

/** 与后端一致的排序实现（升序/降序语义逐一对应 sort_by 取值） */
function sortBans(list: BanResponse[], sortBy: BanSortKey): BanResponse[] {
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

/** 排序 Picker 的返回值收敛：PickerValue 可能是 number / null，非法值回退默认排序 */
function toSortKey(value: unknown): BanSortKey {
  const hit = SORT_OPTIONS.find((option) => option.value === value)
  return hit ? hit.value : 'banned_at_desc'
}

/** 信誉分色调：分数越高越可信（70+ 绿 / 40+ 黄 / 其余红） */
function reputationTone(score: number): Tone {
  if (score >= 70) return 'success'
  if (score >= 40) return 'warning'
  return 'danger'
}

/** 统一把任意异常转为可展示文本；client 抛出的 ApiError 也是 Error 子类 */
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

/** 封禁状态徽标：永久用 danger，临时用 warning（数值在详情里另有精确展示） */
function banStatusBadge(ban: BanResponse) {
  return ban.is_permanent ? (
    <Badge tone="danger">永久</Badge>
  ) : (
    <Badge tone="warning">{formatDuration(ban.remaining_seconds)}</Badge>
  )
}

// ---------------------------------------------------------------------------
// 页面
// ---------------------------------------------------------------------------

export default function Bans() {
  const toast = useToast()
  const { bans: sseBans, payloadSeq } = useSse()

  // SSE 未就绪时的回退：GET /api/v1/bans 恒为分页信封，取第一页 items 即可
  // （SSE 的 bans 事件推的才是全量；此回退只在连接建立前短暂生效）。
  const restBans = useAsync(
    () =>
      getJson<{ items: BanResponse[] }>(BANS_URL).then((page) => page.items),
    [],
  )
  // 取较新的一份而非「SSE 优先」：解封/封禁/批量操作后的 restBans.reload()
  // 必须真正反映到界面（详见 hooks/useLiveData.ts）。
  const liveBans = pickLiveData(sseBans, payloadSeq.bans, restBans)
  const list = liveBans ?? EMPTY_BANS

  const [keyword, setKeyword] = useState('')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [sortBy, setSortBy] = useState<BanSortKey>('banned_at_desc')
  const [sortOpen, setSortOpen] = useState(false)
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

  // 关键词 / 筛选 / 排序变化后回到首屏，避免用户看到「已滚到一半」的旧视图
  useEffect(() => {
    setVisibleCount(PAGE_STEP)
  }, [keyword, statusFilter, sortBy])

  const filtered = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    const matched = list.filter((ban) => {
      if (statusFilter === 'permanent' && !ban.is_permanent) return false
      if (statusFilter === 'temporary' && ban.is_permanent) return false
      if (kw === '') return true
      return (
        ban.ip.toLowerCase().includes(kw) ||
        ban.jail.toLowerCase().includes(kw) ||
        ban.reason.toLowerCase().includes(kw)
      )
    })
    return sortBans(matched, sortBy)
  }, [list, keyword, statusFilter, sortBy])

  const shown = filtered.slice(0, visibleCount)
  const hasMore = visibleCount < filtered.length

  /** 当前排序的中文标签：显示在排序按钮上 */
  const sortLabel = SORT_OPTIONS.find((option) => option.value === sortBy)?.label ?? '最新封禁'

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
      const body: CreateBanRequest = { ip }
      // 留空 → 不发送 duration，后端按永久封禁处理
      if (durationRaw !== '') body.duration = Number(durationRaw)
      if (reason !== '') body.reason = reason
      const resp = await sendJson<CreateBanRequest, BanOperationResponse>(BANS_URL, 'POST', body)
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

  // 详情数据只在「与当前 IP 匹配」时渲染：useAsync 在依赖变化时保留上一份数据，
  // 若不校验，切换查看两个 IP 的详情会先闪出上一个 IP 的记录（标题已换、内容未换）。
  const detailData = detail.data !== null && detail.data.ip === detailIp ? detail.data : null

  return (
    <>
      <PageHeader
        title="封禁管理"
        srOnly
        subtitle={`显示 ${formatNumber(filtered.length, false)} / 共 ${formatNumber(list.length, false)} 条活跃封禁`}
      />

      {/* 下拉刷新与其余数据页一致：移动端刷新本列表的默认手势。
          刷新的是 REST 回退源；已成立的 SSE 通道由新鲜度戳比较决定谁更新
          （见 hooks/useLiveData.ts），因此不会出现「转圈后反而退回旧数据」。 */}
      <PullToRefresh onRefresh={restBans.reload}>
        {/* 外层 .fw-main 已提供内边距，这里只补底部留白 */}
        <div className="fw-page">
        {/* REST 回退失败且两条来源都无数据时，错误对用户可见 */}
        {liveBans === null && restBans.error !== null && (
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

        {/* 筛选：关键词 + 状态 + 排序（全部为本地行为，不产生请求） */}
        <Panel title="筛选" padded={false}>
          <div style={{ padding: '4px 6px 0' }}>
            <SearchBar
              placeholder="搜索 IP / Jail / 原因"
              value={keyword}
              onChange={setKeyword}
              style={{ '--height': '44px' }}
            />
          </div>
          <div style={TOOLBAR}>
            {STATUS_FILTERS.map((option) => (
              <button
                key={option.value}
                type="button"
                className="fw-cmd"
                style={{ ...CMD_WIDE, ...(statusFilter === option.value ? CMD_ON : {}) }}
                aria-pressed={statusFilter === option.value}
                onClick={() => setStatusFilter(option.value)}
              >
                {option.label}
              </button>
            ))}
            {/* 排序用 Picker：7 个选项全部保留，但不占据列表上方的三行空间 */}
            <span style={{ flex: 1 }} />
            <button type="button" className="fw-cmd" style={CMD_WIDE} onClick={() => setSortOpen(true)}>
              排序 {sortLabel} ▾
            </button>
          </div>
        </Panel>

        {/* 操作：单条与批量入口。批量封禁的时长由后端固定为 3600 秒，确认文案与之一致 */}
        <Panel title="操作" padded={false}>
          <div style={TOOLBAR}>
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
          </div>
        </Panel>

        {/* 首屏加载：SSE 与 REST 都还没有结果时给骨架屏，避免误显示「无封禁」 */}
        {liveBans === null && restBans.loading ? (
          <Panel title="活跃封禁" padded>
            <Skeleton.Title animated />
            <Skeleton.Paragraph lineCount={6} animated />
          </Panel>
        ) : (
          <Panel title="活跃封禁" meta={`${formatNumber(filtered.length, false)} 条`} padded={false}>
            {/* 交互提示：行点击与左滑的动作在列表上方一句话讲清 */}
            {shown.length > 0 && <div style={HINT_ROW}>点击行查看详情 · 左滑解封</div>}

            {filtered.length === 0 ? (
              <EmptyState
                title={keyword.trim() === '' && statusFilter === 'all' ? '当前没有活跃封禁' : '没有匹配的封禁记录'}
                description={
                  keyword.trim() === '' && statusFilter === 'all'
                    ? '内核封禁表为空，系统处于平静状态'
                    : '调整关键词或状态筛选后再看；也可能是筛选范围内确实没有记录'
                }
              />
            ) : (
              shown.map((ban, index) => {
                const isSelected = selected.includes(ban.ip)
                const isLast = index === shown.length - 1
                const row = (
                  <div
                    className="fw-row"
                    style={{
                      ...LIST_ROW,
                      // SwipeAction 会把子元素包进滑动轨道，`:last-child` 去线规则在那种
                      // 结构下对每一行都会命中（等于全部无分隔线），因此这里显式控制。
                      borderBottom: isLast ? 'none' : '1px solid var(--fw-border)',
                      background: isSelected ? 'var(--fw-primary-soft)' : undefined,
                    }}
                    onClick={selectMode ? () => toggleSelect(ban.ip) : () => setDetailIp(ban.ip)}
                  >
                    {/* 主行：关键标识（IP）+ 右侧状态标；选择模式下追加勾选框 */}
                    <div style={LIST_ROW_TOP}>
                      <span className="fw-mono" style={{ fontSize: 12, fontWeight: 600 }}>
                        <HighlightText text={ban.ip} query={keyword} />
                      </span>
                      <span style={{ flex: 1 }} />
                      {banStatusBadge(ban)}
                      {selectMode && <Checkbox checked={isSelected} />}
                    </div>
                    {/* 次行：元信息（时间 · Jail · 次数 · 原因），超长单行省略 */}
                    <div style={LIST_ROW_SUB}>
                      <span>{formatDatetime(ban.banned_at)}</span>
                      <span>·</span>
                      <span className="fw-mono">
                        <HighlightText text={ban.jail} query={keyword} />
                      </span>
                      <span>·</span>
                      <span>第 {formatNumber(ban.ban_count, false)} 次</span>
                      {ban.reason !== '' && (
                        <>
                          <span>·</span>
                          <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            <HighlightText text={ban.reason} query={keyword} />
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                )

                // 左滑露出「解封」：移动端对列表项的本能操作，省掉「进详情找按钮」两步。
                // 选择模式下不做左滑：此时整行是「勾选」热区，滑出按钮会与选择语义打架。
                return selectMode ? (
                  <div key={ban.ip}>{row}</div>
                ) : (
                  <SwipeAction
                    key={ban.ip}
                    rightActions={[
                      {
                        key: 'unban',
                        text: busyIp === ban.ip ? '解封中' : '解封',
                        color: 'danger',
                        onClick: () => {
                          void unban(ban.ip)
                        },
                      },
                    ]}
                  >
                    {row}
                  </SwipeAction>
                )
              })
            )}

            {/* 客户端渐进展示：控制长列表的 DOM 规模，数据本身已在内存中 */}
            <InfiniteScroll loadMore={loadMore} hasMore={hasMore} />
          </Panel>
        )}
        </div>
      </PullToRefresh>

      {/* 排序方式：底部 Picker（7 个选项与后端 sort_by 取值一一对应）。
          item-height 抬到 44px：选择器每项本身也是可点元素，不得低于触摸目标下限 */}
      <Picker
        title="排序方式"
        columns={[SORT_OPTIONS]}
        visible={sortOpen}
        value={[sortBy]}
        style={{ '--item-height': '44px' }}
        onClose={() => setSortOpen(false)}
        onConfirm={(value) => {
          setSortBy(toSortKey(value[0]))
          setSortOpen(false)
        }}
      />

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

      {/* 封禁详情：信誉分 / 渐进式等级 / 下次封禁时长；仅在真正解封成功后关闭 */}
      <Popup visible={detailIp !== null} position="bottom" destroyOnClose closeOnMaskClick onMaskClick={() => setDetailIp(null)}>
        <div style={{ maxHeight: '80vh', overflowY: 'auto' }}>
          <div style={POPUP_HEAD}>
            <span className="fw-mono" style={POPUP_HEAD_TITLE}>
              {detailIp}
            </span>
            <button type="button" className="fw-cmd" onClick={() => setDetailIp(null)}>
              关闭
            </button>
          </div>

          <div style={{ padding: 6 }}>
            {detail.error !== null && <NoticeBar color="error" wrap content={`详情加载失败：${detail.error}`} />}
            {detailData === null && detail.error === null && <Skeleton.Paragraph lineCount={6} animated />}

            {detailData !== null && (
              <>
                <Panel title="当前状态" padded={false}>
                  <div style={BADGE_ROW}>
                    <Badge tone={detailData.is_banned ? 'danger' : 'default'}>
                      {detailData.is_banned ? '封禁中' : '未封禁'}
                    </Badge>
                    <Badge tone="primary" dim>
                      {detailData.progressive_level}
                    </Badge>
                    {detailData.was_permanent && (
                      <Badge tone="danger" dim>
                        曾被永久封禁
                      </Badge>
                    )}
                  </div>
                  <Rows>
                    <Row
                      label="IP 信誉分"
                      value={formatNumber(detailData.reputation_score, false)}
                      unit="/ 100"
                      tone={reputationTone(detailData.reputation_score)}
                    />
                    <Row label="阈值乘数" value={`×${detailData.reputation_multiplier}`} />
                  </Rows>
                  {/* 信誉分细条：数值已在上行给出，这里只表达量级 */}
                  <div style={{ padding: '3px 6px 6px' }}>
                    <Meter ratio={detailData.reputation_score / 100} tone={reputationTone(detailData.reputation_score)} />
                    <div style={{ marginTop: 3, fontSize: 10, color: 'var(--fw-text-3)' }}>100 = 完全信任</div>
                  </div>
                </Panel>

                <Panel title="封禁记录" padded={false}>
                  <Rows>
                    <Row label="Jail" value={detailData.jail_name === '' ? 'N/A' : detailData.jail_name} />
                    <Row label="封禁时间" value={formatDatetime(detailData.banned_at)} />
                    <Row
                      label="过期时间"
                      value={detailData.is_permanent ? '永久' : formatDatetime(detailData.expires_at)}
                      tone={detailData.is_permanent ? 'danger' : 'default'}
                    />
                    <Row label="触发前失败次数" value={formatNumber(detailData.fail_count, false)} />
                    <Row label="累计封禁次数" value={formatNumber(detailData.ban_count, false)} />
                    <Row
                      label="上次解封时间"
                      value={detailData.last_unbanned_at > 0 ? formatDatetime(detailData.last_unbanned_at) : '仍在封禁中'}
                    />
                    <Row label="下次封禁时长" value={detailData.next_ban_duration} />
                  </Rows>
                  {/* 原因可能较长：单独一行完整换行展示，不参与 Row 的单行省略 */}
                  <div
                    style={{
                      ...DETAIL_PAD,
                      borderTop: '1px solid var(--fw-border)',
                      fontSize: 11,
                      lineHeight: 1.4,
                      color: 'var(--fw-text-2)',
                      wordBreak: 'break-all',
                    }}
                  >
                    <span style={{ color: 'var(--fw-text-3)' }}>原因 </span>
                    {detailData.reason === '' ? 'N/A' : detailData.reason}
                  </div>
                </Panel>

                {detailData.is_banned && (
                  <Button
                    block
                    color="danger"
                    style={{ minHeight: 44 }}
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
        </div>
      </Popup>
    </>
  )
}
