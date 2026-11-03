import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  App,
  Button,
  Descriptions,
  Drawer,
  Form,
  Input,
  Popconfirm,
  Select,
  Space,
  Tag,
  Typography,
  type TableProps,
} from 'antd'
import {
  ClearOutlined,
  ClockCircleOutlined,
  LockOutlined,
  PlusOutlined,
  ReloadOutlined,
  StopOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { DrawerForm } from '../components/DrawerForm.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { ErrorState } from '../components/state/ErrorState.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import { useAsync } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { useSseDomain, useSseState } from '../providers/SseProvider.tsx'
import { ApiError } from '../api/client.ts'
import {
  batchBan,
  createBan,
  deleteBan,
  getBanDetail,
  getBans,
  unbanTemporary,
} from '../api/endpoints.ts'
import { formatDatetime, formatDuration, formatNumber } from '../lib/format.ts'
import { findInvalidIps, isValidDuration, isValidIp, parseIpList } from '../lib/validation.ts'
import type { BanDetailResponse, BanResponse, BanSortKey, BatchOperationResponse } from '../api/types.ts'

/**
 * 封禁管理页 —— 封禁表的查询、手工封禁、批量处置与解封。
 *
 * 数据读法：REST 分页（page/page_size/sort_by 全在服务端）为准；SSE bans 帧是**镜像全表**，
 * 与分页表形状不同，故不往表里拼帧数据——只在 bans 域 seq 变化时重取当前页，保证「表是活的」
 * 且分页/排序语义不被破坏。
 *
 * 深链两种：`/bans/:ip` 直接打开该 IP 的详情抽屉；`?new=1`（命令面板「新建封禁」）自动拉开
 * 新建抽屉并随即清掉查询参数，避免刷新页面反复弹出。
 *
 * 处置动作全部有二次确认（Popconfirm），批量结果用 notification 完整透出
 * succeeded/failed_count/details，不吞后端的部分失败。
 */

/** 后端批量封禁单次上限（1..100 条）。 */
const BATCH_MAX = 100

/** 批量封禁 duration 缺省值（秒）；后端缺省同样是 3600，不升格为永久。 */
const BATCH_DEFAULT_DURATION = '3600'

const SORT_OPTIONS: Array<{ value: BanSortKey; label: string }> = [
  { value: 'banned_at_desc', label: '封禁时间 · 最新在前' },
  { value: 'banned_at_asc', label: '封禁时间 · 最早在前' },
  { value: 'ip_asc', label: 'IP 地址 · 升序' },
  { value: 'ip_desc', label: 'IP 地址 · 降序' },
  { value: 'jail_asc', label: 'Jail 名称 · 升序' },
  { value: 'remaining_asc', label: '剩余时长 · 升序' },
  { value: 'remaining_desc', label: '剩余时长 · 降序' },
]

interface CreateFormValues {
  ip: string
  duration: string
  reason?: string
}

interface BatchFormValues {
  ips: string
  duration: string
  reason?: string
}

type BanColumns = NonNullable<TableProps<BanResponse>['columns']>

/** 把未知异常归一成可读文案（后端信封 message 优先）。 */
function errorMessage(err: unknown): string {
  return err instanceof ApiError && err.message ? err.message : '操作失败，请稍后重试'
}

/** 批量操作结果的完整透出：汇总行 + 逐条 details（超长截断，可滚动）。 */
function batchResultNode(res: BatchOperationResponse): ReactNode {
  return (
    <Space direction="vertical" size={4}>
      <Typography.Text style={{ fontSize: 13 }}>
        共 {formatNumber(res.total)} 条 · 成功 {formatNumber(res.succeeded)} · 失败{' '}
        {formatNumber(res.failed_count)}
      </Typography.Text>
      {res.details.length > 0 && (
        <div
          className="fw-mono"
          style={{ fontSize: 12, maxHeight: 160, overflowY: 'auto', whiteSpace: 'pre-wrap' }}
        >
          {res.details.slice(0, 20).map((line, i) => (
            <div key={i}>{line}</div>
          ))}
          {res.details.length > 20 && <div>… 其余 {res.details.length - 20} 条省略</div>}
        </div>
      )}
    </Space>
  )
}

export default function Bans() {
  const { message, notification } = App.useApp()
  const navigate = useNavigate()
  const { ip: routeIp } = useParams<{ ip?: string }>()
  const [searchParams, setSearchParams] = useSearchParams()

  const sseState = useSseState()
  const { seq: bansSeq } = useSseDomain('bans')

  // --- 列表查询状态（服务端分页 + 排序） ---
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [sortBy, setSortBy] = useState<BanSortKey>('banned_at_desc')

  const query = useAsync((signal) =>
    getBans({ page, page_size: pageSize, sort_by: sortBy }, signal),
  )

  // refetch 存进 ref：让列定义、SSE 帧、深链处理等长活回调不必依赖其身份
  const refetchRef = useRef(query.refetch)
  refetchRef.current = query.refetch

  // 翻页/改页长/换排序 → 重取（首屏由 useAsync immediate 负责，这里跳过第一次）
  const mountedRef = useRef(false)
  useEffect(() => {
    if (!mountedRef.current) {
      mountedRef.current = true
      return
    }
    refetchRef.current()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, pageSize, sortBy])

  // SSE bans 域来帧（全表镜像）→ 不拼进分页表，只重取当前页
  useEffect(() => {
    if (bansSeq > 0) refetchRef.current()
  }, [bansSeq])

  // 命令面板「刷新当前页」
  useRefreshSignal(() => refetchRef.current())

  // --- 抽屉与深链 ---
  const [detailIp, setDetailIp] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [batchOpen, setBatchOpen] = useState(false)
  const [createForm] = Form.useForm<CreateFormValues>()
  const [batchForm] = Form.useForm<BatchFormValues>()

  // 深链 /bans/:ip → 挂载即打开详情抽屉
  useEffect(() => {
    if (routeIp) setDetailIp(routeIp)
  }, [routeIp])

  // 深链 ?new=1 → 自动拉开新建抽屉一次，随后清掉参数（防刷新反复弹）
  useEffect(() => {
    if (searchParams.get('new') === '1') {
      setCreateOpen(true)
      const next = new URLSearchParams(searchParams)
      next.delete('new')
      setSearchParams(next, { replace: true })
    }
  }, [searchParams, setSearchParams])

  const openDetail = useCallback((ip: string) => setDetailIp(ip), [])

  const closeDetail = useCallback(() => {
    setDetailIp(null)
    if (routeIp) navigate('/bans', { replace: true })
  }, [routeIp, navigate])

  // --- 处置动作 ---
  const handleUnban = useCallback(
    async (ip: string) => {
      try {
        const res = await deleteBan(ip)
        message.success(`已解封 ${res.ip}`)
        refetchRef.current()
      } catch (err) {
        message.error(errorMessage(err))
      }
    },
    [message],
  )

  const [unbanAllLoading, setUnbanAllLoading] = useState(false)
  const handleUnbanAllTemporary = useCallback(async () => {
    setUnbanAllLoading(true)
    try {
      const res = await unbanTemporary()
      notification.open({
        message: '解除全部临时封禁 · 结果',
        description: batchResultNode(res),
        duration: res.failed_count > 0 ? 0 : 6,
      })
      refetchRef.current()
    } catch (err) {
      message.error(errorMessage(err))
    } finally {
      setUnbanAllLoading(false)
    }
  }, [message, notification])

  const submitCreate = useCallback(
    async (values: CreateFormValues) => {
      const ip = (values.ip ?? '').trim()
      if (!isValidIp(ip)) {
        message.error('IP 地址不合法')
        return
      }
      const durationText = (values.duration ?? '').trim()
      if (!isValidDuration(durationText)) {
        message.error('时长须为 0–86400 的整数，或留空表示永久')
        return
      }
      try {
        const res = await createBan({
          ip,
          duration: durationText === '' ? null : Number(durationText),
          reason: values.reason?.trim() || null,
        })
        message.success(
          res.permanent
            ? `已封禁 ${res.ip}（永久）`
            : `已封禁 ${res.ip}（时长 ${formatDuration(res.duration_seconds ?? 0)}）`,
        )
        setCreateOpen(false)
        createForm.resetFields()
        refetchRef.current()
      } catch (err) {
        message.error(errorMessage(err))
      }
    },
    [message, createForm],
  )

  const submitBatch = useCallback(
    async (values: BatchFormValues) => {
      const raw = values.ips ?? ''
      const ips = parseIpList(raw)
      const invalid = findInvalidIps(raw)
      if (ips.length === 0 || invalid.length > 0 || ips.length > BATCH_MAX) {
        message.error('IP 列表未通过校验，请按字段提示修正后再提交')
        return
      }
      const durationText = (values.duration ?? '').trim()
      if (!isValidDuration(durationText)) {
        message.error('时长须为 0–86400 的整数，或留空使用默认 3600 秒')
        return
      }
      try {
        const res = await batchBan({
          ips,
          duration: durationText === '' ? null : Number(durationText),
          reason: values.reason?.trim() || null,
        })
        notification.open({
          message: '批量封禁 · 结果',
          description: batchResultNode(res),
          duration: res.failed_count > 0 ? 0 : 6,
        })
        setBatchOpen(false)
        batchForm.resetFields()
        refetchRef.current()
      } catch (err) {
        message.error(errorMessage(err))
      }
    },
    [message, notification, batchForm],
  )

  // --- 本页派生指标（只用 BanResponse 已有字段） ---
  const items = query.data?.items ?? []
  const derived = useMemo(() => {
    const permanent = items.filter((b) => b.is_permanent).length
    const temporary = items.length - permanent
    const expiringSoon = items.filter(
      (b) => !b.is_permanent && b.remaining_seconds >= 0 && b.remaining_seconds <= 3600,
    ).length
    const banCountSum = items.reduce((sum, b) => sum + b.ban_count, 0)
    return { permanent, temporary, expiringSoon, banCountSum }
  }, [items])

  const total = query.data?.total ?? 0
  const cardsLoading = query.isLoading && query.data == null

  const columns = useMemo<BanColumns>(
    () => [
      {
        title: 'IP 地址',
        dataIndex: 'ip',
        key: 'ip',
        width: 160,
        render: (_: unknown, record: BanResponse) => (
          <Typography.Link className="fw-mono" onClick={() => openDetail(record.ip)}>
            {record.ip}
          </Typography.Link>
        ),
      },
      {
        title: 'Jail',
        dataIndex: 'jail',
        key: 'jail',
        width: 130,
        render: (jail: string) => (jail ? <Tag>{jail}</Tag> : <span>—</span>),
      },
      {
        title: '原因',
        dataIndex: 'reason',
        key: 'reason',
        render: (reason: string) =>
          reason ? (
            <Typography.Text type="secondary" style={{ fontSize: 13 }} ellipsis={{ tooltip: reason }}>
              {reason}
            </Typography.Text>
          ) : (
            <span>—</span>
          ),
      },
      {
        title: '封禁时间',
        dataIndex: 'banned_at',
        key: 'banned_at',
        width: 175,
        render: (ts: number) => <span className="fw-mono">{formatDatetime(ts)}</span>,
      },
      {
        title: '剩余',
        dataIndex: 'remaining_seconds',
        key: 'remaining_seconds',
        width: 110,
        render: (_: unknown, record: BanResponse) =>
          record.is_permanent ? (
            <Tag color="red">永久</Tag>
          ) : (
            <span className="fw-mono">{formatDuration(record.remaining_seconds)}</span>
          ),
      },
      {
        title: '累计封禁',
        dataIndex: 'ban_count',
        key: 'ban_count',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '操作',
        key: 'actions',
        width: 140,
        render: (_: unknown, record: BanResponse) => (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openDetail(record.ip)}>
              详情
            </Button>
            <Popconfirm
              title="确认解封"
              description={`将立即解除对 ${record.ip} 的封禁。`}
              okText="解封"
              okButtonProps={{ danger: true }}
              cancelText="取消"
              onConfirm={() => handleUnban(record.ip)}
            >
              <Button type="link" size="small" danger>
                解封
              </Button>
            </Popconfirm>
          </Space>
        ),
      },
    ],
    [openDetail, handleUnban],
  )

  return (
    <>
      <PageHeader
        title="封禁管理"
        description="封禁表查询、手工/批量封禁、解封与单条封禁的完整画像"
        breadcrumb={[{ title: '防护' }, { title: '封禁管理' }]}
        realtimeState={sseState}
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 16,
          marginBottom: 16,
        }}
      >
        <StatCard
          label="当前封禁数"
          value={formatNumber(total)}
          icon={StopOutlined}
          tone="danger"
          loading={cardsLoading}
          footer={query.data ? `第 ${query.data.page}/${Math.max(query.data.total_pages, 1)} 页` : ' '}
        />
        <StatCard
          label="永久封禁（本页）"
          value={formatNumber(derived.permanent)}
          icon={LockOutlined}
          tone="warning"
          loading={cardsLoading}
          footer="本页条目中 is_permanent 的数量"
        />
        <StatCard
          label="临时封禁（本页）"
          value={formatNumber(derived.temporary)}
          icon={ClockCircleOutlined}
          tone="info"
          loading={cardsLoading}
          footer={`其中 1 小时内到期 ${formatNumber(derived.expiringSoon)} 条`}
        />
        <StatCard
          label="累计封禁次数（本页）"
          value={formatNumber(derived.banCountSum)}
          icon={ThunderboltOutlined}
          loading={cardsLoading}
          footer="本页条目 ban_count 之和（含历史）"
        />
      </div>

      <DataTable<BanResponse>
        data={query.data ? query.data.items : null}
        isLoading={query.isLoading}
        error={query.error}
        onRetry={query.refetch}
        rowKey="ip"
        columns={columns}
        emptyScenario="no-data"
        emptyTitle="暂无封禁"
        emptyDescription="封禁表为空；守护进程判定或手工添加的封禁会出现在这里"
        emptyActionLabel="新建封禁"
        onEmptyAction={() => setCreateOpen(true)}
        toolbar={
          <>
            <Select<BanSortKey>
              value={sortBy}
              onChange={(v) => {
                setSortBy(v)
                setPage(1)
              }}
              options={SORT_OPTIONS}
              style={{ width: 200 }}
              aria-label="排序方式"
            />
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
              新建封禁
            </Button>
            <Button onClick={() => setBatchOpen(true)}>批量封禁</Button>
            <Popconfirm
              title="解除全部临时封禁？"
              description="仅解除带时限的临时封禁，不影响永久封禁；操作不可撤销。"
              okText="全部解除"
              okButtonProps={{ danger: true }}
              cancelText="取消"
              onConfirm={handleUnbanAllTemporary}
            >
              <Button danger icon={<ClearOutlined />} loading={unbanAllLoading}>
                解除全部临时
              </Button>
            </Popconfirm>
            <Button icon={<ReloadOutlined />} onClick={query.refetch} loading={query.isRefreshing}>
              刷新
            </Button>
            <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
              共 {formatNumber(total)} 条
            </Typography.Text>
          </>
        }
        pagination={{
          current: page,
          pageSize,
          total: query.data?.total ?? 0,
          showSizeChanger: true,
          pageSizeOptions: [20, 50, 100, 200],
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
        scroll={{ x: 'max-content' }}
      />

      {/* 新建封禁 */}
      <DrawerForm<CreateFormValues>
        open={createOpen}
        title="新建封禁"
        form={createForm}
        onSubmit={submitCreate}
        onCancel={() => {
          setCreateOpen(false)
          createForm.resetFields()
        }}
        submitText="封禁"
        danger
      >
        <Form.Item
          name="ip"
          label="IP 地址"
          rules={[
            { required: true, message: '请输入要封禁的 IP 地址' },
            {
              validator: (_, value: string) =>
                !value || isValidIp(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error('IP 格式不合法（支持 IPv4 / IPv6）')),
            },
          ]}
        >
          <Input className="fw-mono" placeholder="如 203.0.113.42" autoFocus />
        </Form.Item>
        <Form.Item
          name="duration"
          label="时长（秒）"
          extra="留空 = 永久封禁；否则须为 0–86400 的整数秒（上限 24 小时）。"
          rules={[
            {
              validator: (_, value: string) =>
                value === undefined || isValidDuration(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error('须为 0–86400 的整数，或留空表示永久')),
            },
          ]}
        >
          <Input className="fw-mono" placeholder="留空 = 永久" />
        </Form.Item>
        <Form.Item name="reason" label="原因（可选）">
          <Input placeholder="便于事后追溯的处置原因" maxLength={200} />
        </Form.Item>
      </DrawerForm>

      {/* 批量封禁 */}
      <DrawerForm<BatchFormValues>
        open={batchOpen}
        title="批量封禁"
        form={batchForm}
        onSubmit={submitBatch}
        onCancel={() => {
          setBatchOpen(false)
          batchForm.resetFields()
        }}
        submitText="批量封禁"
        danger
        width={560}
        initialValues={{ duration: BATCH_DEFAULT_DURATION }}
      >
        <Form.Item
          name="ips"
          label={`IP 列表（单次 1–${BATCH_MAX} 条）`}
          rules={[
            { required: true, message: '请输入至少一个 IP' },
            {
              validator: (_, value: string) => {
                const raw = value ?? ''
                const list = parseIpList(raw)
                if (list.length === 0) return Promise.reject(new Error('请输入至少一个 IP'))
                const invalid = findInvalidIps(raw)
                if (invalid.length > 0) {
                  const shown = invalid.slice(0, 10).join('、')
                  const more = invalid.length > 10 ? ` 等 ${invalid.length} 个` : ''
                  return Promise.reject(new Error(`非法 IP：${shown}${more}`))
                }
                if (list.length > BATCH_MAX) {
                  return Promise.reject(
                    new Error(`单次最多 ${BATCH_MAX} 个 IP（当前 ${list.length} 个，已去重）`),
                  )
                }
                return Promise.resolve()
              },
            },
          ]}
          extra="换行、逗号或空格分隔；自动去重。"
        >
          <Input.TextArea
            className="fw-mono"
            rows={8}
            placeholder={'203.0.113.42\n198.51.100.7'}
          />
        </Form.Item>
        <Form.Item
          name="duration"
          label="时长（秒）"
          extra={`批量封禁默认 ${BATCH_DEFAULT_DURATION} 秒；留空按默认执行，不会升格为永久封禁。`}
          rules={[
            {
              validator: (_, value: string) =>
                value === undefined || isValidDuration(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error('须为 0–86400 的整数，或留空使用默认 3600 秒')),
            },
          ]}
        >
          <Input className="fw-mono" />
        </Form.Item>
        <Form.Item name="reason" label="原因（可选）">
          <Input placeholder="应用于本批全部 IP 的处置原因" maxLength={200} />
        </Form.Item>
      </DrawerForm>

      {/* 单条封禁详情（深链 /bans/:ip 同样走这里） */}
      {detailIp && (
        <BanDetailDrawer key={detailIp} ip={detailIp} onClose={closeDetail} onUnban={handleUnban} />
      )}
    </>
  )
}

// ---------------------------------------------------------------------------
// 详情抽屉
// ---------------------------------------------------------------------------

interface BanDetailDrawerProps {
  ip: string
  onClose: () => void
  /** 解封成功后回调（父级负责 message 与列表重取）；抽屉随即关闭。 */
  onUnban: (ip: string) => Promise<void>
}

function BanDetailDrawer({ ip, onClose, onUnban }: BanDetailDrawerProps) {
  const detail = useAsync<BanDetailResponse>((signal) => getBanDetail(ip, signal))

  const items = useMemo(() => {
    const d = detail.data
    if (!d) return []
    return [
      {
        key: 'ip',
        label: 'IP 地址',
        children: <span className="fw-mono">{d.ip}</span>,
      },
      {
        key: 'is_banned',
        label: '封禁状态',
        children: d.is_banned ? <Tag color="red">封禁中</Tag> : <Tag>未封禁</Tag>,
      },
      { key: 'jail_name', label: '来源 Jail', children: d.jail_name || '—' },
      { key: 'reason', label: '封禁原因', children: d.reason || '—' },
      {
        key: 'banned_at',
        label: '封禁时间',
        children: <span className="fw-mono">{formatDatetime(d.banned_at)}</span>,
      },
      {
        key: 'expires_at',
        label: '到期时间',
        children: <span className="fw-mono">{formatDatetime(d.expires_at)}</span>,
      },
      { key: 'is_permanent', label: '永久封禁', children: d.is_permanent ? '是' : '否' },
      { key: 'fail_count', label: '失败次数', children: formatNumber(d.fail_count) },
      { key: 'ban_count', label: '累计封禁次数', children: formatNumber(d.ban_count) },
      {
        key: 'last_unbanned_at',
        label: '最近解封时间',
        children: <span className="fw-mono">{formatDatetime(d.last_unbanned_at)}</span>,
      },
      { key: 'was_permanent', label: '曾被永久封禁', children: d.was_permanent ? '是' : '否' },
      { key: 'progressive_level', label: '递进等级', children: d.progressive_level || '—' },
      { key: 'next_ban_duration', label: '下次封禁时长', children: d.next_ban_duration || '—' },
      { key: 'reputation_score', label: '信誉分', children: formatNumber(d.reputation_score) },
      {
        key: 'reputation_multiplier',
        label: '信誉系数',
        children: formatNumber(d.reputation_multiplier),
      },
    ]
  }, [detail.data])

  return (
    <Drawer
      open
      title={`封禁详情 · ${ip}`}
      width={520}
      onClose={onClose}
      destroyOnHidden
      footer={
        <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button onClick={onClose}>关闭</Button>
          <Popconfirm
            title="确认解封"
            description={`将立即解除对 ${ip} 的封禁。`}
            okText="解封"
            okButtonProps={{ danger: true }}
            cancelText="取消"
            onConfirm={async () => {
              await onUnban(ip)
              onClose()
            }}
          >
            <Button danger disabled={!detail.data}>
              解封
            </Button>
          </Popconfirm>
        </Space>
      }
    >
      {detail.isLoading && detail.data == null && <LoadingState variant="detail" />}
      {detail.error && detail.data == null && (
        <ErrorState error={detail.error} onRetry={detail.refetch} />
      )}
      {detail.data && (
        <Descriptions column={1} size="small" bordered items={items} className="fw-fade-in" />
      )}
    </Drawer>
  )
}
