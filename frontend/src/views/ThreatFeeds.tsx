import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Alert,
  App,
  Button,
  Descriptions,
  Drawer,
  Flex,
  Space,
  Tag,
  Tooltip,
  Typography,
  type TableColumnsType,
} from 'antd'
import {
  CheckCircleOutlined,
  CloudDownloadOutlined,
  DatabaseOutlined,
  ReloadOutlined,
  SyncOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { useSearchParams } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { EmptyState } from '../components/state/EmptyState.tsx'
import { ErrorState } from '../components/state/ErrorState.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import { useAsync } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { ApiError } from '../api/client.ts'
import { getThreatFeed, getThreatFeeds, syncThreatFeeds } from '../api/endpoints.ts'
import { formatDatetime, formatNumber, formatPercent, formatRelative } from '../lib/format.ts'
import type { ThreatFeedResponse, ThreatFeedSyncResult } from '../api/types.ts'

/**
 * 威胁情报页 —— 外部情报源（IPsum / FireHOL 等）的启用状态、条目规模与同步健康度。
 *
 * 功能受后端 flag `threat_feeds.enabled` 控制（默认开启）：关闭时情报源端点统一回
 * HTTP 503，本页据此渲染 disabled 空态并说明开启方法，而不是把它当网络故障重试。
 *
 * 两条同步入口共用一套结果通知：
 *   * 工具条「全量同步」按钮（带按钮级 loading）；
 *   * 命令面板深链 `?sync=1`——挂载即自动同步一次（ref 防 StrictMode 双执行），
 *     完成后清掉查询参数并重取列表，避免刷新页面反复触发同步。
 *
 * 详情抽屉按需拉取单源（GET by id），关闭抽屉即清空 detailId，useAsync 的 enabled
 * 随之翻转，下次打开必然重新取数；渲染时校验 `data.id === detailId`，杜绝把上一个
 * 源的旧数据闪现在新抽屉里。
 */

/** 后端 sync_status 的已知取值（见 daemon threat_feeds.go：never / ok / error）。 */
const SYNC_STATUS_META: Record<string, { label: string; color: string }> = {
  ok: { label: '正常', color: 'green' },
  error: { label: '异常', color: 'red' },
  never: { label: '从未同步', color: 'default' },
}

function syncStatusMeta(status: string): { label: string; color: string } {
  return SYNC_STATUS_META[status] ?? { label: status, color: 'default' }
}

/** 情报源分类 → 中文标签；未知取值原样回显（便于发现后端新增分类）。 */
const CATEGORY_LABELS: Record<string, string> = {
  abuse: '滥用',
  scanner: '扫描',
  botnet: '僵尸网络',
}

function categoryLabel(category: string): string {
  return CATEGORY_LABELS[category] ?? category
}

/** 把后端错误归一成可读文案（ApiError 的 message 已是服务端信封文案）。 */
function errText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback
}

function isFeedsDisabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 503
}

/** 详情抽屉的 Descriptions 条目：覆盖契约载荷的全部字段。 */
function feedDescriptionItems(feed: ThreatFeedResponse) {
  const status = syncStatusMeta(feed.sync_status)
  return [
    { key: 'id', label: 'ID', children: <span className="fw-mono">{feed.id}</span> },
    { key: 'name', label: '名称', children: feed.name },
    {
      key: 'source_url',
      label: '源地址',
      children: (
        <a
          href={feed.source_url}
          target="_blank"
          rel="noreferrer"
          className="fw-mono"
          style={{ fontSize: 12.5, wordBreak: 'break-all' }}
        >
          {feed.source_url}
        </a>
      ),
    },
    {
      key: 'enabled',
      label: '已启用',
      children: <Tag color={feed.enabled ? 'green' : 'default'}>{feed.enabled ? '是' : '否'}</Tag>,
    },
    { key: 'category', label: '分类', children: categoryLabel(feed.category) },
    {
      key: 'confidence',
      label: '置信度',
      children: <span className="fw-mono">{formatPercent(feed.confidence * 100)}</span>,
    },
    {
      key: 'entry_count',
      label: '条目数',
      children: <span className="fw-mono">{formatNumber(feed.entry_count)}</span>,
    },
    {
      key: 'sync_status',
      label: '同步状态',
      children: <Tag color={status.color}>{status.label}</Tag>,
    },
    {
      key: 'last_synced_at',
      label: '最近同步',
      children:
        feed.last_synced_at == null ? (
          <Typography.Text type="secondary">从未同步</Typography.Text>
        ) : (
          <span className="fw-mono">
            {formatRelative(feed.last_synced_at)}（{formatDatetime(feed.last_synced_at)}）
          </span>
        ),
    },
    {
      key: 'last_error',
      label: '最近错误',
      children: feed.last_error ? (
        <Typography.Text type="danger" style={{ fontSize: 12.5, wordBreak: 'break-all' }}>
          {feed.last_error}
        </Typography.Text>
      ) : (
        <Typography.Text type="secondary">—</Typography.Text>
      ),
    },
  ]
}

export default function ThreatFeeds() {
  const { message, notification } = App.useApp()
  const [searchParams, setSearchParams] = useSearchParams()

  // --- 列表加载 ---
  const query = useAsync((signal) => getThreatFeeds(signal))
  const { data, error, isLoading, isRefreshing, refetch } = query

  // refetch 存进 ref：深链同步等长活回调不必依赖其身份
  const refetchRef = useRef(refetch)
  refetchRef.current = refetch

  const feeds = data?.feeds ?? null
  const isDisabled = isFeedsDisabled(error)

  // --- 汇总指标 ---
  const stats = useMemo(() => {
    if (!data) return null
    return {
      total: data.total,
      enabledCount: data.feeds.filter((f) => f.enabled).length,
      entrySum: data.feeds.reduce((sum, f) => sum + f.entry_count, 0),
      // 后端在有 last_error 时会把 sync_status 置为 error，两个条件取并集兜住漂移
      errorCount: data.feeds.filter((f) => f.last_error != null || f.sync_status === 'error')
        .length,
    }
  }, [data])

  // --- 同步（工具条按钮 + 深链共用结果通知） ---
  const [syncing, setSyncing] = useState(false)
  const [deepSyncing, setDeepSyncing] = useState(false)

  const notifySyncResult = useCallback(
    (res: ThreatFeedSyncResult) => {
      notification.success({
        message: '全量同步完成',
        description: (
          <Space direction="vertical" size={2}>
            <span>
              情报源：<span className="fw-mono">{res.feed_id}</span>
            </span>
            <span>
              新增 {formatNumber(res.new_entries)} 条 · 更新 {formatNumber(res.updated_entries)} 条
            </span>
            <span>同步时间：{formatDatetime(res.synced_at)}</span>
          </Space>
        ),
      })
    },
    [notification],
  )

  const notifySyncError = useCallback(
    (err: unknown) => {
      if (isFeedsDisabled(err)) {
        message.warning('威胁情报源未启用（threat_feeds.enabled=false），无法同步')
      } else {
        message.error(errText(err, '同步失败'))
      }
    },
    [message],
  )

  const handleSync = useCallback(async () => {
    setSyncing(true)
    try {
      const res = await syncThreatFeeds()
      notifySyncResult(res)
      refetchRef.current()
    } catch (err) {
      notifySyncError(err)
    } finally {
      setSyncing(false)
    }
  }, [notifySyncResult, notifySyncError])

  // 深链 ?sync=1（命令面板「同步威胁情报」）：挂载即自动同步一次。
  // ref 守卫防 StrictMode 双执行；完成后清参数，防止刷新页面反复同步。
  const deepSyncFired = useRef(false)
  useEffect(() => {
    if (searchParams.get('sync') !== '1') return
    if (deepSyncFired.current) return
    deepSyncFired.current = true

    setDeepSyncing(true)
    void syncThreatFeeds()
      .then((res) => {
        notifySyncResult(res)
        refetchRef.current()
      })
      .catch((err: unknown) => {
        notifySyncError(err)
      })
      .finally(() => {
        setDeepSyncing(false)
        const next = new URLSearchParams(searchParams)
        next.delete('sync')
        setSearchParams(next, { replace: true })
      })
  }, [searchParams, setSearchParams, notifySyncResult, notifySyncError])

  // 顶栏/命令面板广播的「刷新当前页」
  useRefreshSignal(() => refetch())

  // --- 详情抽屉（按需拉取单源） ---
  const [detailId, setDetailId] = useState<string | null>(null)
  const detail = useAsync<ThreatFeedResponse>((signal) => getThreatFeed(detailId ?? '', signal), {
    enabled: detailId != null,
  })
  // 校验 id 匹配：上一源的旧数据不得闪现到新抽屉里
  const detailData = detail.data != null && detail.data.id === detailId ? detail.data : null

  const openDetail = useCallback((id: string) => setDetailId(id), [])
  const closeDetail = useCallback(() => setDetailId(null), [])

  // --- 列定义 ---
  const columns = useMemo<TableColumnsType<ThreatFeedResponse>>(
    () => [
      {
        title: '名称',
        dataIndex: 'name',
        key: 'name',
        render: (name: string, record) => (
          <Space size={6}>
            <Typography.Text strong>{name}</Typography.Text>
            <Tag color="geekblue" style={{ marginInlineEnd: 0 }}>
              {categoryLabel(record.category)}
            </Tag>
          </Space>
        ),
      },
      {
        title: '源地址',
        dataIndex: 'source_url',
        key: 'source_url',
        width: 260,
        render: (url: string) => (
          <Tooltip title={url}>
            <a
              href={url}
              target="_blank"
              rel="noreferrer"
              className="fw-mono"
              style={{
                display: 'block',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                fontSize: 12.5,
              }}
            >
              {url}
            </a>
          </Tooltip>
        ),
      },
      {
        title: '启用',
        dataIndex: 'enabled',
        key: 'enabled',
        width: 72,
        render: (enabled: boolean) => (
          <Tag color={enabled ? 'green' : 'default'} style={{ marginInlineEnd: 0 }}>
            {enabled ? '是' : '否'}
          </Tag>
        ),
      },
      {
        title: '置信度',
        dataIndex: 'confidence',
        key: 'confidence',
        width: 88,
        align: 'right',
        // 后端按 0-1 小数给出（config default.yaml：confidence: 0.8），换算成百分数展示
        render: (confidence: number) => (
          <span className="fw-mono">{formatPercent(confidence * 100)}</span>
        ),
      },
      {
        title: '条目数',
        dataIndex: 'entry_count',
        key: 'entry_count',
        width: 96,
        align: 'right',
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '同步状态',
        dataIndex: 'sync_status',
        key: 'sync_status',
        width: 100,
        render: (status: string) => {
          const meta = syncStatusMeta(status)
          return (
            <Tag color={meta.color} style={{ marginInlineEnd: 0 }}>
              {meta.label}
            </Tag>
          )
        },
      },
      {
        title: '最近同步',
        dataIndex: 'last_synced_at',
        key: 'last_synced_at',
        width: 120,
        render: (ts: number | null) =>
          ts == null ? (
            <Typography.Text type="secondary">从未同步</Typography.Text>
          ) : (
            <Tooltip title={formatDatetime(ts)}>
              <span className="fw-mono">{formatRelative(ts)}</span>
            </Tooltip>
          ),
      },
      {
        title: '最近错误',
        dataIndex: 'last_error',
        key: 'last_error',
        width: 88,
        align: 'center',
        render: (err: string | null) =>
          err ? (
            <Tooltip title={err}>
              <WarningOutlined style={{ color: 'var(--fw-warning)', fontSize: 15 }} />
            </Tooltip>
          ) : (
            <Typography.Text type="secondary">—</Typography.Text>
          ),
      },
      {
        title: '操作',
        key: 'actions',
        width: 80,
        align: 'right',
        render: (_value, record) => (
          <Button type="link" size="small" onClick={() => openDetail(record.id)}>
            详情
          </Button>
        ),
      },
    ],
    [openDetail],
  )

  const cardsLoading = isLoading && data == null

  return (
    <>
      <PageHeader
        title="威胁情报"
        description="外部威胁情报源的启用状态、条目规模与同步健康度"
        breadcrumb={[{ title: '智能' }, { title: '威胁情报' }]}
      />

      {isDisabled ? (
        <EmptyState
          scenario="disabled"
          title="威胁情报源未启用"
          description={
            <>
              守护进程配置 <span className="fw-mono">threat_feeds.enabled=false</span>
              ，情报源端点返回 503。请在配置中开启并重启守护进程后重新加载本页。
            </>
          }
          extra={
            <Button icon={<ReloadOutlined />} onClick={refetch}>
              重新加载
            </Button>
          }
        />
      ) : (
        <Flex vertical gap={16} className="fw-fade-in">
          {(syncing || deepSyncing) && (
            <Alert
              type="info"
              showIcon
              icon={<SyncOutlined spin />}
              message="正在全量同步威胁情报源，请稍候…"
            />
          )}

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
              gap: 16,
            }}
          >
            <StatCard
              label="情报源总数"
              value={formatNumber(stats?.total ?? 0)}
              icon={CloudDownloadOutlined}
              footer="配置中登记的全部情报源（含未启用）"
              loading={cardsLoading}
            />
            <StatCard
              label="已启用"
              value={formatNumber(stats?.enabledCount ?? 0)}
              icon={CheckCircleOutlined}
              tone="success"
              footer="参与自动拉取与判定的情报源"
              loading={cardsLoading}
            />
            <StatCard
              label="累计条目"
              value={formatNumber(stats?.entrySum ?? 0)}
              icon={DatabaseOutlined}
              tone="info"
              footer="各源当前缓存的恶意 IP 条目之和"
              loading={cardsLoading}
            />
            <StatCard
              label="同步异常"
              value={formatNumber(stats?.errorCount ?? 0)}
              icon={WarningOutlined}
              tone={(stats?.errorCount ?? 0) > 0 ? 'danger' : 'default'}
              footer="最近一次同步报错的情报源"
              loading={cardsLoading}
            />
          </div>

          <DataTable<ThreatFeedResponse>
            data={feeds}
            isLoading={isLoading}
            isRefreshing={isRefreshing}
            error={error}
            onRetry={refetch}
            rowKey="id"
            columns={columns}
            emptyScenario="no-data"
            emptyTitle="暂无情报源"
            emptyDescription="守护进程配置里还没有登记任何威胁情报源，可在 threat_feeds.sources 中添加"
            toolbar={
              <>
                <Button
                  type="primary"
                  icon={<SyncOutlined />}
                  onClick={handleSync}
                  loading={syncing || deepSyncing}
                >
                  全量同步
                </Button>
                <Button icon={<ReloadOutlined />} onClick={refetch} loading={isRefreshing}>
                  刷新
                </Button>
                <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
                  共 {stats?.total ?? 0} 个情报源
                </Typography.Text>
              </>
            }
            pagination={{
              pageSize: 20,
              showSizeChanger: true,
              hideOnSinglePage: true,
              showTotal: (t) => `共 ${t} 个`,
            }}
            scroll={{ x: 'max-content' }}
          />
        </Flex>
      )}

      <Drawer open={detailId != null} title="情报源详情" width={480} onClose={closeDetail}>
        {detailData ? (
          <Descriptions column={1} size="small" bordered items={feedDescriptionItems(detailData)} />
        ) : detail.error ? (
          <ErrorState error={detail.error} onRetry={detail.refetch} />
        ) : (
          <LoadingState variant="detail" />
        )}
      </Drawer>
    </>
  )
}
