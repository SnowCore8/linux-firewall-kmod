import { useCallback, useMemo, useState } from 'react'
import {
  App,
  Button,
  Descriptions,
  Drawer,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
  type TableProps,
} from 'antd'
import {
  CheckCircleOutlined,
  ProfileOutlined,
  ReloadOutlined,
  SafetyOutlined,
  ThunderboltOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { PageHeader } from '../components/PageHeader.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { StaleNotice } from '../components/state/StaleNotice.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { useLiveData } from '../hooks/useLiveData.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { useSseDomain, useSseState } from '../providers/SseProvider.tsx'
import { ApiError } from '../api/client.ts'
import { getJails, updateJail } from '../api/endpoints.ts'
import { formatDuration, formatNumber } from '../lib/format.ts'
import type { JailResponse } from '../api/types.ts'

/**
 * 越狱规则页 —— jail 配置（阈值/时长/系数）+ 运行时计数（解析漏斗/触发量）一表看全。
 *
 * 数据读法：SSE jails 域帧与 REST 拉取用 useLiveData 按新鲜度序号仲裁，视图只消费一个 value。
 * 注意 PUT /jails 是**异步生效且不推 SSE 帧**的：切换开关成功后必须 refetch() 重读权威状态，
 * 不能拿 PUT 的回包就地改表（回包只有 name/enabled/status 三个字段）。
 *
 * 表格可读性：主列只放「配置 + 关键计数」，五个解析漏斗指标（lines_parsed → regex_matches →
 * ips_extracted → failed_attempts → bans_triggered）收进展开行；全字段中文画像在详情抽屉。
 */

/** SSE 断连时的 REST 兜底轮询间隔（ms）。 */
const JAILS_POLL_MS = 30_000

type JailColumns = NonNullable<TableProps<JailResponse>['columns']>

/** 把未知异常归一成可读文案（后端信封 message 优先）。 */
function errText(err: unknown, fallback: string): string {
  return err instanceof ApiError && err.message ? err.message : fallback
}

export default function Jails() {
  const { message, modal } = App.useApp()
  const realtimeState = useSseState()

  // --- 主列表：SSE jails 域 + REST 拉取合流 ---
  const jailsDomain = useSseDomain('jails')
  const live = useLiveData<JailResponse[]>({
    sseValue: jailsDomain.value,
    sseSeq: jailsDomain.seq,
    rest: (signal) => getJails(signal),
    refreshInterval: JAILS_POLL_MS,
  })
  const {
    value: jails,
    isLoading,
    isRefreshing,
    isUserFetching,
    error,
    refetch,
  } = live

  // 命令面板「刷新当前页」
  useRefreshSignal(() => refetch())

  // --- 启停开关：按行独立的 in-flight 状态 ---
  const [toggling, setToggling] = useState<Record<string, boolean>>({})

  const applyToggle = useCallback(
    async (record: JailResponse, next: boolean) => {
      setToggling((prev) => ({ ...prev, [record.name]: true }))
      try {
        const res = await updateJail(record.name, { enabled: next })
        message.success(`规则 ${res.name} 已${res.enabled ? '启用' : '停用'}（${res.status}）`)
        // PUT 异步生效且不推 SSE 帧：重取列表拿权威状态
        refetch()
      } catch (err) {
        // Switch 是受控组件（checked 直接来自数据），失败时不更新数据即自然回滚
        message.error(errText(err, '切换失败，请稍后重试'))
        refetch()
      } finally {
        setToggling((prev) => {
          const copy = { ...prev }
          delete copy[record.name]
          return copy
        })
      }
    },
    [message, refetch],
  )

  const handleToggle = useCallback(
    (record: JailResponse) => {
      const next = !record.enabled
      if (next) {
        void applyToggle(record, next)
        return
      }
      // 停用会让该规则停止判定日志，属于防护降级，需二次确认；启用直通
      modal.confirm({
        title: `停用规则 ${record.name}？`,
        content: '停用后该规则将不再判定日志、不再产生新的封禁。',
        okText: '停用',
        okButtonProps: { danger: true },
        cancelText: '取消',
        onOk: () => applyToggle(record, next),
      })
    },
    [modal, applyToggle],
  )

  // --- 详情抽屉 ---
  const [detailName, setDetailName] = useState<string | null>(null)
  const detail = useMemo(
    () => jails?.find((j) => j.name === detailName) ?? null,
    [jails, detailName],
  )

  // --- 本页派生指标（只用 JailResponse 已有字段） ---
  const derived = useMemo(() => {
    const items = jails ?? []
    const enabled = items.filter((j) => j.enabled).length
    const bansTriggered = items.reduce((sum, j) => sum + j.bans_triggered, 0)
    const failedAttempts = items.reduce((sum, j) => sum + j.failed_attempts, 0)
    return { total: items.length, enabled, bansTriggered, failedAttempts }
  }, [jails])

  const cardsLoading = isLoading && jails == null

  const columns = useMemo<JailColumns>(
    () => [
      {
        title: '规则名',
        dataIndex: 'name',
        key: 'name',
        width: 160,
        render: (name: string) => (
          <Typography.Text strong className="fw-mono">
            {name}
          </Typography.Text>
        ),
      },
      {
        title: '启用',
        dataIndex: 'enabled',
        key: 'enabled',
        width: 90,
        render: (_: unknown, record: JailResponse) => (
          <Switch
            size="small"
            checked={record.enabled}
            loading={toggling[record.name] === true}
            onChange={() => handleToggle(record)}
            aria-label={`启用/停用规则 ${record.name}`}
          />
        ),
      },
      {
        title: '当前封禁',
        dataIndex: 'ban_count',
        key: 'ban_count',
        width: 100,
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '重试上限',
        dataIndex: 'max_retries',
        key: 'max_retries',
        width: 120,
        render: (_: unknown, record: JailResponse) => (
          <Tooltip title={`此刻外部新地址实际面对的阈值（已折算高峰系数）：${record.effective_max_retries}`}>
            <Space direction="vertical" size={0}>
              <span className="fw-mono">{record.max_retries}</span>
              {record.effective_max_retries !== record.max_retries && (
                <Typography.Text type="secondary" style={{ fontSize: 12 }} className="fw-mono">
                  生效 {record.effective_max_retries}
                </Typography.Text>
              )}
            </Space>
          </Tooltip>
        ),
      },
      {
        title: '观察窗口',
        dataIndex: 'findtime',
        key: 'findtime',
        width: 110,
        render: (seconds: number) => <span className="fw-mono">{formatDuration(seconds)}</span>,
      },
      {
        title: '封禁时长',
        dataIndex: 'ban_time',
        key: 'ban_time',
        width: 110,
        render: (seconds: number) => <span className="fw-mono">{formatDuration(seconds)}</span>,
      },
      {
        title: '时段',
        dataIndex: 'is_peak_hours',
        key: 'is_peak_hours',
        width: 120,
        render: (_: unknown, record: JailResponse) =>
          record.is_peak_hours ? (
            <Space size={4}>
              <Tag color="orange" style={{ marginInlineEnd: 0 }}>
                高峰
              </Tag>
              <span className="fw-mono">+{record.peak_hours_addend}</span>
            </Space>
          ) : (
            <Tag style={{ marginInlineEnd: 0 }}>常规</Tag>
          ),
      },
      {
        title: '内网加数',
        dataIndex: 'internal_ip_addend',
        key: 'internal_ip_addend',
        width: 100,
        render: (m: number) => <span className="fw-mono">+{m}</span>,
      },
      {
        title: '操作',
        key: 'actions',
        width: 80,
        render: (_: unknown, record: JailResponse) => (
          <Button type="link" size="small" onClick={() => setDetailName(record.name)}>
            详情
          </Button>
        ),
      },
    ],
    [toggling, handleToggle],
  )

  return (
    <>
      <PageHeader
        title="越狱规则"
        description="日志解析规则（jail）的阈值配置、启停切换与运行时触发计数"
        breadcrumb={[{ title: '防护' }, { title: '越狱规则' }]}
        realtimeState={realtimeState}
      />

      <StaleNotice
        visible={live.isStale && live.source !== 'sse'}
        onRetry={refetch}
        style={{ marginBottom: 16 }}
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
          label="规则总数"
          value={formatNumber(derived.total)}
          icon={ProfileOutlined}
          tone="info"
          loading={cardsLoading}
          footer="守护进程当前加载的 jail 数量"
        />
        <StatCard
          label="已启用"
          value={formatNumber(derived.enabled)}
          icon={CheckCircleOutlined}
          tone="success"
          loading={cardsLoading}
          footer={`停用 ${formatNumber(Math.max(derived.total - derived.enabled, 0))} 条`}
        />
        <StatCard
          label="累计触发封禁"
          value={formatNumber(derived.bansTriggered)}
          icon={ThunderboltOutlined}
          tone="danger"
          loading={cardsLoading}
          footer="全部规则 bans_triggered 之和"
        />
        <StatCard
          label="累计失败尝试"
          value={formatNumber(derived.failedAttempts)}
          icon={WarningOutlined}
          tone="warning"
          loading={cardsLoading}
          footer="全部规则 failed_attempts 之和"
        />
      </div>

      <DataTable<JailResponse>
        data={jails}
        isLoading={isLoading}
        isFetching={isUserFetching}
        error={error}
        onRetry={refetch}
        rowKey="name"
        columns={columns}
        emptyScenario="no-data"
        emptyTitle="暂无越狱规则"
        emptyDescription="守护进程尚未配置任何 jail；规则加载后会出现在这里"
        expandable={{
          expandedRowRender: (record: JailResponse) => (
            <Descriptions
              size="small"
              column={{ xs: 1, sm: 2, md: 3, lg: 5 }}
              items={[
                {
                  key: 'lines_parsed',
                  label: '已解析日志行',
                  children: <span className="fw-mono">{formatNumber(record.lines_parsed)}</span>,
                },
                {
                  key: 'regex_matches',
                  label: '正则命中',
                  children: <span className="fw-mono">{formatNumber(record.regex_matches)}</span>,
                },
                {
                  key: 'ips_extracted',
                  label: '提取 IP 数',
                  children: <span className="fw-mono">{formatNumber(record.ips_extracted)}</span>,
                },
                {
                  key: 'failed_attempts',
                  label: '失败尝试',
                  children: <span className="fw-mono">{formatNumber(record.failed_attempts)}</span>,
                },
                {
                  key: 'bans_triggered',
                  label: '触发封禁',
                  children: <span className="fw-mono">{formatNumber(record.bans_triggered)}</span>,
                },
              ]}
            />
          ),
        }}
        toolbar={
          <>
            <Button icon={<ReloadOutlined />} onClick={refetch} loading={isRefreshing}>
              刷新
            </Button>
            <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
              共 {formatNumber(derived.total)} 条规则 · 展开行查看解析漏斗
            </Typography.Text>
          </>
        }
        pagination={false}
        scroll={{ x: 'max-content' }}
      />

      {/* 单条规则详情：全字段中文画像 */}
      <Drawer
        open={detailName !== null}
        title={`规则详情 · ${detailName ?? ''}`}
        width={520}
        onClose={() => setDetailName(null)}
        destroyOnHidden
      >
        {detail ? (
          <JailDescriptions jail={detail} />
        ) : (
          <Typography.Text type="secondary">
            该规则已不在当前列表中，请关闭抽屉后刷新。
          </Typography.Text>
        )}
      </Drawer>
    </>
  )
}

// ---------------------------------------------------------------------------
// 详情抽屉内容
// ---------------------------------------------------------------------------

function JailDescriptions({ jail }: { jail: JailResponse }) {
  const items = useMemo(
    () => [
      {
        key: 'name',
        label: '规则名',
        children: <span className="fw-mono">{jail.name}</span>,
      },
      {
        key: 'enabled',
        label: '启用状态',
        children: jail.enabled ? <Tag color="green">已启用</Tag> : <Tag>已停用</Tag>,
      },
      { key: 'ban_count', label: '当前封禁数', children: formatNumber(jail.ban_count) },
      { key: 'max_retries', label: '重试上限', children: formatNumber(jail.max_retries) },
      {
        key: 'effective_max_retries',
        label: '生效重试上限',
        children: formatNumber(jail.effective_max_retries),
      },
      { key: 'findtime', label: '观察窗口', children: formatDuration(jail.findtime) },
      { key: 'ban_time', label: '封禁时长', children: formatDuration(jail.ban_time) },
      {
        key: 'is_peak_hours',
        label: '当前时段',
        children: jail.is_peak_hours ? <Tag color="orange">高峰</Tag> : <Tag>常规</Tag>,
      },
      {
        key: 'peak_hours_addend',
        label: '高峰加数',
        children: `+${jail.peak_hours_addend}`,
      },
      {
        key: 'internal_ip_addend',
        label: '内网 IP 加数',
        children: `+${jail.internal_ip_addend}`,
      },
      { key: 'lines_parsed', label: '已解析日志行', children: formatNumber(jail.lines_parsed) },
      { key: 'regex_matches', label: '正则命中次数', children: formatNumber(jail.regex_matches) },
      { key: 'ips_extracted', label: '提取 IP 数', children: formatNumber(jail.ips_extracted) },
      { key: 'failed_attempts', label: '失败尝试次数', children: formatNumber(jail.failed_attempts) },
      { key: 'bans_triggered', label: '触发封禁次数', children: formatNumber(jail.bans_triggered) },
    ],
    [jail],
  )

  return (
    <>
      <Descriptions column={1} size="small" bordered items={items} className="fw-fade-in" />
      <Space size={6} style={{ marginTop: 12 }}>
        <SafetyOutlined style={{ color: 'var(--fw-text-secondary)' }} />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          生效重试上限已折算高峰系数；内网/信誉系数按来源地址生效，不计入该值。
        </Typography.Text>
      </Space>
    </>
  )
}
