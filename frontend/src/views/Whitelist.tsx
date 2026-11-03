import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  App,
  Button,
  Flex,
  Form,
  Input,
  Popconfirm,
  Select,
  Space,
  Tag,
  Typography,
  type TableColumnsType,
} from 'antd'
import {
  CheckCircleOutlined,
  DeleteOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { PageHeader } from '../components/PageHeader.tsx'
import { StatCard } from '../components/StatCard.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { DrawerForm } from '../components/DrawerForm.tsx'
import { useLiveData } from '../hooks/useLiveData.ts'
import { useAsync } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { useSseDomain, useSseState } from '../providers/SseProvider.tsx'
import {
  addWhitelist,
  getWhitelist,
  getWhitelistRecommendations,
  removeWhitelist,
} from '../api/endpoints.ts'
import { formatNumber, formatPercent } from '../lib/format.ts'
import { isValidCidr } from '../lib/validation.ts'
import type {
  CreateWhitelistRequest,
  WhitelistEntry,
  WhitelistRecommendation,
} from '../api/types.ts'

/**
 * 白名单页 —— 永不封禁的可信地址/网段维护 + 基于封禁历史的加白推荐。
 *
 * 主列表是「整表镜像」域：SSE 的 whitelist 帧与 REST 拉取同形（WhitelistEntry[]），
 * 用 useLiveData 按新鲜度序号仲裁，视图只消费一个 value；SSE 断连时 REST 轮询自动兜底。
 * 推荐区是 REST 独占（SSE 不推这个视图），用 useAsync 独立管理自己的加载/错误态，
 * 与主列表互不干扰：推荐拉取失败不影响白名单条目展示，反之亦然。
 *
 * 三处写操作（新增 / 移除 / 一键加白）都落到后端后 message 提示 + 重取主列表，
 * 让服务端真值回填界面，不做乐观更新以免与 SSE 帧打架。
 */

/** 主列表 REST 校准轮询间隔：SSE 活着时兜底校准，断连时充当主数据源。 */
const WHITELIST_POLL_MS = 30_000

/** 推荐类型枚举 → 中文标签；未知取值落回原文（契约要求不崩）。 */
const REC_TYPE_LABELS: Record<string, string> = {
  subnet: '网段',
  ip: '单 IP',
}

/** 推荐类型 → Tag 配色；未知取值不给色（走 Tag 默认色）。 */
const REC_TYPE_COLORS: Record<string, string> = {
  subnet: 'geekblue',
  ip: 'green',
}

function recTypeLabel(recType: string): string {
  return REC_TYPE_LABELS[recType] ?? recType
}

/** 把后端错误归一成可读文案（ApiError 继承 Error，message 已是服务端信封文案）。 */
function errText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback
}

const MIN_BANS_OPTIONS = [1, 3, 5, 10, 20, 50].map((n) => ({ label: String(n), value: n }))
const LIMIT_OPTIONS = [10, 20, 50, 100].map((n) => ({ label: String(n), value: n }))

export default function Whitelist() {
  const { message } = App.useApp()
  const realtimeState = useSseState()

  // --- 主列表：SSE whitelist 域 + REST 拉取合流 ---
  const whitelistDomain = useSseDomain('whitelist')
  const live = useLiveData<WhitelistEntry[]>({
    sseValue: whitelistDomain.value,
    sseSeq: whitelistDomain.seq,
    rest: getWhitelist,
    refreshInterval: WHITELIST_POLL_MS,
  })
  const {
    value: entries,
    isLoading: mainLoading,
    isRefreshing: mainRefreshing,
    error: mainError,
    refetch: refetchMain,
  } = live
  const entryCount = entries?.length ?? 0

  // --- 新增白名单抽屉 ---
  const [form] = Form.useForm<CreateWhitelistRequest>()
  const [addOpen, setAddOpen] = useState(false)

  const openAdd = useCallback(() => setAddOpen(true), [])
  const handleAddCancel = useCallback(() => {
    setAddOpen(false)
    form.resetFields()
  }, [form])

  const handleAddSubmit = useCallback(
    async (values: CreateWhitelistRequest) => {
      const cidr = values.cidr.trim()
      try {
        const res = await addWhitelist({ cidr })
        message.success(`已新增白名单：${res.cidr}`)
        setAddOpen(false)
        form.resetFields()
        refetchMain()
      } catch (err) {
        message.error(errText(err, '新增失败'))
      }
    },
    [message, form, refetchMain],
  )

  const handleRemove = useCallback(
    async (cidr: string) => {
      try {
        const res = await removeWhitelist(cidr)
        message.success(`已移除白名单：${res.cidr}`)
        refetchMain()
      } catch (err) {
        message.error(errText(err, '移除失败'))
      }
    },
    [message, refetchMain],
  )

  // --- 推荐区：REST 独占，独立加载/错误态 ---
  const [minBans, setMinBans] = useState(5)
  const [recLimit, setRecLimit] = useState(20)
  const [addingCidr, setAddingCidr] = useState<string | null>(null)

  const recs = useAsync<WhitelistRecommendation[]>((signal) =>
    getWhitelistRecommendations({ min_bans: minBans, limit: recLimit }, signal),
  )
  const {
    data: recData,
    isLoading: recLoading,
    isRefreshing: recRefreshing,
    error: recError,
    refetch: refetchRecs,
  } = recs

  // 阈值/条数变化后重取推荐（首屏由 useAsync 的 immediate 负责，这里跳过第一次）
  const firstRecRun = useRef(true)
  useEffect(() => {
    if (firstRecRun.current) {
      firstRecRun.current = false
      return
    }
    refetchRecs()
  }, [minBans, recLimit, refetchRecs])

  const handleWhitelistRec = useCallback(
    async (cidr: string) => {
      setAddingCidr(cidr)
      try {
        const res = await addWhitelist({ cidr })
        message.success(`已加白：${res.cidr}`)
        refetchMain()
      } catch (err) {
        message.error(errText(err, '加白失败'))
      } finally {
        setAddingCidr(null)
      }
    },
    [message, refetchMain],
  )

  // 顶栏/命令面板广播的「刷新当前页」：主列表与推荐区一起刷
  useRefreshSignal(() => {
    refetchMain()
    refetchRecs()
  })

  const mainColumns = useMemo<TableColumnsType<WhitelistEntry>>(
    () => [
      {
        title: 'CIDR / IP',
        dataIndex: 'cidr',
        key: 'cidr',
        render: (cidr: string) => <span className="fw-mono">{cidr}</span>,
      },
      {
        title: '设备备注',
        dataIndex: 'device',
        key: 'device',
        render: (device: string) =>
          device ? device : <Typography.Text type="secondary">—</Typography.Text>,
      },
      {
        title: '操作',
        key: 'actions',
        width: 96,
        align: 'right',
        render: (_value, record) => (
          <Popconfirm
            title="移除白名单？"
            description={
              <span>
                移除后 <span className="fw-mono">{record.cidr}</span> 将可能被重新封禁。
              </span>
            }
            okText="移除"
            okButtonProps={{ danger: true }}
            cancelText="取消"
            onConfirm={() => handleRemove(record.cidr)}
          >
            <Button danger type="text" size="small" icon={<DeleteOutlined />}>
              移除
            </Button>
          </Popconfirm>
        ),
      },
    ],
    [handleRemove],
  )

  const recColumns = useMemo<TableColumnsType<WhitelistRecommendation>>(
    () => [
      {
        title: '类型',
        dataIndex: 'rec_type',
        key: 'rec_type',
        width: 88,
        render: (recType: string) => (
          <Tag color={REC_TYPE_COLORS[recType]} style={{ marginInlineEnd: 0 }}>
            {recTypeLabel(recType)}
          </Tag>
        ),
      },
      {
        title: '网段 / CIDR',
        dataIndex: 'cidr',
        key: 'cidr',
        render: (cidr: string) => <span className="fw-mono">{cidr}</span>,
      },
      {
        title: '依据',
        dataIndex: 'reason',
        key: 'reason',
        render: (reason: string) => (
          <Typography.Text type="secondary" style={{ fontSize: 12.5 }}>
            {reason}
          </Typography.Text>
        ),
      },
      {
        title: '受影响 IP',
        dataIndex: 'affected_ips',
        key: 'affected_ips',
        width: 104,
        align: 'right',
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '累计封禁',
        dataIndex: 'total_bans',
        key: 'total_bans',
        width: 104,
        align: 'right',
        render: (n: number) => <span className="fw-mono">{formatNumber(n)}</span>,
      },
      {
        title: '证据强度',
        dataIndex: 'confidence',
        key: 'confidence',
        width: 96,
        align: 'right',
        render: (confidence: number) => (
          <span className="fw-mono">{formatPercent(confidence)}</span>
        ),
      },
      {
        title: '操作',
        key: 'actions',
        width: 92,
        align: 'right',
        render: (_value, record) => (
          <Button
            type="link"
            size="small"
            icon={<CheckCircleOutlined />}
            loading={addingCidr === record.cidr}
            onClick={() => handleWhitelistRec(record.cidr)}
          >
            加白
          </Button>
        ),
      },
    ],
    [handleWhitelistRec, addingCidr],
  )

  return (
    <>
      <PageHeader
        title="白名单"
        description="维护永不被封禁的可信地址与网段，并按封禁历史给出可疑误伤的加白推荐"
        breadcrumb={[{ title: '防护' }, { title: '白名单' }]}
        realtimeState={realtimeState}
      />

      <Flex vertical gap={16} className="fw-fade-in">
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
            gap: 16,
          }}
        >
          <StatCard
            label="条目总数"
            value={formatNumber(entryCount)}
            icon={SafetyCertificateOutlined}
            tone="success"
            footer="永不会被封禁的可信地址与网段"
            loading={mainLoading && entries == null}
          />
        </div>

        <DataTable<WhitelistEntry>
          data={entries}
          isLoading={mainLoading}
          error={mainError}
          onRetry={refetchMain}
          rowKey="cidr"
          columns={mainColumns}
          emptyScenario="no-data"
          emptyTitle="白名单为空"
          emptyDescription="白名单里的地址/网段永不会被封禁，可先把可信的内网段或运维 IP 加进来"
          emptyActionLabel="新增白名单"
          onEmptyAction={openAdd}
          toolbar={
            <>
              <Button type="primary" icon={<PlusOutlined />} onClick={openAdd}>
                新增白名单
              </Button>
              <Button icon={<ReloadOutlined />} onClick={refetchMain} loading={mainRefreshing}>
                刷新
              </Button>
              <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
                共 {entryCount} 条
              </Typography.Text>
            </>
          }
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            hideOnSinglePage: true,
            showTotal: (t) => `共 ${t} 条`,
          }}
          scroll={{ x: 'max-content' }}
        />

        <Flex vertical gap={10}>
          <Flex align="baseline" gap={8} wrap="wrap">
            <Typography.Title level={5} style={{ margin: 0 }}>
              加白推荐
            </Typography.Title>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              按封禁历史聚合出的可疑误伤网段，可一键加白
            </Typography.Text>
          </Flex>

          <DataTable<WhitelistRecommendation>
            data={recData}
            isLoading={recLoading}
            error={recError}
            onRetry={refetchRecs}
            rowKey={(record) => `${record.rec_type}:${record.cidr}`}
            columns={recColumns}
            emptyScenario="no-data"
            emptyTitle="暂无加白推荐"
            emptyDescription="当前阈值下没有聚合出可疑误伤的网段，可尝试降低「最小封禁次数」"
            toolbar={
              <>
                <Space size={6}>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    最小封禁次数
                  </Typography.Text>
                  <Select<number>
                    value={minBans}
                    onChange={(v) => setMinBans(v)}
                    options={MIN_BANS_OPTIONS}
                    style={{ width: 84 }}
                  />
                </Space>
                <Space size={6}>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    条数上限
                  </Typography.Text>
                  <Select<number>
                    value={recLimit}
                    onChange={(v) => setRecLimit(v)}
                    options={LIMIT_OPTIONS}
                    style={{ width: 84 }}
                  />
                </Space>
                <Button icon={<ReloadOutlined />} onClick={refetchRecs} loading={recRefreshing}>
                  刷新
                </Button>
                <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
                  共 {recData?.length ?? 0} 条推荐
                </Typography.Text>
              </>
            }
            pagination={{
              pageSize: 10,
              showSizeChanger: true,
              hideOnSinglePage: true,
              showTotal: (t) => `共 ${t} 条推荐`,
            }}
            scroll={{ x: 'max-content' }}
          />
        </Flex>
      </Flex>

      <DrawerForm<CreateWhitelistRequest>
        open={addOpen}
        title="新增白名单"
        form={form}
        onSubmit={handleAddSubmit}
        onCancel={handleAddCancel}
        submitText="新增"
        cancelText="取消"
      >
        <Form.Item
          name="cidr"
          label="CIDR / IP"
          extra="支持 IPv4/IPv6，可带 /前缀；不带前缀视为单主机"
          rules={[
            { required: true, message: '请输入要加白的地址或网段' },
            {
              validator: (_rule, value: string) =>
                !value || isValidCidr(value)
                  ? Promise.resolve()
                  : Promise.reject(new Error('地址或网段格式不正确')),
            },
          ]}
        >
          <Input
            className="fw-mono"
            placeholder="例如 203.0.113.0/24 或 192.168.1.10"
            allowClear
            autoFocus
            aria-label="CIDR 或 IP"
          />
        </Form.Item>
      </DrawerForm>
    </>
  )
}
