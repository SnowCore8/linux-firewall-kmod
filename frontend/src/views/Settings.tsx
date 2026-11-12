import { useEffect, useState, type CSSProperties } from 'react'
import {
  App,
  Button,
  Card,
  Descriptions,
  Flex,
  Form,
  InputNumber,
  Switch,
  Tag,
  TimePicker,
  Typography,
  type FormInstance,
} from 'antd'
import { ReloadOutlined, SaveOutlined, UndoOutlined } from '@ant-design/icons'
import dayjs, { type Dayjs } from 'dayjs'
import { useBlocker } from 'react-router-dom'
import { PageHeader } from '../components/PageHeader.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import { ErrorState } from '../components/state/ErrorState.tsx'
import { useAsync } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { getConfig, getHealth, updateConfig } from '../api/endpoints.ts'
import { formatNumber } from '../lib/format.ts'
import type { RuntimeSnapshot, UpdateConfigRequest, WebuiConfigResponse } from '../api/types.ts'

/**
 * 设置页 —— Web UI / 阈值 / DDoS / 容量配置的读写，外加守护进程运行时探针。
 *
 * 两条数据流各自独立、互不阻塞：
 *   * 配置表单走 getConfig 取快照、updateConfig 落盘；运行时状态走 getHealth（裸探针，
 *     就绪与否由后端 status 给出，前端只如实渲染，不用它去改表单）。
 *
 * 提交纪律是**差分**：onFinish 只把「与服务端快照不同」的字段装进 UpdateConfigRequest，
 * 未改动的一律不出现（后端请求体全字段可选，缺席即不改）。这样既避免把 19 个字段整体
 * 覆盖回去，也让「保存」按钮的可用性等价于「表单确实脏了」。
 *
 * 表单基线（initialValues）始终跟着 config.data 走：rc-form 每次渲染都会用最新的
 * initialValues 刷新内部「重置目标」，所以保存成功后把返回快照写回 config.data，
 * 「重置」与后续脏检查都会以服务端权威值为准，而不是首屏那份旧值。
 *
 * 阈值成对校验：警告必须严格小于严重（pps 一对、syn 一对）。校验器挂在**严重**字段上、
 * 经 dependencies 读兄弟字段，于是无论改动哪一侧都会重算这对约束，错误只落在一处不重复报。
 */

// --- 字段分组（差分与渲染共用同一份键名清单，避免两处漂移）---

/** 数值字段：差分时逐一按数值直接比较。 */
const NUMBER_FIELDS = [
  'sse_push_interval',
  'rate_warning_pps',
  'rate_critical_pps',
  'rate_warning_syn',
  'rate_critical_syn',
  'max_syn_per_second',
  'max_udp_per_second',
  'max_icmp_per_second',
  'max_ack_per_second',
  'max_rst_per_second',
  'max_fin_per_second',
  'max_ban_entries',
  'max_whitelist_entries',
  'max_rate_entries',
  'max_local_ip_cache',
] as const satisfies readonly (keyof WebuiConfigResponse)[]

/** 布尔开关字段：差分时按布尔直接比较。 */
const BOOL_FIELDS = [
  'static_threshold',
  'dynamic_threshold',
  'ddos_detection',
  'risk_engine_enabled',
  'threat_feeds_enabled',
  'cluster_enabled',
  'cluster_audit_only',
] as const satisfies readonly (keyof WebuiConfigResponse)[]

/**
 * 表单值形状：数值/布尔与配置快照同名同型，唯独 clear_logs_at 在表单里是
 * `Dayjs | null`（TimePicker 的值），落库前再格式化成 "HH:mm" 字符串或 null。
 */
interface SettingsFormValues {
  sse_push_interval: number
  rate_warning_pps: number
  rate_critical_pps: number
  rate_warning_syn: number
  rate_critical_syn: number
  max_syn_per_second: number
  max_udp_per_second: number
  max_icmp_per_second: number
  max_ack_per_second: number
  max_rst_per_second: number
  max_fin_per_second: number
  static_threshold: boolean
  dynamic_threshold: boolean
  ddos_detection: boolean
  max_ban_entries: number
  max_whitelist_entries: number
  max_rate_entries: number
  max_local_ip_cache: number
  clear_logs_at: Dayjs | null
  // 功能开关（跨模块）
  risk_engine_enabled: boolean
  threat_feeds_enabled: boolean
  cluster_enabled: boolean
  cluster_audit_only: boolean
}

/** 数值字段统一的栅格布局（窄屏自动折行，宽屏一行多列）。 */
const FIELD_GRID: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
  columnGap: 16,
}

/** InputNumber 在表单里的宽度，避免数字框撑满整格。 */
const NUMBER_STYLE: CSSProperties = { width: '100%' }

/** 探针 status 的两个取值（与后端 health.go 的 ok / degraded 逐字一致）。 */
const STATUS_META: Record<string, { label: string; color: string }> = {
  ok: { label: '就绪', color: 'success' },
  degraded: { label: '降级', color: 'warning' },
}

/** 内核租约 lease_state 的五个取值 → 中文（未知取值原样回显，便于发现后端新增态）。 */
const LEASE_LABELS: Record<string, string> = {
  none: '未注册',
  idle: '空闲',
  held: '已持有',
  refused: '被拒绝',
  lost: '已丢失',
}

/** 把后端异常归一成可读文案（ApiError 继承 Error，message 已是服务端信封文案）。 */
function errText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback
}

/** "HH:mm" 字符串 → Dayjs（今天日期 + 该时分）；空/非法一律 null。不依赖任何 dayjs 插件。 */
function parseHHmm(value: string | null): Dayjs | null {
  if (!value) return null
  const m = /^(\d{1,2}):(\d{2})$/.exec(value.trim())
  if (!m) return null
  const hour = Number(m[1])
  const minute = Number(m[2])
  if (hour > 23 || minute > 59) return null
  return dayjs().hour(hour).minute(minute).second(0).millisecond(0)
}

/** 把任意来源的时间串归一成规范 "HH:mm"（用于差分时两侧同口径比较）；空/非法 → null。 */
function normalizeHHmm(value: string | null): string | null {
  const parsed = parseHHmm(value)
  return parsed ? parsed.format('HH:mm') : null
}

/** 配置快照 → 表单值。 */
function configToForm(cfg: WebuiConfigResponse): SettingsFormValues {
  return {
    sse_push_interval: cfg.sse_push_interval,
    rate_warning_pps: cfg.rate_warning_pps,
    rate_critical_pps: cfg.rate_critical_pps,
    rate_warning_syn: cfg.rate_warning_syn,
    rate_critical_syn: cfg.rate_critical_syn,
    max_syn_per_second: cfg.max_syn_per_second,
    max_udp_per_second: cfg.max_udp_per_second,
    max_icmp_per_second: cfg.max_icmp_per_second,
    max_ack_per_second: cfg.max_ack_per_second,
    max_rst_per_second: cfg.max_rst_per_second,
    max_fin_per_second: cfg.max_fin_per_second,
    static_threshold: cfg.static_threshold,
    dynamic_threshold: cfg.dynamic_threshold,
    ddos_detection: cfg.ddos_detection,
    max_ban_entries: cfg.max_ban_entries,
    max_whitelist_entries: cfg.max_whitelist_entries,
    max_rate_entries: cfg.max_rate_entries,
    max_local_ip_cache: cfg.max_local_ip_cache,
    clear_logs_at: parseHHmm(cfg.clear_logs_at),
    // 功能开关
    risk_engine_enabled: cfg.risk_engine_enabled,
    threat_feeds_enabled: cfg.threat_feeds_enabled,
    cluster_enabled: cfg.cluster_enabled,
    cluster_audit_only: cfg.cluster_audit_only,
  }
}

/**
 * 差分：只挑出与服务端快照 base 不同的字段，装进 UpdateConfigRequest。
 * 数值/布尔直接比；clear_logs_at 两侧都归一成 "HH:mm" 再比，避免格式差异造成伪脏。
 */
function buildDiff(values: SettingsFormValues, base: WebuiConfigResponse): UpdateConfigRequest {
  const diff: UpdateConfigRequest = {}
  for (const key of NUMBER_FIELDS) {
    if (values[key] !== base[key]) diff[key] = values[key]
  }
  for (const key of BOOL_FIELDS) {
    if (values[key] !== base[key]) diff[key] = values[key]
  }
  const clearAt = values.clear_logs_at ? values.clear_logs_at.format('HH:mm') : null
  if (clearAt !== normalizeHHmm(base.clear_logs_at)) diff.clear_logs_at = clearAt
  return diff
}

/** 必填数值字段的校验规则（InputNumber 的 min 负责范围，这里只挡「被清空」）。 */
function requiredNumber(label: string): { required: true; message: string }[] {
  return [{ required: true, message: `请填写${label}` }]
}

/**
 * 成对阈值校验器：断言 sibling（警告）严格小于当前字段（严重）。
 * 挂在严重字段上、配合 dependencies=[警告]，两侧任一改动都会重算，错误只落在严重字段。
 */
function greaterThanSibling(
  form: FormInstance<SettingsFormValues>,
  sibling: keyof SettingsFormValues,
  message: string,
): { validator: (rule: unknown, value: unknown) => Promise<void> } {
  return {
    validator: (_rule: unknown, value: unknown) => {
      const crit = typeof value === 'number' ? value : null
      const warnRaw = form.getFieldValue(sibling)
      const warn = typeof warnRaw === 'number' ? warnRaw : null
      if (crit == null || warn == null) return Promise.resolve()
      return crit > warn ? Promise.resolve() : Promise.reject(new Error(message))
    },
  }
}

/** 布尔探针 → 彩色 Tag（真=绿，假=灰；不喧宾夺主，缺失内核属正常态而非报错）。 */
function boolTag(ok: boolean, yesLabel: string, noLabel: string) {
  return <Tag color={ok ? 'success' : 'default'}>{ok ? yesLabel : noLabel}</Tag>
}

/** 探针 status → Tag（ok/degraded 映射中文，未知取值原样回显）。 */
function statusTag(status: string) {
  const meta = STATUS_META[status]
  return <Tag color={meta?.color ?? 'default'}>{meta ? `${meta.label}（${status}）` : status}</Tag>
}

/** lease_state → 文本（中文标签 + 原文）。 */
function leaseText(state: string): string {
  const label = LEASE_LABELS[state]
  return label ? `${label}（${state}）` : state
}

/** 运行时快照 → Descriptions 条目（中文标签；布尔彩 Tag、status Tag、计数走等宽数字）。 */
function healthItems(snap: RuntimeSnapshot) {
  return [
    { key: 'status', label: '健康状态', children: statusTag(snap.status) },
    { key: 'netlink_ready', label: 'Netlink 链路', children: boolTag(snap.netlink_ready, '就绪', '未就绪') },
    {
      key: 'kmod_proc_present',
      label: '内核模块 procfs',
      children: boolTag(snap.kmod_proc_present, '存在', '缺失'),
    },
    {
      key: 'ban_cache_initialized',
      label: '封禁镜像',
      children: boolTag(snap.ban_cache_initialized, '已初始化', '未初始化'),
    },
    {
      key: 'ban_history_initialized',
      label: '历史库',
      children: boolTag(snap.ban_history_initialized, '已初始化', '未初始化'),
    },
    {
      key: 'active_bans',
      label: '活跃封禁',
      children: <span className="fw-mono">{formatNumber(snap.active_bans)}</span>,
    },
    { key: 'lease_state', label: '内核租约', children: leaseText(snap.lease_state) },
    {
      key: 'lease_losses',
      label: '租约丢失次数',
      children: <span className="fw-mono">{formatNumber(snap.lease_losses)}</span>,
    },
  ]
}

export default function Settings() {
  const { message, modal } = App.useApp()
  const [form] = Form.useForm<SettingsFormValues>()
  const [dirty, setDirty] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const config = useAsync((signal) => getConfig(signal))
  const health = useAsync((signal) => getHealth(signal))

  // 顶栏 / 命令面板广播的「刷新当前页」：配置与探针一起重取。
  useRefreshSignal(() => {
    config.refetch()
    health.refetch()
  })

  const refreshAll = (): void => {
    config.refetch()
    health.refetch()
  }

  // 基线（config.data）变化时重算脏标记：首屏载入、保存回写、刷新拉到新值都经这里对齐。
  useEffect(() => {
    const base = config.data
    if (!base) return
    setDirty(Object.keys(buildDiff(form.getFieldsValue(), base)).length > 0)
  }, [config.data, form])

  // 表单脏时拦截站内导航：确认弹窗决定丢弃离开还是留在本页
  const blocker = useBlocker(dirty)
  useEffect(() => {
    if (blocker.state !== 'blocked') return
    modal.confirm({
      title: '放弃未保存的修改？',
      content: '设置表单有未保存的修改，离开本页将丢弃这些更改。',
      okText: '放弃并离开',
      okButtonProps: { danger: true },
      cancelText: '留在本页',
      onOk: () => blocker.proceed(),
      onCancel: () => blocker.reset(),
    })
  }, [blocker, modal])

  // 表单脏时拦截浏览器刷新/关闭（beforeunload 只能触发浏览器通用确认，文案不可定制）
  useEffect(() => {
    if (!dirty) return
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault()
    }
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => window.removeEventListener('beforeunload', onBeforeUnload)
  }, [dirty])

  const handleValuesChange = (_changed: Partial<SettingsFormValues>, all: SettingsFormValues): void => {
    const base = config.data
    if (!base) return
    setDirty(Object.keys(buildDiff(all, base)).length > 0)
  }

  const handleFinish = async (values: SettingsFormValues): Promise<void> => {
    const base = config.data
    if (!base) return
    const diff = buildDiff(values, base)
    if (Object.keys(diff).length === 0) return
    setSubmitting(true)
    try {
      const updated = await updateConfig(diff)
      message.success('配置已保存')
      // 以返回快照为权威：写回基线（下轮渲染刷新 initialValues）+ 同步表单当前值。
      config.setData(updated)
      form.setFieldsValue(configToForm(updated))
      setDirty(false)
    } catch (err) {
      // 失败保留用户已填内容，仅提示；表单不重置、不清空。
      message.error(errText(err, '保存失败，请稍后重试'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleReset = (): void => {
    // 重置到当前基线（config.data）：rc-form 已把最新 initialValues 作为重置目标。
    form.resetFields()
    setDirty(false)
  }

  const cfg = config.data

  return (
    <>
      <PageHeader
        title="设置"
        description="调整推送间隔、速率阈值、DDoS 检测开关与容量上限，并查看守护进程运行时状态"
        breadcrumb={[{ title: '运维' }, { title: '设置' }]}
        extra={
          <Button
            icon={<ReloadOutlined />}
            onClick={refreshAll}
            loading={config.isRefreshing || health.isRefreshing}
          >
            刷新
          </Button>
        }
      />

      <Flex vertical gap={16} className="fw-fade-in">
        {/* --- 配置表单：加载 / 错误 / 就绪三态 --- */}
        {config.isLoading && cfg == null && <LoadingState variant="detail" />}
        {config.error != null && cfg == null && (
          <ErrorState error={config.error} onRetry={config.refetch} />
        )}

        {cfg != null && (
          <>
            {/* 已持有旧数据时后台刷新失败：内联提示，不打断正在编辑的表单 */}
            {config.error != null && (
              <ErrorState error={config.error} onRetry={config.refetch} compact />
            )}

            <Form<SettingsFormValues>
              form={form}
              layout="vertical"
              initialValues={configToForm(cfg)}
              onFinish={handleFinish}
              onValuesChange={handleValuesChange}
            >
              <Flex vertical gap={16}>
                <Card title="推送与实时" size="small">
                  <Form.Item
                    name="sse_push_interval"
                    label="推送间隔（秒）"
                    extra="SSE 实时推送的最小间隔，越小越实时但负载越高；最小 1 秒"
                    rules={requiredNumber('推送间隔')}
                    style={{ maxWidth: 260, marginBottom: 0 }}
                  >
                    <InputNumber min={1} step={1} precision={0} style={NUMBER_STYLE} />
                  </Form.Item>
                </Card>

                <Card title="速率阈值" size="small">
                  <div style={FIELD_GRID}>
                    <Form.Item
                      name="rate_warning_pps"
                      label="总速率警告（pps）"
                      extra="单 IP 每秒包数达到此值标记为警告"
                      rules={requiredNumber('总速率警告阈值')}
                    >
                      <InputNumber min={0} step={1000} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="rate_critical_pps"
                      label="总速率严重（pps）"
                      extra="须大于总速率警告阈值"
                      dependencies={['rate_warning_pps']}
                      rules={[
                        ...requiredNumber('总速率严重阈值'),
                        greaterThanSibling(form, 'rate_warning_pps', '严重阈值必须大于警告阈值'),
                      ]}
                    >
                      <InputNumber min={0} step={1000} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="rate_warning_syn"
                      label="SYN 速率警告（pps）"
                      extra="单 IP 每秒 SYN 包数达到此值标记为警告"
                      rules={requiredNumber('SYN 速率警告阈值')}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="rate_critical_syn"
                      label="SYN 速率严重（pps）"
                      extra="须大于 SYN 速率警告阈值"
                      dependencies={['rate_warning_syn']}
                      rules={[
                        ...requiredNumber('SYN 速率严重阈值'),
                        greaterThanSibling(form, 'rate_warning_syn', '严重阈值必须大于警告阈值'),
                      ]}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                  </div>
                </Card>

                <Card title="每协议上限" size="small">
                  <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 12 }}>
                    各协议每秒包数上限，超过即判为对应泛洪（同步到内核模块，参考正常主机量级）
                  </Typography.Paragraph>
                  <div style={FIELD_GRID}>
                    <Form.Item
                      name="max_syn_per_second"
                      label="SYN 上限（pps）"
                      rules={requiredNumber('SYN 上限')}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_udp_per_second"
                      label="UDP 上限（pps）"
                      rules={requiredNumber('UDP 上限')}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_icmp_per_second"
                      label="ICMP 上限（pps）"
                      rules={requiredNumber('ICMP 上限')}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_ack_per_second"
                      label="ACK 上限（pps）"
                      rules={requiredNumber('ACK 上限')}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_rst_per_second"
                      label="RST 上限（pps）"
                      rules={requiredNumber('RST 上限')}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_fin_per_second"
                      label="FIN 上限（pps）"
                      rules={requiredNumber('FIN 上限')}
                    >
                      <InputNumber min={0} step={100} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                  </div>
                </Card>

                <Card title="检测开关" size="small">
                  <div style={FIELD_GRID}>
                    <Form.Item
                      name="ddos_detection"
                      label="DDoS 检测总开关"
                      valuePropName="checked"
                      extra="关闭后下方两种阈值检测均不生效"
                    >
                      <Switch />
                    </Form.Item>
                    <Form.Item
                      name="static_threshold"
                      label="静态阈值检测"
                      valuePropName="checked"
                      extra="按上面固定的每协议上限判定"
                    >
                      <Switch />
                    </Form.Item>
                    <Form.Item
                      name="dynamic_threshold"
                      label="动态阈值检测"
                      valuePropName="checked"
                      extra="按历史基线 × 倍数自适应判定"
                    >
                      <Switch />
                    </Form.Item>
                  </div>
                </Card>

                <Card title="功能开关" size="small">
                  <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 12 }}>
                    高级功能模块的启用/禁用，关闭后相关功能将不可用
                  </Typography.Paragraph>
                  <div style={FIELD_GRID}>
                    <Form.Item
                      name="risk_engine_enabled"
                      label="风险引擎"
                      valuePropName="checked"
                      extra="多维风险向量记录与分析 API；关闭后风险引擎页面不可用"
                    >
                      <Switch />
                    </Form.Item>
                    <Form.Item
                      name="threat_feeds_enabled"
                      label="威胁情报源"
                      valuePropName="checked"
                      extra="外部情报拉取与命中封禁；关闭后不再查询 IPsum/FireHOL 等情报源"
                    >
                      <Switch />
                    </Form.Item>
                    <Form.Item
                      name="cluster_enabled"
                      label="集群扫描"
                      valuePropName="checked"
                      extra="协同扫描检测；关闭后不再检测来自同一网段的分布式攻击"
                    >
                      <Switch />
                    </Form.Item>
                    <Form.Item
                      name="cluster_audit_only"
                      label="集群审计模式"
                      valuePropName="checked"
                      extra="仅记录不封禁；开启后集群检测只记日志不自动封禁"
                    >
                      <Switch />
                    </Form.Item>
                  </div>
                </Card>

                <Card title="容量上限" size="small">
                  <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 12 }}>
                    各内核表的最大条目数，决定可承载的规模；调整通常需重载内核模块后生效
                  </Typography.Paragraph>
                  <div style={FIELD_GRID}>
                    <Form.Item
                      name="max_ban_entries"
                      label="封禁表条目"
                      rules={requiredNumber('封禁表最大条目数')}
                    >
                      <InputNumber min={1} step={1024} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_whitelist_entries"
                      label="白名单条目"
                      rules={requiredNumber('白名单最大条目数')}
                    >
                      <InputNumber min={1} step={1024} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_rate_entries"
                      label="速率表条目"
                      extra="支持并发监测的源 IP 数"
                      rules={requiredNumber('速率表最大条目数')}
                    >
                      <InputNumber min={1} step={1024} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                    <Form.Item
                      name="max_local_ip_cache"
                      label="本地 IP 缓存"
                      rules={requiredNumber('本地 IP 缓存最大条目数')}
                    >
                      <InputNumber min={1} step={1024} precision={0} style={NUMBER_STYLE} />
                    </Form.Item>
                  </div>
                </Card>

                <Card title="日志清理" size="small">
                  <Form.Item
                    name="clear_logs_at"
                    label="每日日志清理时间"
                    extra="每天到该时刻（HH:mm）清理历史日志；留空表示不按时间清理"
                    style={{ maxWidth: 260, marginBottom: 0 }}
                  >
                    <TimePicker format="HH:mm" allowClear style={NUMBER_STYLE} placeholder="选择时间" />
                  </Form.Item>
                </Card>

                {/* 提交区：仅在表单脏时可保存/重置 */}
                <Flex justify="flex-end" align="center" gap={12}>
                  {dirty && (
                    <Typography.Text type="warning" style={{ fontSize: 12 }}>
                      有未保存的修改
                    </Typography.Text>
                  )}
                  <Button icon={<UndoOutlined />} onClick={handleReset} disabled={!dirty || submitting}>
                    重置
                  </Button>
                  <Button
                    type="primary"
                    icon={<SaveOutlined />}
                    htmlType="submit"
                    loading={submitting}
                    disabled={!dirty}
                  >
                    保存
                  </Button>
                </Flex>
              </Flex>
            </Form>
          </>
        )}

        {/* --- 运行时状态：独立探针，与配置表单互不阻塞 --- */}
        <Card
          title="运行时状态"
          size="small"
          extra={
            <Button size="small" icon={<ReloadOutlined />} onClick={health.refetch} loading={health.isRefreshing}>
              刷新
            </Button>
          }
        >
          {health.isLoading && health.data == null && <LoadingState variant="detail" />}
          {health.error != null && health.data == null && (
            <ErrorState error={health.error} onRetry={health.refetch} compact />
          )}
          {health.data != null && (
            <>
              {/* 已拿到过一次数据后刷新失败：内联提示，别让运维误以为运行时状态还是新的 */}
              {health.error != null && (
                <ErrorState error={health.error} onRetry={health.refetch} compact />
              )}
              <Descriptions
                column={{ xs: 1, sm: 2, md: 2, lg: 3, xl: 3 }}
                size="small"
                bordered
                items={healthItems(health.data)}
              />
            </>
          )}
        </Card>
      </Flex>
    </>
  )
}
