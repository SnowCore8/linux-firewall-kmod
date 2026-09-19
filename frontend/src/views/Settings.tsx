// Web UI 配置页（二级页，位于「更多」之下）
//
// 做什么：把后端 `GET /api/v1/config` 返回的运行时可配置项以卡片 + 列表形式呈现，
//        并允许就地编辑：SSE 推送间隔、速率告警阈值（总速率 / SYN）、六种协议的每秒
//        上限、三个 DDoS 检测算法开关、四张表的容量上限、以及日志视图的时间过滤起点。
// 影响什么：本页是**唯一的配置写入口**（`PUT /api/v1/config`）。保存会立即：
//          1) 改写守护进程内存中的全局 WebUI 配置；
//          2) 把协议阈值经 netlink 下发内核，DDoS 检测开关写入内核参数
//             （sysfs：fw_ddos_detection / fw_static_threshold / fw_dynamic_threshold）；
//          3) 持久化到运行时配置文件，使守护进程重启后仍生效。
//        因此任何保存都必须二次确认，且失败原因原样呈现给用户。
//
// 一致性策略：
//   * 客户端校验**逐条对齐**后端 `api.rs::update_webui_config`（warning < critical、
//     各阈值/容量非 0、SSE 间隔 1-60、clear_logs_at 空串 = 取消过滤），
//     前端这一层只为减少无效请求；后端仍会独立校验并返回 400。
//   * 只提交**真正被改动**的字段（契约里所有字段可选），避免用陈旧值覆盖别处
//     （例如日志页刚写入的 `clear_logs_at`）已做出的修改。

import { useEffect, useMemo, useState } from 'react'
import { Button, Card, Dialog, Input, List, NavBar, NoticeBar, Skeleton, Switch } from 'antd-mobile'
import { LoopOutline } from 'antd-mobile-icons'
import { useNavigate } from 'react-router-dom'
import type { UpdateConfigRequest, WebuiConfigResponse } from '../api/types'
import { getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { useToast } from '../hooks/useToast'
import { PageHeader } from '../components/PageHeader'
import { formatDatetime } from '../lib/format'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const CONFIG_URL = '/api/v1/config'

/** 次要说明文字样式 */
const MUTED = { color: 'var(--adm-color-text-secondary)', fontSize: 12 } as const

/** 数值型配置项的键（与 Rust `WebuiConfigResponse` 的可编辑数字字段一一对应） */
type NumericKey =
  | 'sse_push_interval'
  | 'rate_warning_pps'
  | 'rate_critical_pps'
  | 'rate_warning_syn'
  | 'rate_critical_syn'
  | 'max_syn_per_second'
  | 'max_udp_per_second'
  | 'max_icmp_per_second'
  | 'max_ack_per_second'
  | 'max_rst_per_second'
  | 'max_fin_per_second'
  | 'max_ban_entries'
  | 'max_whitelist_entries'
  | 'max_rate_entries'
  | 'max_local_ip_cache'

/** 布尔型配置项（DDoS 检测算法开关） */
type BoolKey = 'static_threshold' | 'dynamic_threshold' | 'ddos_detection'

/** 数值键清单：用于构造草稿、校验与差异比较（顺序即界面上的字段顺序无要求） */
const NUMERIC_KEYS = [
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
] as const

/** 布尔键清单 */
const BOOL_KEYS = ['static_threshold', 'dynamic_threshold', 'ddos_detection'] as const

/** 后端明确拒绝取 0 的数值键（协议专项阈值 + 四张表容量） */
const ZERO_FORBIDDEN: readonly NumericKey[] = [
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
]

/** 数值键的中文名：出现在校验错误里，必须与后端错误文案指向同一个字段 */
const NUMERIC_LABELS: Record<NumericKey, string> = {
  sse_push_interval: 'SSE 推送间隔',
  rate_warning_pps: '速率警告阈值',
  rate_critical_pps: '速率严重阈值',
  rate_warning_syn: 'SYN 警告阈值',
  rate_critical_syn: 'SYN 严重阈值',
  max_syn_per_second: 'SYN 阈值',
  max_udp_per_second: 'UDP 阈值',
  max_icmp_per_second: 'ICMP 阈值',
  max_ack_per_second: 'ACK 阈值',
  max_rst_per_second: 'RST 阈值',
  max_fin_per_second: 'FIN 阈值',
  max_ban_entries: '封禁表容量',
  max_whitelist_entries: '白名单容量',
  max_rate_entries: '速率表容量',
  max_local_ip_cache: '本地 IP 缓存容量',
}

/** 布尔键的中文名与说明（说明依据内核模块参数注释与 firewall.h 的字段语义） */
const BOOL_FIELDS: ReadonlyArray<{ key: BoolKey; label: string; hint: string }> = [
  {
    key: 'ddos_detection',
    label: 'DDoS 检测总开关',
    hint: '写入内核参数 fw_ddos_detection；关闭后停止 DDoS 判定，已产生的封禁不受影响',
  },
  {
    key: 'static_threshold',
    label: '静态阈值算法',
    hint: '内核参数 fw_static_threshold；按配置的固定阈值判定，行为可预期',
  },
  {
    key: 'dynamic_threshold',
    label: '动态阈值算法',
    hint: '内核参数 fw_dynamic_threshold；启用后实际阈值 = max(静态阈值, EWMA 基线 × 倍数)，需要样本积累',
  },
]

/** 数值字段元信息：分组渲染时复用 */
interface NumericFieldMeta {
  key: NumericKey
  label: string
  hint: string
}

/** 速率与告警阈值（总速率 + SYN 专项） */
const RATE_FIELDS: readonly NumericFieldMeta[] = [
  { key: 'rate_warning_pps', label: '速率警告阈值', hint: 'pps，必须小于严重阈值' },
  { key: 'rate_critical_pps', label: '速率严重阈值', hint: 'pps，必须大于警告阈值' },
  { key: 'rate_warning_syn', label: 'SYN 警告阈值', hint: 'pps，必须小于 SYN 严重阈值' },
  { key: 'rate_critical_syn', label: 'SYN 严重阈值', hint: 'pps，必须大于 SYN 警告阈值' },
]

/** 协议专项阈值：下发内核，任一为 0 会被后端拒绝 */
const PROTOCOL_FIELDS: readonly NumericFieldMeta[] = [
  { key: 'max_syn_per_second', label: 'SYN', hint: '每秒上限，不能为 0' },
  { key: 'max_udp_per_second', label: 'UDP', hint: '每秒上限，不能为 0' },
  { key: 'max_icmp_per_second', label: 'ICMP', hint: '每秒上限，不能为 0' },
  { key: 'max_ack_per_second', label: 'ACK', hint: '每秒上限，不能为 0' },
  { key: 'max_rst_per_second', label: 'RST', hint: '每秒上限，不能为 0' },
  { key: 'max_fin_per_second', label: 'FIN', hint: '每秒上限，不能为 0' },
]

/** 容量上限：决定各表能容纳的条目数，不能为 0 */
const CAPACITY_FIELDS: readonly NumericFieldMeta[] = [
  { key: 'max_ban_entries', label: '封禁表容量', hint: '条目数，不能为 0' },
  { key: 'max_whitelist_entries', label: '白名单容量', hint: '条目数，不能为 0' },
  { key: 'max_rate_entries', label: '速率表容量', hint: '条目数，不能为 0' },
  { key: 'max_local_ip_cache', label: '本地 IP 缓存容量', hint: '条目数，不能为 0' },
]

/** 把任意抛出物转成可展示文案（client 抛出的 ApiError 就是 Error 子类） */
function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

/** 后端配置 → 编辑草稿（全部转成字符串，便于输入过程中的中间态，如清空后重输） */
function makeNumbers(cfg: WebuiConfigResponse): Record<NumericKey, string> {
  return {
    sse_push_interval: String(cfg.sse_push_interval),
    rate_warning_pps: String(cfg.rate_warning_pps),
    rate_critical_pps: String(cfg.rate_critical_pps),
    rate_warning_syn: String(cfg.rate_warning_syn),
    rate_critical_syn: String(cfg.rate_critical_syn),
    max_syn_per_second: String(cfg.max_syn_per_second),
    max_udp_per_second: String(cfg.max_udp_per_second),
    max_icmp_per_second: String(cfg.max_icmp_per_second),
    max_ack_per_second: String(cfg.max_ack_per_second),
    max_rst_per_second: String(cfg.max_rst_per_second),
    max_fin_per_second: String(cfg.max_fin_per_second),
    max_ban_entries: String(cfg.max_ban_entries),
    max_whitelist_entries: String(cfg.max_whitelist_entries),
    max_rate_entries: String(cfg.max_rate_entries),
    max_local_ip_cache: String(cfg.max_local_ip_cache),
  }
}

/** 后端配置 → 开关草稿 */
function makeFlags(cfg: WebuiConfigResponse): Record<BoolKey, boolean> {
  return {
    static_threshold: cfg.static_threshold,
    dynamic_threshold: cfg.dynamic_threshold,
    ddos_detection: cfg.ddos_detection,
  }
}

/**
 * 校验草稿，返回第一条错误文案；全部合法返回 null。
 * 规则顺序与错误措辞刻意贴近后端 `update_webui_config`，让同一条规则在两端说法一致。
 */
function validateDraft(numbers: Record<NumericKey, string>, clearLogs: string): string | null {
  for (const key of NUMERIC_KEYS) {
    const raw = numbers[key].trim()
    if (raw === '') return `${NUMERIC_LABELS[key]}不能为空`
    // 后端字段是无符号整数：只接受纯数字，明确拒绝负数、小数与科学计数法
    if (!/^\d+$/.test(raw)) return `${NUMERIC_LABELS[key]}必须是不小于 0 的整数`
  }

  /** 已确认是纯数字，这里读取是安全的 */
  const val = (key: NumericKey): number => Number(numbers[key])

  if (val('sse_push_interval') === 0 || val('sse_push_interval') > 60) {
    return 'SSE 推送间隔必须在 1-60 秒之间'
  }
  if (val('rate_warning_pps') >= val('rate_critical_pps')) {
    return '速率警告阈值必须小于严重阈值'
  }
  if (val('rate_warning_syn') >= val('rate_critical_syn')) {
    return 'SYN 警告阈值必须小于严重阈值'
  }
  for (const key of ZERO_FORBIDDEN) {
    if (val(key) === 0) return `${NUMERIC_LABELS[key]}不能为 0`
  }

  // 日志过滤起点：空串 = 取消过滤；非空必须是可解析的时间戳
  if (clearLogs !== '' && Number.isNaN(Date.parse(clearLogs))) {
    return '日志过滤时间格式不合法'
  }
  return null
}

/**
 * 数值输入控件。
 *
 * 为什么要单独封装：antd-mobile 的 Input 根节点 `min-height` 只有 24px，直接塞进
 * List.Item 会得到一个明显小于 44px 的触摸目标；这里把根节点撑到 44px 并让内部
 * <input> 拉伸填满（`alignItems: 'stretch'`），同时用 16px 字号避免 iOS 聚焦时缩放页面。
 */
function NumberInput(props: { label: string; value: string; onChange: (value: string) => void }) {
  const { label, value, onChange } = props
  return (
    <div className="fw-tap" style={{ width: 84 }}>
      <Input
        inputMode="numeric"
        value={value}
        onChange={onChange}
        placeholder="必填"
        aria-label={label}
        style={NUMBER_INPUT_STYLE}
      />
    </div>
  )
}

/** NumberInput 的样式：字面量类型（alignItems）必须用 as const 才能匹配 antd-mobile 的 style 类型 */
const NUMBER_INPUT_STYLE = {
  '--text-align': 'right',
  '--font-size': '16px',
  height: 44,
  alignItems: 'stretch',
} as const

/** 差异结果：待提交的请求体与改动项数量 */
interface DraftDiff {
  payload: UpdateConfigRequest
  changedCount: number
}

/**
 * 只挑出与后端现值不同的字段。
 * 契约里所有字段可选，提交子集可避免「用页面上打开时的旧值」覆盖别处刚做的修改。
 */
function buildPayload(
  numbers: Record<NumericKey, string>,
  flags: Record<BoolKey, boolean>,
  clearLogs: string,
  baseline: WebuiConfigResponse,
): DraftDiff {
  const payload: UpdateConfigRequest = {}
  let changedCount = 0

  for (const key of NUMERIC_KEYS) {
    const value = Number(numbers[key].trim())
    // 草稿非法（NaN）时必然视为有改动，交给校验环节给出明确错误
    if (value !== baseline[key]) {
      payload[key] = value
      changedCount += 1
    }
  }
  for (const key of BOOL_KEYS) {
    if (flags[key] !== baseline[key]) {
      payload[key] = flags[key]
      changedCount += 1
    }
  }
  if (clearLogs !== (baseline.clear_logs_at ?? '')) {
    payload.clear_logs_at = clearLogs
    changedCount += 1
  }
  return { payload, changedCount }
}

/** 把后端保存的 ISO 字符串转成本地可读时间；无法解析时原样返回（不静默丢信息） */
function isoToLocalText(iso: string): string {
  if (iso === '') return '未设置（不做时间过滤）'
  const parsed = Date.parse(iso.includes('T') ? iso : iso.replace(' ', 'T'))
  if (Number.isNaN(parsed)) return iso
  return formatDatetime(Math.floor(parsed / 1000))
}

/** 生成与日志页一致的时间戳形态（本地时间，秒级，空格换成 T） */
function nowTimestamp(): string {
  return formatDatetime(Math.floor(Date.now() / 1000)).replace(' ', 'T')
}

/** 保存 / 撤销操作条：顶部与底部各放一份，长页面无需滚到底才能保存 */
function ActionBar(props: {
  dirty: boolean
  saving: boolean
  onSave: () => void
  onReset: () => void
}) {
  const { dirty, saving, onSave, onReset } = props
  return (
    <div style={{ display: 'flex', gap: 5, margin: '7px 0' }}>
      <Button
        block
        color="primary"
        style={{ flex: 2, minHeight: 44 }}
        loading={saving}
        disabled={!dirty || saving}
        onClick={onSave}
      >
        {dirty ? '保存修改' : '无待保存修改'}
      </Button>
      <Button
        block
        style={{ flex: 1, minHeight: 44 }}
        disabled={!dirty || saving}
        onClick={onReset}
      >
        撤销
      </Button>
    </div>
  )
}

export default function Settings() {
  const navigate = useNavigate()
  const toast = useToast()

  // 配置读取：GET /api/v1/config
  const config = useAsync(() => getJson<WebuiConfigResponse>(CONFIG_URL), [])

  /** 当前后端现值（作为差异比较的基准；保存成功后用后端返回体刷新） */
  const [baseline, setBaseline] = useState<WebuiConfigResponse | null>(null)
  /** 数值草稿：字符串形态，允许输入过程中的空值 */
  const [numbers, setNumbers] = useState<Record<NumericKey, string> | null>(null)
  /** 开关草稿 */
  const [flags, setFlags] = useState<Record<BoolKey, boolean> | null>(null)
  /** 日志过滤起点草稿：空串 = 取消过滤 */
  const [clearLogs, setClearLogs] = useState('')
  const [saving, setSaving] = useState(false)

  // 首次加载或手动刷新后，用后端现值重建草稿（丢弃未保存的本地修改）
  useEffect(() => {
    if (config.data === null) return
    setBaseline(config.data)
    setNumbers(makeNumbers(config.data))
    setFlags(makeFlags(config.data))
    setClearLogs(config.data.clear_logs_at ?? '')
  }, [config.data])

  const ready = numbers !== null && flags !== null && baseline !== null

  /** 是否存在与后端现值不同的字段 */
  const dirty = useMemo(() => {
    if (numbers === null || flags === null || baseline === null) return false
    return buildPayload(numbers, flags, clearLogs, baseline).changedCount > 0
  }, [numbers, flags, clearLogs, baseline])

  /** 修改单个数值字段 */
  const updateNumber = (key: NumericKey, value: string) => {
    setNumbers((prev) => {
      if (prev === null) return prev
      const next = { ...prev }
      next[key] = value
      return next
    })
  }

  /** 修改单个开关 */
  const updateFlag = (key: BoolKey, checked: boolean) => {
    setFlags((prev) => {
      if (prev === null) return prev
      const next = { ...prev }
      next[key] = checked
      return next
    })
  }

  /** 丢弃本地修改，回到后端现值 */
  const resetDraft = () => {
    if (baseline === null) return
    setNumbers(makeNumbers(baseline))
    setFlags(makeFlags(baseline))
    setClearLogs(baseline.clear_logs_at ?? '')
    toast.info('已撤销未保存的修改')
  }

  /** 保存：校验 → 二次确认 → PUT → 用后端返回体重建草稿 */
  const save = async () => {
    if (numbers === null || flags === null || baseline === null) return

    const problem = validateDraft(numbers, clearLogs)
    if (problem !== null) {
      toast.error(problem)
      return
    }

    const { payload, changedCount } = buildPayload(numbers, flags, clearLogs, baseline)
    if (changedCount === 0) {
      toast.info('没有需要保存的修改')
      return
    }

    const confirmed = await Dialog.confirm({
      content: `确定保存 ${changedCount} 项配置修改？阈值会立即同步到内核，可能改变正在生效的封禁判定。`,
      confirmText: '保存',
    })
    if (!confirmed) return

    setSaving(true)
    try {
      const updated = await sendJson<UpdateConfigRequest, WebuiConfigResponse>(CONFIG_URL, 'PUT', payload)
      // 后端返回的完整配置即最新真值：直接作为新基准，避免再次请求造成短暂不一致
      setBaseline(updated)
      setNumbers(makeNumbers(updated))
      setFlags(makeFlags(updated))
      setClearLogs(updated.clear_logs_at ?? '')
      toast.success(`配置已保存（${changedCount} 项）`)
    } catch (e) {
      // 后端会返回 400 + 具体原因（如「速率警告阈值必须小于严重阈值」），原样呈现
      toast.error(`保存失败：${errorText(e)}`)
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      {/* 二级页返回入口：回到收纳本页的「更多」 */}
      <NavBar onBack={() => navigate('/more')}>设置</NavBar>

      <PageHeader
        title="Web UI 配置"
        subtitle="保存即写入守护进程运行时配置并持久化；协议阈值与 DDoS 开关同时下发内核"
        extra={
          <Button
            size="small"
            fill="none"
            style={{ minHeight: 44 }}
            aria-label="重新读取后端配置"
            onClick={() => config.reload()}
          >
            <LoopOutline fontSize={18} />
          </Button>
        }
      />

      <div style={{ paddingBottom: 7 }}>
        {/* 读取失败：错误对用户可见并提供重试 */}
        {config.error !== null && (
          <NoticeBar
            color="error"
            wrap
            content={`配置读取失败：${config.error}`}
            extra={
              <a onClick={() => config.reload()} style={{ color: 'inherit', textDecoration: 'underline' }}>
                重试
              </a>
            }
          />
        )}

        {/* 首屏骨架：配置未就绪时不渲染可编辑控件，避免用户对着空表单修改 */}
        {!ready && config.error === null && (
          <div style={{ marginTop: 7 }}>
            <Skeleton.Title animated />
            <Skeleton.Paragraph lineCount={8} animated />
          </div>
        )}

        {ready && numbers !== null && flags !== null && (
          <>
            {dirty && (
              <NoticeBar
                color="info"
                wrap
                content="有未保存的修改；阈值类配置会立即影响内核判定，请确认后再保存"
              />
            )}

            <ActionBar dirty={dirty} saving={saving} onSave={() => void save()} onReset={resetDraft} />

            {/* 实时推送 */}
            <Card title="实时推送">
              <List>
                <List.Item
                  description="SSE 事件推送周期，单位秒；取值 1-60"
                  extra={
                    <NumberInput
                      label="SSE 推送间隔"
                      value={numbers.sse_push_interval}
                      onChange={(value) => updateNumber('sse_push_interval', value)}
                    />
                  }
                >
                  SSE 推送间隔
                </List.Item>
              </List>
            </Card>

            {/* 速率告警阈值 */}
            <Card title="速率告警阈值" style={{ marginTop: 7 }}>
              <List>
                {RATE_FIELDS.map((field) => (
                  <List.Item
                    key={field.key}
                    description={field.hint}
                    extra={
                      <NumberInput
                        label={field.label}
                        value={numbers[field.key]}
                        onChange={(value) => updateNumber(field.key, value)}
                      />
                    }
                  >
                    {field.label}
                  </List.Item>
                ))}
              </List>
            </Card>

            {/* 协议专项阈值 */}
            <Card title="协议专项阈值（下发内核）" style={{ marginTop: 7 }}>
              <List>
                {PROTOCOL_FIELDS.map((field) => (
                  <List.Item
                    key={field.key}
                    description={field.hint}
                    extra={
                      <NumberInput
                        label={field.label}
                        value={numbers[field.key]}
                        onChange={(value) => updateNumber(field.key, value)}
                      />
                    }
                  >
                    {field.label}
                  </List.Item>
                ))}
              </List>
            </Card>

            {/* DDoS 检测算法开关 */}
            <Card title="DDoS 检测算法" style={{ marginTop: 7 }}>
              <List>
                {BOOL_FIELDS.map((field) => (
                  <List.Item
                    key={field.key}
                    description={field.hint}
                    extra={
                      // 开关外面套 44px 高的容器：antd-mobile 默认尺寸小于触摸目标下限
                      <div className="fw-tap">
                        <Switch
                          checked={flags[field.key]}
                          style={{ '--width': '42px', '--height': '26px' }}
                          onChange={(checked) => updateFlag(field.key, checked)}
                        />
                      </div>
                    }
                  >
                    {field.label}
                  </List.Item>
                ))}
              </List>
            </Card>

            {/* 容量上限 */}
            <Card title="容量上限" style={{ marginTop: 7 }}>
              <List>
                {CAPACITY_FIELDS.map((field) => (
                  <List.Item
                    key={field.key}
                    description={field.hint}
                    extra={
                      <NumberInput
                        label={field.label}
                        value={numbers[field.key]}
                        onChange={(value) => updateNumber(field.key, value)}
                      />
                    }
                  >
                    {field.label}
                  </List.Item>
                ))}
              </List>
            </Card>

            {/* 日志视图时间过滤：本页只写入起点，不直接删除日志文件 */}
            <Card title="日志视图过滤" style={{ marginTop: 7 }}>
              <div style={{ ...MUTED, marginBottom: 5 }}>
                当前起点：{isoToLocalText(clearLogs)}。过滤只影响日志页的展示范围，
                不会删除磁盘上的日志文件。
              </div>
              <List>
                <List.Item
                  description="把起点设为此刻，日志页默认只显示此后的新日志"
                  extra={
                    <Button
                      size="small"
                      style={{ minHeight: 44 }}
                      onClick={() => setClearLogs(nowTimestamp())}
                    >
                      设为当前时间
                    </Button>
                  }
                >
                  过滤起点
                </List.Item>
                <List.Item
                  description="清空起点，日志页恢复显示所有历史行"
                  extra={
                    <Button
                      size="small"
                      style={{ minHeight: 44 }}
                      disabled={clearLogs === ''}
                      onClick={() => setClearLogs('')}
                    >
                      取消过滤
                    </Button>
                  }
                >
                  清除过滤
                </List.Item>
              </List>
            </Card>

            {/* 生效方式说明：让用户知道「保存」之后发生了什么 */}
            <List header="保存后的行为" style={{ marginTop: 7 }}>
              <List.Item>配置写入守护进程内存并持久化到运行时配置文件，重启后保留</List.Item>
              <List.Item>协议阈值与 DDoS 开关会即时同步到内核；同步失败不影响配置保存</List.Item>
              <List.Item>「日志视图过滤」以空字符串保存即表示取消过滤</List.Item>
            </List>

            <ActionBar dirty={dirty} saving={saving} onSave={() => void save()} onReset={resetDraft} />
          </>
        )}
      </div>
    </>
  )
}
