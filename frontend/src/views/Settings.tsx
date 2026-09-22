// Web UI 配置页（二级页，位于「更多」之下）
//
// 做什么：把后端 `GET /api/v1/config` 返回的运行时可配置项组织成**控制台式高密度面板**，
//        并允许就地编辑：SSE 推送间隔、速率告警阈值（总速率 / SYN）、六种协议的每秒
//        上限、三个 DDoS 检测算法开关、四张表的容量上限、以及日志视图的时间过滤起点。
// 影响什么：本页是**唯一的配置写入口**（`PUT /api/v1/config`）。保存会立即：
//          1) 改写守护进程内存中的全局 WebUI 配置；
//          2) 把协议阈值经 netlink 下发内核，DDoS 检测开关写入内核参数
//             （sysfs：fw_ddos_detection / fw_static_threshold / fw_dynamic_threshold）；
//          3) 持久化到运行时配置文件，使守护进程重启后仍生效。
//        因此任何保存都必须二次确认，且失败原因原样呈现给用户。
//
// 版式（控制台式高密度）：
//   * 每组配置一个 Panel；可编辑项是「标签 dim + 方框输入（等宽、右对齐）」的行；
//   * 可点 / 可编辑区域一律 ≥44px（--fw-tap），数据密度不压缩触摸目标；
//   * 约束关系（警告 < 严重、非 0、1-60 秒）以行内 Badge 直接标在数值旁，
//     而不是写成需要通读的长说明——用户扫一眼就知道哪一项不满足。
//
// 一致性策略：
//   * 客户端校验**逐条对齐**后端 `api.rs::update_webui_config`（warning < critical、
//     各阈值/容量非 0、SSE 间隔 1-60、clear_logs_at 空串 = 取消过滤），
//     前端这一层只为减少无效请求；后端仍会独立校验并返回 400。
//   * 只提交**真正被改动**的字段（契约里所有字段可选），避免用陈旧值覆盖别处
//     （例如日志页刚写入的 `clear_logs_at`）已做出的修改。

import { useEffect, useMemo, useState } from 'react'
import { Dialog, PullToRefresh, Skeleton, Switch } from 'antd-mobile'
import { LoopOutline } from 'antd-mobile-icons'
import { useNavigate } from 'react-router-dom'
import type { UpdateConfigRequest, WebuiConfigResponse } from '../api/types'
import { getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { useToast } from '../hooks/useToast'
import { PageHeader } from '../components/PageHeader'
import { BackLink, Badge, Panel, Row, Rows, SubHead, Toolbar, errorText } from '../components/console'
import { formatDatetime } from '../lib/format'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const CONFIG_URL = '/api/v1/config'

/** 面板内的一行 dim 说明（10px 紧凑，不参与密度压缩） */
const DIM_NOTE = {
  fontSize: 10,
  color: 'var(--fw-text-3)',
  lineHeight: 1.45,
  padding: '1px 0',
} as const

/** 错误 / 提示条的方框样式：fw-banner 只带下边框，这里补成完整一圈（页面内独立出现） */
const BANNER_BOX = {
  border: '1px solid var(--fw-border)',
  borderRadius: 'var(--fw-radius)',
  marginBottom: 'var(--fw-gap)',
} as const

/** 行尾「输入 + 标记」的组合容器：横向排列并居中对齐 */
const TAIL_FLEX = { display: 'flex', alignItems: 'center', gap: 4 } as const

/**
 * 双列网格：协议阈值与容量上限用。
 * 固定 2 列（640px 宽时每列 ~310px，360px 窄屏时 ~173px），
 * 单元格 overflow hidden 兜底，避免极窄屏下把面板撑出横向滚动。
 */
const GRID_2 = {
  display: 'grid',
  gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
  gap: 1, // 1px 缝露出网格底色（--fw-border）充当分隔线，与 .fw-tiles 同一手法
  background: 'var(--fw-border)',
} as const

/** 网格单元格：贴边、无内边距（分隔线由网格缝提供），行高抬到触摸目标下限 */
const GRID_CELL = {
  background: 'var(--fw-surface)',
  overflow: 'hidden',
  minHeight: 44,
  borderBottom: 'none',
} as const

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

/**
 * 布尔键的中文名与说明。
 * 说明依据内核模块参数与 firewall.h 的字段语义；标签下方一行 dim 小字，
 * 不再占用独立的大卡片（控制台式密度）。
 */
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
    hint: '内核参数 fw_dynamic_threshold；实际阈值 = max(静态阈值, EWMA 基线 × 倍数)，需要样本积累',
  },
]

/** 数值字段元信息（分组与网格共用） */
interface NumericFieldMeta {
  key: NumericKey
  label: string
  hint: string
}

/** 协议专项阈值：下发内核，任一为 0 会被后端拒绝 */
const PROTOCOL_FIELDS: readonly NumericFieldMeta[] = [
  { key: 'max_syn_per_second', label: 'SYN', hint: '每秒上限，不能为 0' },
  { key: 'max_udp_per_second', label: 'UDP', hint: '每秒上限，不能为 0' },
  { key: 'max_icmp_per_second', label: 'ICMP', hint: '每秒上限，不能为 0' },
  { key: 'max_ack_per_second', label: 'ACK', hint: '每秒上限，不能为 0' },
  { key: 'max_rst_per_second', label: 'RST', hint: '每秒上限，不能为 0' },
  { key: 'max_fin_per_second', label: 'FIN', hint: '每秒上限，不能为 0' },
]

/**
 * 容量上限：决定各表能容纳的条目数，不能为 0。
 * label 是网格内的短名（完整名见 NUMERIC_LABELS，用于校验错误文案）。
 */
const CAPACITY_FIELDS: readonly NumericFieldMeta[] = [
  { key: 'max_ban_entries', label: '封禁表', hint: '条目数，不能为 0' },
  { key: 'max_whitelist_entries', label: '白名单', hint: '条目数，不能为 0' },
  { key: 'max_rate_entries', label: '速率表', hint: '条目数，不能为 0' },
  { key: 'max_local_ip_cache', label: 'IP 缓存', hint: '条目数，不能为 0' },
]

/** 把任意抛出物转成可展示文案（client 抛出的 ApiError 就是 Error 子类） */
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

/** 输入框可点区域 ≥44px，输入框本体 28px：密度与触摸目标分离 */
const INPUT_BOX = {
  flex: '0 1 84px',
  width: 84,
  minWidth: 0,
  height: 28,
  padding: '0 5px',
  textAlign: 'right',
  fontFamily: 'var(--fw-font-mono)',
  fontVariantNumeric: 'tabular-nums',
  fontSize: 16, // 小于 16px 会让 iOS Safari 聚焦时放大整页
  color: 'var(--fw-text)',
  background: 'var(--fw-bg)',
  borderRadius: 'var(--fw-radius-sm)',
  outline: 'none',
} as const

/**
 * 数值输入行尾：标签 + 方框输入 + 单位。
 *
 * 为什么用 <label> 包住输入：输入框本体只有 28px 高（控制台密度），
 * 但可点 / 可聚焦区域由 label 撑到 44px，满足 --fw-tap 下限；
 * 同时 label 的空白区域点击即聚焦输入框（浏览器原生行为），不需要 JS。
 */
function NumInput(props: {
  label: string
  value: string
  unit?: string
  onChange: (value: string) => void
  /** 当前值明显非法（空 / 0 / 越界）时标红，作为保存前的第一眼提示 */
  invalid?: boolean
}) {
  const { label, value, unit, onChange, invalid } = props
  const [focused, setFocused] = useState(false)
  return (
    <label
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'flex-end',
        gap: 4,
        minHeight: 44,
        minWidth: 0,
      }}
    >
      <input
        aria-label={label}
        inputMode="numeric"
        autoComplete="off"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        style={{
          ...INPUT_BOX,
          border: `1px solid ${
            focused
              ? 'var(--fw-primary-strong)'
              : invalid
                ? 'var(--fw-danger)'
                : 'var(--fw-border-strong)'
          }`,
        }}
      />
      {unit !== undefined ? (
        <span className="fw-row-unit" style={{ width: 26 }}>
          {unit}
        </span>
      ) : null}
    </label>
  )
}

/**
 * 阈值对的关系标：把「警告 < 严重」这条约束直接标在数值旁。
 * - 满足：dim 的 green「< 严重」（默认预期，不抢视线）
 * - 违规：danger「≥ 严重」（保存会被后端拒绝，先在此处预警）
 * - 任一侧未填/非法：中性「待填写」（此时比较无意义，不能显示成违规）
 */
function PairBadge(props: { ok: boolean; valid: boolean }) {
  if (!props.valid) return <Badge dim>待填写</Badge>
  return (
    <Badge tone={props.ok ? 'success' : 'danger'} dim={props.ok}>
      {props.ok ? '< 严重' : '≥ 严重'}
    </Badge>
  )
}

/**
 * 保存 / 撤销操作条：全页仅此一份，置于内容末尾——读完最后一屏即就地保存。
 * 顶部不再重复一份操作条：待保存与否已由工具条的常驻状态标表达，同一组按钮
 * 在一页里出现两次只会让人怀疑哪一份才是生效的那个。
 */
function ActionBar(props: {
  dirty: boolean
  count: number
  saving: boolean
  onSave: () => void
  onReset: () => void
}) {
  const { dirty, count, saving, onSave, onReset } = props
  return (
    <div style={{ display: 'flex', gap: 5, marginBottom: 'var(--fw-gap)' }}>
      <button
        type="button"
        className="fw-cmd"
        style={{
          flex: 2,
          color: dirty ? 'var(--fw-primary-strong)' : 'var(--fw-text-3)',
          borderColor: dirty ? 'var(--fw-primary-strong)' : 'var(--fw-border-strong)',
        }}
        disabled={!dirty || saving}
        onClick={onSave}
      >
        {/* 按钮只讲动作、不讲状态：待保存与否由上方工具条的常驻状态标表达，
            两处都写「无待保存修改」会让同一句话在一屏里出现两次 */}
        {saving ? '保存中…' : dirty ? `保存修改（${count}）` : '保存修改'}
      </button>
      <button
        type="button"
        className="fw-cmd"
        style={{ flex: 1 }}
        disabled={!dirty || saving}
        onClick={onReset}
      >
        撤销
      </button>
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

  /** 与后端现值的差异：待提交请求体 + 改动项数（dirty ⇔ changedCount > 0） */
  const diff = useMemo<DraftDiff>(() => {
    if (numbers === null || flags === null || baseline === null) {
      return { payload: {}, changedCount: 0 }
    }
    return buildPayload(numbers, flags, clearLogs, baseline)
  }, [numbers, flags, clearLogs, baseline])
  const dirty = diff.changedCount > 0

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

  // 行内合法性标记（只做展示预警，真值仍以保存时的 validateDraft 为准）
  /** 空值或非纯数字：保存必被拒绝，输入框先标红 */
  const badNumber = (key: NumericKey): boolean => {
    if (numbers === null) return false
    return !/^\d+$/.test(numbers[key].trim())
  }
  /** 非 0 约束字段的预警：空值或字面 0 都标红（两者保存时都会被拒绝） */
  const zeroBad = (key: NumericKey): boolean => badNumber(key) || numbers?.[key].trim() === '0'
  const num = (key: NumericKey): number => (numbers === null ? NaN : Number(numbers[key]))
  const sseValue = numbers?.sse_push_interval.trim() ?? ''
  const sseOk = /^\d+$/.test(sseValue) && Number(sseValue) >= 1 && Number(sseValue) <= 60
  const ppsValid = !badNumber('rate_warning_pps') && !badNumber('rate_critical_pps')
  const synValid = !badNumber('rate_warning_syn') && !badNumber('rate_critical_syn')
  const ppsPairOk = num('rate_warning_pps') < num('rate_critical_pps')
  const synPairOk = num('rate_warning_syn') < num('rate_critical_syn')

  return (
    <>
      {/* 二级页头部：统一工具条——左端返回更多 + 待保存状态 + 重新读取。
          刷新走下拉手势；「读取」是丢弃草稿重新拉配置，语义不同于刷新，故保留 */}
      <Toolbar>
        <BackLink onClick={() => navigate('/more')} />

        <span style={{ flex: 1, minWidth: 0, display: 'flex', justifyContent: 'flex-end' }}>
          {/* 「无待保存修改」是既有的核心状态提示，这里升级为常驻状态标 */}
          <Badge tone={dirty ? 'warning' : 'success'} dim={!dirty}>
            {dirty ? `${diff.changedCount} 项待保存` : '无待保存修改'}
          </Badge>
        </span>

        <button
          type="button"
          className="fw-cmd"
          aria-label="重新读取后端配置"
          disabled={config.loading}
          onClick={() => void config.reload()}
        >
          <LoopOutline /> 读取
        </button>
      </Toolbar>

      {/* 区块标题（h2）：e2e 以 level-2 标题精确匹配本页，文案不可改 */}
      <PageHeader
        title="Web UI 配置"
        srOnly
        subtitle="保存即写入守护进程运行时配置并持久化；协议阈值与 DDoS 开关同时下发内核"
      />

      <PullToRefresh
        onRefresh={async () => {
          await config.reload()
        }}
      >
        <div className="fw-page">
          {/* 读取失败：错误对用户可见并提供重试 */}
          {config.error !== null && (
            <div className="fw-banner fw-banner-danger" style={BANNER_BOX} role="alert">
              <span className="fw-banner-icon">!</span>
              <span style={{ flex: 1, minWidth: 0 }}>配置读取失败：{config.error}</span>
              <a
                onClick={() => void config.reload()}
                role="button"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  minHeight: 44,
                  color: 'inherit',
                  textDecoration: 'underline',
                  cursor: 'pointer',
                }}
              >
                重试
              </a>
            </div>
          )}

          {/* 首屏骨架：配置未就绪时不渲染可编辑控件，避免用户对着空表单修改 */}
          {!ready && config.error === null && (
            <Panel title="配置读取中" meta="LOADING">
              <Skeleton.Title animated />
              <Skeleton.Paragraph lineCount={8} animated />
            </Panel>
          )}

          {ready && numbers !== null && flags !== null && (
            <>
              {dirty && (
                <div
                  style={{
                    fontSize: 10,
                    color: 'var(--fw-warning)',
                    lineHeight: 1.45,
                    marginBottom: 'var(--fw-gap)',
                  }}
                >
                  待保存的值会立即影响内核判定：协议阈值与 DDoS 开关保存后同步到内核（同步失败不影响配置保存）。
                </div>
              )}

              {/* 实时推送 */}
              <Panel title="实时推送" meta="1-60 s">
                <Rows>
                  <Row
                    label="SSE 推送间隔"
                    tail={
                      <span style={TAIL_FLEX}>
                        <NumInput
                          label="SSE 推送间隔"
                          value={numbers.sse_push_interval}
                          unit="s"
                          invalid={!sseOk}
                          onChange={(value) => updateNumber('sse_push_interval', value)}
                        />
                        <Badge tone={sseOk ? 'success' : 'danger'} dim={sseOk}>
                          {sseOk ? '1-60' : '越界'}
                        </Badge>
                      </span>
                    }
                  />
                </Rows>
                <div style={DIM_NOTE}>
                  控制台统计数据经 SSE 按此周期推送（计数器镜像间隔）；越短越实时，也越耗电。
                </div>
              </Panel>

              {/* 速率告警阈值：两对「警告 < 严重」，关系标直接跟在数值后 */}
              <Panel title="速率告警阈值" meta={<Badge dim>警告 &lt; 严重</Badge>}>
                <SubHead>总速率 · pps</SubHead>
                <Rows>
                  <Row
                    label="警告"
                    tail={
                      <span style={TAIL_FLEX}>
                        <NumInput
                          label="速率警告阈值"
                          value={numbers.rate_warning_pps}
                          unit="pps"
                          invalid={badNumber('rate_warning_pps')}
                          onChange={(value) => updateNumber('rate_warning_pps', value)}
                        />
                        <PairBadge ok={ppsPairOk} valid={ppsValid} />
                      </span>
                    }
                  />
                  <Row
                    label="严重"
                    tail={
                      <NumInput
                        label="速率严重阈值"
                        value={numbers.rate_critical_pps}
                        unit="pps"
                        invalid={badNumber('rate_critical_pps')}
                        onChange={(value) => updateNumber('rate_critical_pps', value)}
                      />
                    }
                  />
                </Rows>

                <SubHead>SYN 专项 · pps</SubHead>
                <Rows>
                  <Row
                    label="警告"
                    tail={
                      <span style={TAIL_FLEX}>
                        <NumInput
                          label="SYN 警告阈值"
                          value={numbers.rate_warning_syn}
                          unit="pps"
                          invalid={badNumber('rate_warning_syn')}
                          onChange={(value) => updateNumber('rate_warning_syn', value)}
                        />
                        <PairBadge ok={synPairOk} valid={synValid} />
                      </span>
                    }
                  />
                  <Row
                    label="严重"
                    tail={
                      <NumInput
                        label="SYN 严重阈值"
                        value={numbers.rate_critical_syn}
                        unit="pps"
                        invalid={badNumber('rate_critical_syn')}
                        onChange={(value) => updateNumber('rate_critical_syn', value)}
                      />
                    }
                  />
                </Rows>
              </Panel>

              {/* 协议专项阈值：2 列网格，一屏内看全 6 个协议 */}
              <Panel title="协议专项阈值" meta={<Badge dim>全部 &gt; 0</Badge>} padded={false}>
                <div style={GRID_2}>
                  {PROTOCOL_FIELDS.map((field) => (
                    <div key={field.key} className="fw-row" style={GRID_CELL}>
                      <span className="fw-row-label" style={{ width: 'auto', flexShrink: 0 }}>
                        {field.label}
                      </span>
                      <NumInput
                        label={field.label}
                        value={numbers[field.key]}
                        unit="pps"
                        invalid={zeroBad(field.key)}
                        onChange={(value) => updateNumber(field.key, value)}
                      />
                    </div>
                  ))}
                </div>
                <div style={{ ...DIM_NOTE, padding: '2px 6px' }}>
                  保存后经 netlink 下发内核，作为每 IP 的协议速率判定阈值；任一为 0 会被拒绝。
                </div>
              </Panel>

              {/* DDoS 检测算法开关：标签 + 一行 dim 说明 + 44px 开关行 */}
              <Panel
                title="DDoS 检测算法"
                meta={
                  <Badge tone={flags.ddos_detection ? 'success' : 'danger'} dim>
                    {flags.ddos_detection ? '总开关 ON' : '总开关 OFF'}
                  </Badge>
                }
              >
                <Rows>
                  {BOOL_FIELDS.map((field) => (
                    <div
                      key={field.key}
                      className="fw-row"
                      style={{ minHeight: 44, alignItems: 'center' }}
                    >
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12, color: 'var(--fw-text)' }}>{field.label}</div>
                        <div style={{ fontSize: 10, color: 'var(--fw-text-3)', lineHeight: 1.35 }}>
                          {field.hint}
                        </div>
                      </div>
                      {/* 开关外面套 44px 高的容器：antd-mobile 默认尺寸小于触摸目标下限 */}
                      <div className="fw-tap" style={{ flexShrink: 0 }}>
                        <Switch
                          checked={flags[field.key]}
                          style={{ '--width': '42px', '--height': '26px' }}
                          onChange={(checked) => updateFlag(field.key, checked)}
                        />
                      </div>
                    </div>
                  ))}
                </Rows>
              </Panel>

              {/* 容量上限：2 列网格 */}
              <Panel title="容量上限" meta={<Badge dim>全部 &gt; 0</Badge>} padded={false}>
                <div style={GRID_2}>
                  {CAPACITY_FIELDS.map((field) => (
                    <div key={field.key} className="fw-row" style={GRID_CELL}>
                      <span className="fw-row-label" style={{ width: 'auto', flexShrink: 0 }}>
                        {field.label}
                      </span>
                      <NumInput
                        label={field.label}
                        value={numbers[field.key]}
                        unit="条"
                        invalid={zeroBad(field.key)}
                        onChange={(value) => updateNumber(field.key, value)}
                      />
                    </div>
                  ))}
                </div>
                <div style={{ ...DIM_NOTE, padding: '2px 6px' }}>
                  各表能容纳的最大条目数，取值为不能为 0 的整数。
                </div>
              </Panel>

              {/* 日志视图时间过滤：本页只写入起点，不直接删除日志文件 */}
              <Panel title="日志视图过滤" meta={clearLogs === '' ? '未设置' : '已设置'}>
                <Rows>
                  <Row label="过滤起点" value={isoToLocalText(clearLogs)} wide />
                </Rows>
                <div style={{ display: 'flex', gap: 5, marginTop: 5 }}>
                  <button
                    type="button"
                    className="fw-cmd"
                    style={{ flex: 1 }}
                    onClick={() => setClearLogs(nowTimestamp())}
                  >
                    设为当前时间
                  </button>
                  <button
                    type="button"
                    className="fw-cmd"
                    style={{ flex: 1 }}
                    disabled={clearLogs === ''}
                    onClick={() => setClearLogs('')}
                  >
                    取消过滤
                  </button>
                </div>
                <div style={DIM_NOTE}>
                  只影响日志页的展示范围，不删除磁盘上的日志文件；保存后写入 clear_logs_at 并持久化。
                </div>
              </Panel>

              {/* 生效方式说明：让用户知道「保存」之后发生了什么 */}
              <Panel title="保存后的行为" meta="PUT /api/v1/config">
                <div style={DIM_NOTE}>· 配置写入守护进程内存并持久化到运行时配置文件，重启后保留</div>
                <div style={DIM_NOTE}>· 协议阈值与 DDoS 开关会即时同步到内核；同步失败不影响配置保存</div>
                <div style={DIM_NOTE}>· 「日志视图过滤」以空字符串保存即表示取消过滤</div>
              </Panel>

              <ActionBar
                dirty={dirty}
                count={diff.changedCount}
                saving={saving}
                onSave={() => void save()}
                onReset={resetDraft}
              />
            </>
          )}
        </div>
      </PullToRefresh>
    </>
  )
}
