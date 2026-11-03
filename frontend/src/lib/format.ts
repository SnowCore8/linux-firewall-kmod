/**
 * 数值 / 时间格式化（纯函数，无框架依赖）。
 *
 * 视图与图表共用：把后端返回的裸数字渲染成窄列里可读的短文本。所有函数都不抛异常——
 * 输入非法（NaN / Infinity / 负时间戳）时给安全回退，避免一处脏数据打断整页列表。
 */

/** 整数部分千分位分组。 */
function groupThousands(intPart: string): string {
  return intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}

/** 普通十进制：整数加分组；非整数保留两位小数再分组。 */
function plain(value: number): string {
  const rounded = Number.isInteger(value) ? value : Number(value.toFixed(2))
  const sign = rounded < 0 ? '-' : ''
  const [intPart, fracPart] = Math.abs(rounded).toString().split('.')
  const grouped = groupThousands(intPart)
  return fracPart ? `${sign}${grouped}.${fracPart}` : `${sign}${grouped}`
}

/** 去掉小数末尾多余的 0（"1.50"→"1.5"、"2.00"→"2"）。 */
function trimZeros(text: string): string {
  return text.includes('.') ? text.replace(/0+$/, '').replace(/\.$/, '') : text
}

/** 按量级选保留位数：≥100 取整、≥10 一位、其余两位，保持总宽度稳定。 */
function scaleDigits(scaled: number): string {
  const raw = scaled >= 100 ? scaled.toFixed(0) : scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)
  return trimZeros(raw)
}

const COMPACT_UNITS: ReadonlyArray<{ limit: number; suffix: string }> = [
  { limit: 1e9, suffix: 'G' },
  { limit: 1e6, suffix: 'M' },
  { limit: 1e3, suffix: 'K' },
]

/**
 * 格式化计数类数值。
 * @param compact true=K/M/G 简写（12345→"12.3K"）；false=千分位（"12,345"）
 */
export function formatNumber(value: number, compact = false): string {
  if (!Number.isFinite(value)) return '0'
  if (!compact) return plain(value)
  const abs = Math.abs(value)
  const sign = value < 0 ? '-' : ''
  for (const unit of COMPACT_UNITS) {
    if (abs >= unit.limit) return `${sign}${scaleDigits(abs / unit.limit)}${unit.suffix}`
  }
  return plain(value)
}

/** 字节量：B/KB/MB/GB/TB（1024 进制）。 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const scaled = bytes / 1024 ** exp
  return `${exp === 0 ? scaled : scaleDigits(scaled)} ${units[exp]}`
}

/** 百分数（0-100 口径，后端已按百分数给出）：保留一位小数 + "%"。 */
export function formatPercent(value: number, digits = 1): string {
  if (!Number.isFinite(value)) return '0%'
  return `${value.toFixed(digits)}%`
}

/**
 * 运行时长：`3d 4h` / `5h 12m` / `7m`（不足 1 分钟显示 `0m`）。
 * 后端保证 uptime_seconds 非负；负数/非有限值按 0 处理。
 */
export function formatUptime(seconds: number): string {
  const total = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0
  const days = Math.floor(total / 86_400)
  const hours = Math.floor((total % 86_400) / 3_600)
  const minutes = Math.floor((total % 3_600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

function pad2(value: number): string {
  return String(value).padStart(2, '0')
}

/**
 * Unix 秒时间戳 → 本地 `YYYY-MM-DD HH:MM:SS`。
 * `<= 0`（后端用 0 表示「无记录」）或非法值返回 `"—"`。
 */
export function formatDatetime(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return '—'
  const date = new Date(unixSeconds * 1000)
  if (Number.isNaN(date.getTime())) return '—'
  const ymd = `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`
  const hms = `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`
  return `${ymd} ${hms}`
}

/** 仅时间部分 `HH:MM:SS`（图表 x 轴、日志时间戳用）。 */
export function formatClock(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return '—'
  const date = new Date(unixSeconds * 1000)
  if (Number.isNaN(date.getTime())) return '—'
  return `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`
}

/**
 * 时长（秒）：负数=永久（后端 remaining_seconds === -1）返回 `"永久"`；
 * `>=1h`→`3h 20m`；`>=1m`→`5m 30s`；其余→`12s`。
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return '0s'
  if (seconds < 0) return '永久'
  const total = Math.floor(seconds)
  const hours = Math.floor(total / 3_600)
  const minutes = Math.floor((total % 3_600) / 60)
  const secs = total % 60
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m ${secs}s`
  return `${secs}s`
}

/** 相对时间（"3 分钟前" / "2 小时后"）；用于「最近封禁」「预测下次攻击」等。 */
export function formatRelative(unixSeconds: number, now = Date.now()): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return '—'
  const diffMs = unixSeconds * 1000 - now
  const absSec = Math.abs(Math.round(diffMs / 1000))
  const suffix = diffMs >= 0 ? '后' : '前'
  if (absSec < 60) return `${absSec} 秒${suffix}`
  const minutes = Math.floor(absSec / 60)
  if (minutes < 60) return `${minutes} 分钟${suffix}`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时${suffix}`
  const days = Math.floor(hours / 24)
  return `${days} 天${suffix}`
}

const RATE_UNITS: Readonly<Record<'pps' | 'bps', ReadonlyArray<{ limit: number; suffix: string }>>> = {
  pps: [
    { limit: 1e6, suffix: 'Mpps' },
    { limit: 1e3, suffix: 'Kpps' },
  ],
  bps: [
    { limit: 1e9, suffix: 'Gbps' },
    { limit: 1e6, suffix: 'Mbps' },
    { limit: 1e3, suffix: 'Kbps' },
  ],
}

/** 速率：pps 走 Kpps/Mpps，bps 走 Kbps/Mbps/Gbps；低于 1000 回原值 + 基本单位。 */
export function formatRate(value: number, kind: 'pps' | 'bps'): string {
  const baseUnit = kind === 'pps' ? 'pps' : 'bps'
  if (!Number.isFinite(value)) return `0 ${baseUnit}`
  const abs = Math.abs(value)
  const sign = value < 0 ? '-' : ''
  for (const unit of RATE_UNITS[kind]) {
    if (abs >= unit.limit) return `${sign}${scaleDigits(abs / unit.limit)} ${unit.suffix}`
  }
  return `${sign}${Math.round(abs)} ${baseUnit}`
}

/**
 * 复制文本到剪贴板；全部失败路径**静默降级**，调用方无需 try/catch。
 * 优先异步 Clipboard API（需安全上下文：HTTPS 或 localhost）；局域网 HTTP
 * （`http://192.168.x.x:9119`）下不可用，回退临时 textarea + execCommand('copy')。
 * @returns 是否复制成功（供 UI 决定要不要提示）
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (!text) return false
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // 安全上下文不满足或被拒：落到兼容路径
    }
  }
  try {
    const area = document.createElement('textarea')
    area.value = text
    area.setAttribute('readonly', '')
    area.style.position = 'fixed'
    area.style.top = '-1000px'
    area.style.opacity = '0'
    document.body.appendChild(area)
    area.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(area)
    return ok
  } catch {
    return false
  }
}
