/**
 * 数值 / 时间格式化（纯函数，无框架依赖）
 *
 * 视图层与图表层共用：把后端返回的裸数字渲染成移动端窄屏下可读的短文本。
 * 所有函数都不抛异常，输入异常（NaN / Infinity / 负时间戳）时给出安全回退，
 * 避免一处脏数据把整个列表页打断。
 */

/** 千分位分组（只处理整数部分） */
function groupInteger(integerPart: string): string {
  return integerPart.replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}

/** 普通十进制：整数加千分位；非整数保留两位小数后加千分位 */
function formatPlain(value: number): string {
  const rounded = Number.isInteger(value) ? value : Number(value.toFixed(2))
  const negative = rounded < 0
  const [intPart, fracPart] = Math.abs(rounded).toString().split('.')
  const text = `${negative ? '-' : ''}${groupInteger(intPart)}`
  return fracPart ? `${text}.${fracPart}` : text
}

/** K/M/G 量级表（从大到小匹配） */
const COMPACT_UNITS: ReadonlyArray<{ limit: number; suffix: string }> = [
  { limit: 1e9, suffix: 'G' },
  { limit: 1e6, suffix: 'M' },
  { limit: 1e3, suffix: 'K' },
]

/**
 * 格式化计数类数值。
 * @param compact true = 用 K/M/G 简写（如 12345 → "12.3K"）；false = 千分位（如 "12,345"）
 */
export function formatNumber(value: number, compact: boolean): string {
  if (!Number.isFinite(value)) return '0'
  if (!compact) return formatPlain(value)

  const abs = Math.abs(value)
  const sign = value < 0 ? '-' : ''
  for (const unit of COMPACT_UNITS) {
    if (abs >= unit.limit) {
      const scaled = abs / unit.limit
      // 量级越大保留的有效小数越少，保持总宽度稳定
      const raw = scaled >= 100 ? scaled.toFixed(0) : scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)
      // 去掉多余的末尾 0（"1.50" → "1.5"），整数形态不与小数点冲突
      const trimmed = raw.includes('.') ? raw.replace(/0+$/, '').replace(/\.$/, '') : raw
      return `${sign}${trimmed}${unit.suffix}`
    }
  }
  return formatPlain(value)
}

/**
 * 格式化运行时长。
 * 形态：`3d 4h` / `5h 12m` / `7m`（不足 1 分钟显示 `0m`）。
 * 后端已保证 uptime_seconds 非负；负数或非有限值按 0 处理。
 */
export function formatUptime(seconds: number): string {
  const total = Number.isFinite(seconds) ? Math.max(0, Math.floor(seconds)) : 0
  if (total >= 86_400) {
    return `${Math.floor(total / 86_400)}d ${Math.floor((total % 86_400) / 3600)}h`
  }
  if (total >= 3_600) {
    return `${Math.floor(total / 3_600)}h ${Math.floor((total % 3_600) / 60)}m`
  }
  return `${Math.floor(total / 60)}m`
}

/** 两位补零 */
function pad2(value: number): string {
  return String(value).padStart(2, '0')
}

/**
 * 格式化 Unix 秒时间戳为本地时间 `YYYY-MM-DD HH:MM:SS`。
 * @param unixSeconds 后端时间戳；`<= 0`（后端用 0 表示「无记录」）或非法值返回 `"N/A"`
 */
export function formatDatetime(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return 'N/A'
  const date = new Date(unixSeconds * 1000)
  if (Number.isNaN(date.getTime())) return 'N/A'
  const ymd = `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`
  const hms = `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`
  return `${ymd} ${hms}`
}

/**
 * 格式化时长（秒）。
 * - 负数 = 永久封禁（后端用 `remaining_seconds === -1` 表示），返回 `"永久"`
 * - `>= 1h` → `3h 20m`；`>= 1m` → `5m 30s`；其余 → `12s`
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return '0s'
  if (seconds < 0) return '永久'
  const total = Math.floor(seconds)
  if (total >= 3_600) {
    return `${Math.floor(total / 3_600)}h ${Math.floor((total % 3_600) / 60)}m`
  }
  if (total >= 60) {
    return `${Math.floor(total / 60)}m ${total % 60}s`
  }
  return `${total}s`
}

/** 速率单位表 */
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

/**
 * 格式化速率：`bps` 走 Kbps/Mbps/Gbps，`pps` 走 Kpps/Mpps。
 * 低于 1000 时返回形如 `"512 pps"` 的原值 + 基本单位。
 */
export function formatRate(value: number, kind: 'pps' | 'bps'): string {
  const baseUnit = kind === 'pps' ? 'pps' : 'bps'
  if (!Number.isFinite(value)) return `0 ${baseUnit}`

  const abs = Math.abs(value)
  const sign = value < 0 ? '-' : ''
  for (const unit of RATE_UNITS[kind]) {
    if (abs >= unit.limit) {
      const scaled = abs / unit.limit
      const raw = scaled >= 100 ? scaled.toFixed(0) : scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)
      const trimmed = raw.includes('.') ? raw.replace(/0+$/, '').replace(/\.$/, '') : raw
      return `${sign}${trimmed} ${unit.suffix}`
    }
  }
  return `${sign}${Math.round(abs)} ${baseUnit}`
}

/**
 * 复制文本到剪贴板（复制 IP / CIDR 用）。
 *
 * 全部失败路径都**静默降级**，调用方无需 try/catch：
 * 优先用异步剪贴板 API（需安全上下文：HTTPS 或 localhost）；
 * 在局域网 HTTP（`http://192.168.x.x:9119`）下该 API 不可用，
 * 回退到临时 textarea + `execCommand('copy')` 的兼容路径。
 */
export function copyToClipboard(text: string): void {
  if (!text) return

  const fallback = (): void => {
    try {
      const area = document.createElement('textarea')
      area.value = text
      // 固定定位并移出视口，避免复制瞬间页面跳动
      area.setAttribute('readonly', '')
      area.style.position = 'fixed'
      area.style.top = '-1000px'
      area.style.opacity = '0'
      document.body.appendChild(area)
      area.select()
      document.execCommand('copy')
      document.body.removeChild(area)
    } catch (err) {
      // 复制失败不打断用户操作（用户还能手动长按选择）
      console.debug('[format] 剪贴板不可用，已忽略复制请求', err)
    }
  }

  if (navigator.clipboard?.writeText) {
    void navigator.clipboard.writeText(text).catch(() => {
      // 安全上下文不满足或用户拒绝授权：退回兼容实现
      fallback()
    })
    return
  }
  fallback()
}
