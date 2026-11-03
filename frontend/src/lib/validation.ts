/**
 * 表单校验（纯函数，无框架依赖）。
 *
 * 与后端校验对齐（真源：`src/daemon/internal/http/whitelist.go`、`bans.go` 的
 * AddWhitelist / RemoveWhitelist / CreateBan，以及 `detect/cidr.go` 的归一化）。前端先拦一道，
 * 减少「点了提交才报错」的往返；后端仍会独立校验，前端通过不代表后端一定接受。
 *
 * 口径细节（刻意与后端一致，避免前后端判定分叉）：
 *   * IPv4 十进制**严格**：拒绝前导 0（`01` 不是合法写法，Go 的解析同样拒绝）。
 *   * IPv6 拒绝 zone id（`%eth0`）——`netip.ParseAddr` 不接受。
 *   * CIDR 的 `/` 两侧**不去空白**：`"10.0.0.0 /8"` 必须判非法（后端按 `split('/')` 后严格解析）。
 *   * 面向表单输入的 `isValidIpv4/isValidIp` 会先 trim 整体，容忍首尾空白。
 */

/** 单段十六进制组（IPv6）：1-4 位。 */
const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/

/** 解析严格 IPv4，成功返回 4 个 0-255 的数值，失败返回 null。 */
function parseIpv4(text: string): number[] | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  const octets: number[] = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    if (part.length > 1 && part.startsWith('0')) return null // 前导 0 非法
    const value = Number(part)
    if (value > 255) return null
    octets.push(value)
  }
  return octets
}

/** 严格 IPv4（不去空白）。 */
function isIpv4Strict(text: string): boolean {
  return text !== '' && parseIpv4(text) !== null
}

interface GroupCount {
  groups: number
  ok: boolean
}

/**
 * 数一段不含 `::` 的冒号串里有多少个 16 位组。
 * 尾部允许一段内嵌 IPv4（折算 2 组），且必须是最后一段。
 */
function countGroups(segment: string): GroupCount {
  if (segment === '') return { groups: 0, ok: true }
  const parts = segment.split(':')
  let groups = 0
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (part.includes('.')) {
      if (i !== parts.length - 1) return { groups: 0, ok: false } // 内嵌 IPv4 只能在末尾
      if (parseIpv4(part) === null) return { groups: 0, ok: false }
      groups += 2
    } else {
      if (!HEX_GROUP.test(part)) return { groups: 0, ok: false }
      groups += 1
    }
  }
  return { groups, ok: true }
}

/** 严格 IPv6（不去空白）：支持 `::` 压缩与尾部内嵌 IPv4。 */
function isIpv6Strict(text: string): boolean {
  if (text === '' || text.includes('%')) return false // zone id 不接受
  if (!/^[0-9a-fA-F:.]+$/.test(text)) return false
  if ((text.match(/::/g) ?? []).length > 1) return false // 至多一个 `::`

  if (text.includes('::')) {
    const [left, right] = text.split('::')
    const l = countGroups(left)
    const r = countGroups(right)
    if (!l.ok || !r.ok) return false
    // `::` 至少压缩一组，故显式写出的组数最多 7
    return l.groups + r.groups <= 7
  }

  // 无 `::`：必须写满 8 组，且不能有首尾裸冒号（否则产生空组）
  if (text.startsWith(':') || text.endsWith(':')) return false
  const c = countGroups(text)
  return c.ok && c.groups === 8
}

/** 校验 IPv4（容忍首尾空白）。 */
export function isValidIpv4(ip: string): boolean {
  return isIpv4Strict(ip.trim())
}

/** 校验 IPv6（容忍首尾空白）。 */
export function isValidIpv6(ip: string): boolean {
  return isIpv6Strict(ip.trim())
}

/** 校验 IPv4 或 IPv6（容忍首尾空白）。 */
export function isValidIp(ip: string): boolean {
  const text = ip.trim()
  return isIpv4Strict(text) || isIpv6Strict(text)
}

/**
 * 校验 CIDR：`IPv4/n`、`IPv6/n`；不带前缀时按单主机地址校验。
 * 前缀范围 IPv4≤32、IPv6≤128；拒绝多个 `/`、非数字前缀、负数。
 */
export function isValidCidr(cidr: string): boolean {
  const text = cidr.trim()
  if (text === '') return false

  const slash = text.indexOf('/')
  if (slash === -1) return isIpv4Strict(text) || isIpv6Strict(text) // 无前缀=单主机
  if (text.indexOf('/', slash + 1) !== -1) return false // 只允许一个 `/`

  const addr = text.slice(0, slash)
  const prefixText = text.slice(slash + 1)
  if (!/^\d{1,3}$/.test(prefixText)) return false
  const prefix = Number(prefixText)

  if (isIpv4Strict(addr)) return prefix <= 32
  if (isIpv6Strict(addr)) return prefix <= 128
  return false
}

/**
 * 校验封禁时长（秒）。
 * 空串 = 永久封禁，合法（与后端 duration 缺席/0 的语义一致）；
 * 其余必须是 0..86400 的整数（上限 24 小时，更久请显式选永久）。
 */
export function isValidDuration(duration: string): boolean {
  const text = duration.trim()
  if (text === '') return true
  if (!/^\d+$/.test(text)) return false
  const value = Number(text)
  return Number.isSafeInteger(value) && value <= 86_400
}

/** 一次校验多个 IP（批量封禁输入：换行/逗号/空格分隔），返回非法项列表。 */
export function findInvalidIps(raw: string): string[] {
  const tokens = raw
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter((t) => t !== '')
  return tokens.filter((t) => !isValidIp(t))
}

/** 从多行/逗号文本里解析出候选 IP 列表（去重、去空）。 */
export function parseIpList(raw: string): string[] {
  const seen = new Set<string>()
  for (const token of raw.split(/[\s,]+/)) {
    const text = token.trim()
    if (text !== '') seen.add(text)
  }
  return [...seen]
}
