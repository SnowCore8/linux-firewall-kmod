/**
 * 表单校验（纯函数）
 *
 * 与后端校验保持一致（真源：`src/daemon/web_ui/ban_ops.rs` 的
 * `create_whitelist` / `delete_whitelist` / `create_ban`）：
 * 前端先拦一道，减少无效请求与「点了提交才报错」的体验损耗；
 * 后端仍然会独立校验，前端通过不代表后端一定接受。
 *
 * 注意 `isValidIpv4` / `isValidIp` 会先 trim（面向表单输入，容忍首尾空白），
 * 而 CIDR 校验对 `/` 两侧分别做**严格**校验（不去空白），与后端 `split_once('/')`
 * 后的行为对齐 —— 形如 `"10.0.0.0 /8"` 必须判为非法。
 */

/** 单段十六进制组（IPv6 用）：1-4 位 */
const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/

/** 严格 IPv4（不去空白）：4 段十进制、0-255、禁止前导 0（与 Rust `Ipv4Addr` 解析一致） */
function isIpv4Strict(ip: string): boolean {
  if (ip === '') return false
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false
    // 前导 0（"01"）在 Rust 中解析失败，这里同样拒绝，避免前后端判定不一致
    if (part.length > 1 && part.startsWith('0')) return false
    const value = Number(part)
    return value <= 255
  })
}

/**
 * 严格 IPv6（不去空白）：
 * - 支持完整 8 组写法与 `::` 压缩写法（`::`、`::1`、`2001:db8::1`）
 * - 支持尾部 IPv4 写法（`::ffff:192.168.1.1`），折算为 2 个 16 位组
 * - 拒绝多个 `::`、超过 8 组、空组、非法字符、zone id（`%eth0`）
 */
function isIpv6Strict(ip: string): boolean {
  if (ip === '') return false
  // 后端 `IpAddr::from_str` 不接受 zone id，这里同样拒绝
  if (ip.includes('%')) return false
  if (!/^[0-9a-fA-F:.]+$/.test(ip)) return false

  let body = ip
  // 尾部 IPv4 折算成 2 组
  let tailGroups = 0
  if (body.includes('.')) {
    const lastColon = body.lastIndexOf(':')
    // IPv4 必须出现在最末尾且前面有冒号，否则不是合法 IPv6
    if (lastColon < 0) return false
    if (!isIpv4Strict(body.slice(lastColon + 1))) return false
    body = body.slice(0, lastColon)
    if (body.includes('.')) return false
    tailGroups = 2
  }

  const doubleColonAt = body.indexOf('::')
  if (doubleColonAt !== -1) {
    // 只允许一个 `::`
    if (body.indexOf('::', doubleColonAt + 2) !== -1) return false
    const left = body.slice(0, doubleColonAt)
    const right = body.slice(doubleColonAt + 2)
    const leftGroups = left === '' ? [] : left.split(':')
    const rightGroups = right === '' ? [] : right.split(':')
    if (!leftGroups.every((group) => HEX_GROUP.test(group))) return false
    if (!rightGroups.every((group) => HEX_GROUP.test(group))) return false
    // `::` 本身至少压缩一组，故显式写出的组数最多 7
    return leftGroups.length + rightGroups.length + tailGroups <= 7
  }

  // 无 `::` 时必须写满 8 组，且不能有首尾冒号（否则会产生空组）
  if (body.startsWith(':') || body.endsWith(':')) return false
  const groups = body.split(':')
  if (!groups.every((group) => HEX_GROUP.test(group))) return false
  return groups.length + tailGroups === 8
}

/**
 * 校验 IPv4 地址（容忍首尾空白）。
 * 用法：封禁/白名单表单的即时校验。
 */
export function isValidIpv4(ip: string): boolean {
  return isIpv4Strict(ip.trim())
}

/**
 * 校验 IPv6 地址（容忍首尾空白）。
 * 覆盖压缩写法：`::`、`::1`、`2001:db8::1`、`::ffff:192.168.1.1`。
 */
export function isValidIpv6(ip: string): boolean {
  return isIpv6Strict(ip.trim())
}

/** 校验 IPv4 或 IPv6 地址（容忍首尾空白） */
export function isValidIp(ip: string): boolean {
  const text = ip.trim()
  return isIpv4Strict(text) || isIpv6Strict(text)
}

/**
 * 校验 CIDR：`IPv4/n`、`IPv6/n`；不带前缀时按单主机地址校验。
 * 前缀范围：IPv4 最大 32，IPv6 最大 128；拒绝负数、非数字、多个 `/`。
 */
export function isValidCidr(cidr: string): boolean {
  const text = cidr.trim()
  if (text === '') return false

  const slashAt = text.indexOf('/')
  // 无前缀 = 单主机
  if (slashAt === -1) {
    return isIpv4Strict(text) || isIpv6Strict(text)
  }
  // 只允许一个 `/`
  if (text.indexOf('/', slashAt + 1) !== -1) return false

  const addr = text.slice(0, slashAt)
  const prefixText = text.slice(slashAt + 1)
  if (!/^\d{1,3}$/.test(prefixText)) return false
  const prefix = Number(prefixText)

  if (isIpv4Strict(addr)) return prefix <= 32
  if (isIpv6Strict(addr)) return prefix <= 128
  return false
}

/**
 * 校验封禁时长输入（秒）。
 * - 空字符串 = 永久封禁，合法（与后端 `duration` 省略/为 0 的语义一致）
 * - 其余必须是 0..86400 的整数（上限 24 小时，超出请显式改为永久封禁）
 */
export function isValidDuration(duration: string): boolean {
  const text = duration.trim()
  if (text === '') return true
  if (!/^\d+$/.test(text)) return false
  const value = Number(text)
  if (!Number.isSafeInteger(value)) return false
  return value <= 86_400
}
