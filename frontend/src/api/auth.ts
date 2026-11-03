/**
 * 认证凭据管理 —— 只管「令牌怎么存、怎么编码」，不碰网络。
 *
 * 约束（与守护进程的 HTTP Basic 对齐，迁移前后不变）：
 *   * 令牌 = `base64(username:password)`，存 `sessionStorage['firewall.access_token']`。
 *     用 sessionStorage 而非 localStorage：凭据只在当前标签页存活，关掉即走，缩小留存面。
 *   * fetch 侧显式注入 `Authorization: Basic <token>`（见 client.ts）；EventSource 不能设
 *     请求头，改走 `?access_token=<token>`（见 endpoints.ts 的 SSE URL 构造）。
 *   * 登录成功与否由一次真实 API 探测决定（GET /api/v2/bans，见 endpoints.probeAuth），
 *     不能用 GET / ——那条恒 303 跳 /dashboard，探不出凭据对错。
 *
 * 本文件不含任何 `/api/v…` 字面量：路径知识只住在 contract.ts / endpoints.ts。
 */

import { AUTH } from './contract'

/** sessionStorage 里存放访问令牌的键名。 */
export const ACCESS_TOKEN_KEY = 'firewall.access_token'

/**
 * 把 `user:pass` 编成 Basic 令牌。
 *
 * 先经 UTF-8 字节再 btoa：`btoa` 只接受 Latin-1，凭据里一旦出现非 ASCII 字符（理论上
 * 不该有，但不能让它抛 `InvalidCharacterError` 把登录流程打断），直接 btoa 会炸。
 */
export function encodeBasic(username: string, password: string): string {
  const raw = `${username}:${password}`
  const bytes = new TextEncoder().encode(raw)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

/** 读取当前令牌；未登录返回 null。 */
export function getAccessToken(): string | null {
  try {
    return sessionStorage.getItem(ACCESS_TOKEN_KEY)
  } catch {
    // 隐私模式下 sessionStorage 可能抛 SecurityError：按「无令牌」处理，不让整站崩
    return null
  }
}

/** 写入令牌；传 null 等价于清除。 */
export function setAccessToken(token: string | null): void {
  try {
    if (token === null) sessionStorage.removeItem(ACCESS_TOKEN_KEY)
    else sessionStorage.setItem(ACCESS_TOKEN_KEY, token)
  } catch {
    // 同上：存储不可用时静默降级（本次会话仍在内存里持有凭据由调用方决定）
  }
}

/** 清除令牌（登出 / 401 自动登出）。 */
export function clearAccessToken(): void {
  setAccessToken(null)
}

/** 是否已持有令牌。 */
export function hasAccessToken(): boolean {
  return getAccessToken() !== null
}

/** 构造 `Authorization` 头的值；无令牌返回 null（调用方据此不带头）。 */
export function authorizationHeader(): string | null {
  const token = getAccessToken()
  return token ? `${AUTH.SCHEME} ${token}` : null
}

/** EventSource 用的查询参数名（契约常量，不手写 "access_token"）。 */
export const TOKEN_QUERY_KEY = AUTH.TOKEN_QUERY

/** 触发锁定前允许的连续失败次数（契约常量，供登录页文案与倒计时用）。 */
export const AUTH_FAILURE_THRESHOLD = AUTH.FAILURE_THRESHOLD

/** 一次锁定的持续秒数（契约常量）。 */
export const AUTH_LOCKOUT_SECONDS = AUTH.LOCKOUT_SECONDS

/** 凭据缺失/错误时的 HTTP 状态码（契约常量）。 */
export const AUTH_UNAUTHORIZED_STATUS = AUTH.UNAUTHORIZED_STATUS
