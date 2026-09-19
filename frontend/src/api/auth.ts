/**
 * 访问令牌：唯一凭据来源，供 REST `fetch` 与 `EventSource` 共用。
 *
 * 契约依据（`src/daemon/http_exporter/auth.rs`）：Basic Auth 中间件接受两种凭据来源——
 * `Authorization: Basic <base64(user:pass)>` 请求头，或 query `?access_token=<base64(user:pass)>`
 * （后者专为 `EventSource` 预留：浏览器不允许给 EventSource 设置自定义请求头）。
 *
 * 为什么必须显式携带，而不能依赖浏览器认证弹窗：
 * 1. SPA 外壳（`/`、`/dashboard`）是公开路由，返回的是不含数据的静态壳，
 *    因此顶层文档不会返回 401，浏览器不会弹出、也就不会缓存凭据；
 * 2. 初始加载时 cookie jar 中没有凭据，页面自身发出的 `/api/v1/**` 与
 *    `/api/v1/events` 会全部 401；
 * 3. 更糟的是，每个无凭据请求都会累加服务端的暴力破解计数
 *    （`AUTH_FAILURE_THRESHOLD=10` 后半分钟内锁定，连正确凭据也会被拒），
 *    导致「越刷新越不可用」。
 *
 * 令牌存放于 `sessionStorage`（同源隔离、关闭标签页即失效），与 HTTP Basic 的
 * 明文等价性一致：本项目的 Web UI 本就以 Basic 凭据作访问控制，此处只是把凭据
 * 从「浏览器隐式缓存」迁移到「前端显式携带」，安全性等价但行为确定、可跨移动端。
 */

/** sessionStorage 键名（带项目前缀，避免与同源其他页面冲突） */
const TOKEN_STORAGE_KEY = 'firewall.access_token'

/** 内存缓存：`initAccessToken` 之后所有请求直接复用，避免每次读 storage */
let cachedToken: string | null = null

/**
 * 认证状态变化订阅者。
 * 令牌被清除（登出，或请求收到 401）时需要让界面切回登录页，
 * 而 401 发生在 fetch 层、界面无从感知，因此由本模块广播。
 */
type AuthListener = () => void
const listeners = new Set<AuthListener>()

/** 订阅认证状态变化，返回取消订阅函数 */
export function onAuthChange(listener: AuthListener): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/** 广播认证状态变化（仅在状态确实发生翻转时由内部调用） */
function notifyAuthChange(): void {
  for (const listener of listeners) {
    listener()
  }
}

/**
 * 把明文凭据转成 Basic Auth 令牌（与 `Authorization: Basic` 的值一致）。
 * 先按 UTF-8 编码再走 base64，避免用户名/密码含非 Latin-1 字符时 `btoa` 抛错。
 */
export function encodeCredentials(user: string, pass: string): string {
  const bytes = new TextEncoder().encode(`${user}:${pass}`)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return window.btoa(binary)
}

/**
 * 读取并缓存令牌。
 *
 * 来源优先级：URL query（`?access_token=...`，便于书签直达与外部跳转）→
 * `sessionStorage`（刷新后沿用）。
 *
 * 支持两种 query 位置：`http://host/?access_token=x#/dashboard`（常规 query）
 * 与 `http://host/#/dashboard?access_token=x`（hash 内 query，hash 路由下更常见）。
 *
 * 读取后会把令牌从可见 URL 中移除（`history.replaceState`），避免它出现在
 * 截图、历史记录或分享出去的地址里；已存入 sessionStorage 不影响后续请求。
 *
 * @returns 解析到的令牌；没有则返回 `null`（调用方据此显示登录页）
 */
export function initAccessToken(): string | null {
  let token = readTokenFromUrl()
  if (token) {
    cachedToken = token
    try {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token)
    } catch (err) {
      // 隐私模式等场景下 storage 可能不可写：仅内存缓存本次会话仍可用
      console.debug('[auth] 令牌无法写入 sessionStorage，本次会话仅内存有效', err)
    }
    stripTokenFromUrl()
    return cachedToken
  }

  try {
    token = window.sessionStorage.getItem(TOKEN_STORAGE_KEY)
  } catch (err) {
    console.debug('[auth] 读取 sessionStorage 失败', err)
  }
  cachedToken = token
  return cachedToken
}

/** 主动设置令牌（登录表单提交时使用）。`notify=false` 用于「先验证再切换界面」的登录流程 */
export function setAccessToken(user: string, pass: string, notify = true): string {
  const token = encodeCredentials(user, pass)
  cachedToken = token
  try {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token)
  } catch (err) {
    console.debug('[auth] 令牌无法写入 sessionStorage，本次会话仅内存有效', err)
  }
  if (notify) notifyAuthChange()
  return token
}

/** 清除令牌（登出 / 凭据失效时调用），随后界面应回到登录页 */
export function clearAccessToken(): void {
  if (cachedToken === null) return
  cachedToken = null
  try {
    window.sessionStorage.removeItem(TOKEN_STORAGE_KEY)
  } catch {
    // 清理失败不影响内存态已置空
  }
  notifyAuthChange()
}

/** 当前令牌（可能为 `null`） */
export function getAccessToken(): string | null {
  return cachedToken
}

/** 已认证时返回 `Authorization` 头，未认证时返回空对象（便于对象展开合并） */
export function authHeaders(): Record<string, string> {
  return cachedToken ? { Authorization: `Basic ${cachedToken}` } : {}
}

/**
 * 给 URL 追加 `access_token` query（供 `EventSource` 使用）。
 * 未认证时原样返回，交由服务端 401 与界面错误提示处理。
 */
export function withAccessToken(url: string): string {
  if (!cachedToken) return url
  const separator = url.includes('?') ? '&' : '?'
  return `${url}${separator}access_token=${encodeURIComponent(cachedToken)}`
}

/** 从 URL 中解析令牌：先看常规 query，再看 hash 内的 query */
function readTokenFromUrl(): string | null {
  const fromSearch = new URLSearchParams(window.location.search).get('access_token')
  if (fromSearch) return fromSearch

  const hash = window.location.hash
  const queryStart = hash.indexOf('?')
  if (queryStart >= 0) {
    const fromHash = new URLSearchParams(hash.slice(queryStart + 1)).get('access_token')
    if (fromHash) return fromHash
  }
  return null
}

/** 从地址栏移除令牌，保留其余 query 与 hash（避免污染 hash 路由） */
function stripTokenFromUrl(): void {
  const { origin, pathname, search, hash } = window.location
  const params = new URLSearchParams(search)
  params.delete('access_token')
  const nextSearch = params.toString()

  // hash 内若也带了令牌，同样清掉，但不触碰 hash 路由路径本身
  const hashQueryStart = hash.indexOf('?')
  let nextHash = hash
  if (hashQueryStart >= 0) {
    const hashPath = hash.slice(0, hashQueryStart)
    const hashParams = new URLSearchParams(hash.slice(hashQueryStart + 1))
    hashParams.delete('access_token')
    const hashQuery = hashParams.toString()
    nextHash = hashQuery ? `${hashPath}?${hashQuery}` : hashPath
  }

  const nextUrl = `${origin}${pathname}${nextSearch ? `?${nextSearch}` : ''}${nextHash}`
  if (nextUrl !== window.location.href) {
    window.history.replaceState(window.history.state, '', nextUrl)
  }
}
