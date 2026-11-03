/**
 * HTTP 客户端内核 —— fetch + 信封解包 + 错误分类。
 *
 * 全站所有 REST 调用都经这里，于是「成功长什么样、失败分几类」只有一处定义：
 *   * 成功 = HTTP 2xx **且** 信封 `code === 0`，此时把 `data` 交回调用方；
 *   * 401 = 守护进程回**纯文本**（不经信封），单独归 `unauthorized`，并广播给订阅者
 *     （AuthProvider 据此自动登出 + 跳登录），不让每个调用点各写一遍 401 处理；
 *   * 业务失败（`code !== 0`）归 `business`，带上服务端的 message 与业务码；
 *   * 网络断开归 `network`、超时归 `timeout`、响应体不是合法 JSON 归 `parse`、
 *     其余非 2xx 归 `http`。
 *
 * 特例：`/api/v2/health` **不经信封**（裸 RuntimeSnapshot，200=就绪 / 503=未就绪，
 * 见 defect HTTP_HEALTH_NOT_ENVELOPED），走 `apiFetchRaw` 直接取 JSON。
 *
 * 本文件不出现任何 `/api/v…` 字面量：`path` 一律由 endpoints.ts 从 ROUTES 解出后传入，
 * 客户端只认「一个已经拼好的路径」，与具体路由解耦。
 */

import { authorizationHeader } from './auth'
import type { ApiResponse } from './types'

/** 失败的种类；视图据此选择文案与重试策略。 */
export type ApiErrorKind =
  | 'network' // fetch 被拒（断网、DNS、CORS）
  | 'timeout' // 超过 timeoutMs 主动中断
  | 'unauthorized' // HTTP 401，凭据缺失/错误/锁定
  | 'business' // 信封 code !== 0
  | 'http' // 其余非 2xx
  | 'parse' // 响应体不是合法 JSON
  | 'aborted' // 调用方主动取消（组件卸载等），通常应被忽略

/** 归一化的 API 错误。`message` 优先取服务端信封里的可读文案。 */
export class ApiError extends Error {
  readonly kind: ApiErrorKind
  /** HTTP 状态码；无响应（网络/超时）时为 0。 */
  readonly status: number
  /** 业务码；非业务错误为 0。 */
  readonly code: number

  constructor(kind: ApiErrorKind, message: string, status = 0, code = 0) {
    super(message)
    this.name = 'ApiError'
    this.kind = kind
    this.status = status
    this.code = code
  }

  get isUnauthorized(): boolean {
    return this.kind === 'unauthorized'
  }

  /** 是否值得自动重试（网络/超时/5xx）；业务码与 401 重试无意义。 */
  get isRetryable(): boolean {
    return this.kind === 'network' || this.kind === 'timeout' || this.status >= 500
  }
}

// --- 401 广播：AuthProvider 订阅后自动登出 -----------------------------------

type UnauthorizedListener = () => void
const unauthorizedListeners = new Set<UnauthorizedListener>()

/** 订阅「收到 401」事件；返回取消订阅函数。 */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener)
  return () => unauthorizedListeners.delete(listener)
}

function emitUnauthorized(): void {
  for (const listener of unauthorizedListeners) listener()
}

// --- 请求选项 ----------------------------------------------------------------

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'

/** 查询参数值：null/undefined 会被跳过（不写进 URL）。 */
export type QueryValue = string | number | boolean | null | undefined

export interface ApiRequestOptions {
  method?: HttpMethod
  query?: Record<string, QueryValue>
  /** 请求体；对象会被 JSON 序列化并带上 Content-Type。 */
  body?: unknown
  /** 调用方的取消信号（组件卸载时中断）。 */
  signal?: AbortSignal
  /** 超时毫秒数，默认 15s。SSE 不走这里。 */
  timeoutMs?: number
}

const DEFAULT_TIMEOUT_MS = 15_000

/** 把 query 拼到 path 上；跳过 null/undefined，其余按字符串编码。 */
function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  if (!query) return path
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value === null || value === undefined) continue
    params.set(key, String(value))
  }
  const qs = params.toString()
  return qs ? `${path}?${qs}` : path
}

/** 执行 fetch，返回 Response；把网络/超时/取消归一化成 ApiError。 */
async function doFetch(url: string, opts: ApiRequestOptions): Promise<Response> {
  const method = opts.method ?? 'GET'
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const controller = new AbortController()
  let timedOut = false

  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)

  // 调用方信号与内部超时共用一个 controller：任一触发都中断
  const external = opts.signal
  if (external) {
    if (external.aborted) controller.abort()
    else external.addEventListener('abort', () => controller.abort(), { once: true })
  }

  const headers: Record<string, string> = {}
  const auth = authorizationHeader()
  if (auth) headers.Authorization = auth
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'

  try {
    return await fetch(url, {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: controller.signal,
    })
  } catch (err) {
    if (timedOut) {
      throw new ApiError('timeout', `请求超时（${timeoutMs}ms）：${url}`)
    }
    if (external?.aborted) {
      // 调用方主动取消（组件卸载 / 竞态丢弃）：原样抛出，交给调用方忽略
      throw new ApiError('aborted', '请求已取消', 0, 0)
    }
    throw new ApiError('network', '无法连接到守护进程（网络中断或服务未启动）')
  } finally {
    clearTimeout(timer)
  }
}

/**
 * 信封端点：解 `{code,data,message}`，成功回 data，失败按种类抛 ApiError。
 * 401 走纯文本分支并广播；其余非 2xx 若带合法信封则按业务码归类。
 */
export async function apiFetch<T>(path: string, opts: ApiRequestOptions = {}): Promise<T> {
  const res = await doFetch(buildUrl(path, opts.query), opts)

  if (res.status === 401) {
    emitUnauthorized()
    // 401 是纯文本（如 "Unauthorized\n"），读出来当 message，不按信封解析
    const text = (await res.text().catch(() => '')).trim()
    throw new ApiError('unauthorized', text || '未认证或凭据无效', 401)
  }

  let body: unknown
  try {
    body = await res.json()
  } catch {
    throw new ApiError(
      res.ok ? 'parse' : 'http',
      res.ok ? '响应体不是合法 JSON' : `HTTP ${res.status}`,
      res.status,
    )
  }

  const envelope = body as Partial<ApiResponse<T>> | null
  if (envelope && typeof envelope === 'object' && 'code' in envelope) {
    if (res.ok && envelope.code === 0) {
      return envelope.data as T
    }
    const message = envelope.message || `请求失败（业务码 ${envelope.code}）`
    throw new ApiError('business', message, res.status, envelope.code ?? 0)
  }

  // 不是信封形状：2xx 时按裸值交回（理论上信封端点不会走到），否则按 HTTP 归类
  if (res.ok) return body as T
  throw new ApiError('http', `HTTP ${res.status}`, res.status)
}

/**
 * 裸端点：不解信封，直接把响应体 JSON 当 T 返回（/api/v2/health 专用）。
 * 非 2xx 也尝试解析（health 在 503 时同样带 RuntimeSnapshot）；解析不了才抛。
 */
export async function apiFetchRaw<T>(path: string, opts: ApiRequestOptions = {}): Promise<T> {
  const res = await doFetch(buildUrl(path, opts.query), opts)
  try {
    return (await res.json()) as T
  } catch {
    throw new ApiError(
      res.ok ? 'parse' : 'http',
      res.ok ? '响应体不是合法 JSON' : `HTTP ${res.status}`,
      res.status,
    )
  }
}
