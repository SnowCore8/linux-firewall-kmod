/**
 * HTTP 客户端：fetch 封装 + 后端信封解包 + 统一错误类型
 *
 * 契约要点（来自后端 `src/daemon/http_exporter/handler.rs` 与 `web_ui/api.rs`）：
 * - 所有 `/api/v1/*` 接口返回信封 `{ code, data, message }`
 * - **HTTP 2xx 且 `code === 0`** 才算业务成功；`code !== 0` 时 `message` 为失败原因
 * - 失败一律抛出 `ApiError`，让调用方（视图 / useAsync）无需再判断返回码
 * - 认证由本客户端**显式携带** `Authorization: Basic <令牌>`（令牌来自 api/auth.ts）。
 *   不能依赖浏览器原生认证弹窗：SPA 外壳是公开路由，顶层文档不返回 401，
 *   弹窗永远不会出现，页面自身的 API 请求会全部 401 并触发服务端暴力破解锁定。
 *
 * 影响范围：所有 REST 取数（useAsync / views）。SSE 长连接不走本文件（见 hooks/useSse.ts）。
 */

import { authHeaders, clearAccessToken } from './auth'
import type { ApiResponse } from './types'

/**
 * 请求超时（毫秒）。
 * 后端部分统计端点会扫描 SQLite 历史表（如攻击预测、阈值建议），故留出较宽裕的时间；
 * 超时后抛出可读错误，避免界面永久停在 loading。
 */
const REQUEST_TIMEOUT_MS = 30_000

/**
 * 统一的接口错误。
 * `status` 为 HTTP 状态码；网络层失败（DNS/连接被拒/超时）时为 `0`，
 * 便于调用方区分「服务端明确拒绝」与「根本连不上」。
 */
export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    // 名称固定，便于日志与错误边界识别
    this.name = 'ApiError'
    this.status = status
  }
}

/** 判断响应体是否是后端信封结构（防御网关/代理返回的意外 JSON） */
function isApiEnvelope(payload: unknown): payload is ApiResponse<unknown> {
  if (typeof payload !== 'object' || payload === null) return false
  const candidate = payload as Record<string, unknown>
  return (
    typeof candidate.code === 'number' &&
    typeof candidate.message === 'string' &&
    'data' in candidate
  )
}

/**
 * 发起请求并解包信封。
 *
 * @param url 目标地址（同源相对路径即可）
 * @param init 请求初始化参数
 * @returns 信封中的 `data`
 * @throws ApiError 网络失败（status=0）、非 2xx、`code !== 0`、或响应体不是信封
 */
async function request<T>(url: string, init: RequestInit): Promise<T> {
  // 超时用 AbortController 实现：避免慢查询把界面挂在 loading 状态
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)

  // 显式附加 Basic 凭据（见 api/auth.ts）；用 Headers 合并，兼容 init.headers 的各种形态
  const headers = new Headers(init.headers)
  for (const [key, value] of Object.entries(authHeaders())) {
    headers.set(key, value)
  }

  let response: Response
  try {
    response = await fetch(url, {
      ...init,
      headers,
      // 同源请求带上已缓存的凭据（与显式 Authorization 头冗余，但覆盖代理场景）
      credentials: 'same-origin',
      signal: controller.signal,
    })
  } catch (err) {
    // fetch 只在网络层失败时 reject（连接被拒、DNS、CSP 拦截、abort）
    const aborted = err instanceof DOMException && err.name === 'AbortError'
    const message = aborted
      ? `请求超时（${Math.round(REQUEST_TIMEOUT_MS / 1000)} 秒）：${url}`
      : `网络请求失败：${err instanceof Error ? err.message : String(err)}`
    throw new ApiError(message, 0)
  } finally {
    window.clearTimeout(timer)
  }

  // 先把响应读成文本：非 JSON（如反向代理的 HTML 错误页）时能给出可读回退
  const text = await response.text()

  // 401 = 令牌缺失 / 失效：清除本地令牌，界面据此回到登录页。
  // 注意服务端锁定（连续失败 10 次后半分钟）期间正确凭据也返回 401，
  // 因此这里只清令牌不做自动重登，由用户重新输入触发一次新凭据。
  if (response.status === 401) {
    clearAccessToken()
  }

  if (text === '') {
    // 2xx 空响应体（理论上本后端不产生）：返回 null，由调用方按可空处理
    if (response.ok) return null as T
    throw new ApiError(`HTTP ${response.status}`, response.status)
  }

  let payload: unknown
  try {
    payload = JSON.parse(text)
  } catch {
    // 非 JSON 响应：回退为 HTTP 状态描述
    throw new ApiError(`HTTP ${response.status}`, response.status)
  }

  if (!isApiEnvelope(payload)) {
    // 是 JSON 但不是信封（拿错端点、被代理改写）——按协议违反处理
    throw new ApiError(`HTTP ${response.status}：响应体不符合接口信封格式`, response.status)
  }

  if (!response.ok) {
    // 后端在 4xx/5xx 上同样返回信封，错误原因以 message 为准
    throw new ApiError(payload.message || `HTTP ${response.status}`, response.status)
  }

  if (payload.code !== 0) {
    // HTTP 200 但业务失败（如「速率警告阈值必须小于严重阈值」）
    throw new ApiError(payload.message || `接口返回错误码 ${payload.code}`, response.status)
  }

  return payload.data as T
}

/**
 * GET 请求并返回信封中的 `data`。
 * @throws ApiError 失败时
 */
export function getJson<T>(url: string): Promise<T> {
  return request<T>(url, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  })
}

/**
 * 带 JSON 请求体的写操作（POST / PUT / PATCH / DELETE-with-body）。
 *
 * `body` 为 `undefined` 或 `null` 时不发送请求体 —— 后端部分端点（如批量解封）
 * 不接受 Json 提取器，发了多余的 body 只会新增解析风险。
 *
 * @throws ApiError 失败时
 */
export function sendJson<B, T>(url: string, method: string, body: B): Promise<T> {
  const hasBody = body !== undefined && body !== null
  const init: RequestInit = {
    method,
    headers: hasBody
      ? { Accept: 'application/json', 'Content-Type': 'application/json' }
      : { Accept: 'application/json' },
  }
  if (hasBody) {
    init.body = JSON.stringify(body)
  }
  return request<T>(url, init)
}

/**
 * DELETE 请求并返回信封中的 `data`。
 * 本后端的 DELETE 端点都不带请求体，因此不接收 body 参数。
 * @throws ApiError 失败时
 */
export function delJson<T>(url: string): Promise<T> {
  return request<T>(url, {
    method: 'DELETE',
    headers: { Accept: 'application/json' },
  })
}

/**
 * GET 请求并返回**未套信封**的原始 JSON。
 *
 * 仅用于 `/health`、`/healthz` 这类直接返回裸结构的端点（Rust `RuntimeSnapshot`）。
 * 它们在未就绪时返回 503，但响应体仍是完整 JSON —— 这里故意不按状态码抛错，
 * 让离线横幅能读到 `status: "degraded"` 的具体原因。
 *
 * @throws ApiError 网络失败、响应为空或非 JSON 时
 */
export async function getRawJson<T>(url: string): Promise<T> {
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)

  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json', ...authHeaders() },
      credentials: 'same-origin',
      signal: controller.signal,
    })
  } catch (err) {
    const aborted = err instanceof DOMException && err.name === 'AbortError'
    const message = aborted
      ? `请求超时（${Math.round(REQUEST_TIMEOUT_MS / 1000)} 秒）：${url}`
      : `网络请求失败：${err instanceof Error ? err.message : String(err)}`
    throw new ApiError(message, 0)
  } finally {
    window.clearTimeout(timer)
  }

  const text = await response.text()
  if (text === '') {
    throw new ApiError(`HTTP ${response.status}：空响应体`, response.status)
  }
  try {
    return JSON.parse(text) as T
  } catch {
    throw new ApiError(`HTTP ${response.status}`, response.status)
  }
}
