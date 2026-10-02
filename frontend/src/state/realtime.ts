/**
 * 实时通道（SSE）状态：整个应用只建立**一条** EventSource，任何视图都从这里读数据。
 *
 * 为什么必须全局唯一：每条连接都会占用服务端一个名额（上限见 `/api/v1/stats/sse-status`），
 * 且服务端按域推送整份快照，多个连接纯属浪费。因此这里用模块级单例而非「每个视图各连一个」。
 *
 * 数据新鲜度：每收到某域一帧就盖一个全局单调戳（见 [`nextFreshnessStamp`](../hooks/freshness.ts)），
 * 与 REST 回退共用同一计数器，供 `pickLiveData` 裁决谁更新。
 *
 * 重连策略：指数退避 1→2→4→8→16→32 秒，截断到 30 秒上限；连续失败 ≥2 次时先探测服务端
 * 连接是否已满——已满就停在 `connection_limit` 不再重试（由界面提示用户手动重试），
 * 因为继续重连只会不断挤占名额。
 */

import type {
  BanResponse,
  JailResponse,
  RateResponse,
  StatsResponse,
  WhitelistEntry,
} from '../api/contract'
import { withAccessToken } from '../api/auth'
import { SSE_EVENTS_URL, getSseStatus } from '../api/endpoints'
import { nextFreshnessStamp } from '../hooks/freshness'
import { signal } from '../lib/signals'

/** 连接状态：connecting（握手/重试中）、connected、disconnected（暂时断开、稍后重试）、connection_limit（服务端已满，停止重试） */
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'connection_limit'

/** 趋势图单点：由 `rates` 事件按时间聚合出的全网速率 */
export interface RateHistoryPoint {
  /** 本地时间标签 HH:MM:SS */
  label: string
  /** 所有被追踪 IP 的包速率之和 */
  pps: number
  /** 所有被追踪 IP 的字节速率之和 */
  bps: number
  /** 该时刻被追踪的 IP 数 */
  trackedIps: number
}

/** 各域载荷的新鲜度戳（域名 → 戳），未收到过为 0 */
export interface PayloadSeq {
  stats: number
  bans: number
  jails: number
  rates: number
  whitelist: number
}

/** 实时通道暴露的全部状态 */
export interface SseState {
  status: ConnectionStatus
  stats: StatsResponse | null
  bans: BanResponse[] | null
  jails: JailResponse[] | null
  rates: RateResponse[] | null
  whitelist: WhitelistEntry[] | null
  /** 各域载荷的新鲜度戳，**不参与渲染**，只用于与 REST 快照比较新旧 */
  payloadSeq: PayloadSeq
  /** 速率趋势环形缓冲，最多保留最近 300 点（约 5 分钟窗口） */
  rateHistory: RateHistoryPoint[]
  /** 已连续失败次数（成功握手后归零），用于界面提示「第 N 次重连」 */
  reconnectAttempt: number
}

/** 速率趋势保留点数上限：约 300 × 1 秒推送间隔 = 5 分钟窗口 */
const RATE_HISTORY_LIMIT = 300

/** 重连退避上限（秒） */
const MAX_BACKOFF_SECONDS = 30

/** 首帧前的状态：所有域都还没收到过 */
function createInitialState(): SseState {
  return {
    status: 'connecting',
    stats: null,
    bans: null,
    jails: null,
    rates: null,
    whitelist: null,
    payloadSeq: { stats: 0, bans: 0, jails: 0, rates: 0, whitelist: 0 },
    rateHistory: [],
    reconnectAttempt: 0,
  }
}

/** 当前实时状态（只读信号，可被 `effect` 订阅） */
export const realtime = signal<SseState>(createInitialState())

function patch(next: Partial<SseState>): void {
  realtime.update((current) => ({ ...current, ...next }))
}

/**
 * 写入某域载荷并同时盖新鲜度戳。
 *
 * 必须一次完成：先写载荷、再单独盖戳会让订阅者观察到「数据已更新但戳仍是旧值」的中间态，
 * 那一瞬的裁决会把这份新数据判成旧的（见 `pickLiveData`）。
 */
function commit(domain: keyof PayloadSeq, next: (current: SseState) => Partial<SseState>): void {
  realtime.update((current) => ({
    ...current,
    ...next(current),
    payloadSeq: { ...current.payloadSeq, [domain]: nextFreshnessStamp() },
  }))
}

/** 生成本地时间标签（HH:MM:SS），用作趋势图 X 轴 */
function makeRateLabel(date: Date): string {
  const pad = (value: number): string => String(value).padStart(2, '0')
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/** 把一帧 rates 事件聚合成趋势点（空闲时刻速率为 0 同样入图，保持时间轴连续） */
function toRatePoint(payload: RateResponse[]): RateHistoryPoint {
  let pps = 0
  let bps = 0
  for (const entry of payload) {
    pps += entry.packets_per_sec
    bps += entry.bytes_per_sec
  }
  return { label: makeRateLabel(new Date()), pps, bps, trackedIps: payload.length }
}

/**
 * 探测服务端 SSE 连接上限。探测本身失败（守护进程刚重启、瞬时抖动）不视为「已满」——
 * 否则一次抖动就会被误判成永久停止重连。
 *
 * 只看 `events` 一条流：这里订阅的是 `/api/v1/events`，日志流有自己的上限与订阅者，
 * 它满了与这里无关。
 */
async function probeConnectionLimit(): Promise<boolean> {
  try {
    const info = await getSseStatus()
    return info.events.limit_reached
  } catch (err) {
    // 记到 debug 级别：保留排查线索，又不污染面向用户的 console
    console.debug('[realtime] SSE 状态探测失败，按未达上限处理并继续退避重连', err)
    return false
  }
}

/** 订阅命名事件，只把字符串型 data 交给处理函数（非 MessageEvent / 非字符串一律忽略） */
function subscribe(es: EventSource, event: string, handler: (data: string) => void): void {
  es.addEventListener(event, (ev: Event) => {
    if (ev instanceof MessageEvent && typeof ev.data === 'string') {
      handler(ev.data)
    }
  })
}

/** 解析一帧 JSON；失败只记 debug 并丢弃该帧，不让单帧坏数据打断整条流 */
function parseFrame<T>(domain: string, data: string): T | null {
  try {
    return JSON.parse(data) as T
  } catch (err) {
    console.debug(`[realtime] ${domain} 事件解析失败，丢弃该帧`, err)
    return null
  }
}

/**
 * 启动实时连接（应用根部调用一次）。
 *
 * @returns 停止函数：断开连接并阻止所有迟到回调继续动作
 */
export function startRealtime(): () => void {
  // stopped：停止后阻止所有迟到的定时器/回调继续动作
  let stopped = false
  // source：当前生效的连接，用于丢弃旧连接的迟到事件（防重入的关键）
  let source: EventSource | null = null
  let retryTimer: number | null = null
  // 连续失败次数（成功握手后归零）
  let attempt = 0

  function detach(): void {
    if (source) {
      source.close()
      source = null
    }
  }

  function clearRetryTimer(): void {
    if (retryTimer !== null) {
      window.clearTimeout(retryTimer)
      retryTimer = null
    }
  }

  /** 建立一次连接（含事件订阅与一次性 error 处理） */
  function connect(): void {
    if (stopped) return
    clearRetryTimer()
    detach()
    patch({ status: 'connecting' })

    // 令牌走 query：EventSource 无法设置 Authorization 头（见 api/auth.ts）
    const es = new EventSource(withAccessToken(SSE_EVENTS_URL))
    source = es
    // 本连接周期内 error 是否已处理：避免 onerror 连续触发导致重复调度
    let errorHandled = false

    /** 迟到事件过滤器：停止后、或本连接已被替换时，一律丢弃 */
    const stale = (): boolean => stopped || source !== es

    subscribe(es, 'connected', () => {
      if (stale()) return
      attempt = 0
      errorHandled = false
      patch({ status: 'connected', reconnectAttempt: 0 })
    })
    subscribe(es, 'stats', (data) => {
      if (stale()) return
      const payload = parseFrame<StatsResponse>('stats', data)
      if (payload === null) return
      commit('stats', () => ({ stats: payload }))
    })
    subscribe(es, 'bans', (data) => {
      if (stale()) return
      const payload = parseFrame<BanResponse[]>('bans', data)
      if (payload === null) return
      commit('bans', () => ({ bans: payload }))
    })
    subscribe(es, 'jails', (data) => {
      if (stale()) return
      const payload = parseFrame<JailResponse[]>('jails', data)
      if (payload === null) return
      commit('jails', () => ({ jails: payload }))
    })
    subscribe(es, 'rates', (data) => {
      if (stale()) return
      const payload = parseFrame<RateResponse[]>('rates', data)
      if (payload === null) return
      commit('rates', (current) => {
        const history = [...current.rateHistory, toRatePoint(payload)]
        // 环形缓冲：超出上限时丢弃最旧的采样点
        if (history.length > RATE_HISTORY_LIMIT) {
          history.splice(0, history.length - RATE_HISTORY_LIMIT)
        }
        return { rates: payload, rateHistory: history }
      })
    })
    subscribe(es, 'whitelist', (data) => {
      if (stale()) return
      const payload = parseFrame<WhitelistEntry[]>('whitelist', data)
      if (payload === null) return
      commit('whitelist', () => ({ whitelist: payload }))
    })

    // 底层连接建立时先给出乐观状态：服务端的 connected 命名事件可能滞后到达
    es.onopen = () => {
      if (stale()) return
      attempt = 0
      patch({ status: 'connected', reconnectAttempt: 0 })
    }

    es.onerror = () => {
      if (stale() || errorHandled) return
      errorHandled = true
      void scheduleRetry()
    }
  }

  /** 断开后调度重连：先判连接上限，再按指数退避等待 */
  async function scheduleRetry(): Promise<void> {
    if (stopped) return
    detach()
    attempt += 1
    patch({ status: 'disconnected', reconnectAttempt: attempt })

    if (attempt >= 2 && (await probeConnectionLimit())) {
      if (stopped) return
      // 服务端连接数已满：停止重连，由界面提示用户手动重试
      patch({ status: 'connection_limit' })
      return
    }
    if (stopped) return

    // 指数退避：1、2、4、8、16、32 → 截断到 30 秒上限
    const delayMs = Math.min(2 ** Math.min(attempt, 5), MAX_BACKOFF_SECONDS) * 1000
    retryTimer = window.setTimeout(connect, delayMs)
  }

  connect()

  return () => {
    stopped = true
    clearRetryTimer()
    detach()
  }
}
