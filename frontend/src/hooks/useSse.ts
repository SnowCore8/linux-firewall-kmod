/**
 * SSE 实时数据单例 Context
 *
 * 设计要点（对应契约第 4 节）：
 * - **单例连接**：Provider 挂在应用根部，只创建一条 `EventSource`；
 *   路由切换（hash 路由）不会重建连接，避免每次切页都重新握手、错过增量推送。
 * - **浏览器原生认证**：直连 `GET /api/v1/events`，靠浏览器 Basic Auth 自动附加凭据。
 *   若改成 fetch + 自定义头，会丢掉 EventSource 的语义，故不改。
 * - **指数退避重连**：EventSource 自带的重连节奏不受控，因此收到 error 时主动 close，
 *   由本模块按 `delay = min(2^min(attempt,5), 30)` 秒调度下一次连接。
 * - **防重入**：每个连接周期一个 error 标志，onerror 只处理一次；
 *   同时用「当前连接对象 === 触发者」判断，丢弃旧连接的迟到回调。
 * - **连接上限**：重连第 2 次起先探测 `GET /api/v1/stats/sse-status`，
 *   服务端已达 `MAX_SSE_CONNECTIONS` 时置 `connection_limit` 并**停止**重连
 *   （继续重试只会持续打满服务端日志，且永远不可能成功）。
 *
 * 本文件是 `.ts` 而非 `.tsx`（契约指定的路径），因此不使用 JSX，改用 createElement。
 */

import { createContext, createElement, useContext, useEffect, useReducer } from 'react'
import type { JSX, ReactNode } from 'react'

import { withAccessToken } from '../api/auth'
import { SSE_EVENTS_URL, getSseStatus } from '../api/endpoints'
import type {
  BanResponse,
  JailResponse,
  RateResponse,
  StatsResponse,
  WhitelistEntry,
} from '../api/types'

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

/** SseProvider 通过 Context 暴露的全部实时状态 */
export interface SseState {
  status: ConnectionStatus
  stats: StatsResponse | null
  bans: BanResponse[] | null
  jails: JailResponse[] | null
  rates: RateResponse[] | null
  whitelist: WhitelistEntry[] | null
  /** 速率趋势环形缓冲，最多保留最近 300 点 */
  rateHistory: RateHistoryPoint[]
  /** 已连续失败次数（成功握手后归零），用于界面提示「第 N 次重连」 */
  reconnectAttempt: number
}

/** 速率趋势保留点数上限：约 300 × 1 秒推送间隔 = 5 分钟窗口 */
const RATE_HISTORY_LIMIT = 300

type SseAction =
  | { type: 'connecting' }
  | { type: 'connected' }
  | { type: 'failed'; attempt: number }
  | { type: 'connection_limit' }
  | { type: 'stats'; payload: StatsResponse }
  | { type: 'bans'; payload: BanResponse[] }
  | { type: 'jails'; payload: JailResponse[] }
  | { type: 'rates'; payload: RateResponse[] }
  | { type: 'whitelist'; payload: WhitelistEntry[] }

function createInitialState(): SseState {
  return {
    status: 'connecting',
    stats: null,
    bans: null,
    jails: null,
    rates: null,
    whitelist: null,
    rateHistory: [],
    reconnectAttempt: 0,
  }
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
  return {
    label: makeRateLabel(new Date()),
    pps,
    bps,
    trackedIps: payload.length,
  }
}

function sseReducer(state: SseState, action: SseAction): SseState {
  switch (action.type) {
    case 'connecting':
      return { ...state, status: 'connecting' }
    case 'connected':
      // 握手成功：清零失败计数，避免下次断开时从大的退避基数开始
      return { ...state, status: 'connected', reconnectAttempt: 0 }
    case 'failed':
      return { ...state, status: 'disconnected', reconnectAttempt: action.attempt }
    case 'connection_limit':
      return { ...state, status: 'connection_limit' }
    case 'stats':
      return { ...state, stats: action.payload }
    case 'bans':
      return { ...state, bans: action.payload }
    case 'jails':
      return { ...state, jails: action.payload }
    case 'rates': {
      const next = [...state.rateHistory, toRatePoint(action.payload)]
      // 环形缓冲：超出上限时丢弃最旧的采样点
      if (next.length > RATE_HISTORY_LIMIT) {
        next.splice(0, next.length - RATE_HISTORY_LIMIT)
      }
      return { ...state, rates: action.payload, rateHistory: next }
    }
    case 'whitelist':
      return { ...state, whitelist: action.payload }
    default:
      return state
  }
}

/**
 * 探测服务端 SSE 连接上限。
 * 探测本身失败（守护进程刚重启、瞬时网络抖动）不视为「已满」——
 * 否则一次抖动就会被误判成永久停止重连。
 *
 * 只看 `events` 一条流：本模块订阅的是 `/api/v1/events`，日志流有自己的上限
 * （5）与自己的订阅者，它满了与这里无关。
 */
async function probeConnectionLimit(): Promise<boolean> {
  try {
    const info = await getSseStatus()
    return info.events.limit_reached
  } catch (err) {
    // 记到 debug 级别：保留排查线索，又不污染面向用户的 console
    console.debug('[useSse] SSE 状态探测失败，按未达上限处理并继续退避重连', err)
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

const SseContext = createContext<SseState | null>(null)

/**
 * 实时数据 Provider：整个应用只挂一个，内部持有唯一的 EventSource。
 * 必须在路由之外（应用根部）使用，否则路由切换会重建连接。
 */
export function SseProvider(props: { children: ReactNode }): JSX.Element {
  const [state, dispatch] = useReducer(sseReducer, undefined, createInitialState)

  useEffect(() => {
    // stopped：卸载后阻止所有迟到的定时器/回调继续动作
    let stopped = false
    // source：当前生效的连接；用于丢弃旧连接的迟到事件（防重入的关键）
    let source: EventSource | null = null
    let retryTimer: number | null = null
    // 连续失败次数（成功握手后归零）
    let attempt = 0

    const detach = (): void => {
      if (source) {
        source.close()
        source = null
      }
    }

    const clearRetryTimer = (): void => {
      if (retryTimer !== null) {
        window.clearTimeout(retryTimer)
        retryTimer = null
      }
    }

    /**
     * 建立一次连接（含事件订阅与一次性 error 处理）。
     * 用函数声明而非箭头常量：与 scheduleRetry 互相引用，靠声明提升避免「先用后定义」。
     */
    function connect(): void {
      if (stopped) return
      clearRetryTimer()
      detach()
      dispatch({ type: 'connecting' })

      // 令牌走 query：EventSource 无法设置 Authorization 头（见 api/auth.ts）
      const es = new EventSource(withAccessToken(SSE_EVENTS_URL))
      source = es
      // 本连接周期内 error 是否已处理：避免 onerror 连续触发导致重复调度
      let errorHandled = false

      subscribe(es, 'connected', () => {
        if (stopped || source !== es) return
        attempt = 0
        errorHandled = false
        dispatch({ type: 'connected' })
      })
      subscribe(es, 'stats', (data) => {
        if (stopped || source !== es) return
        try {
          dispatch({ type: 'stats', payload: JSON.parse(data) as StatsResponse })
        } catch (err) {
          console.debug('[useSse] stats 事件解析失败，丢弃该帧', err)
        }
      })
      subscribe(es, 'bans', (data) => {
        if (stopped || source !== es) return
        try {
          dispatch({ type: 'bans', payload: JSON.parse(data) as BanResponse[] })
        } catch (err) {
          console.debug('[useSse] bans 事件解析失败，丢弃该帧', err)
        }
      })
      subscribe(es, 'jails', (data) => {
        if (stopped || source !== es) return
        try {
          dispatch({ type: 'jails', payload: JSON.parse(data) as JailResponse[] })
        } catch (err) {
          console.debug('[useSse] jails 事件解析失败，丢弃该帧', err)
        }
      })
      subscribe(es, 'rates', (data) => {
        if (stopped || source !== es) return
        try {
          dispatch({ type: 'rates', payload: JSON.parse(data) as RateResponse[] })
        } catch (err) {
          console.debug('[useSse] rates 事件解析失败，丢弃该帧', err)
        }
      })
      subscribe(es, 'whitelist', (data) => {
        if (stopped || source !== es) return
        try {
          dispatch({ type: 'whitelist', payload: JSON.parse(data) as WhitelistEntry[] })
        } catch (err) {
          console.debug('[useSse] whitelist 事件解析失败，丢弃该帧', err)
        }
      })

      // 底层连接建立时先给出乐观状态：服务端的 connected 命名事件可能滞后到达
      es.onopen = () => {
        if (stopped || source !== es) return
        attempt = 0
        dispatch({ type: 'connected' })
      }

      es.onerror = () => {
        if (stopped || source !== es || errorHandled) return
        errorHandled = true
        void scheduleRetry()
      }
    }

    /** 断开后调度重连：先判连接上限，再按指数退避等待 */
    async function scheduleRetry(): Promise<void> {
      if (stopped) return
      detach()
      attempt += 1
      dispatch({ type: 'failed', attempt })

      if (attempt >= 2 && (await probeConnectionLimit())) {
        if (stopped) return
        // 服务端连接数已满：停止重连，由界面提示用户手动重试
        dispatch({ type: 'connection_limit' })
        return
      }
      if (stopped) return

      // 指数退避：1、2、4、8、16、32 → 截断到 30 秒上限
      const delayMs = Math.min(2 ** Math.min(attempt, 5), 30) * 1000
      retryTimer = window.setTimeout(connect, delayMs)
    }

    connect()

    return () => {
      stopped = true
      clearRetryTimer()
      detach()
    }
  }, [])

  return createElement(SseContext.Provider, { value: state }, props.children)
}

/**
 * 读取实时状态。
 * @throws Error 在 `<SseProvider>` 之外调用时（说明应用根部漏挂 Provider）
 */
export function useSse(): SseState {
  const ctx = useContext(SseContext)
  if (!ctx) {
    throw new Error('useSse 必须在 <SseProvider> 内使用（请检查应用根部的 Provider 组合）')
  }
  return ctx
}
