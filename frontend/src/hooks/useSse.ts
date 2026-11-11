/**
 * `/api/v2/events` 实时流的核心连接管理（纯 hook，无 JSX）。
 *
 * 门禁约束：`verify_http.py` 的 `check_sse_events` 要求契约声明的每个事件名
 * （connected / stats / bans / jails / whitelist / rates）都**逐字**出现在本文件里
 * （`'x'` 或 `"x"` 形式），且 Go 侧有对应发布点。所以下面用逐个 `addEventListener('名字', …)`
 * 的写法，而不是拿数组循环——字面量必须落在源码里，这条检查才成立。
 *
 * 形状约束（见 http.fwidl 对 /api/v2/events 的 note）：五个域帧的 data 与该域 REST 端点
 * **同源同形**，前端把帧 data 直接按 REST 的类型解析，不写形状分支。唯一的差异是 bans——
 * SSE 帧是**镜像全表**（BanResponse[]），REST 是分页对象；视图按帧整表替换本地状态。
 *
 * 重连策略：EventSource 自带的重连不可控（固定几秒、且不理会「已达连接上限」），这里一律
 * 自己接管——出错即 close，按 `min(2**min(n,5),30)` 秒退避重连；重连前先探一次
 * GET /api/v2/stats/sse-status，若 events.limit_reached 为真就**停手**（再连也是 503），
 * 把状态标成 'limit' 交给 UI 降级到 REST 轮询，而不是无限重试把 503 当网络故障。
 * 连续重连超过 `MAX_RECONNECT_ATTEMPTS`（100）次后进入 'exhausted' 态，停止自动重试，
 * 等用户手动点「重新连接」——避免守护进程长期缺席时无限退避。
 *
 * 重连校准：断线期间服务端不补发错过的帧，恢复连接的那一刻要主动拉一次真值，
 * 否则界面会停在断线前的旧状态，直到下一次域帧或 REST 轮询才纠正。做法是复用站内已有的
 * 「刷新当前页」广播（lib/appEvents）：各页已通过 useRefreshSignal 注册了自己的 REST refetch，
 * 重连成功时广播一次即可，不必为校准再发明一条通道。首次连接不广播——首屏各页本来就会取数，
 * 重复取只是浪费；广播只触发 REST 拉取，不碰连接本身，因此不会自我循环。
 *
 * 日志流（/api/v2/logs/stream）不在这里：它的事件名（connected/log/error）按门禁要求必须
 * 出现在 views/Logs.tsx，故那条流由日志页自己接管。
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { eventsStreamUrl, getSseStatus } from '../api/endpoints'
import { emitRefresh } from '../lib/appEvents.ts'
import { nextSeq } from '../lib/freshness'
import type {
  BanResponse,
  JailResponse,
  RateResponse,
  StatsResponse,
  WhitelistEntry,
} from '../api/types'

/** 连接生命周期状态；UI 据此显示实时灯与降级提示。 */
export type SseConnectionState =
  | 'idle' // 未启用（未登录 / 主动关闭）
  | 'connecting' // 首次握手中
  | 'open' // 已连通、正在收帧
  | 'reconnecting' // 断线退避重连中
  | 'limit' // 服务端连接数已达上限（10），停止重试
  | 'exhausted' // 重连次数耗尽，停止自动重试
  | 'closed' // 主动关闭

/** 每个域各自的数据 + 新鲜度序号（域之间独立更新，独立比较）。 */
export interface SseSnapshot {
  state: SseConnectionState
  stats: StatsResponse | null
  bans: BanResponse[] | null
  jails: JailResponse[] | null
  whitelist: WhitelistEntry[] | null
  rates: RateResponse[] | null
  seq: {
    stats: number
    bans: number
    jails: number
    whitelist: number
    rates: number
  }
  /** 最近一帧到达的时刻（Date.now()）；用于「数据新鲜度」指示。 */
  lastEventAt: number
  /** 已尝试的重连次数（成功连通后归零）。 */
  attempts: number
  /** 进入断开态的时刻（Date.now()）；用于 UI 显示「已断开 X 分钟」。0 表示未断开。 */
  disconnectedAt: number
}

export const INITIAL_SNAPSHOT: SseSnapshot = {
  state: 'idle',
  stats: null,
  bans: null,
  jails: null,
  whitelist: null,
  rates: null,
  seq: { stats: 0, bans: 0, jails: 0, whitelist: 0, rates: 0 },
  lastEventAt: 0,
  attempts: 0,
  disconnectedAt: 0,
}

/** 退避秒数：min(2**min(n,5), 30)。n=0→1s … n≥5→30s（契约规定，两条流共用同一公式）。 */
export function backoffSeconds(attempt: number): number {
  return Math.min(2 ** Math.min(attempt, 5), 30)
}

/** 最大自动重连次数；超过后进入 exhausted 态，停止退避重连，等用户手动重试。 */
export const MAX_RECONNECT_ATTEMPTS = 100

/** 帧的载荷形状：stats 是单个对象，其余四个域是整表数组（与各自的 REST 端点同形）。 */
type FrameShape = 'object' | 'array'

/**
 * 安全解析帧 data，并做**最小**形状校验；不合法返回 null（不因一条坏帧打断整条流）。
 *
 * 为什么不能只写 `JSON.parse(raw) as T`：那只是编译期断言，运行时什么都不查。后端换了形状
 * （null、标量、或把数组写成对象）时，帧会被当数据继续往下渲染，表现为整页空白而不是报错，
 * 排查时看不到任何线索。这里只挡「载荷根本不像本域数据」这一层，不写完整 schema——逐字段
 * 校验与契约重复，维护成本高于收益；DEV 下打一条 warn 便于定位，生产静默丢弃。
 */
function parseFrame<T>(raw: string, shape: FrameShape): T | null {
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    return null
  }
  const isPlainObject = typeof value === 'object' && value !== null && !Array.isArray(value)
  const valid = shape === 'array' ? Array.isArray(value) : isPlainObject
  if (!valid) {
    if (import.meta.env.DEV) {
      console.warn(`[useSse] 丢弃形状不符的帧（期望 ${shape}）：`, raw.slice(0, 200))
    }
    return null
  }
  return value as T
}

/** useEventStream 的返回：连接快照 + 一个手动重连入口。 */
export interface EventStreamResult extends SseSnapshot {
  /** 手动重连：清零退避计数并立即重探（供「已达上限」降级后用户主动重试）。 */
  reconnect: () => void
}

/**
 * 接管 `/api/v2/events` 连接。
 * @param enabled 为 true 且已登录时才连接；false 时保持 idle 并断开已有连接。
 */
export function useEventStream(enabled: boolean): EventStreamResult {
  const [snapshot, setSnapshot] = useState<SseSnapshot>(INITIAL_SNAPSHOT)
  const esRef = useRef<EventSource | null>(null)
  const timerRef = useRef<number | null>(null)
  const attemptsRef = useRef(0)
  const enabledRef = useRef(enabled)
  enabledRef.current = enabled
  // 卸载保护：异步回调（如 getSseStatus 的 .then）在组件卸载后不应再触发状态更新
  const mountedRef = useRef(true)
  // 是否成功连通过：用来区分「首次连接」与「断线重连」，只有后者才需要校准
  const openedOnceRef = useRef(false)
  // 本次重连之前确实丢过一条已建立的连接（断线期间可能有帧被错过）
  const needsResyncRef = useRef(false)

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const closeStream = useCallback(() => {
    clearTimer()
    if (esRef.current) {
      // 先摘 onerror 再 close：避免我们主动关闭时又触发一次错误重连
      esRef.current.onerror = null
      esRef.current.close()
      esRef.current = null
    }
  }, [clearTimer])

  const setState = useCallback((state: SseConnectionState) => {
    setSnapshot((prev) => (prev.state === state ? prev : { ...prev, state }))
  }, [])

  const connect = useCallback(() => {
    if (!enabledRef.current) return
    closeStream()
    setState(attemptsRef.current === 0 ? 'connecting' : 'reconnecting')

    const es = new EventSource(eventsStreamUrl())
    esRef.current = es

    es.addEventListener('connected', () => {
      attemptsRef.current = 0
      const isReconnect = needsResyncRef.current
      needsResyncRef.current = false
      openedOnceRef.current = true
      setSnapshot((prev) => ({ ...prev, state: 'open', attempts: 0, lastEventAt: Date.now(), disconnectedAt: 0 }))
      // 重连成功：立刻广播一次刷新，让各页用 REST 拉回断线期间的真值（错过的事件不会补发）
      if (isReconnect) emitRefresh()
    })

    es.addEventListener('stats', (e: MessageEvent<string>) => {
      const data = parseFrame<StatsResponse>(e.data, 'object')
      if (!data) return
      setSnapshot((prev) => ({
        ...prev,
        state: 'open',
        stats: data,
        seq: { ...prev.seq, stats: nextSeq() },
        lastEventAt: Date.now(),
      }))
    })

    es.addEventListener('bans', (e: MessageEvent<string>) => {
      const data = parseFrame<BanResponse[]>(e.data, 'array')
      if (!data) return
      setSnapshot((prev) => ({
        ...prev,
        state: 'open',
        bans: data,
        seq: { ...prev.seq, bans: nextSeq() },
        lastEventAt: Date.now(),
      }))
    })

    es.addEventListener('jails', (e: MessageEvent<string>) => {
      const data = parseFrame<JailResponse[]>(e.data, 'array')
      if (!data) return
      setSnapshot((prev) => ({
        ...prev,
        state: 'open',
        jails: data,
        seq: { ...prev.seq, jails: nextSeq() },
        lastEventAt: Date.now(),
      }))
    })

    es.addEventListener('whitelist', (e: MessageEvent<string>) => {
      const data = parseFrame<WhitelistEntry[]>(e.data, 'array')
      if (!data) return
      setSnapshot((prev) => ({
        ...prev,
        state: 'open',
        whitelist: data,
        seq: { ...prev.seq, whitelist: nextSeq() },
        lastEventAt: Date.now(),
      }))
    })

    es.addEventListener('rates', (e: MessageEvent<string>) => {
      const data = parseFrame<RateResponse[]>(e.data, 'array')
      if (!data) return
      setSnapshot((prev) => ({
        ...prev,
        state: 'open',
        rates: data,
        seq: { ...prev.seq, rates: nextSeq() },
        lastEventAt: Date.now(),
      }))
    })

    // 退避重连：用 attemptsRef 当前值算延迟（首次失败 n=0→1s），再自增。
    // 定义成 connect 内的具名函数，好让 onerror 的异步分支也能调到同一个实现。
    function scheduleReconnect() {
      if (attemptsRef.current >= MAX_RECONNECT_ATTEMPTS) {
        // 重连次数耗尽：停止自动重试，交给 UI 显示「已断开」与手动重连入口
        setSnapshot((prev) => ({
          ...prev,
          state: 'exhausted',
          disconnectedAt: prev.disconnectedAt || Date.now(),
        }))
        return
      }
      const delay = backoffSeconds(attemptsRef.current) * 1000
      attemptsRef.current += 1
      clearTimer()
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null
        connect()
      }, delay)
    }

    es.onerror = () => {
      // 首次失败或连通后又断：一律自己接管重连（不用 EventSource 自带的不可控重连）
      closeStream()
      // 只记录「丢过一条已建立的连接」：首次就连不上时没有旧状态可校准，不需要重连后补拉
      if (openedOnceRef.current) needsResyncRef.current = true
      if (!enabledRef.current) return
      setSnapshot((prev) => ({
        ...prev,
        state: 'reconnecting',
        attempts: attemptsRef.current,
        disconnectedAt: prev.disconnectedAt || Date.now(),
      }))

      // 重连前探一次上限：达上限就停手，交给 UI 降级到 REST 轮询
      void getSseStatus()
        .then((status) => {
          // 组件已卸载时不再触发状态更新或新建连接
          if (!mountedRef.current) return
          if (!enabledRef.current) return
          if (status.events.limit_reached) {
            attemptsRef.current = 0
            setSnapshot((prev) => ({ ...prev, state: 'limit' }))
            return
          }
          scheduleReconnect()
        })
        .catch(() => {
          // 探测本身失败（多半也是断网）：照常退避重连
          if (mountedRef.current && enabledRef.current) scheduleReconnect()
        })
    }
  }, [closeStream, setState, clearTimer])

  useEffect(() => {
    // StrictMode 下 effect 会 mount→unmount→mount：卸载 effect 会把标志置 false，
    // 重挂载必须复位，否则 getSseStatus 的异步回调会被永久丢弃、自动重连失效。
    mountedRef.current = true
    if (enabled) {
      attemptsRef.current = 0
      connect()
    } else {
      closeStream()
      setSnapshot((prev) => ({ ...prev, state: 'idle' }))
    }
    return closeStream
    // connect/closeStream 均为 useCallback 稳定引用；只在 enabled 翻转时重建连接
  }, [enabled, connect, closeStream])

  // 卸载保护：标记组件已卸载，防止异步回调在卸载后触发状态更新
  useEffect(() => {
    return () => {
      mountedRef.current = false
    }
  }, [])

  // 手动重连：清零退避计数、立即重探。用于「已达上限」降级后的用户主动重试——
  // 服务端名额是瞬时的（别的标签页关掉就腾出来），不该逼用户刷新整页才能恢复实时。
  const reconnect = useCallback(() => {
    if (!enabledRef.current) return
    attemptsRef.current = 0
    setSnapshot((prev) => ({ ...prev, disconnectedAt: 0 }))
    connect()
  }, [connect])

  return { ...snapshot, reconnect }
}
