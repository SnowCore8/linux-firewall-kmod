import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useAsync } from './useAsync.ts'
import { nextSeq, pickFresher } from '../lib/freshness.ts'
import type { ApiError } from '../api/client.ts'

/**
 * 实时 + 轮询的合流点 —— 一个域的数据同时有两条来路：SSE 域帧（快、可能断）和
 * REST 拉取（慢、可靠）。本 hook 用全局新鲜度序号仲裁「谁更新」，视图只消费一个值，
 * 不必关心它这次是从哪条路来的。
 *
 * 为什么两条都留着：SSE 断了（'limit' / 重连中 / 未登录）时，REST 轮询是唯一的兜底；
 * SSE 活着时，REST 轮询退化为低频校准（服务端真值），SSE 负责秒级抖动。两者按 seq 取胜，
 * 于是「慢 REST 晚到」不会把「新 SSE 帧」盖掉，界面不会来回跳。
 *
 * 用法：视图从 SseProvider 取出该域的 `sseValue` 与 `sseSeq` 传进来；REST fetcher 直接给
 * endpoints 里的函数。bans 这类「SSE 是整表、REST 是分页」形状不一致的域，不用本 hook，
 * 由页面自行处理（它需要服务端分页/排序，无法用整表镜像替代）。
 */

export interface LiveDataOptions<T> {
  /** SSE 该域最新值；无帧时为 null。 */
  sseValue: T | null
  /** SSE 该域的新鲜度序号（来自 SseSnapshot.seq）。 */
  sseSeq: number
  /** REST 拉取函数（带取消信号）。 */
  rest: (signal: AbortSignal) => Promise<T>
  /** REST 轮询间隔（ms）；SSE 活着时可放慢，断了它就是主数据源。0=只取一次。 */
  refreshInterval?: number
  /** 为 false 时完全不取（如未登录）。 */
  enabled?: boolean
}

export type LiveSource = 'sse' | 'rest' | null

export interface LiveDataResult<T> {
  value: T | null
  /** 当前值取自哪条路；用于实时/新鲜度徽标。 */
  source: LiveSource
  isLoading: boolean
  isRefreshing: boolean
  /** 仅前台取数（首屏 / 手动刷新 / 翻页）在途；后台轮询与可见性补取不置此位。 */
  isUserFetching: boolean
  isStale: boolean
  error: ApiError | null
  lastUpdatedAt: number
  refetch: () => void
}

/** 浅比较：逐 key 用 Object.is，避免 JSON.stringify 的性能开销与 0/-0、key 顺序误判。 */
function shallowEqual(a: any, b: any): boolean {
  if (Object.is(a, b)) return true
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false

  const keysA = Object.keys(a)
  const keysB = Object.keys(b)
  if (keysA.length !== keysB.length) return false

  for (const key of keysA) {
    if (!Object.prototype.hasOwnProperty.call(b, key) || !Object.is(a[key], b[key])) {
      return false
    }
  }
  return true
}

/** REST 数据与其「发起时」序号绑定的载荷，供 useAsync 原样传递。 */
interface StampedRest<T> {
  data: T
  seq: number
}

/**
 * 把一次 REST 调用的结果与**发起时刻**分配的序号绑在一起。
 *
 * 序号必须在发起时取，不能等响应落地再取：REST 在途期间 SSE 可能已推来更新的帧，
 * 落地时才取号会让慢响应用一个更大的号反过来盖掉那些帧（Jails/Whitelist 要等下一轮
 * 30 秒轮询才纠正）。每次调用都重新取号，重试/取消后重新发起的请求不会复用旧号。
 */
export function stampRestRequest<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
): (signal: AbortSignal) => Promise<StampedRest<T>> {
  return (signal) => {
    const seq = nextSeq()
    return fetcher(signal).then((data) => ({ data, seq }))
  }
}

export function useLiveData<T>(options: LiveDataOptions<T>): LiveDataResult<T> {
  const { sseValue, sseSeq, rest, refreshInterval = 0, enabled = true } = options

  // rest 通常是视图里的内联箭头函数，每次渲染都换身份；存进 ref 让包装函数保持稳定，
  // 避免 useAsync 把它当成新依赖而重建轮询。
  const restRef = useRef(rest)
  restRef.current = rest
  const fetchStamped = useCallback(
    stampRestRequest((signal: AbortSignal) => restRef.current(signal)),
    [],
  )

  const query = useAsync<StampedRest<T>>(fetchStamped, { refreshInterval, enabled })

  // 只在数据真正变化时推进 REST 的展示戳（避免 REST 轮询淹没 SSE），序号沿用发起时
  // 预分配的那个，保证「发起早于 SSE 帧」的响应不会在落地后反超该帧。
  const [restStamped, setRestStamped] = useState<StampedRest<T> | null>(null)
  const prevDataRef = useRef<T | null>(null)
  useEffect(() => {
    const stamped = query.data
    if (stamped != null) {
      // 浅比较：避免 JSON.stringify 的性能开销与 0/-0、key 顺序误判
      const changed =
        prevDataRef.current === null || !shallowEqual(prevDataRef.current, stamped.data)
      if (changed) {
        prevDataRef.current = stamped.data
        setRestStamped(stamped)
      }
    }
  }, [query.data])

  const sseStamped = useMemo(
    () => (sseValue != null ? { data: sseValue, seq: sseSeq } : null),
    [sseValue, sseSeq],
  )

  // pickFresher：a=SSE（实时源，相等时偏向它），b=REST
  const winner = pickFresher<T>(sseStamped, restStamped)

  return {
    value: winner?.data ?? null,
    source: winner == null ? null : winner === sseStamped ? 'sse' : 'rest',
    isLoading: query.isLoading && winner == null,
    isRefreshing: query.isRefreshing,
    isUserFetching: query.isUserFetching,
    isStale: query.isStale,
    error: query.error,
    lastUpdatedAt: query.lastUpdatedAt,
    refetch: query.refetch,
  }
}
