import { useEffect, useMemo, useState } from 'react'
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
  isStale: boolean
  error: ApiError | null
  lastUpdatedAt: number
  refetch: () => void
}

export function useLiveData<T>(options: LiveDataOptions<T>): LiveDataResult<T> {
  const { sseValue, sseSeq, rest, refreshInterval = 0, enabled = true } = options

  const query = useAsync<T>(rest, { refreshInterval, enabled })

  // 给每次 REST 成功落地盖一个 seq（data 引用每轮都变，effect 随之重新盖号）
  const [restStamped, setRestStamped] = useState<{ data: T; seq: number } | null>(null)
  useEffect(() => {
    if (query.data != null) setRestStamped({ data: query.data, seq: nextSeq() })
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
    isStale: query.isStale,
    error: query.error,
    lastUpdatedAt: query.lastUpdatedAt,
    refetch: query.refetch,
  }
}
