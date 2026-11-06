import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../api/client.ts'
import { isPageVisible } from '../lib/visibility.ts'

/**
 * 通用异步数据状态机 —— 取代 TanStack Query，作为全站 REST 读取的唯一入口。
 *
 * 一处集中三件事，免得每个视图各写一遍：
 *   * 竞态丢弃：用自增 runId + AbortController，只有「最后一次发起的」请求能写状态；
 *     旧请求即便晚到也被丢弃，组件卸载则中断在途请求（`aborted` 错误被吞掉不置错）。
 *   * 三态区分：`isLoading`（首屏、尚无数据）/ `isRefreshing`（有数据、后台再取）/
 *     `isStale`（持有旧数据但这次失败了）——骨架屏只在 isLoading 出，避免刷新时闪空。
 *   * 前台 / 后台取数分离：`isUserFetching` 只在首屏、手动刷新、翻页时为真；内部轮询与
 *     可见性补取走 `refetchSilent`，不置此位。表格遮罩绑 `isUserFetching`，于是后台轮询
 *     静默换数据、不会用 loading 遮罩（pointer-events:none）挡住用户点击。
 *   * 轮询：`refreshInterval` 到点自动重取，`pauseWhenHidden` 时页面不可见则暂停，
 *     回到前台立即补一次，省得后台标签页空跑请求。
 */

export interface AsyncState<T> {
  data: T | null
  error: ApiError | null
  /** 首屏加载中（还没有任何数据）。 */
  isLoading: boolean
  /** 有一次请求在途（含后台轮询）。 */
  isRefreshing: boolean
  /** 仅「前台取数」在途：首屏、手动刷新、翻页。后台轮询不置此位。 */
  isUserFetching: boolean
  /** 持有旧数据但最近一次刷新失败。 */
  isStale: boolean
  /** 最近一次成功写入数据的时刻（ms epoch）；0 表示从未成功。 */
  lastUpdatedAt: number
}

export interface UseAsyncOptions {
  /** 自动刷新间隔（ms）；0 或缺省 = 不轮询。 */
  refreshInterval?: number
  /** 为 false 时不发起请求（如依赖尚未就绪）。 */
  enabled?: boolean
  /** 轮询时页面不可见则暂停；默认 true。 */
  pauseWhenHidden?: boolean
  /** 首屏是否立即取；默认 true。 */
  immediate?: boolean
}

export interface UseAsyncResult<T> extends AsyncState<T> {
  /** 手动重取（工具条刷新、命令面板、失败重试共用）；视为前台取数，会置 isUserFetching。 */
  refetch: () => void
  /** 静默重取（SSE 帧驱动、内部轮询）；只更新数据，不触发前台加载态与表格遮罩。 */
  refetchSilent: () => void
  /** 就地改数据（乐观更新 / SSE 帧喂入）；不动 error 与 loading。 */
  setData: (updater: T | ((prev: T | null) => T | null)) => void
  /** 清空错误（用户在错误态里点了「知道了」）。 */
  clearError: () => void
}

function initialState<T>(): AsyncState<T> {
  return {
    data: null,
    error: null,
    isLoading: false,
    isRefreshing: false,
    isUserFetching: false,
    isStale: false,
    lastUpdatedAt: 0,
  }
}

export function useAsync<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  options: UseAsyncOptions = {},
): UseAsyncResult<T> {
  const {
    refreshInterval = 0,
    enabled = true,
    pauseWhenHidden = true,
    immediate = true,
  } = options

  const [state, setState] = useState<AsyncState<T>>(() => ({
    ...initialState<T>(),
    isLoading: enabled && immediate,
    isRefreshing: enabled && immediate,
    isUserFetching: enabled && immediate,
  }))

  // fetcher 每渲染都是新函数；存进 ref 由 run 读，避免把它列进 effect 依赖导致每次渲染重取。
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const runIdRef = useRef(0)
  const abortRef = useRef<AbortController | null>(null)
  const mountedRef = useRef(true)
  const hasDataRef = useRef(false)
  const timerRef = useRef<number | null>(null)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const scheduleNext = useCallback(() => {
    if (refreshInterval <= 0 || !enabled) return
    clearTimer()
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null
      // 页面不可见时不空跑，改为等可见性恢复时补取（见下方 visibilitychange）
      if (pauseWhenHidden && !isPageVisible()) return
      // 轮询是后台行为：静默重取，不置 isUserFetching，避免表格遮罩挡住点击
      void run({ silent: true })
    }, refreshInterval)
    // run 在下面声明；这里用函数提升引用它
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshInterval, enabled, pauseWhenHidden, clearTimer])

  const run = useCallback((opts?: { silent?: boolean }) => {
    if (!enabled) return
    const silent = opts?.silent ?? false
    const id = ++runIdRef.current
    // 中断上一次在途请求
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    const startedWithNoData = !hasDataRef.current
    if (mountedRef.current) {
      setState((prev) => ({
        ...prev,
        error: null,
        isLoading: startedWithNoData,
        isRefreshing: true,
        // 前台取数才置 isUserFetching；后台轮询（silent）保持原值不动
        isUserFetching: silent ? prev.isUserFetching : true,
      }))
    }

    void fetcherRef
      .current(controller.signal)
      .then((data) => {
        if (!mountedRef.current || id !== runIdRef.current) return
        hasDataRef.current = true
        setState({
          data,
          error: null,
          isLoading: false,
          isRefreshing: false,
          isUserFetching: false,
          isStale: false,
          lastUpdatedAt: Date.now(),
        })
      })
      .catch((err: unknown) => {
        if (!mountedRef.current || id !== runIdRef.current) return
        if (err instanceof ApiError && err.kind === 'aborted') return
        const apiErr =
          err instanceof ApiError ? err : new ApiError('network', '未知错误')
        setState((prev) => ({
          ...prev,
          error: apiErr,
          isLoading: false,
          isRefreshing: false,
          isUserFetching: false,
          isStale: hasDataRef.current,
        }))
      })
      .finally(() => {
        if (mountedRef.current && id === runIdRef.current) scheduleNext()
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, scheduleNext])

  // 启停：enabled 由 false→true 或首屏时发起
  useEffect(() => {
    if (!enabled) {
      abortRef.current?.abort()
      clearTimer()
      return
    }
    if (immediate) run()
    else scheduleNext()
    return () => {
      clearTimer()
    }
    // run/scheduleNext 依赖 enabled 与 refreshInterval；仅在启停或间隔变化时重建
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, refreshInterval, immediate])

  // 卸载时中断在途请求
  useEffect(() => {
    return () => {
      abortRef.current?.abort()
      clearTimer()
    }
  }, [clearTimer])

  // 页面回到前台：若在轮询且有暂停策略，立即补取一次
  useEffect(() => {
    if (refreshInterval <= 0 || !pauseWhenHidden || !enabled) return
    const onVisible = () => {
      // 回到前台补取属于后台校准，静默进行，不打断用户当前操作
      if (isPageVisible()) run({ silent: true })
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshInterval, pauseWhenHidden, enabled])

  const refetch = useCallback(() => {
    run()
  }, [run])

  const refetchSilent = useCallback(() => {
    run({ silent: true })
  }, [run])

  const setData = useCallback<UseAsyncResult<T>['setData']>((updater) => {
    setState((prev) => {
      const next =
        typeof updater === 'function'
          ? (updater as (p: T | null) => T | null)(prev.data)
          : (updater as T)
      hasDataRef.current = next !== null
      return { ...prev, data: next }
    })
  }, [])

  const clearError = useCallback(() => {
    setState((prev) => ({ ...prev, error: null, isStale: false }))
  }, [])

  return { ...state, refetch, refetchSilent, setData, clearError }
}
