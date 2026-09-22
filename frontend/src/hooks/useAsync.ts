/**
 * 通用异步取数状态 Hook
 *
 * 视图层统一入口：把「发起请求 → loading → 成功/失败 → 手动重载 → 可选轮询」这套状态机
 * 收敛到一处，避免每个页面各写一份 useEffect + 三个 useState，并且保证：
 * - 组件卸载后不再 setState（防止 React 警告与内存泄漏）
 * - 依赖变化时前一次请求的结果不会覆盖后一次（避免竞态导致的错数据）
 * - 错误统一转成可展示的字符串，绝不吞掉
 * - 「本次不需要该数据」不覆盖已有数据（分区取数的关键，见 opts.skipWhen）
 *
 * 注意：`deps` 会被展开为 useEffect 的依赖数组，**长度必须稳定**（React 硬性要求），
 * 因此不要在调用处按条件增减依赖项。
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import { nextFreshnessStamp } from './freshness'

/** useAsync 暴露给视图的状态对象 */
export interface AsyncState<T> {
  /** 最近一次成功的数据；未加载完成或失败时为 null */
  data: T | null
  /** 是否正在请求中（重载时保留上一次数据，避免界面闪空） */
  loading: boolean
  /** 失败原因（已转成中文可读文案）；成功时为 null */
  error: string | null
  /**
   * 本份数据的新鲜度戳：每次成功写入 `data` 取一个全局单调戳（见
   * [`nextFreshnessStamp`](./freshness.ts)）。**不参与渲染取值**，只作「谁更新」的序关系，
   * 供 [`pickLiveData`](./useLiveData.ts) 与 SSE 载荷的比较使用。
   */
  dataSeq: number
  /**
   * 手动重新拉取。返回的 Promise 在**本次取数落定**（成功或失败）后才 resolve——
   * 下拉刷新的转圈指示要等数据真的到齐再收起，否则会出现「指示已收起、数据还没到」。
   */
  reload: () => Promise<void>
}

/** 把任意抛出物转成可展示的文案（ApiError 的 message 已经是后端原文） */
function toMessage(err: unknown): string {
  if (err instanceof Error && err.message) return err.message
  if (typeof err === 'string' && err) return err
  return '请求失败，请稍后重试'
}

export interface AsyncOptions<T> {
  /** 首帧占位数据，用于在 SSE 数据到达前渲染骨架 */
  initial?: T | null
  /**
   * 轮询间隔（毫秒）。设置后按此间隔自动重新取数。
   *
   * 两条自动节流规则（移动端省电，且不影响正确性）：
   * - 页面被切到后台（`document.hidden`）时暂停，回到前台立即补一次取数；
   * - 上一次取数尚未返回时跳过本次触发，避免请求堆积。
   *
   * 只用于**没有实时推送**的数据（内核侧累计统计等）。已有 SSE 推送的域不要设它——
   * 那会让 REST 快照与推流互相覆盖（两者共用新鲜度戳，后写入者胜出）。
   */
  pollMs?: number
  /**
   * 「本次不需要该数据」的哨兵值：取数函数返回它时**不覆盖已有数据**。
   *
   * 用于分区式页面：各分区的取数函数按当前激活分区决定是否真发请求，未激活时返回
   * 哨兵（通常是 `null`）。若不加区分地写入，切到别的分区会把先前分区的数据清成
   * 哨兵值，切回来就得重新等一遍——表现就是「切个 tab 就闪骨架」。
   */
  skipWhen?: T
}

/**
 * @param fn 取数函数（内部会捕获其异常）
 * @param deps 依赖数组，变化时自动重新取数（长度需稳定）
 * @param opts 见 [`AsyncOptions`]
 */
export function useAsync<T>(
  fn: () => Promise<T>,
  deps: unknown[],
  opts?: AsyncOptions<T>,
): AsyncState<T> {
  // 用 ref 持最新 fn：调用处通常传内联箭头函数，若把它放进依赖会导致无限重渲染
  const fnRef = useRef(fn)
  fnRef.current = fn

  const [data, setData] = useState<T | null>(opts?.initial ?? null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // 成功写入 data 的次数，用作「本份数据的新鲜度」序号（见 AsyncState.dataSeq）
  const [dataSeq, setDataSeq] = useState(0)
  // 自增计数作为「手动重载」的触发源，加入依赖数组即可重新执行取数
  const [reloadNonce, setReloadNonce] = useState(0)

  // 每次取数分配一个序号，只有最新序号的结果才允许写入状态（丢弃过期响应）
  const requestSeq = useRef(0)
  // 正在进行的取数是否在飞（轮询据此跳过重叠触发）
  const inFlight = useRef(false)
  // 上一次取数的落定回调（由 reload 挂上，供下拉刷新等待）
  const settleRef = useRef<(() => void) | null>(null)

  const pollMs = opts?.pollMs
  // skipWhen 用 ref 持住：调用处通常传字面量 null，放进依赖会让效果反复重跑
  const skipWhenRef = useRef(opts?.skipWhen)

  useEffect(() => {
    const seq = ++requestSeq.current
    inFlight.current = true
    setLoading(true)
    setError(null)

    /** 本次取数落定：通知等待者（先清空，避免重复调用）并把在飞标记复位 */
    const settle = (): void => {
      if (seq !== requestSeq.current) return
      inFlight.current = false
      const done = settleRef.current
      settleRef.current = null
      done?.()
    }

    fnRef
      .current()
      .then((result) => {
        // 组件已卸载或被更新的请求取代：丢弃结果
        if (seq !== requestSeq.current) return
        // 「本次不需要该数据」：保留原数据与错误，只结束加载态
        if (skipWhenRef.current !== undefined && result === skipWhenRef.current) {
          setLoading(false)
          return
        }
        setData(result)
        // 与 data 同一次提交里写入，保证「dataSeq 变了 ⇔ data 是新的那份」
        setDataSeq(nextFreshnessStamp())
        setError(null)
      })
      .catch((err: unknown) => {
        if (seq !== requestSeq.current) return
        setError(toMessage(err))
      })
      .finally(() => {
        if (seq !== requestSeq.current) return
        setLoading(false)
        settle()
      })

    // 卸载或依赖变化时让本次结果失效，避免对已卸载组件 setState
    return () => {
      if (seq === requestSeq.current) {
        requestSeq.current = seq + 1
        // 结果已被作废，等待者不能永远挂着
        const done = settleRef.current
        settleRef.current = null
        done?.()
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- deps 由调用方显式给出
  }, [...deps, reloadNonce])

  const reload = useCallback(() => {
    return new Promise<void>((resolve) => {
      settleRef.current = resolve
      setReloadNonce((n) => n + 1)
    })
  }, [])

  // 轮询：独立的定时器，只在需要时存在
  useEffect(() => {
    if (!pollMs || pollMs <= 0) return
    let timer: number | null = null

    const stop = (): void => {
      if (timer !== null) {
        window.clearInterval(timer)
        timer = null
      }
    }
    const start = (): void => {
      stop()
      timer = window.setInterval(() => {
        // 后台标签页不取数；上一次未返回则跳过本轮（避免请求堆积）
        if (document.hidden || inFlight.current) return
        setReloadNonce((n) => n + 1)
      }, pollMs)
    }

    // 回到前台立刻补一次，不必等下一个整周期
    const onVisibility = (): void => {
      if (document.hidden) {
        stop()
        return
      }
      setReloadNonce((n) => n + 1)
      start()
    }

    if (!document.hidden) start()
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [pollMs])

  return { data, loading, error, dataSeq, reload }
}
