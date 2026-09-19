/**
 * 通用异步取数状态 Hook
 *
 * 视图层统一入口：把「发起请求 → loading → 成功/失败 → 手动重载」这套状态机收敛到一处，
 * 避免每个页面各写一份 useEffect + 三个 useState，并且保证：
 * - 组件卸载后不再 setState（防止 React 警告与内存泄漏）
 * - 依赖变化时前一次请求的结果不会覆盖后一次（避免竞态导致的错数据）
 * - 错误统一转成可展示的字符串，绝不吞掉
 *
 * 注意：`deps` 会被展开为 useEffect 的依赖数组，**长度必须稳定**（React 硬性要求），
 * 因此不要在调用处按条件增减依赖项。
 */

import { useCallback, useEffect, useRef, useState } from 'react'

/** useAsync 暴露给视图的状态对象 */
export interface AsyncState<T> {
  /** 最近一次成功的数据；未加载完成或失败时为 null */
  data: T | null
  /** 是否正在请求中（重载时保留上一次数据，避免界面闪空） */
  loading: boolean
  /** 失败原因（已转成中文可读文案）；成功时为 null */
  error: string | null
  /** 手动重新拉取（用于下拉刷新 / 失败重试按钮） */
  reload: () => void
}

/** 把任意抛出物转成可展示的文案（ApiError 的 message 已经是后端原文） */
function toMessage(err: unknown): string {
  if (err instanceof Error && err.message) return err.message
  if (typeof err === 'string' && err) return err
  return '请求失败，请稍后重试'
}

/**
 * @param fn 取数函数（内部会捕获其异常）
 * @param deps 依赖数组，变化时自动重新取数（长度需稳定）
 * @param opts.initial 首帧占位数据，用于在 SSE 数据到达前渲染骨架
 */
export function useAsync<T>(
  fn: () => Promise<T>,
  deps: unknown[],
  opts?: { initial?: T | null },
): AsyncState<T> {
  // 用 ref 持最新 fn：调用处通常传内联箭头函数，若把它放进依赖会导致无限重渲染
  const fnRef = useRef(fn)
  fnRef.current = fn

  const [data, setData] = useState<T | null>(opts?.initial ?? null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // 自增计数作为「手动重载」的触发源，加入依赖数组即可重新执行取数
  const [reloadNonce, setReloadNonce] = useState(0)

  // 每次取数分配一个序号，只有最新序号的结果才允许写入状态（丢弃过期响应）
  const requestSeq = useRef(0)

  useEffect(() => {
    const seq = ++requestSeq.current
    setLoading(true)
    setError(null)

    fnRef
      .current()
      .then((result) => {
        // 组件已卸载或被更新的请求取代：丢弃结果
        if (seq !== requestSeq.current) return
        setData(result)
        setError(null)
      })
      .catch((err: unknown) => {
        if (seq !== requestSeq.current) return
        setError(toMessage(err))
      })
      .finally(() => {
        if (seq !== requestSeq.current) return
        setLoading(false)
      })

    // 卸载或依赖变化时让本次结果失效，避免对已卸载组件 setState
    return () => {
      if (seq === requestSeq.current) {
        requestSeq.current = seq + 1
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- deps 由调用方显式给出
  }, [...deps, reloadNonce])

  const reload = useCallback(() => {
    setReloadNonce((n) => n + 1)
  }, [])

  return { data, loading, error, reload }
}
