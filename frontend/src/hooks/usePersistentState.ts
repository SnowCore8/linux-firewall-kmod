import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * localStorage 持久化状态 + 跨标签同步。
 *
 * 主题、密度、侧边栏折叠这类偏好要跨刷新、跨标签保持一致：本 hook 写入 localStorage，
 * 并订阅 `storage` 事件——在**另一个**标签改了值时，本标签跟着更新（`storage` 事件不在
 * 触发它的那个标签里冒泡，所以本标签自己的 set 不会自我回环）。
 *
 * 序列化用 JSON；读回失败（脏数据 / 手改）时回退到初始值，不抛。
 */

export interface PersistentStateOptions {
  /** 是否在 storage 事件里跨标签同步；默认 true。 */
  syncTabs?: boolean
}

export function usePersistentState<T>(
  key: string,
  initialValue: T,
  options: PersistentStateOptions = {},
): [T, (value: T | ((prev: T) => T)) => void] {
  const { syncTabs = true } = options

  const read = useCallback((): T => {
    try {
      const raw = window.localStorage.getItem(key)
      if (raw === null) return initialValue
      return JSON.parse(raw) as T
    } catch {
      return initialValue
    }
    // initialValue 仅作为回退，不参与依赖（引用可能每渲染都变）
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  const [value, setValue] = useState<T>(read)
  const valueRef = useRef(value)
  valueRef.current = value

  const set = useCallback(
    (next: T | ((prev: T) => T)) => {
      setValue((prev) => {
        const resolved = typeof next === 'function' ? (next as (p: T) => T)(prev) : next
        try {
          window.localStorage.setItem(key, JSON.stringify(resolved))
        } catch {
          // 存储写满 / 隐私模式禁用：内存里照常更新，只是不落盘
        }
        return resolved
      })
    },
    [key],
  )

  useEffect(() => {
    if (!syncTabs) return
    const onStorage = (e: StorageEvent) => {
      if (e.key !== key || e.newValue === null) return
      try {
        const parsed = JSON.parse(e.newValue) as T
        setValue(parsed)
      } catch {
        // 忽略脏值
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [key, syncTabs])

  return [value, set]
}
