import { useEffect, useRef } from 'react'
import { onRefresh } from '../lib/appEvents.ts'

/**
 * 订阅命令面板/顶栏广播的「刷新当前页」信号。
 *
 * 页面把自己的 refetch（通常来自 useAsync/useLiveData）传进来即可；handler 存进 ref，
 * 所以每次渲染传入新函数也不会导致重复订阅/退订。返回的清理随组件卸载自动退订。
 */
export function useRefreshSignal(handler: () => void): void {
  const handlerRef = useRef(handler)
  handlerRef.current = handler
  useEffect(() => onRefresh(() => handlerRef.current()), [])
}
