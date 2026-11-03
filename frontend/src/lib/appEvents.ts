/**
 * 应用级事件总线 —— 目前只有一条「刷新当前页」信号。
 *
 * 为什么用 DOM CustomEvent 而不是 context：命令面板是全局单例，它要触发「当前页刷新」，
 * 但**当前页是哪个、它的 refetch 在哪**只有页面自己知道。若把每个页面的 refetch 注册进
 * 全局 context，命令面板就要和所有页面强耦合。用一条广播信号解耦：命令面板 emit，当前
 * 挂载的页面订阅并各自 refetch，命令面板无需知道有谁在听。
 *
 * 刻意极简：不引第三方事件库，window 上的 addEventListener 足够，且天然随页面卸载清理。
 */

export const REFRESH_EVENT = 'fw:refresh'

/** 广播一次「刷新当前页」。 */
export function emitRefresh(): void {
  window.dispatchEvent(new CustomEvent(REFRESH_EVENT))
}

/** 订阅刷新信号；返回取消订阅函数。 */
export function onRefresh(handler: () => void): () => void {
  const listener = () => handler()
  window.addEventListener(REFRESH_EVENT, listener)
  return () => window.removeEventListener(REFRESH_EVENT, listener)
}
