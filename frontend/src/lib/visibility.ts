/**
 * 页面可见性小工具：轮询与实时流在标签页隐藏时应暂停，回到前台立即恢复。
 * 单独成文件是为了让 useAsync / SseProvider 共用同一个判定，避免各处各写一遍
 * `document.hidden` 与兼容前缀。
 */

/** 当前页面是否可见（前台标签且窗口未最小化）。 */
export function isPageVisible(): boolean {
  if (typeof document === 'undefined') return true
  return document.visibilityState !== 'hidden'
}

/** 订阅可见性变化；回调收到「现在是否可见」。返回取消订阅函数。 */
export function onVisibilityChange(handler: (visible: boolean) => void): () => void {
  if (typeof document === 'undefined') return () => {}
  const listener = () => handler(isPageVisible())
  document.addEventListener('visibilitychange', listener)
  return () => document.removeEventListener('visibilitychange', listener)
}
