/**
 * 全局轻提示（toast）队列。
 *
 * 取代原先基于 antd-mobile `Toast.show` 的命令式调用：这里只维护一个待渲染队列，
 * 由界面外壳把队列内容画成真实 DOM（见 `components/Toaster.tsx`）。
 * 好处是提示不再依赖第三方渲染器，也不必为 React 19 的命令式兼容做任何垫片。
 *
 * 停留时长区分对待：失败信息通常更长，用户需要读完后端给出的原因。
 */

import { signal } from '../lib/signals'

/** 提示类型（决定配色与图标） */
export type ToastKind = 'success' | 'error' | 'info'

/** 队列中的一条提示 */
export interface ToastEntry {
  id: number
  kind: ToastKind
  message: string
}

/** 各类提示的停留时长（毫秒） */
const SUCCESS_DURATION_MS = 2000
const ERROR_DURATION_MS = 3000
const INFO_DURATION_MS = 2000

/** 当前待显示的提示，最新的排在末尾（界面按顺序从上往下堆叠） */
export const toasts = signal<ToastEntry[]>([])

let nextId = 1

/** 空内容不弹提示：避免后端返回空 message 时出现一个空白框 */
function isBlank(message: string): boolean {
  return message.trim() === ''
}

function push(kind: ToastKind, message: string, durationMs: number): void {
  if (isBlank(message)) return
  const id = nextId++
  toasts.update((current) => [...current, { id, kind, message }])
  window.setTimeout(() => {
    toasts.update((current) => current.filter((entry) => entry.id !== id))
  }, durationMs)
}

/** 手动移除一条提示（用户点击关闭） */
export function dismissToast(id: number): void {
  toasts.update((current) => current.filter((entry) => entry.id !== id))
}

/** 操作成功提示 */
export function toastSuccess(message: string): void {
  push('success', message, SUCCESS_DURATION_MS)
}

/** 失败提示（停留更久，便于阅读后端返回的错误原因） */
export function toastError(message: string): void {
  push('error', message, ERROR_DURATION_MS)
}

/** 中性信息提示 */
export function toastInfo(message: string): void {
  push('info', message, INFO_DURATION_MS)
}
