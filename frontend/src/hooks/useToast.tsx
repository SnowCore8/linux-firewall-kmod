/**
 * 操作反馈（Toast）Hook
 *
 * 包一层 antd-mobile 的 `Toast`，把「提示样式」和「提示时长」统一在一处，
 * 视图层只关心业务语义：成功 / 失败 / 一般信息。
 *
 * 用 Context 而非直接 re-export 的原因：视图在 `<ToastProvider>` 之外调用
 * `useToast()` 时会立刻抛出明确错误（而不是静默丢失提示），
 * 且后续要替换提示实现（如换成自定义气泡）时只改这一处。
 */

import { createContext, useContext, useMemo } from 'react'
// React 19 起 JSX 命名空间不再挂到全局，必须显式按类型导入才能写 JSX.Element
import type { JSX, ReactNode } from 'react'
import { Toast } from 'antd-mobile'

/** useToast 暴露的三个提示方法 */
interface ToastApi {
  /** 操作成功提示（带成功图标，2 秒后自动消失） */
  success: (msg: string) => void
  /** 失败提示（带叉号图标，停留稍久，便于阅读后端返回的错误原因） */
  error: (msg: string) => void
  /** 中性信息提示（无图标） */
  info: (msg: string) => void
}

/** 各类提示的停留时长（毫秒）：失败信息通常更长，需要读完原因 */
const SUCCESS_DURATION_MS = 2000
const ERROR_DURATION_MS = 3000
const INFO_DURATION_MS = 2000

/** 空内容不弹提示：避免后端返回空 message 时出现一个空白框 */
function isBlank(msg: string): boolean {
  return msg.trim() === ''
}

const ToastContext = createContext<ToastApi | null>(null)

/** 提示 Provider：包裹应用，使 useToast 在任意子树可用 */
export function ToastProvider(props: { children: ReactNode }): JSX.Element {
  const api = useMemo<ToastApi>(
    () => ({
      success: (msg: string) => {
        if (isBlank(msg)) return
        Toast.show({ icon: 'success', content: msg, duration: SUCCESS_DURATION_MS })
      },
      error: (msg: string) => {
        if (isBlank(msg)) return
        // 失败不用 mask：用户可能想立刻重试或复制错误信息
        Toast.show({ icon: 'fail', content: msg, duration: ERROR_DURATION_MS, maskClickable: true })
      },
      info: (msg: string) => {
        if (isBlank(msg)) return
        Toast.show({ content: msg, duration: INFO_DURATION_MS })
      },
    }),
    [],
  )

  return <ToastContext.Provider value={api}>{props.children}</ToastContext.Provider>
}

/**
 * 获取提示方法。
 * @throws Error 在 `<ToastProvider>` 之外调用时
 */
export function useToast(): {
  success: (msg: string) => void
  error: (msg: string) => void
  info: (msg: string) => void
} {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    throw new Error('useToast 必须在 <ToastProvider> 内使用（请检查应用根部的 Provider 组合）')
  }
  return ctx
}
