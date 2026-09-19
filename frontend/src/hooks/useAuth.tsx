/**
 * 认证状态 Context：把 api/auth.ts 的令牌状态暴露给界面。
 *
 * 为什么需要一层 Context：令牌可能在 fetch 层被清除（请求收到 401 时
 * `client.ts` 会调用 `clearAccessToken`），界面必须能感知并切回登录页，
 * 否则会停在一堆失败的请求上。`api/auth.ts` 通过 `onAuthChange` 广播变化，
 * 这里把它转成 React 状态。
 */

import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'

import { clearAccessToken, getAccessToken, onAuthChange } from '../api/auth'

/** AuthProvider 通过 Context 暴露的认证状态与操作 */
export interface AuthState {
  /** 当前访问令牌；`null` 表示未认证（应显示登录页） */
  token: string | null
  /** 登出：清除令牌并回到登录页 */
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

/**
 * 认证 Provider：应用最外层（SseProvider 之外）。
 * 初始值直接取模块缓存 —— `main.tsx` 会先调用 `initAccessToken()` 完成
 * 「URL 令牌 → sessionStorage」的解析，因此这里读到的一定是最终值。
 */
export function AuthProvider(props: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => getAccessToken())

  useEffect(
    () =>
      onAuthChange(() => {
        setToken(getAccessToken())
      }),
    [],
  )

  const logout = useCallback(() => {
    clearAccessToken()
  }, [])

  return <AuthContext.Provider value={{ token, logout }}>{props.children}</AuthContext.Provider>
}

/**
 * 读取认证状态。
 * @throws Error 在 `<AuthProvider>` 之外调用时（说明应用根部漏挂 Provider）
 */
export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth 必须在 <AuthProvider> 内使用（请检查应用根部的 Provider 组合）')
  }
  return ctx
}
