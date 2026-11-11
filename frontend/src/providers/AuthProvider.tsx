import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { ApiError, onUnauthorized } from '../api/client.ts'
import {
  ACCESS_TOKEN_KEY,
  AUTH_FAILURE_THRESHOLD,
  AUTH_LOCKOUT_SECONDS,
  clearAccessToken,
  encodeBasic,
  hasAccessToken,
  setAccessToken,
} from '../api/auth.ts'
import { probeAuth } from '../api/endpoints.ts'

/**
 * 认证 Provider —— 令牌生命周期 + 登录/登出 + 401 自动登出 + 锁定倒计时的单一真相源。
 *
 * 关键约束（迁移前后不变）：
 *   * 令牌 = base64(user:pass)，存 localStorage；登录成功与否由一次真实探测决定
 *     （probeAuth 打 GET /api/v2/bans，不能用恒 303 的 GET /）。
 *   * 任何 REST 调用收到 401 都会经 client.ts 的 onUnauthorized 广播到这里 → 自动清令牌
 *     并跳登录，不让某个视图停在「拿着废令牌反复失败」的状态。
 *   * 连续失败达 AUTH_FAILURE_THRESHOLD 次后进入本地锁定倒计时（镜像守护进程的锁定窗口），
 *     倒计时内禁用登录按钮，避免用户把账号越试越死、也省得每次都等后端 401 回包。
 */

export type AuthStatus = 'authenticating' | 'authenticated' | 'unauthenticated'

export interface AuthContextValue {
  status: AuthStatus
  isAuthenticated: boolean
  isLoggingIn: boolean
  /** 最近一次登录失败的可读文案；null 表示无错误。 */
  error: string | null
  /** 连续失败次数（成功登录后归零）。 */
  failCount: number
  /** 触发锁定的阈值（契约常量）。 */
  threshold: number
  /** 本地锁定剩余秒数；0 表示未锁定。 */
  lockoutRemaining: number
  login: (username: string, password: string) => Promise<boolean>
  logout: () => void
  clearError: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>(() =>
    hasAccessToken() ? 'authenticated' : 'unauthenticated',
  )
  const [isLoggingIn, setIsLoggingIn] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [failCount, setFailCount] = useState(0)
  const [lockoutRemaining, setLockoutRemaining] = useState(0)

  const failCountRef = useRef(0)
  failCountRef.current = failCount
  const lockoutRemainingRef = useRef(0)
  lockoutRemainingRef.current = lockoutRemaining
  const lockoutTimerRef = useRef<number | null>(null)

  const clearLockoutTimer = useCallback(() => {
    if (lockoutTimerRef.current !== null) {
      window.clearInterval(lockoutTimerRef.current)
      lockoutTimerRef.current = null
    }
  }, [])

  /** 启动本地锁定倒计时（秒级递减，归零自动解锁）。 */
  const startLockout = useCallback(() => {
    setLockoutRemaining(AUTH_LOCKOUT_SECONDS)
    clearLockoutTimer()
    lockoutTimerRef.current = window.setInterval(() => {
      setLockoutRemaining((prev) => {
        if (prev <= 1) {
          clearLockoutTimer()
          setFailCount(0)
          // 锁定到期：清掉「已锁定」残留提示，还给用户一个干净的登录表单
          setError(null)
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }, [clearLockoutTimer])

  // 401 自动登出：任何在途请求收到 401 都会广播到这里
  useEffect(() => {
    return onUnauthorized(() => {
      clearAccessToken()
      setStatus('unauthenticated')
    })
  }, [])

  // 跨 tab 同步登出：其他 tab 清除 token 时，当前 tab 也跟着登出
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === ACCESS_TOKEN_KEY && e.newValue === null) {
        setStatus('unauthenticated')
        setFailCount(0)
        setError(null)
        clearLockoutTimer()
        setLockoutRemaining(0)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [clearLockoutTimer])

  useEffect(() => clearLockoutTimer, [clearLockoutTimer])

  const login = useCallback(
    async (username: string, password: string): Promise<boolean> => {
      if (lockoutRemainingRef.current > 0) {
        setError(`登录已被锁定，请在 ${lockoutRemainingRef.current} 秒后重试`)
        return false
      }
      setIsLoggingIn(true)
      setError(null)
      setStatus('authenticating')

      const token = encodeBasic(username, password)
      setAccessToken(token)

      try {
        await probeAuth()
        setAccessToken(token)
        setFailCount(0)
        setStatus('authenticated')
        return true
      } catch (err) {
        // 探测失败：清掉刚写的令牌
        clearAccessToken()
        if (err instanceof ApiError && err.isUnauthorized) {
          // 仅凭据错误（401）计入失败次数；网络/服务端错误不推进锁定计数，
          // 免得断网时把账号「越试越接近锁定」
          const next = failCountRef.current + 1
          setFailCount(next)
          if (next >= AUTH_FAILURE_THRESHOLD) {
            startLockout()
            setError(
              err.message || `连续失败 ${next} 次，已锁定 ${AUTH_LOCKOUT_SECONDS} 秒`,
            )
          } else {
            setError(
              err.message ||
                `用户名或密码错误（还可尝试 ${AUTH_FAILURE_THRESHOLD - next} 次）`,
            )
          }
        } else if (err instanceof ApiError) {
          setError(err.message)
        } else {
          setError('登录失败：无法连接到守护进程')
        }
        setStatus('unauthenticated')
        return false
      } finally {
        setIsLoggingIn(false)
      }
    },
    [startLockout],
  )

  const logout = useCallback(() => {
    clearAccessToken()
    setFailCount(0)
    setError(null)
    clearLockoutTimer()
    setLockoutRemaining(0)
    setStatus('unauthenticated')
  }, [clearLockoutTimer])

  const clearError = useCallback(() => setError(null), [])

  const value = useMemo<AuthContextValue>(
    () => ({
      status,
      isAuthenticated: status === 'authenticated',
      isLoggingIn,
      error,
      failCount,
      threshold: AUTH_FAILURE_THRESHOLD,
      lockoutRemaining,
      login,
      logout,
      clearError,
    }),
    [status, isLoggingIn, error, failCount, lockoutRemaining, login, logout, clearError],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth 必须在 <AuthProvider> 内使用')
  return ctx
}
