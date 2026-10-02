/**
 * 认证状态。
 *
 * 初始值直接取模块缓存 —— 应用入口会先调用 `initAccessToken()` 完成
 * 「URL 令牌 → sessionStorage」的解析，因此这里读到的一定是最终值。
 *
 * 令牌本身由 `api/auth.ts` 管理（含订阅广播），本模块只把它镜像成信号供界面读取，
 * 避免每个视图各自 `getAccessToken()` 而错过变化。
 */

import { clearAccessToken, getAccessToken, onAuthChange } from '../api/auth'
import { effect, signal } from '../lib/signals'

/** 当前访问令牌；`null` 表示未认证（应显示登录页） */
export const accessToken = signal<string | null>(getAccessToken())

/**
 * 建立认证副作用：把 `api/auth.ts` 的令牌变更同步到信号，并初始化首值。
 *
 * @returns 停止函数（应用根卸载时调用）
 */
export function initAuth(): () => void {
  // 本模块被求值到订阅建立之间可能已经发生过变更，先对一次基准
  accessToken.set(getAccessToken())
  return onAuthChange(() => {
    accessToken.set(getAccessToken())
  })
}

/** 登出：清除令牌，界面随即回到登录页 */
export function logout(): void {
  clearAccessToken()
}
