import { App as AntdApp } from 'antd'
import { RouterProvider } from 'react-router-dom'
import { ThemeProvider } from '../providers/ThemeProvider.tsx'
import { AuthProvider } from '../providers/AuthProvider.tsx'
import { NotificationProvider } from '../providers/NotificationProvider.tsx'
import { SseProvider } from '../providers/SseProvider.tsx'
import { ErrorBoundary } from '../providers/ErrorBoundary.tsx'
import { router } from './router.tsx'

/**
 * Provider 组合根 —— 依赖顺序决定嵌套顺序，从外到内：
 *
 *   ThemeProvider（含 AntD ConfigProvider：主题 token / 暗色算法 / 中文 locale）
 *     └ AntdApp（提供上下文感知的 notification/message/modal 实例，随主题走）
 *         └ ErrorBoundary（兜住下面任何一层渲染崩溃）
 *             └ AuthProvider（令牌生命周期；SSE 依赖它决定是否连接）
 *                 └ NotificationProvider（用 AntdApp 的实例弹 toast；实时告警的落点）
 *                     └ SseProvider（唯一一条 events 连接；useAuth 决定 enabled）
 *                         └ RouterProvider（页面组件在此消费以上全部 context）
 *
 * 顺序不能乱的两条硬约束：
 *   1. NotificationProvider 必须在 AntdApp 之内——它调 App.useApp() 拿主题感知的通知实例，
 *      用静态 notification.xxx 会在暗色下渲染成亮色；
 *   2. SseProvider 必须在 AuthProvider 之内——它读 isAuthenticated 决定连不连实时流，
 *      未登录时连接会被守护进程 401 拒绝，白白触发退避重连。
 */
export default function App() {
  return (
    <ThemeProvider>
      <AntdApp>
        <ErrorBoundary>
          <AuthProvider>
            <NotificationProvider>
              <SseProvider>
                <RouterProvider router={router} />
              </SseProvider>
            </NotificationProvider>
          </AuthProvider>
        </ErrorBoundary>
      </AntdApp>
    </ThemeProvider>
  )
}
