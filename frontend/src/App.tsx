// 路由表：hash 路由 + AppShell 外壳
//
// 为什么必须用 hash 路由：守护进程（src/daemon/http_exporter/handler.rs）只对
// /、/dashboard、/bans、/whitelist、/jails、/ddos、/logs、/settings、/more
// 这些页面路径返回 HTML，且没有 catch-all。若用 history 路由，用户在 /bans 上按
// 刷新会被服务端 404。hash 路由（#/bans）永远只请求 `/`，因此刷新与直达都安全。
//
// 路由层级：
//   /            AppShell（顶栏 + 底部 TabBar + 离线横幅）
//     ├─ index   → 重定向到 /dashboard
//     ├─ dashboard / bans / whitelist / ddos / more      ← TabBar 一级页
//     ├─ jails / logs / settings                          ← 收纳在「更多」下的二级页
//     └─ *        → 未匹配路径提示页（不静默重定向，便于发现错误链接）
import { Button } from 'antd-mobile'
import { createHashRouter, Navigate, RouterProvider, useNavigate } from 'react-router-dom'

import AppShell from './components/AppShell'
import EmptyState from './components/EmptyState'
import { useAuth } from './hooks/useAuth'
import { SseProvider } from './hooks/useSse'
import Bans from './views/Bans'
import Dashboard from './views/Dashboard'
import Ddos from './views/Ddos'
import Globe from './views/Globe'
import Jails from './views/Jails'
import Login from './views/Login'
import Logs from './views/Logs'
import More from './views/More'
import Settings from './views/Settings'
import Whitelist from './views/Whitelist'

/**
 * 未匹配路由的兜底页。
 * 仍然位于 AppShell 之内，因此用户可以用底部 TabBar 走回正常页面。
 */
function RouteNotFound() {
  const navigate = useNavigate()
  return (
    <EmptyState
      title="页面不存在"
      description="该地址没有对应的页面，可能链接已失效。"
      action={
        <Button color="primary" fill="outline" onClick={() => navigate('/dashboard', { replace: true })}>
          返回仪表盘
        </Button>
      }
    />
  )
}

const router = createHashRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      // 根路径（#/ 或 #）重定向到仪表盘，不做停留
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: 'dashboard', element: <Dashboard /> },
      { path: 'bans', element: <Bans /> },
      { path: 'whitelist', element: <Whitelist /> },
      { path: 'ddos', element: <Ddos /> },
      // 「更多」页收纳的二级页
      { path: 'jails', element: <Jails /> },
      { path: 'globe', element: <Globe /> },
      { path: 'logs', element: <Logs /> },
      { path: 'settings', element: <Settings /> },
      { path: 'more', element: <More /> },
      { path: '*', element: <RouteNotFound /> },
    ],
  },
])

/**
 * 认证闸门：未持有访问令牌时只渲染登录页。
 *
 * 为什么需要：SPA 外壳是公开路由（不含数据），数据一律经受保护的 `/api/v1/*` 取用，
 * 因此未认证时若直接渲染主界面，只会看到一屏 401 失败与「加载中」。先登录、
 * 把令牌写进 `api/auth.ts`，后续 fetch 与 EventSource 都自动携带。
 *
 * SseProvider 放在闸门**内部**：未认证时不挂载，就不会建立无令牌的 EventSource
 * 连接（那会持续 401 并喂大服务端暴力破解计数，最终把正确凭据一起锁死）。
 * 它仍然包在 RouterProvider 之外，因此路由切换不会重建连接。
 */
function AuthGate() {
  const { token } = useAuth()
  if (!token) return <Login />
  return (
    <SseProvider>
      <RouterProvider router={router} />
    </SseProvider>
  )
}

export default function App() {
  return <AuthGate />
}
