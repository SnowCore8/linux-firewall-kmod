import { lazy, type ReactElement } from 'react'
import { createHashRouter, Navigate, useLocation } from 'react-router-dom'
import AppShell from './AppShell.tsx'
import Login from '../views/Login.tsx'
import { useAuth } from '../providers/AuthProvider.tsx'
import { DEFAULT_PATH, NAV_ITEMS } from './nav.ts'

/**
 * 路由表 —— hash 路由（守护进程无 catch-all，只能靠 # 承载前端路由，迁移前后不变）。
 *
 * 结构：/login 是公开闸门；其余全部挂在 RequireAuth 保护的 AppShell 之下，作为它的子路由
 * 渲染进 <Outlet/>。页面组件一律 React.lazy 懒加载，切页时由外壳的 LoadingBoundary（Suspense）
 * 兜底成骨架屏，避免首屏一次性下载所有页面的代码。
 *
 * 深链：/bans/:ip、/analysis/ip/:ip 复用同一个页面组件，由页面读 useParams 决定是否自动
 * 打开对应详情抽屉——这样「实时告警点进来直达某 IP」与「手动浏览」走同一条渲染路径。
 */

const Dashboard = lazy(() => import('../views/Dashboard.tsx'))
const Bans = lazy(() => import('../views/Bans.tsx'))
const Whitelist = lazy(() => import('../views/Whitelist.tsx'))
const Jails = lazy(() => import('../views/Jails.tsx'))
const Ddos = lazy(() => import('../views/Ddos.tsx'))
const Risk = lazy(() => import('../views/Risk.tsx'))
const ThreatFeeds = lazy(() => import('../views/ThreatFeeds.tsx'))
const Analysis = lazy(() => import('../views/Analysis.tsx'))
const Logs = lazy(() => import('../views/Logs.tsx'))
const Settings = lazy(() => import('../views/Settings.tsx'))

/** 未登录时重定向到登录页；已登录访问 /login 由 Login 自身跳回概览。 */
function RequireAuth({ children }: { children: ReactElement }): ReactElement {
  const { isAuthenticated } = useAuth()
  const location = useLocation()
  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  return children
}

/** 未匹配路由：已知路径的深链前缀交给对应页，其余回概览（不做硬 404，控制台里 404 意义不大）。 */
function NotFound(): ReactElement {
  const location = useLocation()
  const known = NAV_ITEMS.some(
    (item) => location.pathname === item.path || location.pathname.startsWith(`${item.path}/`),
  )
  return <Navigate to={known ? location.pathname : DEFAULT_PATH} replace />
}

export const router = createHashRouter([
  { path: '/login', element: <Login /> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <AppShell />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <Navigate to={DEFAULT_PATH} replace /> },
      { path: 'dashboard', element: <Dashboard /> },
      { path: 'bans', element: <Bans /> },
      { path: 'bans/:ip', element: <Bans /> },
      { path: 'whitelist', element: <Whitelist /> },
      { path: 'jails', element: <Jails /> },
      { path: 'ddos', element: <Ddos /> },
      { path: 'risk', element: <Risk /> },
      { path: 'threat-feeds', element: <ThreatFeeds /> },
      { path: 'analysis', element: <Analysis /> },
      { path: 'analysis/ip/:ip', element: <Analysis /> },
      { path: 'logs', element: <Logs /> },
      { path: 'settings', element: <Settings /> },
      { path: '*', element: <NotFound /> },
    ],
  },
])
