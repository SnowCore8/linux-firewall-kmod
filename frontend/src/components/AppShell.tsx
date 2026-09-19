// 应用外壳：顶栏（页面标题 + SSE 状态 + 主题切换 + 搜索）+ 离线横幅 + 底部 TabBar
//
// 移动端优先的关键约束（本文件是这些约束的唯一实现处）：
//   1. 底部 TabBar 是主入口：5 个一级页；「更多」页再收纳 jails / logs / settings
//   2. 触摸目标 ≥ 44px：TabBar 单项高度由 antd-mobile 保证（≥48px），
//      顶栏按钮统一用 .fw-iconbtn（min 44x44）
//   3. 安全区适配：顶栏补 env(safe-area-inset-top)（PWA 独立窗口的状态栏），
//      底部由 TabBar 的 safeArea 属性补 insets，内容区 padding 里预留 TabBar 高度
//   4. 页面内容用 <Outlet /> 渲染；整体套 ErrorBoundary，并以当前路径为复位键
//
// 连接状态语义（来自 useSse）：
//   connected 正常 / connecting 连接中 / disconnected 已断开(自动重连) / connection_limit 连接数超限(停止重连)
import { TabBar } from 'antd-mobile'
import {
  AppOutline,
  CheckShieldOutline,
  CloseOutline,
  ExclamationCircleOutline,
  ExclamationTriangleOutline,
  HistogramOutline,
  LockOutline,
  LoopOutline,
  MoreOutline,
  SearchOutline,
} from 'antd-mobile-icons'
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'

import { useSse } from '../hooks/useSse'
import type { ConnectionStatus } from '../hooks/useSse'
import { useAuth } from '../hooks/useAuth'
import { useTheme } from '../hooks/useTheme'
import { CommandPalette } from './CommandPalette'
import { ErrorBoundary } from './ErrorBoundary'

/** 底部 TabBar 的 5 个一级入口（顺序即展示顺序） */
const TABS: { key: string; path: string; title: string; icon: ReactNode }[] = [
  { key: 'dashboard', path: '/dashboard', title: '仪表盘', icon: <AppOutline /> },
  { key: 'bans', path: '/bans', title: '封禁', icon: <LockOutline /> },
  { key: 'whitelist', path: '/whitelist', title: '白名单', icon: <CheckShieldOutline /> },
  { key: 'ddos', path: '/ddos', title: 'DDoS', icon: <HistogramOutline /> },
  { key: 'more', path: '/more', title: '更多', icon: <MoreOutline /> },
]

/** 收纳在「更多」下的二级页：命中时底部高亮「更多」，用户不会丢失位置感 */
const MORE_CHILD_PATHS = ['/jails', '/logs', '/settings']

/** 顶栏标题（与路由一一对应，未知路径回退到应用名） */
const PAGE_TITLES: Record<string, string> = {
  '/dashboard': '仪表盘',
  '/bans': '封禁管理',
  '/whitelist': '白名单',
  '/ddos': 'DDoS 监控',
  '/more': '更多',
  '/jails': 'Jail 管理',
  '/logs': '日志',
  '/settings': '设置',
}

/** SSE 状态 → 顶栏状态灯文案与颜色 */
const STATUS_DISPLAY: Record<ConnectionStatus, { label: string; color: string }> = {
  connected: { label: '实时', color: 'var(--fw-success)' },
  connecting: { label: '连接中', color: 'var(--fw-warning)' },
  disconnected: { label: '已断开', color: 'var(--fw-danger)' },
  connection_limit: { label: '连接超限', color: 'var(--fw-danger)' },
}

/** 横幅内容；null 表示无需展示 */
interface Banner {
  tone: 'danger' | 'warning'
  icon: ReactNode
  text: string
}

export function AppShell() {
  const location = useLocation()
  const navigate = useNavigate()
  const { status, reconnectAttempt } = useSse()
  const { theme, toggle } = useTheme()
  const { logout } = useAuth()

  const [online, setOnline] = useState(() => navigator.onLine)
  const [paletteOpen, setPaletteOpen] = useState(false)

  // 网络在线状态：仅监听浏览器事件，不做轮询（省电，且 offline 事件足够可靠）
  useEffect(() => {
    const handleOnline = () => setOnline(true)
    const handleOffline = () => setOnline(false)
    window.addEventListener('online', handleOnline)
    window.addEventListener('offline', handleOffline)
    return () => {
      window.removeEventListener('online', handleOnline)
      window.removeEventListener('offline', handleOffline)
    }
  }, [])

  // 去掉尾部斜杠：避免 `/bans/` 命中不到标题与 Tab 高亮
  const path = location.pathname.length > 1 ? location.pathname.replace(/\/+$/, '') : location.pathname
  const pageTitle = PAGE_TITLES[path] ?? 'Firewall'
  const activeTab = MORE_CHILD_PATHS.includes(path) ? 'more' : TABS.find((tab) => tab.path === path)?.key
  const statusDisplay = STATUS_DISPLAY[status]

  // 横幅按「影响程度」排序：真离线 > 服务端连接超限 > 断开重连 > 重连中
  let banner: Banner | null = null
  if (!online) {
    banner = {
      tone: 'danger',
      icon: <ExclamationCircleOutline />,
      text: '设备已离线：数据停止刷新，恢复网络后会自动重连。',
    }
  } else if (status === 'connection_limit') {
    banner = {
      tone: 'danger',
      icon: <ExclamationTriangleOutline />,
      text: '服务端 SSE 连接数已达上限，已停止自动重连。请关闭其它控制台标签页后刷新本页。',
    }
  } else if (status === 'disconnected') {
    banner = {
      tone: 'warning',
      icon: <ExclamationCircleOutline />,
      text: `实时连接已中断，正在自动重连（第 ${reconnectAttempt} 次）…`,
    }
  } else if (status === 'connecting' && reconnectAttempt > 0) {
    banner = {
      tone: 'warning',
      icon: <LoopOutline />,
      text: `正在重连（第 ${reconnectAttempt} 次）…`,
    }
  }

  return (
    <div className="fw-shell">
      <div className="fw-head">
        <header className="fw-topbar">
          <h1 className="fw-topbar-title">{pageTitle}</h1>

          <div className="fw-topbar-actions">
            {/* SSE 连接状态灯：颜色 + 文案双通道，色盲用户也能分辨 */}
            <span
              className="fw-status"
              style={{ color: statusDisplay.color }}
              role="status"
              aria-label={`实时连接状态：${statusDisplay.label}`}
            >
              <span className="fw-status-dot" />
              {statusDisplay.label}
            </span>

            {/* 主题切换：antd-mobile-icons 没有太阳/月亮图标，用文字标出当前主题，
                比塞一个语义不符的图标更易读；aria-label 说明点击后的动作 */}
            <button
              type="button"
              className="fw-iconbtn"
              style={{ fontSize: 12 }}
              aria-label={`切换主题（当前${theme === 'dark' ? '深色' : '浅色'}主题）`}
              onClick={toggle}
            >
              {theme === 'dark' ? '深色' : '浅色'}
            </button>

            <button
              type="button"
              className="fw-iconbtn"
              aria-label="打开命令面板（搜索页面）"
              onClick={() => setPaletteOpen(true)}
            >
              <SearchOutline />
            </button>

            {/* 登出：清除令牌并回到登录页（AuthGate 依据令牌状态切换渲染） */}
            <button type="button" className="fw-iconbtn" aria-label="退出登录" onClick={logout}>
              <CloseOutline />
            </button>
          </div>
        </header>

        {banner ? (
          <div className={`fw-banner fw-banner-${banner.tone}`} role="alert">
            <span className="fw-banner-icon">{banner.icon}</span>
            <span>{banner.text}</span>
          </div>
        ) : null}
      </div>

      <main className="fw-main">
        {/* resetKey=当前路径：在错误页点了底部导航后边界自动复位，不会卡在旧错误上 */}
        <ErrorBoundary resetKey={path}>
          <Outlet />
        </ErrorBoundary>
      </main>

      <TabBar className="fw-tabbar" activeKey={activeTab} safeArea>
        {TABS.map((tab) => (
          <TabBar.Item
            key={tab.key}
            title={tab.title}
            icon={tab.icon}
            // 点击已激活的 Tab 不重复入栈，避免「返回」需要连按多次
            onClick={() => {
              if (tab.path !== path) navigate(tab.path)
            }}
          />
        ))}
      </TabBar>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  )
}

export default AppShell
