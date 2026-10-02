// 应用外壳：顶栏（品牌标记 + 页面标题 + 连接状态 + 主题 / 刷新 / 退出）+ 离线横幅 + 底部 TabBar
//
// 控制台取向（与 styles/global.css 的设计系统一致）：
//   · 顶栏按 --fw-topbar-h 压到 40px，品牌用 `▌FW` 终端标记而不是大标题；
//     右侧一律是等宽小字的文字按钮（10px），避免图标语义歧义，
//     同时保持 ≥44px 的可点区域（见 TOPBAR_BTN 的负外边距说明）。
//   · 离线 / 断连横幅挂在顶栏之下（同属 sticky 头），用 fw-banner-* 上色，
//     是「实时数据不可信」的唯一全局提示位——页面内不再重复提示。
//   · 底部 TabBar 是主入口（5 个一级页）；jails / logs / settings 收纳在「更多」下，
//     命中这些二级路径时「更多」保持高亮，用户不会丢失位置感。
//
// 移动端关键约束（本文件是这些约束的唯一实现处）：
//   1. 触摸目标 ≥ 44px：顶栏按钮走 .fw-iconbtn（min 44×44）；TabBar 由 antd-mobile
//      保证（min-height 48px），二者都不低于 --fw-tap。
//   2. 安全区适配：顶栏补 env(safe-area-inset-top)（PWA 独立窗口的状态栏会盖住顶栏），
//      底部由 TabBar 的 safeArea 属性补 insets，内容区 padding 里预留 TabBar 高度。
//   3. 页面内容用 <Outlet /> 渲染；整体套 ErrorBoundary，复位键 = 当前路径 + 刷新计数。
//   4. .fw-shell 上不得加 transform / filter：那会创建新的包含块，使 .fw-tabbar 的
//      fixed 定位失效（TabBar 会跟着内容滚动）。
//
// 刷新语义：点「刷新」自增计数 → 路由子树整体重建 → 各视图的 useAsync 重新取数。
// 不做整页 reload：那会重建 SSE 连接（横幅闪一次、首帧重收），而页内重取已足够——
// SSE 与 REST 两份数据本来就由新鲜度戳裁决谁更新（见 hooks/useLiveData.ts）。
//
// 连接状态语义（来自 useSse）：
//   connected 正常 / connecting 连接中 / disconnected 已断开(自动重连) / connection_limit 连接数超限(停止重连)
import { TabBar } from 'antd-mobile'
import {
  AppOutline,
  CheckShieldOutline,
  ExclamationCircleOutline,
  ExclamationTriangleOutline,
  HistogramOutline,
  LockOutline,
  LoopOutline,
  MoreOutline,
} from 'antd-mobile-icons'
import { useEffect, useState } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'

import { useAuth } from '../hooks/useAuth'
import { useSse } from '../hooks/useSse'
import type { ConnectionStatus } from '../hooks/useSse'
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
const MORE_CHILD_PATHS = ['/jails', '/globe', '/logs', '/settings']

/** 顶栏标题（与路由一一对应，未知路径回退到应用名） */
const PAGE_TITLES: Record<string, string> = {
  '/dashboard': '仪表盘',
  '/bans': '封禁管理',
  '/whitelist': '白名单',
  '/ddos': 'DDoS 监控',
  '/more': '更多',
  '/jails': 'Jail 管理',
  '/globe': '攻击地图',
  '/logs': '日志',
  '/settings': '设置',
}

/** SSE 状态 → 顶栏状态灯文案与颜色（颜色 + 文案双通道，色盲用户也能分辨） */
const STATUS_DISPLAY: Record<ConnectionStatus, { label: string; color: string }> = {
  connected: { label: '实时', color: 'var(--fw-success)' },
  connecting: { label: '连接中', color: 'var(--fw-warning)' },
  disconnected: { label: '断开', color: 'var(--fw-danger)' },
  connection_limit: { label: '超限', color: 'var(--fw-danger)' },
}

/**
 * 顶栏文字按钮样式。
 *
 * 负外边距的用途：.fw-iconbtn 的可点区域是 44px，而顶栏只有 40px——
 * 负外边距把它对行的「布局占位」压回 40px（flex 行高按外边距盒计算），
 * 按钮盒本身仍是 44px 高（只是上下各溢出 2px，透明背景看不出来），
 * 于是「顶栏实际 40px」与「点击区 ≥44px」两个约束同时成立。
 */
const TOPBAR_BTN: CSSProperties = {
  fontSize: 10,
  letterSpacing: '0.04em',
  marginTop: -2,
  marginBottom: -2,
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
  // 页内刷新计数：自增即重建路由子树（见文件头「刷新语义」）
  const [refreshNonce, setRefreshNonce] = useState(0)

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
          {/* 品牌标记：终端提示符形态，替代大标题（顶栏高度靠它不需要更大字号） */}
          <span className="fw-mark" aria-hidden="true">
            ▌FW
          </span>
          <h1 className="fw-topbar-title">{pageTitle}</h1>

          <div className="fw-topbar-actions">
            {/* SSE 连接状态灯：仅正常时呼吸（断开/重连中静止，避免误导为「还在跳」） */}
            <span
              className="fw-status"
              style={{ color: statusDisplay.color }}
              role="status"
              aria-label={`实时连接状态：${statusDisplay.label}`}
            >
              <span
                className={`fw-status-dot${status === 'connected' ? ' fw-dot-live' : ''}`}
              />
              {statusDisplay.label}
            </span>

            {/* 主题切换：antd-mobile-icons 没有日/月图标，用文字标出当前主题，
                比塞一个语义不符的图标更易读；aria-label 说明点击后的动作 */}
            <button
              type="button"
              className="fw-iconbtn"
              style={TOPBAR_BTN}
              aria-label={`切换主题（当前${theme === 'dark' ? '深色' : '浅色'}主题）`}
              onClick={toggle}
            >
              {theme === 'dark' ? '深色' : '浅色'}
            </button>

            {/* 页内刷新：重建当前页面子树，让各视图重新取一遍 REST 数据 */}
            <button
              type="button"
              className="fw-iconbtn"
              style={TOPBAR_BTN}
              aria-label="刷新当前页面数据"
              onClick={() => setRefreshNonce((n) => n + 1)}
            >
              刷新
            </button>

            {/* 登出：清除令牌并回到登录页（AuthGate 依据令牌状态切换渲染） */}
            <button
              type="button"
              className="fw-iconbtn"
              style={TOPBAR_BTN}
              aria-label="退出登录"
              onClick={logout}
            >
              退出
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
        {/* resetKey=路径 + 刷新计数：切换路由或点刷新都会让边界复位，不会卡在旧错误上 */}
        <ErrorBoundary resetKey={`${path}:${refreshNonce}`}>
          <Outlet key={refreshNonce} />
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

      {/* 命令面板保留 Ctrl/Cmd+K 热键入口（顶栏不再为它占位；移动端导航由 TabBar 承担） */}
      <CommandPalette />
    </div>
  )
}

export default AppShell
