import { Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Button, Drawer, Dropdown, Flex, Layout, Menu, Tooltip, Typography, type MenuProps } from 'antd'
import {
  BulbFilled,
  BulbOutlined,
  CompressOutlined,
  ExpandOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SearchOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { NAV_GROUPS, NAV_ITEMS } from './nav.ts'
import { useTheme } from '../providers/ThemeProvider.tsx'
import { useAuth } from '../providers/AuthProvider.tsx'
import { useSse } from '../providers/SseProvider.tsx'
import { useNotify } from '../providers/NotificationProvider.tsx'
import { useIsBelow } from '../hooks/useMediaQuery.ts'
import { useHotkey, IS_MAC } from '../hooks/useHotkey.ts'
import { usePersistentState } from '../hooks/usePersistentState.ts'
import { emitRefresh } from '../lib/appEvents.ts'
import { threatLabel, threatRank } from '../theme/tokens.ts'
import { RealtimeBadge } from '../components/state/RealtimeBadge.tsx'
import { NotificationCenter } from '../components/NotificationCenter.tsx'
import { CommandPalette } from '../components/CommandPalette.tsx'
import { ErrorBoundary } from '../providers/ErrorBoundary.tsx'
import { LoadingState } from '../components/state/LoadingState.tsx'
import type { SseConnectionState } from '../hooks/useSse.ts'

/**
 * 应用外壳 —— 侧边栏 + 顶栏 + 内容区的桌面布局，全站唯一的框架层。
 *
 * 响应式策略（桌面优先，逐级降级）：
 *   * ≥lg(1024)：常驻侧边栏，可手动折叠（折叠态持久化 + 跨标签同步）；
 *   * md–lg(768–1023)：侧边栏自动折叠为图标条（省横向空间给表格）；
 *   * <md(768)：侧边栏收进抽屉，顶栏出现汉堡按钮——此时表格由页面各自降级为卡片/横滚。
 *
 * 顶栏聚合全局能力：命令面板入口（mod+K）、实时状态灯、主题/密度切换、通知中心、账户菜单。
 * 这些是「跨页常驻」的，放顶栏而非各页，保证在任何页面都能一键触达。
 *
 * 实时告警：外壳订阅 SSE 连接态与威胁等级，在**状态跃迁**时推通知（降级/重连/等级升高），
 * 让运维即便盯着别的页面也不会错过关键变化。跃迁去抖：只在真正变化时推一次。
 */

const { Header, Sider, Content } = Layout

/** 把 mod 组合键渲染成当前平台的实际按键标签：macOS 显示 ⌘K，其余显示 Ctrl+K。 */
const modLabel = (key: string): string => (IS_MAC ? `⌘${key}` : `Ctrl+${key}`)

function BrandMark({ collapsed }: { collapsed: boolean }) {
  return (
    <Flex
      align="center"
      gap={10}
      style={{ height: 'var(--fw-header-height)', padding: collapsed ? '0 16px' : '0 20px', overflow: 'hidden' }}
    >
      <span
        aria-hidden
        style={{
          width: 26,
          height: 26,
          flex: 'none',
          borderRadius: 6,
          border: '2px solid var(--fw-brand)',
          display: 'grid',
          placeItems: 'center',
          color: 'var(--fw-brand)',
          fontWeight: 700,
          fontSize: 13,
        }}
      >
        F
      </span>
      {!collapsed && (
        <Typography.Text strong style={{ fontSize: 15, whiteSpace: 'nowrap' }}>
          Firewall
        </Typography.Text>
      )}
    </Flex>
  )
}

export default function AppShell() {
  const location = useLocation()
  const navigate = useNavigate()
  const { isDark, toggleMode, density, toggleDensity } = useTheme()
  const { logout } = useAuth()
  const sse = useSse()
  const { notify } = useNotify()

  const isMobile = useIsBelow('md')
  const isNarrow = useIsBelow('lg')
  const [collapsedPref, setCollapsedPref] = usePersistentState<boolean>('firewall.sider.collapsed', false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)

  // 窄屏强制折叠（图标条），宽屏用用户偏好
  const collapsed = isNarrow ? true : collapsedPref

  useHotkey('mod+k', () => setPaletteOpen(true))
  useHotkey('mod+j', () => toggleMode())
  useHotkey('r', () => emitRefresh())

  // 路由变化时关闭移动抽屉
  useEffect(() => {
    setDrawerOpen(false)
  }, [location.pathname])

  const menuItems = useMemo<MenuProps['items']>(
    () =>
      NAV_GROUPS.map((group) => ({
        type: 'group' as const,
        label: group.title,
        children: group.items.map((item) => {
          const Icon = item.icon
          return {
            key: item.path,
            icon: <Icon />,
            label: item.label,
            title: item.label,
          }
        }),
      })),
    [],
  )

  const selectedKey = useMemo(() => {
    const p = location.pathname
    const match = NAV_ITEMS.find((item) => p === item.path || p.startsWith(`${item.path}/`))
    return match ? match.path : p
  }, [location.pathname])

  // --- 实时告警：仅在状态跃迁时推通知 ---
  const prevSseState = useRef<SseConnectionState>(sse.state)
  useEffect(() => {
    const prev = prevSseState.current
    const now = sse.state
    if (prev === now) return
    prevSseState.current = now
    if (now === 'limit') {
      notify({
        type: 'warning',
        title: '实时连接已达上限',
        message: '已降级为 REST 轮询刷新，数据仍会更新但不再秒级推送。',
        source: '实时流',
      })
    } else if (now === 'reconnecting' && prev === 'open') {
      notify({
        type: 'info',
        title: '实时连接中断，正在重连',
        message: '按退避策略自动重连；期间数据以轮询兜底。',
        source: '实时流',
      })
    } else if (now === 'open' && prev !== 'connecting' && prev !== 'idle') {
      notify({ type: 'success', title: '实时连接已恢复', source: '实时流' })
    }
  }, [sse.state, notify])

  const prevThreatRank = useRef<number>(-1)
  useEffect(() => {
    const level = sse.stats?.threat_level?.level
    if (!level) return
    const rank = threatRank(level)
    const prev = prevThreatRank.current
    if (prev === -1) {
      prevThreatRank.current = rank
      return
    }
    if (rank > prev) {
      notify({
        type: rank >= 3 ? 'error' : 'warning',
        title: `威胁等级升高至「${threatLabel(level)}」`,
        message: '请关注概览与封禁页的实时变化。',
        source: '威胁态势',
        link: '/dashboard',
      })
    }
    prevThreatRank.current = rank
  }, [sse.stats?.threat_level?.level, notify])

  const userMenu = useMemo<MenuProps['items']>(
    () => [
      {
        key: 'logout',
        icon: <LogoutOutlined />,
        label: '退出登录',
        danger: true,
        onClick: () => logout(),
      },
    ],
    [logout],
  )

  const onMenuClick: MenuProps['onClick'] = ({ key }) => navigate(key)

  const siderMenu = (
    <Menu
      mode="inline"
      theme={isDark ? 'dark' : 'light'}
      selectedKeys={[selectedKey]}
      items={menuItems}
      onClick={onMenuClick}
      inlineCollapsed={collapsed}
      style={{ borderInlineEnd: 'none', background: 'transparent' }}
    />
  )

  const collapseToggle = isMobile ? (
    <Tooltip title="打开导航">
      <Button type="text" icon={<MenuUnfoldOutlined />} onClick={() => setDrawerOpen(true)} aria-label="打开导航" />
    </Tooltip>
  ) : (
    <Tooltip title={collapsed ? '展开侧边栏' : '折叠侧边栏'}>
      <Button
        type="text"
        icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
        onClick={() => setCollapsedPref((c) => !c)}
        aria-label={collapsed ? '展开侧边栏' : '折叠侧边栏'}
      />
    </Tooltip>
  )

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {!isMobile && (
        <Sider
          theme={isDark ? 'dark' : 'light'}
          width={232}
          collapsedWidth={64}
          collapsed={collapsed}
          breakpoint={undefined}
          style={{ position: 'sticky', top: 0, height: '100vh', overflow: 'hidden', borderInlineEnd: '1px solid var(--fw-border)' }}
        >
          <Flex vertical style={{ height: '100%' }}>
            <BrandMark collapsed={collapsed} />
            <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>{siderMenu}</div>
            {!collapsed && (
              <div
                style={{
                  padding: '10px 20px',
                  borderTop: '1px solid var(--fw-border)',
                  fontSize: 11,
                  lineHeight: 1.9,
                  color: 'var(--fw-text-secondary)',
                  whiteSpace: 'nowrap',
                }}
              >
                <div>
                  <kbd className="fw-mono">R</kbd> 刷新当前页
                </div>
                <div>
                  <kbd className="fw-mono">{modLabel('K')}</kbd> 命令面板 ·{' '}
                  <kbd className="fw-mono">{modLabel('J')}</kbd> 切换主题
                </div>
              </div>
            )}
          </Flex>
        </Sider>
      )}

      {isMobile && (
        <Drawer
          placement="left"
          open={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          width={240}
          closable={false}
          styles={{ body: { padding: 0 } }}
        >
          <BrandMark collapsed={false} />
          {siderMenu}
        </Drawer>
      )}

      <Layout>
        <Header
          style={{
            position: 'sticky',
            top: 0,
            zIndex: 10,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            borderBottom: '1px solid var(--fw-border)',
          }}
        >
          {collapseToggle}

          <Button
            type="text"
            onClick={() => setPaletteOpen(true)}
            icon={<SearchOutlined />}
            style={{ color: 'var(--fw-text-secondary)', minWidth: 180, justifyContent: 'flex-start' }}
            aria-label="打开命令面板"
          >
            <span style={{ marginRight: 'auto', fontSize: 13 }}>搜索或输入命令</span>
            <kbd className="fw-mono" style={{ fontSize: 11, opacity: 0.7 }}>
              {isMobile ? 'K' : modLabel('K')}
            </kbd>
          </Button>

          <Flex align="center" gap={4} style={{ marginLeft: 'auto' }}>
            <RealtimeBadge state={sse.state} lastEventAt={sse.lastEventAt} showLabel={!isMobile} />
            <Tooltip title={isDark ? `切换到亮色 (${modLabel('J')})` : `切换到暗色 (${modLabel('J')})`}>
              <Button
                type="text"
                icon={isDark ? <BulbFilled /> : <BulbOutlined />}
                onClick={toggleMode}
                aria-label="切换主题"
              />
            </Tooltip>
            <Tooltip title={density === 'standard' ? '切换到紧凑密度' : '切换到标准密度'}>
              <Button
                type="text"
                icon={density === 'standard' ? <CompressOutlined /> : <ExpandOutlined />}
                onClick={toggleDensity}
                aria-label="切换密度"
              />
            </Tooltip>
            <NotificationCenter />
            <Dropdown menu={{ items: userMenu }} placement="bottomRight" trigger={['click']}>
              <Button type="text" icon={<UserOutlined />} aria-label="账户菜单" />
            </Dropdown>
          </Flex>
        </Header>

        <Content style={{ overflowX: 'hidden' }}>
          <div className="fw-app-content">
            <ErrorBoundary key={location.pathname}>
              <LoadingBoundary>
                <Outlet />
              </LoadingBoundary>
            </ErrorBoundary>
          </div>
        </Content>
      </Layout>

      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} onRefresh={emitRefresh} />
    </Layout>
  )
}

/**
 * 懒加载路由的 Suspense 兜底：切换页面时显示表格骨架而非空白。
 * 单独抽出来是为了让 ErrorBoundary 的 key（按路径复位）与 Suspense 各管一件事。
 */
function LoadingBoundary({ children }: { children: ReactNode }) {
  return (
    <Suspense fallback={<LoadingState variant="table" rows={8} />}>{children}</Suspense>
  )
}
