// 命令面板：一处输入即可跳转任意页面（受控件：可用 Ctrl / Cmd + K 唤起）
//
// 交互约定：
//   - 打开方式：Ctrl/Cmd+K（组件内自行注册，全局生效），或由父组件控制 open 打开
//   - 键盘：↑/↓ 移动光标、Enter 执行、Esc 关闭（事件从 SearchBar 的 input 冒泡到内容区）
//   - 触摸：每条命令整行可点（≥44px），手机端无需键盘也能用
//
// 受控/非受控两种用法都支持（两种写法都能编过，避免调用方被绑死）：
//   <CommandPalette />                                  ← 非受控，仅热键
//   <CommandPalette open={open} onOpenChange={setOpen} /> ← 受控，可由顶栏按钮打开
import { Popup, SearchBar } from 'antd-mobile'
import type { InputRef } from 'antd-mobile'
import {
  AppOutline,
  CheckShieldOutline,
  FileOutline,
  HistogramOutline,
  LockOutline,
  MoreOutline,
  SearchOutline,
  SetOutline,
  UnorderedListOutline,
} from 'antd-mobile-icons'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

import { useTheme } from '../hooks/useTheme'
import { EmptyState } from './EmptyState'

export interface CommandPaletteProps {
  /** 受控打开状态；不传则由组件内部维护（配合热键） */
  open?: boolean
  /** 打开状态变化回调；受控/非受控都会触发 */
  onOpenChange?: (open: boolean) => void
}

interface PaletteCommand {
  /** 稳定唯一 id，同时作为路径类命令的跳转目标 */
  id: string
  title: string
  description: string
  /** 额外检索词（中文别名 / 英文名 / 路径片段） */
  keywords: string
  /** 行首图标；antd-mobile-icons 无主题类图标，动作类命令可以不传 */
  icon?: ReactNode
  run: () => void
}

/**
 * 计算某条命令对当前查询的匹配得分。
 * 返回 null 表示不匹配（多词查询按「全部命中」处理，即 AND 语义）。
 * 权重：标题前缀 > 标题包含 > 其它字段包含，让最相关的命令排在前面。
 */
function scoreCommand(command: PaletteCommand, tokens: string[]): number | null {
  const title = command.title.toLowerCase()
  const haystack =
    `${title} ${command.description.toLowerCase()} ${command.keywords.toLowerCase()} ${command.id}`.toLowerCase()

  let score = 0
  for (const token of tokens) {
    if (title.startsWith(token)) score += 3
    else if (title.includes(token)) score += 2
    else if (haystack.includes(token)) score += 1
    else return null
  }
  return score
}

const ICON_STYLE: CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: 17,
  height: 17,
  flexShrink: 0,
  fontSize: 16,
  color: 'var(--fw-text-3)',
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate()
  const { theme, toggle } = useTheme()

  const [internalOpen, setInternalOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)

  const searchRef = useRef<InputRef>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const isControlled = open !== undefined
  const visible = open ?? internalOpen

  /** 统一的开关入口：受控时只通知父组件，非受控时同时更新内部状态 */
  const changeOpen = useCallback(
    (next: boolean) => {
      if (!isControlled) setInternalOpen(next)
      onOpenChange?.(next)
    },
    [isControlled, onOpenChange],
  )

  const go = useCallback(
    (path: string) => {
      navigate(path)
      changeOpen(false)
    },
    [changeOpen, navigate],
  )

  const commands = useMemo<PaletteCommand[]>(() => {
    const entries: [string, string, string, string, ReactNode][] = [
      ['/dashboard', '仪表盘', '总览、威胁等级与今日封禁', 'dashboard 首页 概览 统计', <AppOutline key="i" />],
      ['/bans', '封禁管理', '查看、新增、解封被封 IP', 'bans ban 封禁 ip 黑名单 解封', <LockOutline key="i" />],
      ['/whitelist', '白名单', '可信 IP 与网段管理', 'whitelist 白名单 cidr 可信 放行', <CheckShieldOutline key="i" />],
      ['/ddos', 'DDoS 监控', '实时速率、协议分布与攻击面', 'ddos 速率 pps 流量 攻击 syn', <HistogramOutline key="i" />],
      ['/jails', 'Jail 管理', '日志源、阈值与启用开关', 'jail 阈值 开关 日志源', <UnorderedListOutline key="i" />],
      ['/logs', '日志', '日志检索与实时跟踪', 'logs 日志 检索 跟踪', <FileOutline key="i" />],
      ['/settings', '设置', '阈值、容量与检测开关', 'settings 设置 配置 阈值 容量', <SetOutline key="i" />],
      ['/more', '更多', '二级功能入口', 'more 更多 其它 其他', <MoreOutline key="i" />],
    ]

    const list: PaletteCommand[] = entries.map(([path, title, description, keywords, icon]) => ({
      id: path,
      title,
      description,
      keywords,
      icon,
      run: () => go(path),
    }))

    // 动作类命令（并非页面跳转）一并纳入，统一检索。
    // 不配图标：antd-mobile-icons 里没有主题/外观类图标，留空比用错图标更好。
    list.push({
      id: 'toggle-theme',
      title: theme === 'dark' ? '切换到浅色主题' : '切换到深色主题',
      description: `当前：${theme === 'dark' ? '深色' : '浅色'}主题`,
      keywords: 'theme 主题 深色 浅色 夜间 外观',
      run: () => {
        toggle()
        changeOpen(false)
      },
    })

    return list
  }, [changeOpen, go, theme, toggle])

  const filtered = useMemo(() => {
    const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
    if (tokens.length === 0) return commands

    return commands
      .map((command) => ({ command, score: scoreCommand(command, tokens) }))
      .filter((entry): entry is { command: PaletteCommand; score: number } => entry.score !== null)
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.command)
  }, [commands, query])

  // 全局热键：Ctrl/Cmd + K 切换面板。带修饰键，输入框内打字也不会误触发。
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'k') return
      event.preventDefault()
      changeOpen(!(open ?? internalOpen))
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [changeOpen, internalOpen, open])

  // 每次打开重置查询与光标，避免上次的搜索结果残留
  useEffect(() => {
    if (!visible) return
    setQuery('')
    setCursor(0)
  }, [visible])

  // 光标越界保护：过滤结果变短（边输入边过滤）时把光标夹回合法范围
  useEffect(() => {
    setCursor((prev) => (prev >= filtered.length ? Math.max(filtered.length - 1, 0) : prev))
  }, [filtered.length])

  // 光标移动后把当前项滚进可视区（键盘上下键操作时不会跑到屏幕外）
  useEffect(() => {
    const active = listRef.current?.querySelector<HTMLElement>('[data-active="true"]')
    active?.scrollIntoView({ block: 'nearest' })
  }, [cursor, filtered])

  const close = useCallback(() => changeOpen(false), [changeOpen])

  const onContentKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        close()
        return
      }
      if (event.key === 'ArrowDown') {
        event.preventDefault()
        if (filtered.length > 0) setCursor((prev) => (prev + 1) % filtered.length)
        return
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault()
        if (filtered.length > 0) setCursor((prev) => (prev - 1 + filtered.length) % filtered.length)
        return
      }
      if (event.key === 'Enter') {
        event.preventDefault()
        filtered[cursor]?.run()
      }
    },
    [close, cursor, filtered],
  )

  return (
    <Popup
      visible={visible}
      position="top"
      // 关闭路径只走 onMaskClick 一条：避免与 closeOnMaskClick 双触发
      closeOnMaskClick={false}
      onMaskClick={close}
      // 展示动画结束后再聚焦，把手机软键盘直接带出来（不依赖固定延时）
      afterShow={() => searchRef.current?.focus()}
      bodyStyle={{
        display: 'flex',
        flexDirection: 'column',
        maxHeight: '76vh',
        paddingTop: 'calc(var(--fw-safe-top) + 5px)',
        paddingBottom: 5,
        borderBottomLeftRadius: 10,
        borderBottomRightRadius: 10,
        background: 'var(--fw-surface)',
      }}
    >
      <div onKeyDown={onContentKeyDown} style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <SearchBar
          ref={searchRef}
          value={query}
          onChange={setQuery}
          placeholder="搜索页面或操作…（Ctrl / ⌘ + K）"
          searchIcon={<SearchOutline />}
          style={{ '--background': 'var(--fw-surface-hi)' }}
        />

        <div
          ref={listRef}
          role="listbox"
          aria-label="命令列表"
          style={{ overflowY: 'auto', WebkitOverflowScrolling: 'touch', padding: '2px 5px 0' }}
        >
          {filtered.length === 0 ? (
            <EmptyState
              compact
              title="没有匹配的命令"
              description={`未找到与「${query.trim()}」相关的页面或操作`}
            />
          ) : (
            filtered.map((command, index) => {
              const active = index === cursor
              return (
                <div
                  key={command.id}
                  role="option"
                  aria-selected={active}
                  data-active={active ? 'true' : 'false'}
                  onClick={command.run}
                  onMouseEnter={() => setCursor(index)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    minHeight: 'var(--fw-tap)',
                    padding: '4px 6px',
                    borderRadius: 'var(--fw-radius-sm)',
                    cursor: 'pointer',
                    background: active ? 'var(--fw-primary-soft)' : 'transparent',
                  }}
                >
                  <span style={{ ...ICON_STYLE, color: active ? 'var(--fw-primary-strong)' : 'var(--fw-text-3)' }}>
                    {command.icon}
                  </span>
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span
                      style={{
                        display: 'block',
                        fontSize: 14,
                        fontWeight: 500,
                        color: active ? 'var(--fw-primary-strong)' : 'var(--fw-text)',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {command.title}
                    </span>
                    <span
                      style={{
                        display: 'block',
                        fontSize: 12,
                        color: 'var(--fw-text-3)',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {command.description}
                    </span>
                  </span>
                  {command.id.startsWith('/') ? (
                    <span className="fw-mono" style={{ fontSize: 11, color: 'var(--fw-text-3)', flexShrink: 0 }}>
                      {command.id}
                    </span>
                  ) : null}
                </div>
              )
            })
          )}
        </div>
      </div>
    </Popup>
  )
}

export default CommandPalette
