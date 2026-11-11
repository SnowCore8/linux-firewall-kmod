import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react'
import { Input, Modal, Tag, Typography, type InputRef } from 'antd'
import {
  EnterOutlined,
  SearchOutlined,
  SwapOutlined,
  LogoutOutlined,
  PlusOutlined,
  SyncOutlined,
  CompressOutlined,
} from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { NAV_ITEMS, type NavIcon } from '../app/nav.ts'
import { useTheme } from '../providers/ThemeProvider.tsx'
import { useAuth } from '../providers/AuthProvider.tsx'
import { useSseConnection } from '../providers/SseProvider.tsx'

/**
 * 命令面板（Ctrl/Cmd+K）—— 键盘全可达的跳转 + 快捷动作入口。
 *
 * 一个输入框统一两类命令：页面跳转（来自 nav.ts，模糊匹配 label/keywords）与快捷动作
 * （新建封禁、同步情报、切主题/密度、登出）。↑↓ 选择、Enter 执行、Esc 关闭——手不离键盘
 * 就能在多页控制台里穿梭，这对安全运维（经常要快速跳到某页再动手）是核心效率项。
 *
 * 快捷动作用「导航 + 查询参数」表达意图（如 /bans?new=1 让封禁页自动开新建弹窗），
 * 避免命令面板直接持有各页的弹窗状态——那会让它和每个页面强耦合。
 */

interface Command {
  id: string
  label: string
  group: string
  hint?: string
  keywords: string
  icon: NavIcon
  run: () => void
}

export interface CommandPaletteProps {
  open: boolean
  onClose: () => void
  /** 手动触发一次全局刷新（各页把 refetch 注册进来）。 */
  onRefresh?: () => void
}

/** 极简模糊匹配：子串命中即可，label 前缀命中排在前面。 */
function score(query: string, cmd: Command): number {
  if (!query) return 0
  const q = query.toLowerCase()
  const label = cmd.label.toLowerCase()
  if (label === q) return 100
  if (label.startsWith(q)) return 80
  if (label.includes(q)) return 60
  if (cmd.keywords.includes(q)) return 40
  if (cmd.keywords.split(' ').some((k) => k.startsWith(q))) return 30
  return -1
}

export function CommandPalette({ open, onClose, onRefresh }: CommandPaletteProps) {
  const navigate = useNavigate()
  const { toggleMode, toggleDensity, isDark, density } = useTheme()
  const { logout } = useAuth()
  const sseConn = useSseConnection()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const listRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<InputRef>(null)

  const commands = useMemo<Command[]>(() => {
    const go = (path: string): Command['run'] => () => {
      navigate(path)
      onClose()
    }
    const pageCmds: Command[] = NAV_ITEMS.map((item) => ({
      id: `nav:${item.path}`,
      label: item.label,
      group: '跳转到',
      hint: item.description,
      keywords: [item.path, ...(item.keywords ?? [])].join(' '),
      icon: item.icon,
      run: go(item.path),
    }))

    const actionCmds: Command[] = [
      {
        id: 'act:new-ban',
        label: '新建封禁',
        group: '快捷动作',
        keywords: 'ban new 封禁 新建 加黑',
        icon: PlusOutlined,
        run: () => {
          navigate('/bans?new=1')
          onClose()
        },
      },
      {
        id: 'act:sync-feeds',
        label: '同步威胁情报',
        group: '快捷动作',
        keywords: 'threat sync 情报 同步 刷新',
        icon: SyncOutlined,
        run: () => {
          navigate('/threat-feeds?sync=1')
          onClose()
        },
      },
      {
        id: 'act:refresh',
        label: '刷新当前页数据',
        group: '快捷动作',
        hint: onRefresh ? undefined : '当前页未提供刷新',
        keywords: 'refresh reload 刷新',
        icon: SyncOutlined,
        run: () => {
          onRefresh?.()
          onClose()
        },
      },
      {
        id: 'act:theme',
        label: isDark ? '切换到亮色主题' : '切换到暗色主题',
        group: '外观',
        keywords: 'theme dark light 主题 暗 亮',
        icon: SwapOutlined,
        run: () => {
          toggleMode()
          onClose()
        },
      },
      {
        id: 'act:density',
        label: density === 'standard' ? '切换到紧凑密度' : '切换到标准密度',
        group: '外观',
        keywords: 'density compact 密度 紧凑',
        icon: CompressOutlined,
        run: () => {
          toggleDensity()
          onClose()
        },
      },
      {
        id: 'act:logout',
        label: '退出登录',
        group: '账户',
        hint: sseConn.isLive ? '实时流将断开' : undefined,
        keywords: 'logout signout 登出 退出',
        icon: LogoutOutlined,
        run: () => {
          logout()
          onClose()
        },
      },
    ]

    return [...actionCmds, ...pageCmds]
  }, [navigate, onClose, onRefresh, isDark, density, toggleMode, toggleDensity, logout, sseConn.isLive])

  const filtered = useMemo(() => {
    const scored = commands
      .map((cmd) => ({ cmd, s: score(query.trim(), cmd) }))
      .filter((x) => x.s >= 0)
    scored.sort((a, b) => b.s - a.s)
    return scored.map((x) => x.cmd)
  }, [commands, query])

  // 打开时复位输入与选中项，并聚焦输入框
  useEffect(() => {
    if (open) {
      setQuery('')
      setActive(0)
      const t = window.setTimeout(() => inputRef.current?.focus(), 0)
      return () => window.clearTimeout(t)
    }
  }, [open])

  // 选中项变化时滚进可视区
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [active, filtered.length])

  // 按 group 分段渲染
  const grouped = useMemo(() => {
    const order: string[] = []
    const map = new Map<string, Command[]>()
    for (const cmd of filtered) {
      if (!map.has(cmd.group)) {
        map.set(cmd.group, [])
        order.push(cmd.group)
      }
      map.get(cmd.group)!.push(cmd)
    }
    return order.map((g) => ({ group: g, items: map.get(g)! }))
  }, [filtered])

  // 渲染顺序 = 分组后展平。选中态、Enter 执行、aria-activedescendant 都必须用这个顺序：
  // 同组项在按分数排序的 filtered 里可能不连续，分组会把它们聚拢，两个顺序就此错位——
  // 若仍用 filtered[active] 执行，Enter 会跑到另一条命令上（防火墙控制台里可能误触登出/封禁）。
  const ordered = useMemo(() => grouped.flatMap((s) => s.items), [grouped])

  const runActive = () => {
    const cmd = ordered[active]
    if (cmd) cmd.run()
  }

  const onKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((i) => (ordered.length === 0 ? 0 : (i + 1) % ordered.length))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((i) => (ordered.length === 0 ? 0 : (i - 1 + ordered.length) % ordered.length))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      runActive()
    }
  }

  // 预计算每个分组起始的 flat index，避免渲染期间变异
  const groupStartIndex = useMemo(() => {
    const starts = new Map<string, number>()
    let acc = 0
    for (const section of grouped) {
      starts.set(section.group, acc)
      acc += section.items.length
    }
    return starts
  }, [grouped])

  return (
    <Modal
      open={open}
      onCancel={onClose}
      footer={null}
      closable={false}
      width={560}
      styles={{ body: { padding: 0 } }}
      style={{ top: 96 }}
      destroyOnHidden
    >
      <div style={{ padding: 12, borderBottom: '1px solid var(--fw-border)' }}>
        <Input
          ref={inputRef}
          size="large"
          variant="borderless"
          prefix={<SearchOutlined style={{ color: 'var(--fw-text-secondary)' }} />}
          placeholder="搜索页面或执行命令…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value)
            setActive(0)
          }}
          onKeyDown={onKeyDown}
          aria-label="命令面板搜索"
          role="combobox"
          aria-expanded={open}
          aria-controls="fw-cmd-listbox"
          aria-haspopup="listbox"
          aria-autocomplete="list"
          aria-describedby="fw-cmd-hints"
          aria-activedescendant={
            ordered.length > 0 ? `fw-cmd-option-${Math.min(active, ordered.length - 1)}` : undefined
          }
        />
      </div>
      <div
        ref={listRef}
        id="fw-cmd-listbox"
        style={{ maxHeight: 380, overflowY: 'auto', padding: '6px 0' }}
        role="listbox"
        aria-label="命令列表"
      >
        {filtered.length === 0 ? (
          <Typography.Text type="secondary" style={{ display: 'block', padding: 24, textAlign: 'center' }}>
            没有匹配的命令
          </Typography.Text>
        ) : (
          grouped.map((section) => (
            <div key={section.group}>
              <Typography.Text
                type="secondary"
                style={{ display: 'block', padding: '8px 14px 4px', fontSize: 11, letterSpacing: 0.5 }}
              >
                {section.group}
              </Typography.Text>
              {section.items.map((cmd, itemIdx) => {
                const index = (groupStartIndex.get(section.group) ?? 0) + itemIdx
                const isActive = index === active
                const Icon = cmd.icon
                return (
                  <div
                    key={cmd.id}
                    id={`fw-cmd-option-${index}`}
                    data-index={index}
                    role="option"
                    aria-selected={isActive}
                    onClick={cmd.run}
                    onMouseEnter={() => setActive(index)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      padding: '8px 14px',
                      cursor: 'pointer',
                      background: isActive
                        ? 'color-mix(in srgb, var(--fw-brand) 14%, transparent)'
                        : 'transparent',
                      borderInlineStart: `2px solid ${isActive ? 'var(--fw-brand)' : 'transparent'}`,
                    }}
                  >
                    <Icon style={{ fontSize: 15, color: isActive ? 'var(--fw-brand)' : 'var(--fw-text-secondary)' }} />
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <Typography.Text strong={isActive} style={{ fontSize: 13 }}>
                        {cmd.label}
                      </Typography.Text>
                      {cmd.hint && (
                        <Typography.Text
                          type="secondary"
                          ellipsis
                          style={{ display: 'block', fontSize: 11 }}
                        >
                          {cmd.hint}
                        </Typography.Text>
                      )}
                    </span>
                    {isActive && (
                      <Tag icon={<EnterOutlined />} bordered={false} style={{ marginInlineEnd: 0 }}>
                        Enter
                      </Tag>
                    )}
                  </div>
                )
              })}
            </div>
          ))
        )}
      </div>
      {/* 键盘提示的可访问副本：视觉提示行屏幕阅读器读不到顺序语义，这里给输入框一段
          aria-describedby 关联的完整说明（含 Esc 关闭），焦点进入时一并播报。 */}
      <span id="fw-cmd-hints" className="fw-sr-only">
        命令面板按键：上下方向键选择命令，Enter 执行当前命令，Esc 关闭命令面板；也可直接输入关键词搜索。
      </span>
      <div
        aria-hidden
        style={{
          padding: '8px 14px',
          borderTop: '1px solid var(--fw-border)',
          display: 'flex',
          gap: 16,
          fontSize: 11,
          color: 'var(--fw-text-secondary)',
        }}
      >
        <span>↑↓ 选择</span>
        <span><EnterOutlined /> 执行</span>
        <span>Esc 关闭</span>
      </div>
    </Modal>
  )
}
