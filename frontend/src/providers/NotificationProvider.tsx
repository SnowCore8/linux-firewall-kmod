import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { App } from 'antd'

/**
 * 通知中心 Provider —— 非阻塞告警的汇聚点：既弹一次 toast，又进可回溯列表。
 *
 * 为什么两处都留：toast 只在弹出那一刻可见，运维可能正盯着别的页面错过它；列表让「刚才
 * 闪过去的那条」还能翻回来。安全事件（威胁升级、DDoS、SSE 断连）尤其不能只靠一闪而过的 toast。
 *
 * toast 用 AntD `App.useApp()` 拿到的**上下文感知**实例（主题/语言随 ConfigProvider），
 * 而非静态 `notification.xxx`——静态方法拿不到主题上下文，暗色下会渲染成亮色。因此本
 * Provider 必须挂在 AntD `<App>` 之内（见 app/App.tsx）。
 *
 * 列表只保留最近 MAX_ITEMS 条，FIFO 丢弃最旧的，避免长会话内存无界增长。
 */

export type NoticeType = 'info' | 'success' | 'warning' | 'error'

export interface NoticeItem {
  id: number
  type: NoticeType
  title: string
  message?: string
  /** 创建时刻（ms epoch）。 */
  at: number
  read: boolean
  /** 来源标签（如「实时流」「威胁态势」），便于在列表里归类。 */
  source?: string
  /** 点击可跳转的路由（如某 IP 的分析页）。 */
  link?: string
}

export interface NotificationContextValue {
  items: NoticeItem[]
  unreadCount: number
  /** 推一条通知：弹 toast + 进列表。返回新条目 id。 */
  notify: (input: Omit<NoticeItem, 'id' | 'at' | 'read'>) => number
  markAllRead: () => void
  markRead: (id: number) => void
  clear: () => void
  dismiss: (id: number) => void
}

const NotificationContext = createContext<NotificationContextValue | null>(null)

const MAX_ITEMS = 50

const TOAST_PLACEMENT = 'topRight' as const

export function NotificationProvider({ children }: { children: ReactNode }) {
  const { notification } = App.useApp()
  const [items, setItems] = useState<NoticeItem[]>([])
  const idRef = useRef(0)

  const notify = useCallback<NotificationContextValue['notify']>(
    (input) => {
      const id = ++idRef.current
      const item: NoticeItem = { ...input, id, at: Date.now(), read: false }
      setItems((prev) => [item, ...prev].slice(0, MAX_ITEMS))

      // 非阻塞 toast；带一个「知道了」以外的自动关闭时长，按严重程度区分
      const duration = input.type === 'error' ? 0 : input.type === 'warning' ? 6 : 4
      notification.open({
        type: input.type,
        message: input.title,
        description: input.message,
        placement: TOAST_PLACEMENT,
        duration,
        key: String(id),
      })
      return id
    },
    [notification],
  )

  const markAllRead = useCallback(() => {
    setItems((prev) => (prev.every((i) => i.read) ? prev : prev.map((i) => ({ ...i, read: true }))))
  }, [])

  const markRead = useCallback((id: number) => {
    setItems((prev) => prev.map((i) => (i.id === id ? { ...i, read: true } : i)))
  }, [])

  const clear = useCallback(() => setItems([]), [])

  const dismiss = useCallback((id: number) => {
    setItems((prev) => prev.filter((i) => i.id !== id))
    notification.destroy(String(id))
  }, [notification])

  const unreadCount = useMemo(() => items.filter((i) => !i.read).length, [items])

  const value = useMemo<NotificationContextValue>(
    () => ({ items, unreadCount, notify, markAllRead, markRead, clear, dismiss }),
    [items, unreadCount, notify, markAllRead, markRead, clear, dismiss],
  )

  return <NotificationContext.Provider value={value}>{children}</NotificationContext.Provider>
}

export function useNotify(): NotificationContextValue {
  const ctx = useContext(NotificationContext)
  if (!ctx) throw new Error('useNotify 必须在 <NotificationProvider> 内使用')
  return ctx
}
