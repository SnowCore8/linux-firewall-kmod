import { createContext, useContext, useMemo, type ReactNode } from 'react'
import { useEventStream, type SseConnectionState, type SseSnapshot } from '../hooks/useSse.ts'
import { useAuth } from './AuthProvider.tsx'
import type {
  BanResponse,
  JailResponse,
  RateResponse,
  StatsResponse,
  WhitelistEntry,
} from '../api/types.ts'

/**
 * 实时流 Provider —— 把 `/api/v2/events` 的连接管理（useEventStream）挂到全局，
 * 全站只维持**一条** events 连接，各页按域订阅同一份快照。
 *
 * 为什么放 Provider 而不是每页各连一条：守护进程对 events 流有连接上限（10），多个标签/
 * 多个页面各连会很快撞上限被判 503。集中一条、按域分发，既省名额又让「实时灯」全站一致。
 *
 * 门禁约束：事件名字面量（connected/stats/bans/jails/whitelist/rates）住在 useSse.ts，
 * 本文件只消费它导出的快照，不重复声明事件名。
 *
 * 日志流（/api/v2/logs/stream）不在这里：它的事件名字面量按门禁要求必须落在 views/Logs.tsx，
 * 故由日志页自己接管那条连接（上限 5，独立退避）。
 */

/** 可订阅的五个数据域（与 useSse 的快照字段一一对应）。 */
export type SseDomain = 'stats' | 'bans' | 'jails' | 'whitelist' | 'rates'

/** 各域的值类型映射（供 useSseDomain 泛型推断）。 */
export interface SseDomainValue {
  stats: StatsResponse | null
  bans: BanResponse[] | null
  jails: JailResponse[] | null
  whitelist: WhitelistEntry[] | null
  rates: RateResponse[] | null
}

export interface SseContextValue extends SseSnapshot {
  /** 是否已建立可用连接（open）；用于决定是否降级到 REST 轮询。 */
  isLive: boolean
  /** 是否处于「连接数达上限」的降级态。 */
  isLimited: boolean
}

const SseContext = createContext<SseContextValue | null>(null)

export function SseProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth()
  const snapshot = useEventStream(isAuthenticated)

  const value = useMemo<SseContextValue>(
    () => ({
      ...snapshot,
      isLive: snapshot.state === 'open',
      isLimited: snapshot.state === 'limit',
    }),
    [snapshot],
  )

  return <SseContext.Provider value={value}>{children}</SseContext.Provider>
}

/** 取整份实时快照（含连接状态、各域值与 seq）。 */
export function useSse(): SseContextValue {
  const ctx = useContext(SseContext)
  if (!ctx) throw new Error('useSse 必须在 <SseProvider> 内使用')
  return ctx
}

/** 只取连接状态（实时灯 / 降级提示用），避免订阅整份快照导致无关域更新时重渲染。 */
export function useSseState(): SseConnectionState {
  return useSse().state
}

/**
 * 取单个域的「值 + 新鲜度序号」，喂给 useLiveData 做 SSE/REST 仲裁。
 * 泛型按域收窄：`useSseDomain('stats')` 得到 `StatsResponse | null`。
 */
export function useSseDomain<D extends SseDomain>(
  domain: D,
): { value: SseDomainValue[D]; seq: number } {
  const ctx = useContext(SseContext)
  if (!ctx) throw new Error('useSseDomain 必须在 <SseProvider> 内使用')
  return { value: ctx[domain], seq: ctx.seq[domain] }
}
