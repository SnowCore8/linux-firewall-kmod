import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useRef,
  useSyncExternalStore,
  type ReactNode,
} from 'react'
import {
  INITIAL_SNAPSHOT,
  useEventStream,
  type SseConnectionState,
  type SseSnapshot,
} from '../hooks/useSse.ts'
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
 * 为什么不用 context 下发整份快照：快照随帧变化（每秒最多 5 次），context value 一变，
 * **所有**消费者连同整棵子树都要重渲染。这里改成外部 store + useSyncExternalStore：
 * 订阅方只在自己那一项真的变了时才重渲染——连接态只在跃迁时换引用，域数据只在该域更新时
 * 换引用，逐帧变化的「最近一帧时刻」只喂给真正显示「x 秒前」的徽标。Provider 自己仍会随帧
 * 重渲染，但它只渲染一个 value 恒定的 context，children 元素引用不变，子树不会被带动。
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

/** 单个域的「值 + 新鲜度序号」。 */
export type SseDomainSlice<D extends SseDomain> = { value: SseDomainValue[D]; seq: number }

/** 连接生命周期摘要——只在状态跃迁（或重试计数）时换成新引用。 */
export interface SseConnectionInfo {
  state: SseConnectionState
  /** 是否已建立可用连接（open）；用于决定是否降级到 REST 轮询。 */
  isLive: boolean
  /** 是否处于「连接数达上限」的降级态。 */
  isLimited: boolean
  /** 是否处于「重连次数耗尽」态（需用户手动重连）。 */
  isExhausted: boolean
  /** 已尝试的重连次数（成功连通后归零）。 */
  attempts: number
  /** 进入断开态的时刻（Date.now()）；0 表示未断开。 */
  disconnectedAt: number
  /** 手动重连：清零退避计数并立即重探（供降级后的用户主动重试）。 */
  reconnect: () => void
}

/** 逐帧变化的新鲜度——只给真正显示「x 秒前」的叶子组件订阅。 */
export interface SseFreshness {
  /** 最近一帧到达的时刻（Date.now()）；用于「数据新鲜度」指示。 */
  lastEventAt: number
  /** 进入断开态的时刻（Date.now()）；用于显示「已断开 X 分钟」。0 表示未断开。 */
  disconnectedAt: number
}

const SSE_DOMAINS: SseDomain[] = ['stats', 'bans', 'jails', 'whitelist', 'rates']

/** 域 → 缓存切片的内部形状；具体值类型在 hook 出口处按域收窄，存储层不必区分。 */
type SseSliceCache = Record<SseDomain, { value: unknown; seq: number }>

/**
 * 外部 store：快照的唯一真实来源。
 *
 * useSyncExternalStore 要求「数据没变时必须返回同一个引用」，所以连接摘要、新鲜度、每个域的
 * 切片都在 publish 里预先缓存好：只有对应字段真的变了才换对象，其余保持原引用，订阅者由此
 * 得到天然的细粒度唤醒——这正是它取代 context 的意义。
 */
interface SseStore {
  subscribe: (listener: () => void) => () => void
  getState: () => SseConnectionState
  getConnection: () => SseConnectionInfo
  getFreshness: () => SseFreshness
  getDomain: (domain: SseDomain) => SseSliceCache[SseDomain]
  publish: (next: SseSnapshot) => void
  setReconnect: (fn: () => void) => void
}

function createSseStore(initial: SseSnapshot): SseStore {
  let snapshot = initial
  const listeners = new Set<() => void>()

  // 手动重连的回调每次渲染都是新引用（useCallback 依赖 connect）；用一个稳定的转发函数兜住，
  // 否则连接摘要会被误判成「变了」，订阅方跟着白重渲染。
  let reconnectRef: () => void = () => {}
  const reconnect = () => reconnectRef()

  const buildConnection = (s: SseSnapshot): SseConnectionInfo => ({
    state: s.state,
    isLive: s.state === 'open',
    isLimited: s.state === 'limit',
    isExhausted: s.state === 'exhausted',
    attempts: s.attempts,
    disconnectedAt: s.disconnectedAt,
    reconnect,
  })

  let connection = buildConnection(snapshot)
  let freshness: SseFreshness = {
    lastEventAt: snapshot.lastEventAt,
    disconnectedAt: snapshot.disconnectedAt,
  }
  const slices: SseSliceCache = {
    stats: { value: snapshot.stats, seq: snapshot.seq.stats },
    bans: { value: snapshot.bans, seq: snapshot.seq.bans },
    jails: { value: snapshot.jails, seq: snapshot.seq.jails },
    whitelist: { value: snapshot.whitelist, seq: snapshot.seq.whitelist },
    rates: { value: snapshot.rates, seq: snapshot.seq.rates },
  }

  return {
    subscribe(listener) {
      listeners.add(listener)
      // 退订与订阅严格配对：StrictMode 的双挂载会依次 subscribe → unsubscribe → subscribe
      return () => listeners.delete(listener)
    },
    getState: () => snapshot.state,
    getConnection: () => connection,
    getFreshness: () => freshness,
    getDomain: (domain) => slices[domain],
    publish(next) {
      const prev = snapshot
      if (next === prev) return
      snapshot = next

      if (
        next.state !== prev.state ||
        next.attempts !== prev.attempts ||
        next.disconnectedAt !== prev.disconnectedAt
      ) {
        connection = buildConnection(next)
      }
      if (next.lastEventAt !== prev.lastEventAt || next.disconnectedAt !== prev.disconnectedAt) {
        freshness = { lastEventAt: next.lastEventAt, disconnectedAt: next.disconnectedAt }
      }
      for (const domain of SSE_DOMAINS) {
        if (next[domain] !== prev[domain] || next.seq[domain] !== prev.seq[domain]) {
          slices[domain] = { value: next[domain], seq: next.seq[domain] }
        }
      }

      // 先快照监听器再逐个通知：监听器在回调里退订不会影响本轮遍历
      for (const listener of [...listeners]) listener()
    },
    setReconnect(fn) {
      reconnectRef = fn
    },
  }
}

/** 由 Provider 提供的 store 句柄；对象本身恒定，所以它作为 context 不会引发任何重渲染。 */
const SseStoreContext = createContext<SseStore | null>(null)

export function SseProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth()
  const { reconnect, ...snapshot } = useEventStream(isAuthenticated)

  const storeRef = useRef<SseStore | null>(null)
  if (storeRef.current === null) storeRef.current = createSseStore(INITIAL_SNAPSHOT)
  const store = storeRef.current

  store.setReconnect(reconnect)

  // 用 layout effect 灌快照：子组件先按上一帧的数据渲染，提交前同步写入并通知订阅者，
  // 不会出现「先画旧值、再闪一次」；也不必把整份快照塞进 context。
  useLayoutEffect(() => {
    store.publish(snapshot)
  })

  return <SseStoreContext.Provider value={store}>{children}</SseStoreContext.Provider>
}

function useSseStore(): SseStore {
  const store = useContext(SseStoreContext)
  if (!store) throw new Error('useSse* 必须在 <SseProvider> 内使用')
  return store
}

/**
 * 只取连接状态（实时灯 / 降级提示用）。
 * 只在状态跃迁时返回新值，帧到达本身不会唤起重渲染。
 */
export function useSseState(): SseConnectionState {
  const store = useSseStore()
  return useSyncExternalStore(store.subscribe, store.getState, store.getState)
}

/** 取连接生命周期摘要（状态 + 降级标志 + 手动重连）；同样只在跃迁时重渲染。 */
export function useSseConnection(): SseConnectionInfo {
  const store = useSseStore()
  return useSyncExternalStore(store.subscribe, store.getConnection, store.getConnection)
}

/** 取逐帧变化的新鲜度；只给实时徽标这类叶子组件用。 */
export function useSseFreshness(): SseFreshness {
  const store = useSseStore()
  return useSyncExternalStore(store.subscribe, store.getFreshness, store.getFreshness)
}

/**
 * 取单个域的「值 + 新鲜度序号」，喂给 useLiveData 做 SSE/REST 仲裁。
 * 泛型按域收窄：`useSseDomain('stats')` 得到 `StatsResponse | null`。
 * 只有该域自己更新时才换引用，别的域推帧不会唤起重渲染。
 */
export function useSseDomain<D extends SseDomain>(domain: D): SseDomainSlice<D> {
  const store = useSseStore()
  const getSlice = useCallback(
    () => store.getDomain(domain) as SseDomainSlice<D>,
    [store, domain],
  )
  return useSyncExternalStore(store.subscribe, getSlice, getSlice)
}
