/**
 * 异步取数资源：把「发起请求 → loading → 成功/失败 → 手动重取 → 可选轮询」
 * 收敛成一个由信号驱动的对象，取代原先的 `useAsync` hook。
 *
 * 与旧实现保持同一套语义（这些保证来自真实的移动端踩坑，不要简化掉）：
 * - 过期响应不覆盖后发请求的结果（每次取数带序号，只有最新序号的落定才写状态）
 * - 失败一律转成可展示的中文文案，绝不吞掉
 * - 轮询在页面切到后台（`document.hidden`）时暂停，回到前台立即补一次
 * - 上一次取数未返回时跳过本次轮询触发，避免慢查询下请求堆积
 * - `skipWhen` 命中时**不覆盖**已有数据：分区式页面在未激活分区里返回哨兵值，
 *   若照常写入，切走再切回就会把已取到的数据清空，表现为「切个 tab 就闪骨架」
 *
 * 使用方式：在渲染函数里读 `resource.state.get()`，并在 `effect` 中调用 `start()`
 * 拿到停止函数（视图销毁时执行）。
 */

import { nextFreshnessStamp } from '../hooks/freshness'
import type { ReadonlySignal } from '../lib/signals'
import { effect, signal } from '../lib/signals'

/** 资源对外暴露的状态快照 */
export interface AsyncState<T> {
  /** 最近一次成功的数据；未加载完成或失败时为 null */
  data: T | null
  /** 是否正在请求中（重取时保留上一次数据，避免界面闪空） */
  loading: boolean
  /** 失败原因（已转成可读文案）；成功时为 null */
  error: string | null
  /**
   * 本份数据的新鲜度戳：每次成功写入 `data` 取一个全局单调戳
   * （见 [`nextFreshnessStamp`](../hooks/freshness.ts)）。**不参与渲染取值**，
   * 只作「谁更新」的序关系，供实时载荷与 REST 快照的比较使用。
   */
  dataSeq: number
  /** 手动重新取数；返回的 Promise 在本次取数落定（成功或失败）后才 resolve */
  reload: () => Promise<void>
}

export interface AsyncOptions<T> {
  /** 首帧占位数据，用于在实时推送到达前渲染骨架 */
  initial?: T | null
  /**
   * 轮询间隔（毫秒），也可以是一个读取函数——传入读信号的函数时，
   * 配置变化会自动重排定时器。只用于**没有实时推送**的数据：已有推送的域
   * 若同时轮询，两条来源会互相覆盖。
   */
  pollMs?: number | (() => number)
  /** 「本次不需要该数据」的哨兵值，见文件头说明 */
  skipWhen?: T
}

/** 一个可启动、可停止、可手动重取的取数资源 */
export interface AsyncResource<T> {
  /** 当前状态（只读信号，可被 `effect` 订阅） */
  readonly state: ReadonlySignal<AsyncState<T>>
  /** 启动首取与轮询，返回停止函数（清定时器并丢弃在飞响应） */
  start(): () => void
  /** 立即重取一次，Promise 在落定后 resolve */
  reload(): Promise<void>
}

/** 把任意抛出物转成可展示文案（`ApiError.message` 已是后端原文） */
function toMessage(err: unknown): string {
  if (err instanceof Error && err.message) return err.message
  if (typeof err === 'string' && err) return err
  return '请求失败，请稍后重试'
}

/**
 * @param fn 取数函数（异常由本资源捕获）
 * @param opts 见 [`AsyncOptions`]
 */
export function createAsync<T>(fn: () => Promise<T>, opts?: AsyncOptions<T>): AsyncResource<T> {
  const state = signal<AsyncState<T>>({
    data: opts?.initial ?? null,
    loading: true,
    error: null,
    dataSeq: 0,
    reload,
  })

  // 每次取数分配一个序号，只有最新序号的结果允许写入（丢弃过期响应）
  let requestSeq = 0
  // 是否有取数在飞（轮询据此跳过重叠触发）
  let inFlight = false
  // 本次取数的落定回调，由 reload 挂上，供「等数据真的到齐」的交互使用
  let settle: (() => void) | null = null
  let timer: number | null = null
  let stopped = false

  function patch(next: Partial<AsyncState<T>>): void {
    state.update((current) => ({ ...current, ...next, reload }))
  }

  /** 通知等待者本次取数已落定（先清空，避免重复调用） */
  function finish(): void {
    const done = settle
    settle = null
    if (done) done()
  }

  function load(): Promise<void> {
    const seq = ++requestSeq
    inFlight = true
    patch({ loading: true, error: null })

    return new Promise<void>((resolve) => {
      settle = resolve
      fn().then(
        (value) => {
          if (seq !== requestSeq || stopped) {
            // 已被更新的请求取代：不写状态，但必须落定，否则 reload 会一直挂着
            finish()
            return
          }
          if (value === opts?.skipWhen) {
            // 「本次不需要该数据」：保留已有数据，也不消耗新鲜度戳
            inFlight = false
            patch({ loading: false })
            finish()
            return
          }
          inFlight = false
          patch({ data: value, loading: false, error: null, dataSeq: nextFreshnessStamp() })
          finish()
        },
        (err) => {
          if (seq !== requestSeq || stopped) {
            finish()
            return
          }
          inFlight = false
          patch({ loading: false, error: toMessage(err) })
          finish()
        },
      )
    })
  }

  function reload(): Promise<void> {
    return load()
  }

  function readPollMs(): number {
    const configured = opts?.pollMs
    if (configured === undefined) return 0
    return typeof configured === 'function' ? configured() : configured
  }

  /** 按当前间隔（重新）排定轮询；间隔为 0 表示不轮询 */
  function schedule(): void {
    if (timer !== null) {
      window.clearInterval(timer)
      timer = null
    }
    const ms = readPollMs()
    if (stopped || ms <= 0) return
    timer = window.setInterval(() => {
      // 后台标签页停摆可省电；上次未返回时跳过，避免慢查询堆积
      if (document.hidden || inFlight) return
      void load()
    }, ms)
  }

  /** 回到前台时立即补一次，避免用户切回来看到停留在旧值的看板 */
  function onVisible(): void {
    if (document.hidden || inFlight || stopped) return
    void load()
  }

  function start(): () => void {
    const stopPoll = effect(() => {
      schedule()
    })
    document.addEventListener('visibilitychange', onVisible)
    void load()

    return () => {
      stopped = true
      stopPoll()
      document.removeEventListener('visibilitychange', onVisible)
      if (timer !== null) {
        window.clearInterval(timer)
        timer = null
      }
      finish()
    }
  }

  return {
    state,
    start,
    reload,
  }
}
