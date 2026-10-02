/**
 * 极简响应式核心。
 *
 * 运行时没有虚拟 DOM，刷新语义是「订阅者重跑一次渲染函数」，因此只需要
 * 「信号 + 副作用」这一对原语：信号持有值并记录读过它的副作用；副作用每次重跑时
 * 重新收集依赖，因此依赖是动态的（条件分支没走到就不建立依赖）。
 *
 * 不变量：渲染函数内不得写信号。副作用运行期间的写入不会再次触发重跑，
 * 靠它驱动状态会丢更新 —— 状态变更一律放到事件回调或数据到达处。
 */

/** 副作用回调：无参数、无返回值，重跑即重建视图 */
export type Observer = () => void

export interface ReadonlySignal<T> {
  get(): T
}

export interface Signal<T> extends ReadonlySignal<T> {
  set(value: T): void
  update(update: (current: T) => T): void
}

/** 当前正在收集依赖的副作用 */
interface Collector {
  observer: Observer
  disposers: (() => void)[]
}

let collector: Collector | null = null

/** 创建信号。值相等（Object.is）时写入不通知，避免无意义的重挂。 */
export function signal<T>(initial: T): Signal<T> {
  let value = initial
  const observers = new Set<Observer>()

  const assign = (next: T): void => {
    if (Object.is(next, value)) {
      return
    }
    value = next
    for (const observer of [...observers]) {
      observer()
    }
  }

  return {
    get(): T {
      if (collector !== null) {
        const active = collector
        observers.add(active.observer)
        active.disposers.push(() => observers.delete(active.observer))
      }
      return value
    },
    set: assign,
    update(update: (current: T) => T): void {
      assign(update(value))
    },
  }
}

/**
 * 副作用：立即执行一次，之后任一被读信号变化就重跑；重跑前解绑上一轮依赖。
 * 返回停止函数。
 */
export function effect(run: () => void): () => void {
  let disposers: (() => void)[] = []
  let stopped = false
  let running = false

  const execute = (): void => {
    if (stopped || running) {
      return
    }
    for (const dispose of disposers) {
      dispose()
    }
    disposers = []

    running = true
    const previous = collector
    collector = { observer: execute, disposers }
    try {
      run()
    } finally {
      collector = previous
      running = false
    }
  }

  execute()

  return () => {
    stopped = true
    for (const dispose of disposers) {
      dispose()
    }
    disposers = []
  }
}
