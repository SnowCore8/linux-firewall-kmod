/**
 * 看板数据的自动刷新间隔。
 *
 * 从服务端配置 `webui.sse_push_interval` 取刷新节奏，作为**没有实时推送**的分区
 * （内核侧累计统计：热力图、协议分布、扫描探测等）的轮询间隔。
 *
 * 为何与推送间隔同源而不是另配一个常量：一个页面内的两类数据若用两种节奏，用户会看到
 * 同一屏里有的数字在动、有的不动，无法判断哪个是陈旧的。
 *
 * 边界：仅在服务端未配置或读取失败时回落到常量 [`FALLBACK_POLL_MS`]；不改变服务端配置。
 */

import { getConfig } from '../api/endpoints'

/** 读不到配置时的保守回落值（秒级看板足够，且不过度消耗移动端电量） */
export const FALLBACK_POLL_MS = 5000

/** 服务端对 `sse_push_interval` 的校验区间，越界值一律回落 */
const MIN_SECONDS = 1
const MAX_SECONDS = 60

/**
 * 模块级缓存：多视图共用一次请求。
 *
 * 配置在运行期可能被设置页改写，但**刷新间隔本身**不需要秒级同步——下次页面加载自然会
 * 取到新值，为此在每个视图里反复请求 `/api/v1/config` 不划算。
 */
let cached: Promise<number> | null = null

function loadIntervalMs(): Promise<number> {
  if (!cached) {
    cached = getConfig()
      .then((cfg) => {
        const seconds = cfg.sse_push_interval
        if (seconds >= MIN_SECONDS && seconds <= MAX_SECONDS) return seconds * 1000
        return FALLBACK_POLL_MS
      })
      .catch(() => {
        // 读取失败不缓存失败结果：下次进入视图时再试一次
        cached = null
        return FALLBACK_POLL_MS
      })
  }
  return cached
}

/**
 * 取看板自动刷新间隔（毫秒）的读取函数。
 *
 * 首帧即返回 [`FALLBACK_POLL_MS`]（配置未到），配置到达后更新——因此调用处可直接传进
 * `createAsync(..., { pollMs })`，无需等待。
 */
export function pollIntervalReader(): () => number {
  let ms = FALLBACK_POLL_MS
  void loadIntervalMs().then((value) => {
    ms = value
  })
  return () => ms
}
