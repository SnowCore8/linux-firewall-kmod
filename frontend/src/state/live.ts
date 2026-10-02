/**
 * 「实时通道 vs REST 回退」的取值裁决。
 *
 * 比较两份来源的新鲜度戳（共用 [`nextFreshnessStamp`](../hooks/freshness.ts) 的全局
 * 单调计数器），返回写入更晚的那一份。两者都为空时返回 null，由调用方用语义默认值兜底。
 *
 * 为何不能写成 `live ?? rest.data`：那样只要实时通道到过任何一帧，REST 那份此后永远
 * 取不到；一旦某域在服务端没有生产者（帧不会重发），写操作后的重取与页内刷新按钮就
 * 全成了死代码，只能靠整页刷新（重连、重收首帧）才更新。
 *
 * 为何两来源必须共用一个计数器：各自计数会让比较退化成「谁计的数更大」而非「谁更新」。
 * 典型反例是 REST 每 5 秒轮询、推送每 1 秒一帧——独立计数器下 REST 的计数会在小节拍上
 * 反超，把更旧的 REST 快照判成更新的那份。
 */

import type { AsyncState } from './async'

/**
 * 取实时与回退两份数据中较新的一份。
 *
 * @param live    实时通道当前载荷（该域尚未收到帧时为 null）
 * @param liveSeq 实时通道该域的新鲜度戳
 * @param rest    同一域 REST 回退的取数资源状态
 * @returns       较新的数据；两者都没有时返回 null
 */
export function pickLiveData<T>(live: T | null, liveSeq: number, rest: AsyncState<T>): T | null {
  if (live === null) return rest.data
  if (rest.data === null) return live
  // 戳更大者胜出；相等只可能出现在两边都没写入过（都为 0）的情形
  return rest.dataSeq > liveSeq ? rest.data : live
}

/**
 * 判断「两条来源都还没有数据」。
 *
 * 与 `pickLiveData(...) === null` 等价，但意图更清楚：调用处通常先拿 `pickLiveData`
 * 的结果渲染，再单独判断要不要骨架或错误，避免把「取到的数据本身为空」与「还没取到」
 * 混为一谈。
 */
export function noDataYet<T>(live: T | null, rest: AsyncState<T>): boolean {
  return live === null && rest.data === null
}
