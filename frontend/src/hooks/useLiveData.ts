/**
 * 「实时通道 vs REST 回退」的取值裁决。
 *
 * 做什么：比较两份来源的新鲜度戳（共用 [`nextFreshnessStamp`](./freshness.ts) 的全局
 *         单调计数器），返回写入更晚的那一份数据。两者都为空时返回 null，由调用方用
 *         语义默认值兜底。
 *
 * 影响什么：取代原先的 `sseX ?? restX.data`。后者是「SSE 优先」——只要 SSE 到过任何一帧，
 *           `sseX` 就恒为非 null，REST 那份此后**永远取不到**；于是一旦某个域在服务端
 *           没有生产者（帧不会重发），写操作后的 `reload()` 与页内刷新按钮全部变成死代码，
 *           界面只能靠整页刷新（重连 SSE、重收首帧）才更新。本裁决让「后到的写入」胜出，
 *           两侧的刷新路径都真正生效。
 *
 * 为什么必须共用同一个计数器：两个来源各自计数时，比较退化成「谁计的数更大」而非「谁更新」。
 *          典型反例——REST 每 5 s 轮询、SSE 每 1 s 推帧，独立计数器下 REST 的计数值会在
 *          小节拍上反超 SSE，把更旧的 REST 快照判成更新的那份。共用计数器后，戳的大小
 *          严格等价于「写入时刻的先后」。
 *
 * 边界：不解决「服务端到底推不推」。某域在服务端无生产者时该域仍需靠 REST 刷新，此时戳比较
 *       恰好选中 REST 那份，行为正确。
 */

import type { AsyncState } from './useAsync'

/**
 * 取实时与回退两份数据中较新的一份。
 *
 * @param live     实时通道当前载荷（该域尚未收到帧时为 null）
 * @param liveSeq  实时通道该域的新鲜度戳（`useSse().payloadSeq[domain]`）
 * @param rest     同一域 REST 回退的 `useAsync` 结果
 * @returns        较新的数据；两者都没有时返回 null
 */
export function pickLiveData<T>(
  live: T | null,
  liveSeq: number,
  rest: AsyncState<T>,
): T | null {
  if (live === null) return rest.data
  if (rest.data === null) return live
  // 戳更大者胜出；相等只可能出现在两边都没写入过（都为 0）的情形
  return rest.dataSeq > liveSeq ? rest.data : live
}

/**
 * 判断「两条来源都还没有数据」。
 *
 * 用于骨架屏与错误提示的判据：此时界面确实无内容可显示。与 `pickLiveData(...) === null`
 * 等价，但**意图更清楚**——调用处通常先拿 `pickLiveData` 的结果做渲染，再单独判断要不要
 * 骨架/错误，避免把「取到的数据本身为空」与「还没取到」混为一谈。
 *
 * @param live     实时通道当前载荷
 * @param rest     同一域 REST 回退的 `useAsync` 结果
 */
export function noDataYet<T>(live: T | null, rest: AsyncState<T>): boolean {
  return live === null && rest.data === null
}
