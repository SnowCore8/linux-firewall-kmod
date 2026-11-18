/**
 * 新鲜度仲裁 —— 一个进程内单调递增的序号，SSE 与 REST 共用。
 *
 * 为什么需要：同一个读数（比如 current_bans）有两条来路——SSE 域帧推来的、REST 拉来的。
 * 两条路各有延迟，谁后到不一定谁更新（一次慢 REST 可能在一条新 SSE 帧之后才落地）。若视图
 * 简单用「SSE ?? REST」或「后到覆盖」，同一个数字就会取决于它从哪条路读出来，界面来回跳。
 *
 * 办法：给每次「拿到一份新数据」都盖一个全局递增序号（seq）。视图比较两个来源的 seq，
 * 取**更大**的那个，而不是取某个固定来源。序号只增不减、跨来源可比，于是「谁更新」有了
 * 唯一答案，与到达顺序无关。
 *
 * 这是一个刻意极简的模块级计数器：不需要持久化、不需要跨标签（每个标签自己连自己的 SSE）。
 */

let counter = 0

/** 取下一个新鲜度序号（严格递增，进程内唯一）。 */
export function nextSeq(): number {
  counter += 1
  return counter
}

/** 当前序号（不推进）；用于初始化「尚无数据」的基准。 */
export function currentSeq(): number {
  return counter
}

/** REST 数据与其「发起时」序号绑定的载荷，供 useAsync 原样传递。 */
export interface StampedRest<T> {
  data: T
  seq: number
}

/**
 * 把一次 REST 调用的结果与**发起时刻**分配的序号绑在一起。
 *
 * 序号必须在发起时取，不能等响应落地再取：REST 在途期间 SSE 可能已推来更新的帧，
 * 落地时才取号会让慢响应用一个更大的号反过来盖掉那些帧（Jails/Whitelist 要等下一轮
 * 30 秒轮询才纠正）。每次调用都重新取号，重试/取消后重新发起的请求不会复用旧号。
 *
 * 它不依赖 React 与 API 客户端；放在这个纯逻辑模块里，E2E 用例才能直接执行它，
 * 不必经 useLiveData/useAsync 把 import.meta.env 拖进用例加载链。
 */
export function stampRestRequest<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
): (signal: AbortSignal) => Promise<StampedRest<T>> {
  return (signal) => {
    const seq = nextSeq()
    return fetcher(signal).then((data) => ({ data, seq }))
  }
}

/**
 * 在两个带 seq 的来源里挑更新的那个。
 * a/b 任一为空则取另一个；都非空取 seq 更大者；相等时偏向 a（约定 a 为实时源）。
 */
export function pickFresher<T>(
  a: { data: T; seq: number } | null,
  b: { data: T; seq: number } | null,
): { data: T; seq: number } | null {
  if (!a) return b
  if (!b) return a
  return a.seq >= b.seq ? a : b
}
