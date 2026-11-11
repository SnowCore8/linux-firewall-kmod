/**
 * REST / SSE 新鲜度仲裁回归用例。
 *
 * 为什么放在 E2E 目录：仓库没有前端单元测试运行器（frontend/package.json 无 test
 * 脚本、无 .test.ts、未装 vitest/jest），@playwright/test 是唯一能直接执行 .ts 的
 * 现成工具。本文件不访问页面也不依赖守护进程，只验证 useLiveData 的序号预分配语义。
 */

import { expect, test } from '@playwright/test'
import { stampRestRequest } from '../../frontend/src/hooks/useLiveData.ts'
import { nextSeq, pickFresher } from '../../frontend/src/lib/freshness.ts'

test.describe('useLiveData 新鲜度仲裁', () => {
  test('REST 在途期间到达的 SSE 帧不会被晚到的 REST 响应覆盖', async () => {
    let resolveRest!: (value: string) => void
    // 模拟一次慢 REST：发起时取号，响应由测试手动放行
    const pending = stampRestRequest(
      () =>
        new Promise<string>((resolve) => {
          resolveRest = resolve
        }),
    )(new AbortController().signal)

    // 请求已发起但未落地，此时 SSE 推来一帧；该帧的序号更大
    const sse = { data: 'sse-newer', seq: nextSeq() }
    resolveRest('rest-older')
    const rest = await pending

    expect(rest.seq).toBeLessThan(sse.seq)
    expect(pickFresher(sse, rest)).toBe(sse)
  })

  test('响应先于 SSE 帧落地时 REST 仍能胜出', async () => {
    const sse = { data: 'sse-older', seq: nextSeq() }
    const rest = await stampRestRequest(async () => 'rest-newer')(new AbortController().signal)

    expect(rest.seq).toBeGreaterThan(sse.seq)
    expect(pickFresher(sse, rest)).toBe(rest)
  })

  test('每次发起都分配新序号，重试不复用旧号', async () => {
    const wrap = stampRestRequest(async () => 'data')
    const first = await wrap(new AbortController().signal)
    const second = await wrap(new AbortController().signal)

    expect(second.seq).toBeGreaterThan(first.seq)
  })
})
