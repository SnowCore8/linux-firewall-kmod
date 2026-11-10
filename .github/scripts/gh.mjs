/**
 * 调 `gh` 取数，只此一处实现。
 *
 * 为什么收成一份：同一件事（跑 gh、拿 JSON、解析失败怎么办）曾有五份副本，各自
 * 定了 `maxBuffer` 与「空输出回什么」。空输出回 `null` 还是回 `[]` 是**调用点的
 * 语义**，不是取数层该猜的 —— 猜错的方向正好是最坏的那个：列表取空被当成「没有
 * 候选」而不是「取数失败」，巡检就会安静地不叫人。
 *
 * 所以这里只做三件事：跑、解析、把选择权交给调用方。
 *
 * 出错一律抛。`execFileSync` 抛出的异常带着 gh 的原文，调用方要决定是「这轮失败」
 * 还是「这一条当没有」—— 两种都有正当场景，但必须显式选。
 *
 * 测试：`node --test .github/scripts/markers.test.mjs`（与标记共用一份用例文件）
 */

import { execFileSync } from 'node:child_process';

/** 一次取回上千条评论也够。上限高一点不占内存，只防「无上限」。 */
const MAX_BUFFER = 32 * 1024 * 1024;

/** 跑一次 gh，返回去掉首尾空白的标准输出。 */
export function gh(args) {
  return execFileSync('gh', args, { encoding: 'utf8', maxBuffer: MAX_BUFFER }).trim();
}

/**
 * 跑一次 gh 并按 JSON 解析。
 *
 * `fallback` 决定空输出算什么：默认 `null`（「没有这个对象」），列表场景传 `[]`。
 * 不要把默认值定成 `[]` —— 单个对象的调用点会拿到一个空数组，接着读它的字段全是
 * undefined，再往下就是「安静地判成一个都不满足」。
 */
export function ghJson(args, { fallback = null } = {}) {
  const raw = gh(args);
  return raw ? JSON.parse(raw) : fallback;
}

/** 分页取回摊成一行的对象（`--jq '.[]'`），逐行解析。 */
export function ghLines(args) {
  return gh(args)
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}
