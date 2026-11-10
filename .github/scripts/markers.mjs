/**
 * 正文里的 `<!-- qwen:… -->` 标记，只此一处实现。
 *
 * 为什么要收成一份：这些标记决定「谁被叫醒」「能不能合并」，而它们的解法各自演化过
 * 一遍 —— route.mjs 自己一条正则，merge-request.mjs 自己一条，review.mjs 又一条，
 * patrol.mjs 用子串。改标记格式时漏掉一处不会报错，只会安静地不派活、不合并。
 *
 * 共同前提：一律先剥代码再判。贴一段日志、一段 diff、一行「协议长这样」的行内代码是
 * 写描述的常规做法，那些片段里的标记是引用，不是要求它生效（理由见 markdown.mjs）。
 *
 * **强度不统一是刻意的**，不要顺手抹平：
 *
 * - `verdict` / `merge-request` 直接决定能不能进主干，所以要求独占一行、该行不能再有
 *   别的内容。用 `contains` 的话，一句「CI 还是红的，等绿了我再写 …」会被读成批准。
 * - `handoff` / `to` 只是请人接手或来读一眼，最坏后果是多跑一轮模型，所以出现在句子
 *   中间也认 —— 认不出来的代价是「该叫的人一直没人叫」，比多跑一轮更糟。
 *
 * 测试：`node --test .github/scripts/markers.test.mjs`
 */

import { stripCode } from './markdown.mjs';

// ────────────────────────── 交接与点名（宽松） ──────────────────────────

// reason 用 [\s\S]*? 而不是 [^>]*?：后者遇到 reason 里一个 `>` 就整条匹配不上，
// 交接被静默丢弃 —— 作者以为自己交出去了，实际谁也没被叫醒。宁可把 `>` 当普通字符。
// 同理，标记里也允许写 `>` 之外的任何内容，包括换行（多行 reason 是常规写法）。
const HANDOFF_RE = /<!--\s*qwen:handoff=([a-z]+)\s+reason=([\s\S]*?)\s*-->/i;
const CALL_RE = /<!--\s*qwen:to=([a-z]+)\s*-->/i;

/** `handoff=名字 reason=一句话` → `{ to, reason }`；没有就是 null。 */
export function parseHandoff(text) {
  const m = HANDOFF_RE.exec(stripCode(text));
  return m ? { to: m[1].toLowerCase(), reason: (m[2] || '').trim() } : null;
}

/** `to=名字` → 名字；没有就是 null。 */
export function parseCall(text) {
  const m = CALL_RE.exec(stripCode(text));
  return m ? m[1].toLowerCase() : null;
}

/** 正文里有没有交接标记（数额度用，不要具体值）。 */
export const hasHandoff = (text) => HANDOFF_RE.test(stripCode(text));

/** 正文里有没有点名标记。 */
export const hasCall = (text) => CALL_RE.test(stripCode(text));

// ────────────────────────── 合并申请与评审结论（严格） ──────────────────────────

/**
 * 独占一行的标记：整行只能是这个标记，前后允许空白。
 *
 * 允许行尾 `\r`：正文可能来自 Windows 侧的日志，而 stripCode 只按 `\n` 切行。
 */
const ownLine = (body) => new RegExp(`^[^\\S\\n]*${body}[^\\S\\n]*$`, 'm');

const REQUEST_LINE = ownLine('<!--\\s*qwen:merge-request\\s*-->');

const verdictLine = (verdict) => ownLine(`<!--\\s*qwen:verdict=${verdict}\\s*-->`);

const APPROVE_LINE = verdictLine('approve');
const REJECT_LINE = verdictLine('request-changes');

/** 陈实这一轮申请合并了吗。 */
export const hasMergeRequest = (text) => REQUEST_LINE.test(stripCode(text));

/** 周正在正文里写了等效批准（四人共用一个 App 时的那条退路）。 */
export const hasApproveMarker = (text) => APPROVE_LINE.test(stripCode(text));

/** 周正在正文里写了等效的「要求修改」。 */
export const hasRejectMarker = (text) => REJECT_LINE.test(stripCode(text));

// ────────────────────────── 签名（严格） ──────────────────────────

/**
 * 评论签名 `<!-- qwen:role=<名字> -->`。
 *
 * 用完整标记而不是 `/qwen:role=nora/`：后者连 `qwen:role=nora-extra` 也认，
 * 而那行不可能是签名。签名判的是「这个人这一轮真的发过话」，认错就等于
 * 把一轮没发生的发言当成发生了。
 */
export function hasRole(text, role) {
  return new RegExp(`<!--\\s*qwen:role=${role}\\s*-->`).test(stripCode(text));
}
