/**
 * 评审结论与人工闸标签的共用规则。
 *
 * 为什么单独成文件：合并闸门（merge-gate.mjs）与巡检（patrol.mjs）判的是同一件事
 * ——「当前提交上有没有仍然成立的批准」。这条属于评审语义，不属于巡检也不属于闸门，
 * 各写一份就会在改一边时误伤另一边。
 *
 * 测试：`node --test .github/scripts/review.test.mjs`
 */

import { stripCode } from './markdown.mjs';

/**
 * 人放的闸：放上去就是「先别动」。
 *
 * 合并闸门（merge-gate.mjs）、巡检（patrol.mjs）、以及包在 gh 外面的 no-merge-gh
 * 都按这份清单判。no-merge-gh 是 bash，无法 import，它那份写在脚本里，
 * 由 no-merge-gh.test.mjs 比对两者一致 —— 少一处同步就意味着某一层看不见这道闸。
 */
export const STOP_LABELS = ['do-not-merge', 'manual-review'];

export const hasStopLabel = (labels) =>
  (labels || []).some((l) => STOP_LABELS.includes(l.name));

/** 最新一条评审要能覆盖前面的：新的 REQUEST_CHANGES 之后不该还按旧的批准合并。 */
export const latestReview = (reviews) =>
  [...(reviews || [])].sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt))[0];

/**
 * 正文里的标记只在「独占一行」时才算数。
 *
 * 这两个判据决定的是能不能合并，所以不能是 `contains`：一句「CI 还是红的，等绿了
 * 我再写 …」会把那个标记当成正当理由提出来，`contains` 直接把它读成批准 —— 一条
 * 明说「现在不行」的评审就这样放行了最危险的一步。代码块里的引用同理（贴一段
 * 解释、贴一段日志），所以先剥代码再比整行。
 *
 * 历史 42 条标记全部是独占一行的字面形态，锚定到整行不会漏认任何一条。
 */
const VERDICT_LINE = (verdict) =>
  new RegExp(`^[ \\t]*<!--\\s*qwen:verdict=${verdict}\\s*-->[ \\t]*$`, 'm');

const APPROVE_LINE = VERDICT_LINE('approve');
const REJECT_LINE = VERDICT_LINE('request-changes');

export const isApprove = (r) =>
  r.state === 'APPROVED' || APPROVE_LINE.test(stripCode(r.body));

export const isReject = (r) =>
  r.state === 'CHANGES_REQUESTED' || REJECT_LINE.test(stripCode(r.body));

/**
 * 当前提交上有没有一个仍然成立的批准。
 *
 * 「仍然成立」要求三件事：评审挂在当前 head 上、是批准、且它比任何停留在当前 head
 * 上的驳回都新。用旧提交上的批准去合新代码，是这套规矩里最危险的一步。
 */
export function approvedAtHead(pr) {
  const head = pr.headRefOid || '';
  if (!head) return false;
  const atHead = (pr.reviews || []).filter((r) => r.commit?.oid === head);
  const ok = latestReview(atHead.filter(isApprove));
  const no = latestReview(atHead.filter(isReject));
  if (!ok) return false;
  return !no || new Date(ok.submittedAt) > new Date(no.submittedAt);
}
