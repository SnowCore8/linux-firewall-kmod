/**
 * 周正这一轮的结论：批准 / 要求修改 / 只是说了句话。
 *
 * 判据归 review.mjs —— 合并闸门与巡检判的是同一件事（「当前提交上有没有仍然成立的
 * 批准」），各写一份就会在改一边时误伤另一边。这里只负责取数与回写。
 *
 * 为什么不能只看 `state`：四个人共用一个 App 时，GitHub 不允许 App 批准自己开的 PR，
 * 周正只能退成 `event=COMMENT` 加正文里的 `<!-- qwen:verdict=approve -->` 标记
 * （README 与 QWEN.md 都写着这条路）。只看 `state` 就会把那种批准读成
 * `comment`，日志与闸门的判断对不上。
 *
 * 用法（workflow 里就这么一行，取数与判定分工同 dispatch.mjs）：
 *   node .github/scripts/verdict.mjs
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';

import { isApprove, isReject, latestReview } from './review.mjs';

const gh = (args) =>
  execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }).trim();
const ghJson = (args) => JSON.parse(gh(args) || 'null');

/**
 * 从这一轮之前就在的评审里，挑出提交在当前 head 上的最后一条，给出结论。
 *
 * 只认挂在 `headSha` 上的评审：上一轮留在旧提交上的批准不是这一轮的结论。也正因为
 * 要按提交筛，取回时不能依赖「最新的那条」—— 那条可能是挂在旧提交上的。
 */
export function verdictFrom(reviews, headSha) {
  const atHead = (reviews || []).filter((r) => r.commit && r.commit.oid === headSha);
  const last = latestReview(atHead);
  if (!last) return { verdict: 'comment', state: '', reason: '当前提交上没有评审' };
  // isApprove / isReject 同时认 state 与正文标记，与闸门用的是同一份判据
  if (isApprove(last)) return { verdict: 'approve', state: last.state, reason: '批准' };
  if (isReject(last)) return { verdict: 'request-changes', state: last.state, reason: '要求修改' };
  return { verdict: 'comment', state: last.state, reason: '只留了意见' };
}

const writeOutput = (key, value) => {
  const target = process.env.GITHUB_OUTPUT;
  if (target) appendFileSync(target, `${key}=${value}\n`);
  else process.stdout.write(`${key}=${value}\n`);
};

function main() {
  const repo = process.env.REPOSITORY || '';
  const prNumber = process.env.PR_NUMBER || '';
  const headSha = process.env.HEAD_SHA || '';

  if (process.env.SKIP === 'true') {
    writeOutput('verdict', 'skipped');
    process.stdout.write(`跳过评审：${process.env.SKIP_REASON || '未说明原因'}\n`);
    return;
  }

  if (!repo || !prNumber || !headSha) {
    // 缺哪一样都判不了。判不了的时候说「comment」是安全的：它既不会被当成批准，
    // 也不会让谁以为被驳回了。
    writeOutput('verdict', 'comment');
    process.stdout.write(`缺少取数条件（repo=${repo} pr=${prNumber} head=${headSha}），本轮结论记为 comment\n`);
    return;
  }

  let reviews;
  try {
    reviews = ghJson([
      'api', `repos/${repo}/pulls/${prNumber}/reviews?per_page=100`, '--paginate',
      '--jq', '[.[] | {state: .state, body: .body, submittedAt: .submitted_at, commit: {oid: .commit_id}}]',
    ]);
  } catch (err) {
    // 取不到评审不等于「没有评审」，但也不能因此当成批准。记为 comment 并说明原因，
    // 让人在日志里看到是取数失败而不是确实没评。
    writeOutput('verdict', 'comment');
    process.stderr.write(`取评审失败，本轮结论记为 comment：${err && err.message ? err.message : String(err)}\n`);
    return;
  }

  const { verdict, state, reason } = verdictFrom(reviews, headSha);
  writeOutput('verdict', verdict);
  process.stdout.write(`本次评审结论：${verdict}（state=${state || '未提交评审'}，${reason}）\n`);
}

if (process.argv[1] && process.argv[1].endsWith('verdict.mjs')) {
  main();
}
