#!/usr/bin/env node
/**
 * 定时巡检：没人叫的时候，自己看一眼有没有该接手却没人动的活。
 *
 * 为什么要单独一个脚本，而不是把判断写在 workflow 的 github-script 里：
 * 巡检是「该不该叫醒一个人」的规则，写错了会叫错人、或者该叫的人一直没人叫。
 * 这种规则必须能在本地对着真实数据跑一遍看结果，塞进 yml 就只剩「推上去等一小时」。
 *
 * 用法（workflow 里也是这么调的）：
 *   node .github/scripts/patrol.mjs miles [--repo owner/name]
 *   node .github/scripts/patrol.mjs frank [--repo owner/name]
 *   node .github/scripts/patrol.mjs nora  [--repo owner/name]
 *
 * 输出写进 $GITHUB_OUTPUT（本地没这个文件时打到 stdout），键值形如：
 *   found=true|false
 *   number=<PR 或 Issue 编号>
 *   head_ref=<分支名>        （仅 miles / frank）
 *   reason=<给人看的一句话>
 *
 * 调模型的成本是这个脚本存在的理由：每一块都先跑几秒的扫描，扫不到候选就直接退出，
 * 不叫任何人。
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

// 这两个标签是人放的闸：放上去就是「先别动」。巡检不能绕过 —— 否则人刚说停，
// 下一小时的巡检又把它推起来，那这个闸就白设了。
const STOP_LABELS = ['do-not-merge', 'manual-review'];

// 顾清的场子。她还没看完的 Issue 不该被叶澜抢走。
const NORA_SKIP_LABELS = ['status/needs-triage', 'manual-review'];

const MINUTE = 60000;
const HOUR = 3600000;

/**
 * 把 gh 给的 check runs 数组折成一个状态。
 * 只认三种：还在跑（PENDING）、有失败（FAILURE）、全都好（SUCCESS）。
 * SKIPPED / NEUTRAL 不算失败 —— 被跳过的 job 不代表代码有问题。
 */
export function rollupState(checks) {
  const list = Array.isArray(checks) ? checks : [];
  if (!list.length) return '';
  if (list.some((c) => c.status && c.status !== 'COMPLETED')) return 'PENDING';
  const bad = ['FAILURE', 'ERROR', 'TIMED_OUT', 'CANCELLED', 'ACTION_REQUIRED'];
  if (list.some((c) => bad.includes(c.conclusion))) return 'FAILURE';
  return 'SUCCESS';
}

/** 最新一条评审要能覆盖前面的：新的 REQUEST_CHANGES 之后不该还按旧的批准合并。 */
const latest = (reviews) => [...reviews].sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt))[0];

const isApprove = (r) => r.state === 'APPROVED' || /qwen:verdict=approve/.test(r.body || '');
const isReject = (r) => r.state === 'CHANGES_REQUESTED' || /qwen:verdict=request-changes/.test(r.body || '');

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
  const ok = latest(atHead.filter(isApprove));
  const no = latest(atHead.filter(isReject));
  if (!ok) return false;
  return !no || new Date(ok.submittedAt) > new Date(no.submittedAt);
}

/**
 * 陈实该处理的 PR：自家分支上，已经批准该合并了，或者检查红了没人管。
 *
 * 别人的 PR 一律跳过 —— 他不是那些 PR 的作者。
 */
export function pickForMiles(prs, { now, idleMinutes = 15, ownPrefix = 'qwen-fix-' } = {}) {
  const picked = [];
  for (const pr of prs) {
    if (!String(pr.headRefName || '').startsWith(ownPrefix)) continue;
    if (pr.isDraft) continue;
    if ((pr.labels || []).some((l) => STOP_LABELS.includes(l.name))) continue;

    const idle = (now - new Date(pr.updatedAt).getTime()) / MINUTE;
    if (idle < idleMinutes) continue;

    const rollup = rollupState(pr.statusCheckRollup);
    // 还在跑就别催，等它跑完
    if (rollup === 'PENDING') continue;

    const approved = approvedAtHead(pr);
    const minutes = Math.round(idle);

    if (rollup === 'FAILURE') {
      picked.push({
        pr,
        idle,
        reason: `#${pr.number} 的检查没通过，已经 ${minutes} 分钟没人管`,
      });
    } else if (approved && pr.mergeable === 'CONFLICTING') {
      picked.push({
        pr,
        idle,
        reason: `#${pr.number} 已经批准，但和主干冲突了，需要解决`,
      });
    } else if (approved) {
      // 没有 else if (mergeable === 'MERGEABLE')：GitHub 的 mergeable 是懒计算的，
      // 刚推完提交时经常返回 UNKNOWN，实测一个稳定响应的 PR 连查三次都是 UNKNOWN。
      // 按「必须是 MERGEABLE」来判，已批准该合并的 PR 就永远叫不到人 —— 恰好把巡检
      // 要解决的问题漏掉。能不能合由陈实自己核（他的合并前自查本来就包含
      // 「mergeable 不是 CONFLICTING」），巡检只负责把人叫到位。
      picked.push({
        pr,
        idle,
        reason: `#${pr.number} 已经批准、检查也通过（${rollup || '无检查'}），该合并了`,
      });
    }
  }
  // 等得最久的先处理
  picked.sort((a, b) => b.idle - a.idle);
  return picked;
}

/**
 * 周正该评审的 PR：开了一会儿，而**当前提交**上还没有人评审过。
 *
 * 判据是「当前提交」而不是「有没有评审」：作者推了新提交之后，旧评审就不再覆盖它，
 * 那正是最容易漏掉的空档 —— 评审记录里写着有人看过，看的是上一版。
 */
export function pickForFrank(prs, { now, idleMinutes = 30 } = {}) {
  const picked = [];
  for (const pr of prs) {
    if (pr.isDraft) continue;
    if ((pr.labels || []).some((l) => STOP_LABELS.includes(l.name))) continue;

    const waiting = (now - new Date(pr.createdAt).getTime()) / MINUTE;
    if (waiting < idleMinutes) continue;

    const head = pr.headRefOid || '';
    const reviewedAtHead = (pr.reviews || []).some((r) => r.commit?.oid === head);
    if (reviewedAtHead) continue;

    picked.push({
      pr,
      waiting,
      reason: `#${pr.number} 开了 ${Math.round(waiting / 60)} 小时，当前提交上还没有评审`,
    });
  }
  picked.sort((a, b) => b.waiting - a.waiting);
  return picked;
}

/**
 * 只看 Issue 自身就能判断的几件事：标签、停了多久、有没有开着的 PR 在做。
 *
 * 单独拆出来是为了省掉取评论的那几十次 API 调用：评论要一条一条问，
 * 50 个 Issue 就是 50 次请求；而上面这几条判据用列表接口返回的数据就够。
 * 先过这一关，只给过筛的 Issue 去取评论。
 */
export function noraCandidate(issue, { now, openPrs = [], idleHours = 24 } = {}) {
  if ((issue.labels || []).some((l) => NORA_SKIP_LABELS.includes(l.name))) return false;

  const idle = (now - new Date(issue.updatedAt).getTime()) / HOUR;
  if (idle < idleHours) return false;

  // 「#9」不该被提到「#90」的 PR 顶掉，所以后面要卡一个非数字边界
  const mentions = new RegExp(`#${issue.number}(?!\\d)`);
  if (openPrs.some((pr) => mentions.test(pr.body || ''))) return false;

  return true;
}

/**
 * 叶澜该定的 Issue：停了很久，而这件事没有任何下一步。
 *
 * 「没有下一步」的判据是三条，任何一条成立都不用她再说一次：
 *   - 有开着的 PR 提到它（已经在推进了）
 *   - 评论里有交接标记（有人接下了）
 *   - 她自己已经说过话（再说一遍就是重复）
 */
export function pickForNora(issues, { now, commentsByIssue = new Map(), openPrs = [], idleHours = 24 } = {}) {
  const picked = [];
  for (const issue of issues) {
    if (!noraCandidate(issue, { now, openPrs, idleHours })) continue;

    const comments = commentsByIssue.get(issue.number) || [];
    if (comments.some((c) => /qwen:handoff=/.test(c.body || ''))) continue;
    if (comments.some((c) => /qwen:role=nora/.test(c.body || ''))) continue;

    const idle = (now - new Date(issue.updatedAt).getTime()) / HOUR;
    const hint = comments.length === 0 ? '还没有任何回复' : `最后一条之后没有下一步（共 ${comments.length} 条评论）`;
    picked.push({
      issue,
      idle,
      reason: `#${issue.number} 停了 ${Math.round(idle)} 小时，${hint}`,
    });
  }
  picked.sort((a, b) => b.idle - a.idle);
  return picked;
}

// ────────────────────────── 取数（只在 CLI 模式跑） ──────────────────────────

const ghJson = (args) => JSON.parse(execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }) || '[]');

function repoArgs() {
  const i = process.argv.indexOf('--repo');
  const repo = i >= 0 ? process.argv[i + 1] : '';
  return repo ? ['--repo', repo] : [];
}

const PR_FIELDS = [
  'number', 'headRefName', 'headRefOid', 'isDraft', 'mergeable', 'body',
  'createdAt', 'updatedAt', 'labels', 'statusCheckRollup', 'reviews',
].join(',');

function loadOpenPrs() {
  return ghJson([
    'pr', 'list', ...repoArgs(), '--state', 'open', '--limit', '100', '--json', PR_FIELDS,
  ]);
}

function loadOpenIssues() {
  return ghJson([
    'issue', 'list', ...repoArgs(), '--state', 'open', '--limit', '50',
    '--json', 'number,title,labels,updatedAt,comments',
  ]);
}

function loadComments(number) {
  try {
    return ghJson(['issue', 'view', String(number), ...repoArgs(), '--json', 'comments', '--jq', '.comments']);
  } catch {
    return [];
  }
}

function emit(result, summary) {
  const lines = [];
  if (!result) {
    lines.push('found=false');
  } else {
    lines.push('found=true');
    lines.push(`number=${result.number}`);
    if (result.headRef) lines.push(`head_ref=${result.headRef}`);
    lines.push(`reason=${result.reason}`);
  }

  const out = process.env.GITHUB_OUTPUT;
  const text = `${lines.join('\n')}\n`;
  if (out) fs.appendFileSync(out, text);
  else process.stdout.write(text);

  // 「没有候选」和「取数失败」在输出里长得一样，都会是 found=false。
  // 所以扫描过的数量和样本也打出来，让人能从日志看出到底是哪种。
  if (summary) process.stderr.write(`${summary}\n`);
  process.stderr.write(result ? `叫人了：${result.reason}\n` : '这一块不叫任何人\n');
}

async function main() {
  const role = process.argv[2];
  const now = Number(process.env.PATROL_NOW || Date.now());

  if (role === 'miles') {
    const prs = loadOpenPrs();
    const found = pickForMiles(prs, {
      now,
      idleMinutes: Number(process.env.PATROL_IDLE_MINUTES || 15),
    })[0];
    emit(
      found && { number: found.pr.number, headRef: found.pr.headRefName, reason: `巡检发现：${found.reason}` },
      `扫了 ${prs.length} 个开着的 PR（自家分支符合 ${prs.filter((p) => String(p.headRefName).startsWith('qwen-fix-')).length} 个）`,
    );
    return;
  }

  if (role === 'frank') {
    const prs = loadOpenPrs();
    const found = pickForFrank(prs, {
      now,
      idleMinutes: Number(process.env.PATROL_REVIEW_IDLE_MINUTES || 30),
    })[0];
    emit(
      found && { number: found.pr.number, headRef: found.pr.headRefName, reason: `巡检发现：${found.reason}` },
      `扫了 ${prs.length} 个开着的 PR`,
    );
    return;
  }

  if (role === 'nora') {
    const idleHours = Number(process.env.PATROL_DECISION_IDLE_HOURS || 24);
    const issues = loadOpenIssues();
    const openPrs = loadOpenPrs();

    // 先过一遍不需要评论的判据，只给过筛的去取评论 —— 否则 50 个 Issue 就是 50 次调用
    const candidates = issues
      .filter((i) => noraCandidate(i, { now, openPrs, idleHours }))
      .slice(0, Number(process.env.PATROL_MAX_INSPECT || 15));

    const commentsByIssue = new Map(candidates.map((i) => [i.number, loadComments(i.number)]));
    const found = pickForNora(candidates, { now, commentsByIssue, openPrs, idleHours })[0];
    emit(
      found && { number: found.issue.number, reason: `巡检发现：${found.reason}` },
      `扫了 ${issues.length} 条开着的 Issue，其中 ${candidates.length} 条需要翻评论（其余已被标签/时长/在做 排除）`,
    );
    return;
  }

  process.stderr.write(`用法：patrol.mjs <miles|frank|nora> [--repo owner/name]\n`);
  process.exit(2);
}

// 被 import 时不执行，只有当脚本跑起来才取数
if (process.argv[1] && process.argv[1].endsWith('patrol.mjs')) {
  await main();
}
