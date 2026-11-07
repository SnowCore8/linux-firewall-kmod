#!/usr/bin/env node
/**
 * 合并闸门：把「能不能合」从模型的判断里拿出来，交给这个脚本机械判定。
 *
 * 为什么要有它：合并前条件原本写在 auto-miles.toml 的提示词里，由陈实自己读、
 * 自己判断、自己执行 `gh pr merge`。实测两次都没逐条对上 —— PR #38 在「浏览器端到端
 * 测试」判失败后照常合并（他判断为「与本次无关的 flaky」，判断可能对，但没落证据），
 * PR #39 在批准挂在旧提交 447ff12a 的情况下，于新提交 b2763785 上合并。提示词写了
 * 这两条，他就是没执行：证明「写给人读的清单」不构成闸门。
 *
 * 所以分工改成：模型只负责判断「该不该合」并写出申请，条件由这个脚本核。
 * 模型写完 merge-request 就结束，合并由 qwen-miles.yml 的闸门步骤调用本脚本执行。
 *
 * 用法（workflow 里也是这么调的）：
 *   node .github/scripts/merge-gate.mjs <pr> --repo owner/name            # 只判定
 *   node .github/scripts/merge-gate.mjs <pr> --repo owner/name --merge    # 判定通过就合并
 *
 * 退出码：0 = 通过（或已在 --merge 下合并成功）；1 = 被拦；2 = 用法错误。
 *
 * 判据只收「能机械判」的四条。第五条「变更内容与 PR 描述一致」机器判不了，
 * 不进闸门 —— 假装判了比不判更坏。
 */

import { execFileSync } from 'node:child_process';
import { approvedAtHead } from './patrol.mjs';

// 人放的闸：放上去就是「先别动」。合并闸门必须认这两个标签，否则闸门本身成了绕道。
export const STOP_LABELS = ['do-not-merge', 'manual-review'];

const FAILURE_CONCLUSIONS = ['FAILURE', 'ERROR', 'TIMED_OUT', 'CANCELLED', 'ACTION_REQUIRED'];
const FAILURE_STATES = ['FAILURE', 'ERROR'];
const PENDING_STATES = ['PENDING', 'EXPECTED', 'QUEUED', 'IN_PROGRESS'];

/**
 * 单个检查项归一成三种：PENDING / FAILURE / SUCCESS。
 *
 * 不复用 patrol.mjs 的 rollupState：那个只看 `conclusion`，而 statusCheckRollup 里
 * 老式的 StatusContext 用的是 `state`（没有 conclusion 字段）——巡检只需要整体结论，
 * 少认一种元素无伤；闸门要把每个失败项的名字报出来，漏认就会把红的说成绿的。
 */
export function checkState(item) {
  const status = item.status || '';
  if (status && status !== 'COMPLETED') return 'PENDING';
  const conclusion = item.conclusion || '';
  if (FAILURE_CONCLUSIONS.includes(conclusion)) return 'FAILURE';
  if (conclusion === 'SUCCESS') return 'SUCCESS';
  const state = item.state || '';
  if (FAILURE_STATES.includes(state)) return 'FAILURE';
  if (PENDING_STATES.includes(state)) return 'PENDING';
  if (state === 'SUCCESS') return 'SUCCESS';
  // SKIPPED / NEUTRAL / 未知：被跳过的 job 不代表代码有问题，不阻塞
  return 'SUCCESS';
}

export function failedCheckNames(pr) {
  const list = Array.isArray(pr.statusCheckRollup) ? pr.statusCheckRollup : [];
  return list.filter((c) => checkState(c) === 'FAILURE').map((c) => c.name || c.context || '(未命名检查)');
}

export function isPending(pr) {
  const list = Array.isArray(pr.statusCheckRollup) ? pr.statusCheckRollup : [];
  return list.some((c) => checkState(c) === 'PENDING');
}

/**
 * 逐条判定。返回 {ok, rules[], tolerated[]}，rules 里每项带给人看的一句话。
 *
 * preexisting 是「在 base 分支同一提交上也失败」的检查名，由 CLI 侧查出来传进来 ——
 * 判定本身不做 I/O，才能对着构造的数据跑测试。
 */
export function evaluateMerge({ pr, preexisting = [] }) {
  const rules = [];
  const add = (id, ok, detail) => rules.push({ id, ok, detail });

  const approved = approvedAtHead(pr);
  add(
    'approval-at-head',
    approved,
    approved
      ? `当前提交 ${String(pr.headRefOid || '').slice(0, 8)} 上有仍然成立的批准`
      : `当前提交 ${String(pr.headRefOid || '').slice(0, 8)} 上没有有效批准：批准必须挂在 head 上，且比任何驳回都新`,
  );

  const stopLabels = (pr.labels || []).map((l) => l.name).filter((n) => STOP_LABELS.includes(n));
  add(
    'no-stop-label',
    stopLabels.length === 0,
    stopLabels.length ? `带闸标签：${stopLabels.join('、')}` : '没有 do-not-merge / manual-review 标签',
  );

  add('not-draft', !pr.isDraft, pr.isDraft ? 'PR 仍是草稿' : '不是草稿');

  const conflicting = pr.mergeable === 'CONFLICTING';
  add(
    'not-conflicting',
    !conflicting,
    conflicting ? '和主干冲突，需要先解决' : `mergeable=${pr.mergeable || 'UNKNOWN'}`,
  );

  const failed = failedCheckNames(pr);
  const tolerated = failed.filter((n) => preexisting.includes(n));
  const blocking = failed.filter((n) => !preexisting.includes(n));

  if (blocking.length) {
    add('checks', false, `检查失败且不是主干上已有的：${blocking.join('、')}`);
  } else if (tolerated.length) {
    add('checks', true, `只有主干上同样失败的检查：${tolerated.join('、')}（合并说明里要写明）`);
  } else if (isPending(pr)) {
    add('checks', false, '还有检查在跑');
  } else {
    const total = (pr.statusCheckRollup || []).length;
    add('checks', true, total ? '检查全部完成且没有失败' : '这个 PR 没有配检查');
  }

  return {
    ok: rules.every((r) => r.ok),
    rules,
    tolerated,
    blocking,
  };
}

/** 给人看的判定表。合并不了时原样贴到 PR 上，别让人去翻日志。 */
export function formatVerdict(result) {
  const head = result.ok ? '✅ 可以合并' : '⛔ 不能合并';
  const lines = [head, ''];
  for (const rule of result.rules) {
    lines.push(`- ${rule.ok ? '✅' : '❌'} \`${rule.id}\` — ${rule.detail}`);
  }
  return lines.join('\n');
}

// ────────────────────────── 取数（只在 CLI 模式跑） ──────────────────────────

const gh = (args) =>
  execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }).trim();
const ghJson = (args) => JSON.parse(gh(args) || 'null');

// `gh pr view --json` 里没有 baseRefOid（实测报 Unknown JSON field），base 提交哈希另外查。
const PR_FIELDS = [
  'number', 'headRefName', 'headRefOid', 'baseRefName',
  'isDraft', 'mergeable', 'labels', 'statusCheckRollup', 'reviews', 'state',
].join(',');

/**
 * 查某个失败检查在 base 分支上是不是也一样失败。
 *
 * 为什么需要这条：主干本来就红的时候，按「检查项没有失败」任何 PR 都永远合不了，
 * 而修它又得先把 PR 合进去 —— 死循环。陈实 PR #38 遇到的就是这个局面（Jail 开关的
 * e2e 从 3c9b1437 起在 master 上一直红）。正确的出路不是「他觉得无关就合」，
 * 而是「拿数据证明主干上同样红」，并且把这件事写进合并说明。
 */
function preexistingFailures(names, repo, baseSha) {
  const out = [];
  for (const name of names) {
    let conclusions = [];
    try {
      const data = ghJson([
        'api',
        `repos/${repo}/commits/${baseSha}/check-runs?check_name=${encodeURIComponent(name)}&filter=latest`,
      ]);
      // REST 接口的 conclusion 是小写（failure），gh pr view 给的是大写（FAILURE），
      // 统一抬成大写在两边比对，否则「主干上同样红」永远认不出来
      conclusions = (data?.check_runs || []).map((r) => String(r.conclusion || '').toUpperCase());
    } catch {
      // 查不到就按「不是预存在」处理：宁可拦下来让人看，也不要凭空放行
      continue;
    }
    if (conclusions.length && conclusions.every((c) => FAILURE_CONCLUSIONS.includes(c))) out.push(name);
  }
  return out;
}

function loadPr(number, repo) {
  return ghJson(['pr', 'view', String(number), '--repo', repo, '--json', PR_FIELDS]);
}

/** base 分支当前的提交哈希。查不到返回空串 —— 调用方按「不是预存在」处理。 */
function baseShaOf(repo, branch) {
  try {
    return ghJson(['api', `repos/${repo}/branches/${encodeURIComponent(branch)}`])?.commit?.sha || '';
  } catch {
    return '';
  }
}

function waitForChecks(number, repo, minutes) {
  const deadline = Date.now() + minutes * 60000;
  for (;;) {
    const pr = loadPr(number, repo);
    if (!isPending(pr)) return pr;
    if (Date.now() >= deadline) return pr;
    // 同步等：这个脚本跑在 workflow 步骤里，没有别的事可做
    execFileSync('sleep', ['30']);
  }
}

function announce(number, repo, body) {
  try {
    gh(['pr', 'comment', String(number), '--repo', repo, '--body', body]);
  } catch {
    // 发不出评论不该让判定结果失真；判定本身已经在 stdout 上
  }
}

function main() {
  const argv = process.argv.slice(2);
  const repoIdx = argv.indexOf('--repo');
  const repo = repoIdx >= 0 ? argv[repoIdx + 1] || '' : '';
  const doMerge = argv.includes('--merge');
  const waitMinutes = Number(process.env.MILES_CI_WAIT_MINUTES || 10);

  // PR 号是第一个不是标志、也不是 --repo 的值的位置参数。不能直接取 argv[0]：
  // `--repo owner/name 39` 这种顺序会把它当成 PR 号，报出来的是 gh 的错而不是用法。
  const number = argv.find((arg, i) => !arg.startsWith('-') && i !== repoIdx + 1);

  if (!number || !/^\d+$/.test(number) || !repo) {
    process.stderr.write('用法：merge-gate.mjs <pr> --repo owner/name [--merge]\n');
    process.exit(2);
  }

  let pr = loadPr(number, repo);
  if (pr.state !== 'OPEN') {
    // 走到这里说明 PR 是这一轮里被合掉的，但不是闸门合的 —— 闸门只在 OPEN 上动手。
    process.stderr.write(
      `PR #${number} 现在是 ${pr.state}：这一轮开始前它是开着的，合掉它的不是闸门。\n`,
    );
    process.exit(1);
  }

  // 检查还在跑就先等，最多 MILES_CI_WAIT_MINUTES 分钟；等完还是 PENDING 就按未完成拦下
  if (doMerge && isPending(pr)) pr = waitForChecks(number, repo, waitMinutes);

  const failed = failedCheckNames(pr);
  const baseSha = failed.length ? baseShaOf(repo, pr.baseRefName) : '';
  const preexisting = failed.length && baseSha ? preexistingFailures(failed, repo, baseSha) : [];
  const result = evaluateMerge({ pr, preexisting });

  const verdict = formatVerdict(result);
  process.stdout.write(`${verdict}\n`);

  if (!result.ok) {
    if (doMerge) {
      const blocking = result.rules.filter((r) => !r.ok).map((r) => `- \`${r.id}\` — ${r.detail}`).join('\n');
      announce(
        number,
        repo,
        `## ⛔ 闸门拦下了这次合并\n\n申请合并，但条件没满足：\n\n${blocking}\n\n` +
          '闸门是 `.github/scripts/merge-gate.mjs`，判定结果就在上面几行，不用翻日志。\n\n' +
          '<!-- qwen:role=miles -->',
      );
    }
    process.exit(1);
  }

  if (!doMerge) {
    process.stdout.write('（只判定，没有合并；加 --merge 才会执行）\n');
    process.exit(0);
  }

  gh(['pr', 'merge', String(number), '--repo', repo, '--squash', '--delete-branch']);

  const issue = String(pr.headRefName || '').replace(/^qwen-fix-/, '');
  const toleratedNote = result.tolerated.length
    ? `\n\n合并时这些检查在主干上同样失败，不是本次改动引入：${result.tolerated.join('、')}。`
    : '';

  announce(
    number,
    repo,
    `## ✅ 已合并\n\nSquash 合并并删除分支 \`${pr.headRefName}\`。${toleratedNote}\n\n` +
      '判定由 `.github/scripts/merge-gate.mjs` 逐条核过，结果见上一条评论之外的运行日志。\n\n' +
      '<!-- qwen:role=miles -->',
  );

  if (issue && /^\d+$/.test(issue)) {
    try {
      gh(['issue', 'close', issue, '--repo', repo, '--comment', `已由 #${number} 修复`]);
    } catch {
      // PR 正文里的 Closes #n 可能已经关掉了它，重复关闭失败不算问题
    }
  }

  process.exit(0);
}

if (process.argv[1] && process.argv[1].endsWith('merge-gate.mjs')) {
  main();
}
