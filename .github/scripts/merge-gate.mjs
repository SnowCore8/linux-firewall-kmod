#!/usr/bin/env node
/**
 * 合并闸门：把「能不能合」从模型的判断里拿出来，交给这个脚本机械判定。
 *
 * 为什么要有它：写在提示词里的合并条件是给人读的清单，只在读的人当时愿意遵守时
 * 才生效。闸门要在没人遵守时也生效，所以条件由脚本核，模型只负责判断「该不该合」
 * 并写出申请。
 *
 * 模型写完 merge-request 就结束，合并由 qwen-miles.yml 的闸门步骤调用本脚本执行。
 *
 * 用法（workflow 里也是这么调的）：
 *   node .github/scripts/merge-gate.mjs <pr> --repo owner/name            # 只判定
 *   node .github/scripts/merge-gate.mjs <pr> --repo owner/name --merge    # 判定通过就合并
 *
 * 退出码：0 = 通过（或已在 --merge 下合并成功）；1 = 被拦；2 = 用法错误。
 *
 * 判据只收「能机械判」的五条。第六条「变更内容与 PR 描述一致」机器判不了，
 * 不进闸门 —— 假装判了比不判更坏。判据逐条说明见 docs/merge-gate.md。
 */

import { execFileSync } from 'node:child_process';

// 取数只有一份实现，见 gh.mjs。这里 `execFileSync` 只剩 `sleep` 一处用途。
import { gh, ghJson } from './gh.mjs';

// 评审语义与人工闸标签都归 review.mjs。闸门不自己判「当前提交上有没有仍然成立的
// 批准」—— 那要跟巡检判同一件事，两处各写一份迟早不一致。
import { approvedAtHead, hasStopLabel, STOP_LABELS } from './review.mjs';

// 「哪些行是别人引用的代码」这件事只有一份，在 markdown.mjs。
import { tickCheckboxes } from './markdown.mjs';

// 人放的闸：放上去就是「先别动」。合并闸门必须认这两个标签，否则闸门本身成了绕道。
export { STOP_LABELS };

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

  // 取出具体是哪几个闸标签：判定只需要真假，但贴到 PR 上时要说是哪一个
  const stopLabels = (pr.labels || []).map((l) => l.name).filter((n) => STOP_LABELS.includes(n));
  add(
    'no-stop-label',
    !hasStopLabel(pr.labels),
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

  // 顺序要紧：先问「还在跑没有」，再问「失败的是不是主干上也红」。
  // 反过来写会漏掉一类 PR —— 主干红着（比如那张 test 检查），PR 上另有一项还在跑，
  // 于是走了「只有主干上同样失败的检查」这条放行分支，合并说明里只提了红的那项，
  // 「检查全部跑完」这一条判据就被静默跳过了。
  if (blocking.length) {
    add('checks', false, `检查失败且不是主干上已有的：${blocking.join('、')}`);
  } else if (isPending(pr)) {
    add('checks', false, '还有检查在跑');
  } else if (tolerated.length) {
    add('checks', true, `只有主干上同样失败的检查：${tolerated.join('、')}（合并说明里要写明）`);
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

// `gh pr view --json` 里没有 baseRefOid（实测报 Unknown JSON field），base 提交哈希另外查。
const PR_FIELDS = [
  'number', 'headRefName', 'headRefOid', 'baseRefName',
  'isDraft', 'mergeable', 'labels', 'statusCheckRollup', 'reviews', 'state',
].join(',');

/**
 * 查某个失败检查在 base 分支上是不是也一样失败。
 *
 * 为什么需要这条：主干本来就红的时候，按「检查项没有失败」任何 PR 都永远合不了，
 * 而修它又得先把 PR 合进去 —— 死循环。正确的出路不是「他觉得无关就合」，
 * 而是「拿数据证明主干上同样红」，并且把这件事写进合并说明。
 */
function preexistingFailures(names, repo, baseSha) {
  const out = [];
  for (const name of names) {
    let conclusions = [];
    try {
      const data = ghJson([
        'api',
        `repos/${encodeURIComponent(repo)}/commits/${baseSha}/check-runs?check_name=${encodeURIComponent(name)}&filter=latest`,
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

/**
 * 去掉「这次运行自己产生的检查项」。
 *
 * 闸门跑在陈实那次运行里，而那次运行本身就是 PR 上的一个检查项（`分派`、`陈实 / 动手`）。
 * 不剔掉的话，`isPending` 永远看到自己在跑：先白等满 MILES_CI_WAIT_MINUTES，再以
 * 「还有检查在跑」拦下自己 —— 每张 PR 都合不了。
 *
 * 判据是 detailsUrl 里那一段 `/runs/<runId>/`，只在 CI 里有 GITHUB_RUN_ID，本地跑为空、
 * 一律保留。
 */
export function withoutOwnRun(checks, runId) {
  const list = Array.isArray(checks) ? checks : [];
  if (!runId) return list;
  const marker = `/runs/${runId}/`;
  return list.filter((check) => !String(check?.detailsUrl || '').includes(marker));
}

/**
 * 去掉「这条代理链路自己的检查项」，只留别人的。
 *
 * 同一个 PR 上，周正批准一次就起一次陈实的运行，而 `qwen-miles.yml` 把这些运行
 * 串在同一并发组里：闸门占着槽位，排在后面的那次就起不来，它的 `陈实 / 动手`
 * 检查项一直挂着。等它等于等自己 —— 白等满 `MILES_CI_WAIT_MINUTES`，再以
 * 「还有检查在跑」拦下，而真正验代码的 `测试` 可能早就绿了。
 *
 * 判据是 `workflowName`：`测试` 来自 `qwen-ci.yml`，属于另一条 workflow；
 * `分派` / `陈实 / 动手` / 被跳过的角色都是调度那一条的。只有 CI 里有
 * `GITHUB_WORKFLOW`，本地跑为空、一个都不剔。
 */
export function withoutOwnWorkflow(checks, workflowName) {
  const list = Array.isArray(checks) ? checks : [];
  if (!workflowName) return list;
  return list.filter((check) => check?.workflowName !== workflowName);
}

function loadPr(number, repo) {
  const pr = ghJson(['pr', 'view', String(number), '--repo', repo, '--json', PR_FIELDS]);
  if (pr && 'statusCheckRollup' in pr) {
    pr.statusCheckRollup = withoutOwnWorkflow(
      withoutOwnRun(pr.statusCheckRollup, process.env.GITHUB_RUN_ID || ''),
      process.env.GITHUB_WORKFLOW || '',
    );
  }
  return pr;
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

/**
 * 把 Issue 里没勾的 checkbox 勾上，返回勾了几项。
 *
 * QWEN.md 的合并规范里写着这一条，而在这之前没有任何代码碰过它 —— 清单会一直空着，
 * 下一个人读到的是「还没做完」。
 *
 * 失败不抛：合并已经发生了，这时候让整轮失败只会报出一句「闸门自己出错了」，
 * 而五条判据其实全过了。所以只在 stderr 里说清楚，合并说明里不写勾了几项。
 */
export function tickIssueChecklist(issue, repo) {
  try {
    const body = ghJson(['issue', 'view', String(issue), '--repo', repo, '--json', 'body'])?.body || '';
    const { body: next, ticked } = tickCheckboxes(body);
    if (!ticked) return 0;
    gh(['issue', 'edit', String(issue), '--repo', repo, '--body', next]);
    return ticked;
  } catch (err) {
    process.stderr.write(
      `Issue #${issue} 的 checklist 没勾上：${err && err.message ? err.message : String(err)}\n`,
    );
    return 0;
  }
}

function main() {
  const argv = process.argv.slice(2);
  const repoIdx = argv.indexOf('--repo');
  const repo = repoIdx >= 0 ? argv[repoIdx + 1] || '' : '';
  const doMerge = argv.includes('--merge');
  const waitMinutes = Number(process.env.MILES_CI_WAIT_MINUTES || 10);

  // 拦下时人第一句问的就是「它在等什么」。把剔掉的那条链路先说出来，那三个字
  // 加上去就是全部答案：属于它的检查项一个都不等了。这个变量只有 CI 里有。
  const ownWorkflow = process.env.GITHUB_WORKFLOW || '';
  if (ownWorkflow) {
    process.stdout.write(`闸门只核 \`${ownWorkflow}\` 这条链路之外的检查项\n`);
  }

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
  const linked = Boolean(issue) && /^\d+$/.test(issue);
  const ticked = linked ? tickIssueChecklist(issue, repo) : 0;
  const toleratedNote = result.tolerated.length
    ? `\n\n合并时这些检查在主干上同样失败，不是本次改动引入：${result.tolerated.join('、')}。`
    : '';
  const checklistNote = ticked
    ? `\n\nIssue #${issue} 里的 checklist 已勾完（${ticked} 项）。`
    : '';

  announce(
    number,
    repo,
    `## ✅ 已合并\n\nSquash 合并并删除分支 \`${pr.headRefName}\`。${toleratedNote}${checklistNote}\n\n` +
      '判定由 `.github/scripts/merge-gate.mjs` 逐条核过，结果见上一条评论之外的运行日志。\n\n' +
      '<!-- qwen:role=miles -->',
  );

  if (linked) {
    try {
      gh(['issue', 'close', issue, '--repo', repo, '--comment', `已由 #${number} 修复`]);
    } catch {
      // PR 正文里的 Closes #n 可能已经关掉了它，重复关闭失败不算问题
    }
  }

  process.exit(0);
}

if (process.argv[1] && process.argv[1].endsWith('merge-gate.mjs')) {
  try {
    main();
  } catch (err) {
    // 崩溃不能退出 1：1 是「条件没满足，结论已贴在 PR 上」，会被读成闸门判过了。
    // 取数失败（令牌权限不够、接口报错）属于判据根本没跑完，用 2，那一步会失败。
    process.stderr.write(`闸门自己出错了，判据没跑完：${err && err.message ? err.message : String(err)}\n`);
    process.exit(2);
  }
}
