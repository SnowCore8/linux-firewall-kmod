/**
 * 每一轮开始前「这件事还该不该做、该怎么做」的判断。
 *
 * 四份工作流里各有一段内联 JS 做这件事：顾清挑要处理的 Issue、叶澜确认目标还开着、
 * 陈实算出模式和分支、周正判断这次评审是不是多余。它们全都是这个形状 ——
 * 取回几个字段，比对，然后决定跑不跑模型。
 *
 * 写在内联 JS 里的代价是判不对也不会报错：少一个字段就是 `undefined`，而
 * `undefined !== 'open'` 恰好为真，于是「跳过」这件事安静地发生，日志里只有一行
 * `skip=false` 看的人是放心的。所以判据搬到这里，纯函数、可单测，取数留在 CLI 层。
 *
 * 用法（workflow 里就这么一行）：
 *   node .github/scripts/context.mjs clara|nora|miles|frank
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';

/** 我方分支前缀。陈实只碰这一类分支，别人的 PR 一律不动。 */
export const OWNED_BRANCH_PREFIX = 'qwen-fix-';

export const isOwnedBranch = (ref) => String(ref || '').startsWith(OWNED_BRANCH_PREFIX);

const issueNumberOfBranch = (ref) => String(ref || '').slice(OWNED_BRANCH_PREFIX.length);

// ───────────────────────── 顾清：挑要处理的 Issue ─────────────────────────

/**
 * 决定这一轮处理哪几条 Issue。
 *
 * `single` 是有编号时直接处理那一条；`batch` 是定时巡检，从「没有标签的」和「标了
 * status/needs-triage 的」两个来源取并集。两个来源都要：只扫无标签的会漏掉被标了
 * 待分诊的，而那张标签正是上一轮自己贴上去的。
 */
export function prepareClara({ issueNumber = '', unlabeled = [], needsTriage = [], batchLimit = 5 } = {}) {
  if (issueNumber) {
    return { handled: true, mode: 'single', targets: String(issueNumber), reason: `本次处理 #${issueNumber}` };
  }

  const numbers = [...unlabeled, ...needsTriage]
    .map((n) => Number(n))
    // 去重、排序都按数字来：字符串排序会把 100 排在 99 前面，批量时先处理的是大编号
    .filter((n) => Number.isInteger(n) && n > 0)
    .filter((n, i, all) => all.indexOf(n) === i)
    .sort((a, b) => a - b)
    .slice(0, Math.max(0, Number(batchLimit) || 0));

  if (!numbers.length) return { handled: false, mode: 'batch', targets: '', reason: '没有需要处理的 Issue' };

  return { handled: true, mode: 'batch', targets: numbers.join(','), reason: `本次处理：${numbers.join(',')}` };
}

// ───────────────────────── 叶澜：目标还开着吗 ─────────────────────────

export function prepareNora({ number, issue } = {}) {
  if (!issue) return { proceed: false, reason: `取不到 #${number} 的状态，不做产品决策` };
  if (issue.state !== 'open') return { proceed: false, reason: `#${number} 已关闭，不再做产品决策` };
  return { proceed: true, reason: `对 #${number} 做产品决策` };
}

// ───────────────────────── 陈实：模式和分支 ─────────────────────────

/**
 * 算出这一轮跑在哪个模式、动哪个分支。
 *
 * 三件事按这个顺序判，顺序本身是判据：
 *   1. 分支是不是我方的 —— 别人的 PR 连读都不往下读；
 *   2. Issue 编号从分支名推 —— 推不出来就退化成空串，后面按无关联 Issue 处理；
 *   3. 对象还开着吗 —— 已合并的 PR 再跑一轮只会把改动写到一个死分支上。
 */
export function prepareMiles({
  number,
  onPr = false,
  issueNumber = '',
  prNumber = '',
  headRef = '',
  pull = null,
  issue = null,
  defaultBranch = 'master',
} = {}) {
  const n = Number(number);

  if (onPr) {
    const mode = 'respond-pr';
    // PR 编号就是 number，不信任调用方另传的那个：两者不一致时以对象本身为准
    const pr = String(n);
    if (!pull) {
      return { skip: true, skipReason: `取不到 PR #${n}，不修改任何分支`, mode, issueNumber, prNumber: pr };
    }
    const ref = pull.headRef;
    if (!isOwnedBranch(ref)) {
      return { skip: true, skipReason: `分支 ${ref} 不是我方创建的，不修改他人的 PR`, mode, issueNumber, prNumber: pr };
    }
    const linked = issueNumber || issueNumberOfBranch(ref);
    if (pull.state !== 'open') {
      return { skip: true, skipReason: '该 PR 已关闭或已合并', mode, issueNumber: linked, prNumber: pr };
    }
    return {
      skip: false,
      mode,
      issueNumber: linked,
      prNumber: pr,
      headRef: ref,
      baseBranch: pull.baseRef,
      previousHead: ref,
    };
  }

  const linked = String(n);
  const ref = `${OWNED_BRANCH_PREFIX}${linked}`;
  if (!issue) {
    return { skip: true, skipReason: `取不到 Issue #${linked}，不动手`, mode: 'fix-issue', issueNumber: linked };
  }
  if (issue.state !== 'open') {
    return { skip: true, skipReason: '该 Issue 已关闭', mode: 'fix-issue', issueNumber: linked };
  }
  return {
    skip: false,
    mode: 'fix-issue',
    issueNumber: linked,
    prNumber: String(prNumber || ''),
    headRef: ref,
    baseBranch: defaultBranch,
    // 修 Issue 时分支可能还不存在，没有「上一轮的起点」可言
    previousHead: '',
  };
}

// ───────────────────────── 周正：这次评审是不是多余 ─────────────────────────

/**
 * 判断这一轮要不要真的评审。
 *
 * 「当前提交上已有评审」只挡机器人发起的叫醒：同一件事会被安排两遍 —— PR 一打开
 * 就叫了周正，陈实随后又在 PR 上写一条交接评论。人写「再看看」是他明确要看，哪怕
 * 没有新提交，所以 `senderIsBot` 为假时不跳过。
 *
 * 判据放在这里而不是路由里：路由判定的时刻（PR 打开后约 10 秒）第一次的评审还没
 * 提交，看出去永远是「没有评审」；而 qwen-frank 的并发组按 pr_number 分组、
 * `queue: max`，第二次一定排在第一次之后启动，到这一刻评审已经落地。
 */
export function prepareFrank({ prNumber, pull = null, reviews = [], senderIsBot = false } = {}) {
  if (!pull) return { skip: true, skipReason: `取不到 PR #${prNumber}`, headRef: '', isOwnPr: false };

  const headRef = pull.headRef;
  const skip = [];
  if (pull.state !== 'open') skip.push('PR 已关闭或已合并');
  if (pull.draft) skip.push('PR 仍是草稿');
  if (pull.isFork) skip.push('PR 来自 fork，无法读取完整上下文');

  const reviewedAtHead = reviews.some((r) => r.commitId === pull.headSha);
  if (reviewedAtHead && senderIsBot) skip.push('当前提交上已有评审，这次是机器人重复叫醒');

  return {
    skip: skip.length > 0,
    skipReason: skip.join('；'),
    headRef,
    headSha: pull.headSha,
    isOwnPr: isOwnedBranch(headRef),
    // 跳过原因是「重复叫醒」而不是拒绝评审时，值得在运行注解里说一声：
    // 静默跳过等于没人知道这次没评
    repeated: reviewedAtHead && senderIsBot,
  };
}

// ────────────────────────── 取数（只在 CLI 模式跑） ──────────────────────────

const ghJson = (args) => JSON.parse(execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }).trim() || 'null');

/**
 * 写结论。有 GITHUB_OUTPUT 就写进去（workflow 里就是这个形状），本地跑没有这个
 * 文件，退回 stdout —— 这样同一个函数在本地和 CI 里都能对着看。
 */
const writeOutputs = (pairs) => {
  const target = process.env.GITHUB_OUTPUT;
  const lines = Object.entries(pairs).map(([key, value]) => `${key}=${value}`);
  if (!target) {
    process.stdout.write(`${lines.join('\n')}\n`);
    return;
  }
  appendFileSync(target, `${lines.join('\n')}\n`);
};

function runClara(repo, batchLimit) {
  const list = (args) => {
    try {
      const out = execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).trim();
      return out.split('\n').filter(Boolean);
    } catch {
      // 取不到就当作这个来源没有候选。两个来源都取不到时 handled=false，
      // 也就是这一轮不跑模型 —— 宁可少处理，不要对着空列表瞎跑
      return [];
    }
  };
  const base = ['issue', 'list', '--repo', repo, '--state', 'open', '--limit', String(batchLimit), '--json', 'number', '--jq', '.[].number'];
  const result = prepareClara({
    issueNumber: process.env.ISSUE_NUMBER || '',
    unlabeled: list([...base, '--search', 'no:label']),
    needsTriage: list([...base, '--label', 'status/needs-triage']),
    batchLimit,
  });
  writeOutputs({ handled: result.handled, MODE: result.mode, TARGETS: result.targets });
  process.stdout.write(`${result.reason}\n`);
}

function runNora(repo) {
  const number = process.env.NUMBER;
  let issue = null;
  try {
    issue = ghJson(['api', `repos/${repo}/issues/${number}`, '--jq', '{state: .state}']);
  } catch {
    issue = null;
  }
  const result = prepareNora({ number, issue });
  writeOutputs({ proceed: result.proceed });
  process.stdout.write(`${result.reason}\n`);
}

/** gh 的 REST 字段是下划线，这里摊平成 prepareMiles 认的形状。 */
const pullShape = (data) => ({
  headRef: data.head?.ref || '',
  baseRef: data.base?.ref || '',
  state: data.state || '',
});

function runMiles(repo) {
  const number = process.env.NUMBER;
  const onPr = process.env.ON_PR === 'true';
  const fetchOr = (args) => {
    try {
      return ghJson(args);
    } catch {
      return null;
    }
  };

  const pull = onPr ? fetchOr(['api', `repos/${repo}/pulls/${number}`, '--jq', '{state, head: {ref: .head.ref}, base: {ref: .base.ref}}']) : null;
  const issue = onPr
    ? null
    : fetchOr(['api', `repos/${repo}/issues/${number}`, '--jq', '{state: .state}']);

  const result = prepareMiles({
    number,
    onPr,
    issueNumber: process.env.ISSUE_NUMBER || '',
    prNumber: process.env.PR_NUMBER || '',
    headRef: process.env.HEAD_REF_INPUT || '',
    pull: pull ? pullShape(pull) : null,
    issue,
    defaultBranch: process.env.DEFAULT_BRANCH || 'master',
  });

  writeOutputs({
    skip: result.skip,
    skip_reason: result.skipReason || '',
    mode: result.mode,
    issue_number: result.issueNumber || '',
    pr_number: result.prNumber || '',
    head_ref: result.headRef || '',
    base_branch: result.baseBranch || '',
    previous_head: result.previousHead || '',
  });
  process.stdout.write(
    result.skip
      ? `跳过：${result.skipReason}\n`
      : `模式 ${result.mode}，分支 ${result.headRef} → ${result.baseBranch}，Issue #${result.issueNumber}，PR #${result.prNumber || '无'}\n`,
  );
}

function runFrank(repo) {
  const prNumber = process.env.PR_NUMBER;
  let pull = null;
  let reviews = [];
  try {
    const data = ghJson(['api', `repos/${repo}/pulls/${prNumber}`, '--jq',
      '{state, draft, head: {ref: .head.ref, sha: .head.sha, isFork: (.head.repo.fork // false)}}']);
    pull = {
      state: data.state,
      draft: Boolean(data.draft),
      headRef: data.head?.ref || '',
      headSha: data.head?.sha || '',
      isFork: Boolean(data.head?.isFork),
    };
    reviews = ghJson(['api', `repos/${repo}/pulls/${prNumber}/reviews?per_page=100`, '--paginate',
      '--jq', '[.[] | {commitId: .commit_id, state: .state}]']);
  } catch {
    pull = null;
  }

  // 变量名要与工作流里那个 env 键一致。写成 SENDER_IS_BOT 时工作流传的是 SENDER_TYPE，
  // 于是这里恒为 false，「机器人重复叫醒不再评」那一条在 CI 里从未生效过 —— 而它不会报错。
  const result = prepareFrank({ prNumber, pull, reviews, senderIsBot: process.env.SENDER_TYPE === 'Bot' });
  writeOutputs({
    head_ref: result.headRef || '',
    head_sha: result.headSha || '',
    is_own_pr: result.isOwnPr,
    skip: result.skip,
    skip_reason: result.skipReason || '',
  });
  if (result.repeated) {
    // 静默跳过等于没人知道这次没评：留一条注解，不往 PR 上发评论
    process.stdout.write(`::notice::当前提交 ${String(result.headSha || '').slice(0, 8)} 上已有评审，这次机器人叫醒不再是必要的\n`);
  }
  process.stdout.write(`PR #${prNumber} 分支 ${result.headRef}，我方分支=${result.isOwnPr}，跳过原因=${result.skipReason || '无'}\n`);
}

function main() {
  const role = process.argv[2];
  const repo = process.env.REPOSITORY || '';
  if (!repo) {
    process.stderr.write('用法：context.mjs <clara|nora|miles|frank>（需要 REPOSITORY）\n');
    process.exit(2);
  }
  const handlers = {
    clara: () => runClara(repo, Number(process.env.BATCH_LIMIT || 5)),
    nora: () => runNora(repo),
    miles: () => runMiles(repo),
    frank: () => runFrank(repo),
  };
  const handler = handlers[role];
  if (!handler) {
    process.stderr.write(`不认识的角色：${role}\n`);
    process.exit(2);
  }
  try {
    handler();
  } catch (err) {
    // 取数失败不能用 exit 1：1 在这里的含义是「跳过了」，会被读成一切正常。
    process.stderr.write(`判断该不该跑这一轮时出错：${err && err.message ? err.message : String(err)}\n`);
    process.exit(2);
  }
}

if (process.argv[1] && process.argv[1].endsWith('context.mjs')) {
  main();
}
