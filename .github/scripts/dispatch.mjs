#!/usr/bin/env node
/**
 * dispatch 的 I/O 层：把 GitHub 的事件摊平成 route() 要的形状，再把结论写回 workflow。
 *
 * 分工是刻意的：
 *   route.mjs    只判断，没有网络、没有文件，能单测
 *   dispatch.mjs 只取数与回写，不判断
 *
 * 这样「该派给谁」这件事可以在本地用一组数据反复验，而这里留下的只有
 * 「怎么把事件原文变成那几个字段」这种一眼能看懂的搬运。
 * 搬运本身也有测试：字段名对不上会让 route() 拿到 undefined，然后安静地什么都不派。
 *
 * 用法（workflow 里就这么一行）：
 *   node .github/scripts/dispatch.mjs
 *
 * 需要的环境变量：
 *   GH_TOKEN                          取数用（App 令牌或 github.token）
 *   GITHUB_REPOSITORY                 owner/name
 *   GITHUB_EVENT_PATH                 事件原文，Actions 自动提供
 *   GITHUB_EVENT_NAME                 事件名，Actions 自动提供
 *   QWEN_MENTION                      触发词，默认 @qwencoder
 *   AGENT_MAX_HANDOFFS / AGENT_MAX_CALLS / AGENT_CALL_COOLDOWN_MINUTES
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

import {
  route,
  parseHandoff,
  parseCall,
  recentBotComments,
  countRecentHandoffs,
  recentCalls,
  handoffLimitMessage,
  PEOPLE,
} from './route.mjs';

const REPO = process.env.GITHUB_REPOSITORY || '';

/** 取数一律走 gh：与 patrol.mjs 一致，省得再引一个 SDK */
function gh(args) {
  const raw = execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  return raw.trim() ? JSON.parse(raw) : null;
}

const api = (path) => gh(['api', `repos/${REPO}/${path}`]);

const isPull = (number) => Boolean(api(`issues/${number}`)?.pull_request);
const headRefOf = (number) => api(`pulls/${number}`)?.head?.ref || '';

/**
 * 分页取回的每个元素各自一行 JSON（NDJSON），逐行解析。
 *
 * 为什么不用 `--slurp`：那个 flag 只有较新的 gh 才有，本机 `gh version 2.46.0`
 * （Ubuntu 官方包）直接报 `unknown flag: --slurp`。README 把「本地跑一遍 dispatch」
 * 当成验证手段，用上新 flag 就等于把这条路堵死，而报错长得像脚本自己坏了。
 *
 * 也不能直接 `JSON.parse` 整个输出：`gh api --paginate` 不带 --jq 时把各页的数组
 * 首尾相接（`[...][...]`），超过一页就解析不了。
 *
 * `--jq '.[]'` 两头都避开：gh 对每页分别跑 jq，把数组摊成一行一个对象，跨页累加。
 * 对象的字符串字段里换行会被转义成 `\n`，所以一行始终是一个完整的 JSON。
 */
const ghLines = (args) =>
  execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));

export function commentsOf(number) {
  // 取不到评论不能当成「没有评论」—— 那会让防打转闸门失效，机器人可以无限转交。
  // 宁可这次运行失败（report-failure 会在话题里说明），也不要在没有依据的情况下继续派活。
  // 出错时 execFileSync 抛异常，正好落到这条。
  return ghLines(['api', '--paginate', '--jq', '.[]', `repos/${REPO}/issues/${number}/comments`]);
}

/**
 * 事件原文 → route() 的输入。这里所有的 `dep` 都是为了能在测试里替换掉 I/O。
 */
export function buildInput({ event, eventName, env = process.env, deps = {} }) {
  const { isPull: checkPr = isPull, commentsOf: readComments = commentsOf } = deps;
  const now = Number(env.DISPATCH_NOW || Date.now());
  const manualNumber = eventName === 'workflow_dispatch' ? String(event.inputs?.number || '') : '';

  const issue = event.issue;
  const pr = event.pull_request;

  const payload = {
    issueNumber: issue?.number ?? '',
    prNumber: pr?.number ?? '',
    commentBody: event.comment?.body || '',
    reviewBody: event.review?.body || '',
    issueBody: issue?.body || '',
    prBody: pr?.body || '',
    issueIsPr: Boolean(issue?.pull_request),
    prIsFork: Boolean(pr?.head?.repo?.fork),
    reviewState: event.review?.state || '',
    prHeadRef: pr?.head?.ref || '',
    assignee: event.assignee?.login || '',
    assigneeType: event.assignee?.type || '',
    // 手动触发的事件里没有 Issue/PR 正文，得自己问一次它是不是 PR
    ...(manualNumber ? { issueIsPr: checkPr(manualNumber) } : {}),
  };

  const senderType = event.sender?.type || '';
  const authorAssociation =
    event.comment?.author_association ||
    event.review?.author_association ||
    event.issue?.author_association ||
    event.pull_request?.author_association ||
    '';

  const gates = {
    now,
    maxHandoffs: Number(env.AGENT_MAX_HANDOFFS || 20),
    maxCalls: Number(env.AGENT_MAX_CALLS || 40),
    cooldownMinutes: Number(env.AGENT_CALL_COOLDOWN_MINUTES || 10),
  };

  // 只在真的要判额度时才数评论：这几十次 API 调用没必要每条事件都付。
  // 判据很窄 —— 机器人自己发的、且带交接或点名标记。
  const body = payload.commentBody || payload.reviewBody || '';
  const needsCounting = senderType === 'Bot' && (parseHandoff(body) || parseCall(body));
  const number = payload.issueNumber || payload.prNumber;
  if (needsCounting && number) {
    // 触发本次运行的那条评论不是「历史」，它正是这次要判的动作本身。
    // 不剔掉的话，点名冷却会拿它当「上一次点名」，算出来 waited 恒为 0 ——
    // 机器人之间的 `<!-- qwen:to=… -->` 永远发不出去，人写的才过得去。
    // 交接额度与每日上限有同一处依赖：它们数的都该是「之前发生过几次」。
    const triggerId = event.comment?.id;
    const history = readComments(number).filter((c) => triggerId == null || c.id !== triggerId);
    const recent = recentBotComments(history, now);
    gates.recentHandoffs = countRecentHandoffs(recent);
    gates.calls = recentCalls(recent);
  }

  return {
    eventName,
    action: event.action || '',
    payload,
    senderType,
    authorAssociation,
    actor: env.ACTOR || '',
    mention: (env.QWEN_MENTION || '@qwencoder').toLowerCase(),
    gates,
    manual: { number: manualNumber, role: String(event.inputs?.role || '') },
  };
}

/** 多行安全：reason 里可能带换行，用 heredoc 才不会把输出截断 */
export function formatOutput(key, value) {
  return `${key}<<__END__\n${value}\n__END__\n`;
}

const OUTPUT_KEYS = ['role', 'who', 'number', 'on_pr', 'reason', 'issue_number', 'pr_number', 'head_ref'];

/**
 * 结果 → 输出行。不派活时角色留空：下游四个 job 的 if 都不成立，一个模型都不会启动。
 *
 * who 是 role 对应的中文名，给「出错说明」那条评论用：那句话要写给人看，
 * 而 route.mjs 里已经有一份英文名到中文名的对应，这里直接带出去，别在 yml 里再抄一张表 ——
 * 抄出来的那张改了名字不会报错，只会在出错说明里叫错人。
 *
 * eventNumber 只在 fail 时用得上：route() 判出「配置有误」时手里没有编号，
 * 而下游要知道去哪个话题里说明。由调用方从事件里取，纯函数才好测。
 */
export function outputLines(result, eventNumber = '') {
  const values = { role: '' };
  if (result.kind === 'assign') {
    Object.assign(values, {
      role: result.role,
      who: PEOPLE[result.role] || '',
      number: String(result.number ?? ''),
      on_pr: result.onPr ? 'true' : 'false',
      reason: result.reason,
      issue_number: String(result.issueNumber ?? ''),
      pr_number: String(result.prNumber ?? ''),
      head_ref: result.headRef || '',
    });
  } else if (result.kind === 'fail') {
    // 失败时也要把编号写出去：qwen-dispatch.yml 的 report-failure 判据是
    // `needs.route.outputs.number != ''`，编号空着它就不出面 —— 于是这次失败
    // 只在 Actions 里留一行红叉，话题里一个字都没有。而失败恰恰是最需要说明的。
    // role 仍留空：这次是失败的，不该顺手把活派给谁。
    const n = Number(eventNumber);
    if (Number.isFinite(n) && n > 0) values.number = String(n);
  }
  return OUTPUT_KEYS.filter((k) => k in values).map((k) => formatOutput(k, values[k]));
}

/** 事件里的编号。取数失败时也要能用 —— report-failure 靠它才知道去哪个话题里说明。 */
export const numberOfEvent = (event) =>
  event?.issue?.number ?? event?.pull_request?.number ?? (event?.inputs?.number ? Number(event.inputs.number) : '');

function writeOutput(lines) {
  const text = lines.join('');
  const file = process.env.GITHUB_OUTPUT;
  if (file) fs.appendFileSync(file, text);
  else process.stdout.write(text);
}

function main() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) throw new Error('缺少 GITHUB_EVENT_PATH');
  const event = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
  const eventName = process.env.GITHUB_EVENT_NAME || '';

  let input;
  try {
    input = buildInput({ event, eventName });
  } catch (error) {
    // 取数失败就把编号写出去，好让 report-failure 能在话题里说明这次没处理完。
    // role 仍然留空 —— 这次是失败的，不该顺手把活派给谁。
    const number = numberOfEvent(event);
    if (number !== '') writeOutput([formatOutput('number', String(number))]);
    process.stderr.write(`取数失败：${error.message}\n`);
    throw error;
  }

  let result = route(input);

  // 需要 PR 分支名时再问一次，带上结果重调 —— route() 没有副作用，重入是安全的
  if (result.kind === 'need-pull') {
    const number = input.payload.issueNumber || input.payload.prNumber || Number(input.manual.number);
    result = route({ ...input, pull: { headRef: headRefOf(number) } });
  }

  if (result.kind === 'assign') {
    process.stderr.write(
      `路由：${result.role} #${result.number} on_pr=${result.onPr} 原因=${result.reason}\n`,
    );
  } else if (result.kind === 'ignore') {
    process.stderr.write(`${result.why}\n`);
  } else if (result.kind === 'handoff-limit') {
    // 静默丢弃会让人以为交接生效了，这里留一条说明；这条不带交接标记，不会再触发下一轮
    execFileSync(
      'gh',
      ['issue', 'comment', String(result.number), '--repo', REPO, '--body', handoffLimitMessage(result)],
      { encoding: 'utf8' },
    );
    process.stderr.write(
      `最近 24 小时已有 ${result.recent} 次自动交接，超过上限 ${result.max}，停止自动转交，已在话题里说明\n`,
    );
  }

  // 先把输出写掉再失败：report-failure 靠 number 才知道去哪个话题里说明
  writeOutput(outputLines(result, numberOfEvent(event)));

  if (result.kind === 'fail') {
    process.stderr.write(`${result.why}\n`);
    process.exit(1);
  }
}

// 被 import 时不执行，只有脚本自己跑起来才取数
if (process.argv[1] && process.argv[1].endsWith('dispatch.mjs')) {
  main();
}
