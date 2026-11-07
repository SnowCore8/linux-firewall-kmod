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

function commentsOf(number) {
  // 取不到评论不能当成「没有评论」—— 那会让防打转闸门失效，机器人可以无限转交。
  // 宁可这次运行失败（report-failure 会在话题里说明），也不要在没有依据的情况下继续派活。
  //
  // --slurp 是必须的：`gh api --paginate` 默认把每页的 JSON 数组直接拼在输出里，
  // 一旦评论超过 100 条就是 `[...][...]`，JSON.parse 直接抛；--slurp 会包成
  // `[[...],[...]]`，flatten 之后才是完整的一份。
  const pages = gh(['api', '--paginate', '--slurp', `repos/${REPO}/issues/${number}/comments`]);
  return (pages || []).flat() || [];
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
    const recent = recentBotComments(readComments(number), now);
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

const OUTPUT_KEYS = ['role', 'number', 'on_pr', 'reason', 'issue_number', 'pr_number', 'head_ref'];

/** 结果 → 输出行。不派活时角色留空：下游四个 job 的 if 都不成立，一个模型都不会启动。 */
export function outputLines(result) {
  const values = { role: '' };
  if (result.kind === 'assign') {
    Object.assign(values, {
      role: result.role,
      number: String(result.number ?? ''),
      on_pr: result.onPr ? 'true' : 'false',
      reason: result.reason,
      issue_number: String(result.issueNumber ?? ''),
      pr_number: String(result.prNumber ?? ''),
      head_ref: result.headRef || '',
    });
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
  writeOutput(outputLines(result));

  if (result.kind === 'fail') {
    process.stderr.write(`${result.why}\n`);
    process.exit(1);
  }
}

// 被 import 时不执行，只有脚本自己跑起来才取数
if (process.argv[1] && process.argv[1].endsWith('dispatch.mjs')) {
  main();
}
