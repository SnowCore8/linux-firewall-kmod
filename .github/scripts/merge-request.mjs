#!/usr/bin/env node
/**
 * 这一轮陈实有没有申请合并：正文里有一行独占一段的 `<!-- qwen:merge-request -->`。
 *
 * 为什么单独成文件：这段判断原先写在 qwen-miles.yml 里，用 `grep -Eq` 直接扫原文。
 * 于是它和 route.mjs、review.mjs、patrol.mjs 踩过的坑一模一样 —— 有人贴一段
 * 「协议长这样」的围栏、或引用一行行内代码，标记就被当成真的申请。
 *
 * 方向也同样是坏的那个：这里误认会把闸门叫起来跑（闸门自己的五条仍然全核），
 * 代价是「陈实没说要合，却被合了」。判断逻辑放在 yml 里就只能靠推上去试，
 * 放进这个文件才能对着真实形状的正文跑一遍。
 *
 * 用法（workflow 里也是这么调的，正文走标准输入）：
 *   node .github/scripts/merge-request.mjs < 正文
 *
 * 退出码：0 = 申请了；1 = 没申请。
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

// 判据（独占一行、先剥代码）在 markers.mjs，与评审结论共用同一份定义。
// 调用方一直从本文件取这个判断，所以这里继续导出。
import { hasMergeRequest } from './markers.mjs';

export { hasMergeRequest };

/**
 * 从这一轮的最终回复与评论里找出申请，返回 `'final-reply'` / `'comment'` / `''`。
 *
 * 两处都认：陈实既可能把结论写成最终回复，也可能写成评论。看的是「这一轮动过的」
 * 评论而不是「最后一条」—— 上一轮留下的标记不是这一轮的申请。
 *
 * 取数失败要重试并把 gh 的报错打出来：之前查不出原因，就是因为 `2>/dev/null ||
 * true` 把「缺 GITHUB_TOKEN」这个真原因吞掉了。
 */
export function findMergeRequest({ reply = '', comments = () => '', attempts = 3 } = {}) {
  if (hasMergeRequest(reply)) return 'final-reply';
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    let text = '';
    try {
      text = comments();
    } catch (err) {
      process.stderr.write(`取评论失败（第 ${attempt} 次）：${err && err.message ? err.message : String(err)}\n`);
      text = '';
    }
    if (hasMergeRequest(text)) return 'comment';
  }
  return '';
}

/**
 * 这一轮最后一段 assistant 文本。
 *
 * 取「最后一段 text」而不是「最后一个 assistant 条目」：那一轮可能就是发评论的
 * 工具调用，里面没有 text 块，取后者会拿到空串。
 */
export function lastAssistantText(logPath) {
  try {
    const all = JSON.parse(fs.readFileSync(logPath, 'utf8'));
    const texts = (Array.isArray(all) ? all : [])
      .filter((e) => e && e.type === 'assistant')
      .flatMap((e) => (e.message?.content || []).filter((c) => c.type === 'text').map((c) => c.text));
    return texts.length ? texts[texts.length - 1] : '';
  } catch {
    return '';
  }
}

const writeOutput = (key, value) => {
  const target = process.env.GITHUB_OUTPUT;
  if (target) fs.appendFileSync(target, `${key}=${value}\n`);
  else process.stdout.write(`${key}=${value}\n`);
};

function main() {
  const repo = process.env.REPOSITORY || '';
  const prNumber = process.env.PR_NUMBER || '';
  const startedAt = process.env.STARTED_AT || '';

  const reply = lastAssistantText('qwen-artifacts/stdout.log');

  // 不给 API 传 since：与其猜服务端怎么筛，不如整份取回再按 updated_at 自己筛。
  // 这一轮之前就存在的评论不算。
  const comments = () => {
    if (!prNumber || !startedAt) return '';
    const filter = `[.[] | select(.user.type == "Bot") | select(.updated_at >= "${startedAt}") | .body] | join("\\n\\n")`;
    return execFileSync(
      'gh',
      ['api', `repos/${repo}/issues/${prNumber}/comments?per_page=100`, '--jq', filter],
      { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
    );
  };

  const from = findMergeRequest({ reply, comments });
  writeOutput('requested', from ? 'true' : 'false');
  process.stdout.write(from ? `陈实申请了合并（来自 ${from}），交给闸门判定。\n` : '这一轮没有申请合并。\n');
}

// 被 import 时只导出判断，不碰标准输入
if (process.argv[1] && process.argv[1].endsWith('merge-request.mjs')) {
  if (process.env.REPOSITORY) {
    main();
  } else {
    const text = fs.readFileSync(0, 'utf8');
    process.exit(hasMergeRequest(text) ? 0 : 1);
  }
}
