#!/usr/bin/env node
/**
 * 这一轮的工作流到底跑完了没有。
 *
 * 为什么要单独判：`qwen -p '/miles-fix {…}'` 在工作流失败时**退出码仍是 0**。
 * 实测（把脚本改成 `throw new Error("boom")`）：
 *
 *   $ qwen -p '/ping' --approval-mode yolo ; echo $?
 *   0
 *
 * 失败只体现在转录里 —— 那条 tool_result 带 `is_error: true`，内容是
 * `Workflow failed: boom` 加一段运行摘要。于是「陈实这一轮失败了」在 CI 里会
 * 被读成成功：闸门照常核、job 照常绿，只是这次什么都没做。
 *
 * 这与 run-agent 里那条「API 报错时 CLI 退出 0」是同一类问题，只是那一层看的是
 * 最后一段 assistant 文本，自建工作流之后要看的换成了工作流自己的结果。
 *
 * 用法（workflow 里就是这么调的）：
 *   node .github/scripts/workflow-run.mjs
 *
 * 退出码：0 = 跑完了；1 = 失败；2 = 找不到转录（无从判断，不能当成功）。
 */

import fs from 'node:fs';

const TRANSCRIPT = 'qwen-artifacts/stdout.log';

/** 工作流失败时那条 tool_result 的内容前缀。 */
const FAILED_PREFIX = 'Workflow failed:';

/**
 * 从转录里找出与工作流有关的那条 tool_result。
 *
 * 判定是「工作流调用」而不是「任何失败」：同一个转录里别处也可能有失败的工具调用
 * （某次 grep 没命中也会 is_error），把它读成「工作流失败」会误伤。
 */
export function findWorkflowResult(entries) {
  const list = Array.isArray(entries) ? entries : [];
  const results = [];
  for (const entry of list) {
    if (!entry || entry.type !== 'user') continue;
    for (const part of entry.message?.content ?? []) {
      if (part?.type !== 'tool_result') continue;
      const text = typeof part.content === 'string' ? part.content : '';
      // 成功的形状是「一段 JSON，里面有 runId」，失败的是「Workflow failed: …」。
      // 两者都不带的话就不是工作流那一条。
      if (text.startsWith(FAILED_PREFIX)) results.push({ ok: false, text });
      else if (/"runId"\s*:/.test(text) && !part.is_error) results.push({ ok: true, text });
    }
  }
  return results.length ? results[results.length - 1] : null;
}

const readTranscript = (file) => {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return { error: err && err.message ? err.message : String(err) };
  }
};

/** 把 workflow 的结论摘要从结果文本里取出来，只留人要看的那几行。 */
export function summarize(text) {
  const lines = String(text || '')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  const keep = lines.filter((l) =>
    /^(runId|script|agents|tokens|Workflow failed)/.test(l) || l.startsWith('--- '),
  );
  return (keep.length ? keep : lines.slice(0, 6)).join('\n');
}

function main() {
  const role = process.env.ROLE || 'unknown';
  if (!fs.existsSync(TRANSCRIPT)) {
    // 没有转录就无从判断。当成失败：静默通过等于这一轮没人知道发生了什么。
    process.stderr.write(`::error title=没有转录::找不到 ${TRANSCRIPT}，无法判断工作流是否跑完。\n`);
    process.exit(2);
  }

  const parsed = readTranscript(TRANSCRIPT);
  if (parsed && parsed.error) {
    process.stderr.write(`::error title=转录读不了::${TRANSCRIPT} 不是合法 JSON：${parsed.error}\n`);
    process.exit(2);
  }

  const result = findWorkflowResult(parsed);
  if (!result) {
    // 没有工作流那次调用，说明这一轮根本没走到工作流上（比如模型把命令当普通文本
    // 回了一句）。这不是「跑完了」，也不是「工作流失败」，但同样不能算成功。
    process.stderr.write(
      `::error title=这一轮没有跑工作流::转录里找不到工作流的调用结果。${role} 这一轮没有按预期的路径执行。\n`,
    );
    process.exit(2);
  }

  if (!result.ok) {
    const excerpt = summarize(result.text).slice(0, 800).replace(/::/g, ';;');
    process.stderr.write(`::error title=工作流没有跑完::${role} 这一轮中止了，下面的原因来自工作流自己。\n`);
    process.stderr.write(`${excerpt}\n`);
    process.exit(1);
  }

  process.stdout.write(`工作流已跑完。\n${summarize(result.text)}\n`);
}

if (process.argv[1] && process.argv[1].endsWith('workflow-run.mjs')) {
  main();
}
