/**
 * 工作流这一轮跑完了没有。
 *
 * 判据只有一个来源：CLI 的 JSON 转录里，工作流那次工具调用返回了什么。实测两种形状
 * （`qwen -p '/名字' -o json`）：
 *
 *   成功：tool_result.is_error = false，content 里有 `"runId": "wf_…"` 和 `"result": …`
 *   失败：tool_result.is_error = true，  content 以 `Workflow failed: <原因>` 开头
 *
 * 关键在于 CLI 这两种情况都退出 0。所以这里测的不是「能不能解析」，而是
 * 「解析出来的形状对不上时会不会当成成功」—— 那条正是这个仓库反复踩的坑。
 *
 *   /usr/bin/node --test .github/scripts/workflow-run.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { findWorkflowResult, summarize } from './workflow-run.mjs';

/** 造一条 tool_result，形状照实测抄。 */
const toolResult = (content, isError = false) => ({
  type: 'user',
  message: { content: [{ type: 'tool_result', tool_use_id: 'call_1', is_error: isError, content }] },
});

const OK_TEXT =
  '```json\n{\n  "runId": "wf_192036ebcc1256d7",\n  "meta": {"name": "Miles fix"},\n' +
  '  "phases": [{"title": "取证"}],\n  "logs": [],\n  "result": {"outcome": "handoff"}\n}\n```';

const FAIL_TEXT =
  'Workflow failed: boom-probe\n--- workflow run ---\nrunId: wf_3dd1eee5cfdbc616\n' +
  'script: /tmp/wf-probe/.qwen/workflows/ping.js\nagents: 0 dispatched · 0 completed · 0 failed\n' +
  'tokens: 0 spent (no cap)';

test('成功那次认成成功', () => {
  const found = findWorkflowResult([{ type: 'system' }, toolResult(OK_TEXT)]);
  assert.ok(found, '应当认出工作流那一条');
  assert.equal(found.ok, true);
});

test('失败那次不会被认成成功', () => {
  // CLI 退出码是 0，所以这一条是唯一的防线。认错的话「工作流中途抛错」会变成
  // 「这一轮跑完了、什么都没做」，闸门照常核、job 照常绿。
  const found = findWorkflowResult([toolResult(FAIL_TEXT, true)]);
  assert.ok(found);
  assert.equal(found.ok, false);
});

test('只看最后一条工作流结果', () => {
  const found = findWorkflowResult([toolResult(FAIL_TEXT, true), toolResult(OK_TEXT)]);
  assert.equal(found.ok, true, '重跑一次成功之后不该还挂着上一次的失败');
});

test('别的工具调用失败不算工作流失败', () => {
  // 一次 grep 没命中、一次 gh 报错，都会是 is_error 的 tool_result。
  // 把它们读成「工作流失败」会让这一轮无故变红。
  const grepFail = toolResult('No matches found for pattern: foo', true);
  const found = findWorkflowResult([grepFail, toolResult(OK_TEXT)]);
  assert.equal(found.ok, true);
});

test('压根没跑工作流时返回 null', () => {
  // 模型把命令当成普通文本回了一句、或者压根没调用工具 —— 都不是「跑完了」，
  // 调用方按 2 处理（无从判断，不能当成功）。
  assert.equal(findWorkflowResult([{ type: 'system' }, toolResult('hello', false)]), null);
  assert.equal(findWorkflowResult([]), null);
  assert.equal(findWorkflowResult(null), null);
});

test('内容不是字符串时不当成功', () => {
  const odd = { type: 'user', message: { content: [{ type: 'tool_result', is_error: false, content: [{ type: 'text' }] }] } };
  assert.equal(findWorkflowResult([odd]), null);
});

test('摘要只留要看的那几行', () => {
  const out = summarize(FAIL_TEXT);
  assert.ok(out.includes('Workflow failed: boom-probe'), out);
  assert.ok(out.includes('runId: wf_3dd1eee5cfdbc616'), out);
  // 每行都 trim 过、空行不留：这段会原样进 ::error 的注解，缩进和空行只会撑大日志
  assert.ok(!/\n\n/.test(out), out);
  for (const line of out.split('\n')) assert.equal(line, line.trim(), `多了缩进：${line}`);
});

test('认不出关键行时退回前几行', () => {
  // 形状变了（上游改了输出格式）也不能返回空串 —— 空摘要读起来像「没有问题」
  const out = summarize('第一行\n第二行\n第三行');
  assert.ok(out.includes('第一行'), out);
});
