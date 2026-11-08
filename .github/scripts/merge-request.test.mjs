/**
 * 「这一轮申请了合并吗」的测试。
 *
 * 判错的方向是坏的：把引用当成申请，闸门会被叫起来跑一遍；闸门自己的五条仍然
 * 全核，但「陈实没说要合」这件事已经丢了。反过来漏认一条真申请，PR 就一直躺着
 * 没人合 —— 巡检过一阵会再叫一次，代价只是一轮。
 *
 *   /usr/bin/node --test .github/scripts/merge-request.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { findMergeRequest, hasMergeRequest, lastAssistantText } from './merge-request.mjs';

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'merge-request.mjs');

test('单独占一行 → 算申请', () => {
  assert.equal(hasMergeRequest('结论：可以合。\n\n<!-- qwen:merge-request -->\n'), true);
});

test('行内引用不算申请', () => {
  // 陈实常在正文里解释协议本身
  assert.equal(
    hasMergeRequest('申请就是写一行 `<!-- qwen:merge-request -->`，闸门认它。'),
    false,
  );
});

test('围栏里贴出来的标记不算申请', () => {
  const body = [
    '协议长这样：',
    '',
    '```',
    '<!-- qwen:merge-request -->',
    '```',
    '',
    '这一轮我先不合，等周正看完。',
  ].join('\n');
  assert.equal(hasMergeRequest(body), false);
});

test('和别的内容挤在同一行不算 —— 标记要独占一段', () => {
  assert.equal(hasMergeRequest('可以合了 <!-- qwen:merge-request -->'), false);
  assert.equal(hasMergeRequest('<!-- qwen:merge-request --> 合吧'), false);
});

test('围栏关掉之后的真标记照旧算数', () => {
  const body = ['```', '<!-- qwen:merge-request -->', '```', '', '不过这次是真的：', '', '<!-- qwen:merge-request -->'].join('\n');
  assert.equal(hasMergeRequest(body), true);
});

test('多行空白与 \\r 不影响判断', () => {
  assert.equal(hasMergeRequest('  <!-- qwen:merge-request -->  \r\n'), true);
  assert.equal(hasMergeRequest('\t<!--   qwen:merge-request   -->\t'), true);
});

test('空正文不崩，也不当成申请', () => {
  assert.equal(hasMergeRequest(''), false);
  assert.equal(hasMergeRequest(undefined), false);
});

test('命令本身：正文走标准输入，退出码说话', () => {
  // workflow 里就是 `node .github/scripts/merge-request.mjs <<< "$REPLY"`，
  // 取的是退出码而不是输出，所以这条必须把真实进程跑起来。
  //
  // REPOSITORY 必须显式清掉：它在环境里时脚本会走 main() 那条路（去 gh 取评论），
  // 而不是读标准输入。本意是钉住 stdin 这条路，别让宿主的 shell 影响结论。
  const asked = (input) =>
    spawnSync(process.execPath, [SCRIPT], {
      input,
      encoding: 'utf8',
      env: { ...process.env, REPOSITORY: '' },
    }).status;
  assert.equal(asked('\n<!-- qwen:merge-request -->\n'), 0);
  assert.equal(asked('```\n<!-- qwen:merge-request -->\n```\n'), 1);
});

// ───────────────────────── 取数那一半 ─────────────────────────
// 纯判断对了，取数取错一样等于没做：读错了那一轮的输出、或者把上一轮的评论当成
// 这一轮的申请。

test('最终回复里写了标记，就不用再去翻评论', () => {
  let asked = false;
  const from = findMergeRequest({
    reply: '结论：可以合。\n\n<!-- qwen:merge-request -->',
    comments: () => {
      asked = true;
      return '';
    },
  });
  assert.equal(from, 'final-reply');
  assert.equal(asked, false, '最终回复已经给出答案，不该再发一次请求');
});

test('最终回复没有，就去这一轮动过的评论里找', () => {
  const from = findMergeRequest({ reply: '改完了。', comments: () => '改动说明\n\n<!-- qwen:merge-request -->' });
  assert.equal(from, 'comment');
});

test('两处都没有 → 没申请', () => {
  assert.equal(findMergeRequest({ reply: '这一轮只是回答问题。', comments: () => '同上' }), '');
});

test('评论取不到时会重试，重试完仍然没有就算没申请（不抛）', () => {
  let calls = 0;
  const from = findMergeRequest({
    reply: '',
    comments: () => {
      calls += 1;
      throw new Error('gh: Resource not accessible by integration');
    },
  });
  assert.equal(from, '');
  assert.equal(calls, 3, '失败要重试三次，而不是一次就放弃');
});

test('第一次取评论失败，第二次拿到也算申请', () => {
  let calls = 0;
  const from = findMergeRequest({
    reply: '',
    comments: () => {
      calls += 1;
      if (calls === 1) throw new Error('临时故障');
      return '<!-- qwen:merge-request -->';
    },
  });
  assert.equal(from, 'comment');
  assert.equal(calls, 2);
});

test('最后一段 assistant 文本：跳过没有 text 块的条目', () => {
  // 真实形状：那一轮最后是发评论的工具调用，条目里没有 text
  const dir = mkdtempSync(path.join(tmpdir(), 'mr-'));
  const log = path.join(dir, 'stdout.log');
  writeFileSync(
    log,
    JSON.stringify([
      { type: 'assistant', message: { content: [{ type: 'text', text: '先说一句' }] } },
      { type: 'assistant', message: { content: [{ type: 'tool_use', name: 'run_shell_command' }] } },
    ]),
  );
  try {
    assert.equal(lastAssistantText(log), '先说一句', '取最后一段 text，不是最后一个条目');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('读不到输出文件时返回空串，不抛', () => {
  assert.equal(lastAssistantText('/nonexistent/stdout.log'), '');
});
