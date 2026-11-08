/**
 * no-merge-gh 的测试：哪些调用要挡住，哪些要原样放行。
 *
 * 包装器是合并闸门之外唯一一层「拦在动作之前」的东西，它对两种输入敏感：
 *   - 合并入口（`pr merge`、REST/GraphQL 的 merge）
 *   - 摘掉闸标签（`pr edit --remove-label do-not-merge`），摘了之后闸门就查不到这道闸
 *
 * 判错的方向不对称：多挡一次是有人多点一下；漏挡一次是把人放的闸自己拆了。所以
 * 「必须挡」和「必须放行」两类都要有测试钉着，尤其放行那几条 —— 包装器挡错一次，
 * 陈实连改 PR 标题都做不到。
 *
 *   /usr/bin/node --test .github/scripts/no-merge-gh.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const WRAPPER = join(dirname(fileURLToPath(import.meta.url)), 'no-merge-gh');

// 假 gh：把收到的参数原样打回来，用来分辨「透传了」还是「没到这一层」
const dir = mkdtempSync(join(tmpdir(), 'no-merge-gh-test-'));
const FAKE_GH = join(dir, 'real-gh');
writeFileSync(FAKE_GH, '#!/usr/bin/env bash\nprintf "PASS-THROUGH %s\\n" "$*"\n');
chmodSync(FAKE_GH, 0o755);
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));

/** 跑一次包装器。返回 {code, out, err}，不抛。 */
function run(args, env = {}) {
  try {
    const out = execFileSync(WRAPPER, args, {
      encoding: 'utf8',
      env: { ...process.env, REAL_GH: FAKE_GH, QWEN_MERGE_GATE: '', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: 0, out, err: '' };
  } catch (error) {
    return { code: error.status ?? -1, out: error.stdout || '', err: error.stderr || '' };
  }
}

// ─────────────────────────── 合并入口必须挡 ───────────────────────────

test('拦 gh pr merge', () => {
  const r = run(['pr', 'merge', '25', '--squash']);
  assert.equal(r.code, 1);
  assert.match(r.err, /没有合并权限/);
  assert.doesNotMatch(r.out, /PASS-THROUGH/);
});

test('拦 REST 合并入口 /pulls/<n>/merge', () => {
  const r = run(['api', 'repos/a/b/pulls/25/merge', '-X', 'PUT']);
  assert.equal(r.code, 1);
  assert.match(r.err, /没有合并权限/);
});

test('拦 GraphQL 的 mergePullRequest', () => {
  const r = run(['api', 'graphql', '-f', 'query=mutation{mergePullRequest(input:{}){}}']);
  assert.equal(r.code, 1);
  assert.match(r.err, /没有合并权限/);
});

// ─────────────────────────── 摘闸标签必须挡 ───────────────────────────

test('拦 pr edit --remove-label 后跟 do-not-merge', () => {
  const r = run(['pr', 'edit', '25', '--remove-label', 'do-not-merge']);
  assert.equal(r.code, 1);
  assert.match(r.err, /没有摘闸标签的权限/);
  assert.match(r.err, /只有人能摘/);
});

test('拦 pr edit --remove-label=manual-review', () => {
  const r = run(['pr', 'edit', '25', '--remove-label=manual-review']);
  assert.equal(r.code, 1);
  assert.match(r.err, /没有摘闸标签的权限/);
});

test('拦逗号列表里夹着闸标签', () => {
  const r = run(['pr', 'edit', '25', '--remove-label', 'bug,triage,do-not-merge']);
  assert.equal(r.code, 1);
  assert.match(r.err, /没有摘闸标签/);
});

test('标签名带空格也认得出', () => {
  const r = run(['pr', 'edit', '25', '--remove-label', 'bug, manual-review']);
  assert.equal(r.code, 1);
  assert.match(r.err, /没有摘闸标签/);
});

test('闸门自己（QWEN_MERGE_GATE=1）可以摘标签', () => {
  const r = run(['pr', 'edit', '25', '--remove-label', 'do-not-merge'], { QWEN_MERGE_GATE: '1' });
  assert.equal(r.code, 0);
  assert.match(r.out, /PASS-THROUGH/);
});

// ─────────────────────────── 其余必须放行 ───────────────────────────

test('摘普通标签照常透传', () => {
  const r = run(['pr', 'edit', '25', '--remove-label', 'bug']);
  assert.equal(r.code, 0);
  assert.match(r.out, /PASS-THROUGH pr edit 25 --remove-label bug/);
});

test('给 PR 加闸标签照常透传（那是人放闸的动作）', () => {
  const r = run(['pr', 'edit', '25', '--add-label', 'do-not-merge']);
  assert.equal(r.code, 0);
  assert.match(r.out, /PASS-THROUGH pr edit 25 --add-label do-not-merge/);
});

test('改标题照常透传', () => {
  const r = run(['pr', 'edit', '25', '--title', '新标题']);
  assert.equal(r.code, 0);
  assert.match(r.out, /PASS-THROUGH/);
});

test('pr view 照常透传', () => {
  const r = run(['pr', 'view', '25', '--json', 'state']);
  assert.equal(r.code, 0);
  assert.match(r.out, /PASS-THROUGH pr view 25 --json state/);
});

test('issue edit 的 --remove-label 不被拦（那不是合并闸）', () => {
  const r = run(['issue', 'edit', '25', '--remove-label', 'do-not-merge']);
  assert.equal(r.code, 0);
  assert.match(r.out, /PASS-THROUGH/);
});

test('QWEN_MERGE_GATE=1 时合并也放行（闸门本体的调用）', () => {
  const r = run(['pr', 'merge', '25', '--squash', '--delete-branch'], { QWEN_MERGE_GATE: '1' });
  assert.equal(r.code, 0);
  assert.match(r.out, /PASS-THROUGH pr merge 25 --squash --delete-branch/);
});

test('找不到真实 gh 时失败，不 exec 回自己', () => {
  const r = run(['pr', 'view', '25'], { REAL_GH: WRAPPER });
  assert.equal(r.code, 127);
  assert.match(r.err, /找不到真实的 gh/);
});

// ─────────────────────── 与 JS 那份清单必须一致 ───────────────────────

test('包装器里的闸标签清单与 review.mjs 的 STOP_LABELS 完全一致', async () => {
  // 这个文件是 bash，没法 import review.mjs，所以清单各写一份。不同步的后果是
  // 某一层看不见人放的闸：闸门拦得住、包装器却放行摘标签，或者反过来。
  const { STOP_LABELS } = await import('./review.mjs');
  const source = execFileSync('grep', ['-E', '^STOP_LABELS=', WRAPPER], { encoding: 'utf8' }).trim();
  const bashList = source
    .replace(/^STOP_LABELS=/, '')
    .replace(/^['"]|['"]$/g, '')
    .split(/[\s,]+/)
    .filter(Boolean);
  assert.deepEqual(bashList, STOP_LABELS);
});
