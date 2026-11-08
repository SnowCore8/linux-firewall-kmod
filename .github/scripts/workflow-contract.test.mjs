/**
 * 工作流与脚本之间的字段契约。
 *
 * `dispatch.mjs` 把结论写进 `GITHUB_OUTPUT`，`qwen-dispatch.yml` 把它声明成 `route` job 的输出，
 * 下游四个 job 再按名字取。这三处的名字对不上不会有任何报错：脚本照写、job 照跑，
 * 取到的是空串 —— 于是谁都没被叫醒，或者一句「没跑完的是：」后面空着。
 *
 * 错的代价是安静地不干活，所以这条契约靠测试盯着，而不是靠改的时候想起来。
 *
 *   /usr/bin/node --test .github/scripts/workflow-contract.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { outputLines } from './dispatch.mjs';
import { OWN_MARKER } from './route.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const FILE = path.join('.github', 'workflows', 'qwen-dispatch.yml');
const yml = readFileSync(path.join(ROOT, FILE), 'utf8');
const lines = yml.split('\n');

/** 某个 job 的 `outputs:` 块里声明了哪些键。 */
function declaredOutputs(job) {
  const head = lines.indexOf(`  ${job}:`);
  assert.notEqual(head, -1, `${FILE} 里找不到 job ${job}`);

  let i = head + 1;
  for (; i < lines.length && !/^ {2}\S/.test(lines[i]); i += 1) {
    if (lines[i] === '    outputs:') break;
  }
  assert.equal(lines[i], '    outputs:', `${job} job 里没有 outputs:，下游取到的会全是空串`);

  const keys = [];
  for (let j = i + 1; j < lines.length; j += 1) {
    const m = /^ {6}([a-z_]+):/.exec(lines[j]);
    if (!m) break;
    keys.push(m[1]);
  }
  assert.ok(keys.length, `${job} 的 outputs: 下面一个键都没取到`);
  return keys;
}

/** outputLines() 会写出哪些键。 */
const emittedKeys = (result) => outputLines(result).map((line) => line.slice(0, line.indexOf('<<')));

const declared = declaredOutputs('route');
const consumed = [...new Set([...yml.matchAll(/needs\.route\.outputs\.([a-z_]+)/g)].map((m) => m[1]))];

test('下游取的每个输出都声明过', () => {
  for (const key of consumed) {
    assert.ok(declared.includes(key), `needs.route.outputs.${key} 没有在 route 的 outputs 里声明，取到的是空串`);
  }
});

test('脚本写出的每个键都声明过', () => {
  const written = new Set([
    ...emittedKeys({
      kind: 'assign',
      role: 'miles',
      number: 9,
      onPr: true,
      reason: '收到评审：approved',
      issueNumber: '7',
      prNumber: 9,
      headRef: 'qwen-fix-7',
    }),
    ...emittedKeys({ kind: 'ignore', why: '不用你管' }),
    ...emittedKeys({ kind: 'handoff-limit', role: 'miles', number: 7, recent: 21, max: 20 }),
  ]);

  for (const key of written) {
    assert.ok(declared.includes(key), `dispatch.mjs 写出 ${key}，route 的 outputs 里没有它，这个值会被丢掉`);
  }
  // 不派活时只写 role：下游四个 job 的 if 都不成立，一个模型都不该启动
  assert.deepEqual(emittedKeys({ kind: 'ignore', why: '不用你管' }), ['role']);
});

test('声明过的每个输出都有人取', () => {
  for (const key of declared) {
    assert.ok(consumed.includes(key), `route 声明了 ${key}，没有任何 job 取它`);
  }
});

// ───────────────────── 机器人自己开的 Issue ─────────────────────

/** 会自己开 Issue 的工作流。 */
const issueCreators = readdirSync(path.join(ROOT, '.github', 'workflows'))
  .filter((f) => f.endsWith('.yml'))
  .filter((f) => readFileSync(path.join(ROOT, '.github', 'workflows', f), 'utf8').includes('gh issue create'));

test('每个会自己开 Issue 的工作流都写了「我方」标记', () => {
  // route.mjs 里「我方开的话题上有人回复 → 顾清」这条规则认的是 OWN_MARKER，
  // 而它只在正文里出现时才算数。工作流开 Issue 时不写这行，那条规则就永远不成立：
  // 机器开的那张单子上，人回一句「这个还是红的」不会叫醒任何人 —— QWEN.md 里
  // 「自己开的 Issue 有新回复 → 顾清」就这么静默失效了（和 issues.assigned 同一类）。
  assert.ok(issueCreators.length, '一个 gh issue create 都没找到，这条测试就白跑了');
  for (const file of issueCreators) {
    const text = readFileSync(path.join(ROOT, '.github', 'workflows', file), 'utf8');
    assert.ok(
      text.includes(OWN_MARKER),
      `${file} 会自己开 Issue，但正文里没有 ${OWN_MARKER}`,
    );
  }
});

test('标记字符串本身没被改坏', () => {
  // 工作流里是原样写死的，route.mjs 改了常量而那边没跟，就会各认各的
  assert.equal(OWN_MARKER, '<!-- qwen:opened-by=agent -->');
});

