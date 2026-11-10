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
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { outputLines } from './dispatch.mjs';

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

// ───────────────────── skip 路径静默行为 ─────────────────────

/**
 * qwen-miles.yml 的 skip 路径：只点反应、不发评论。
 *
 * context.mjs 决定什么时候 skip，workflow 决定 skip 时做什么。
 * 如果 skip 时仍然发评论（比如「这条我不动手」），dispatch 会丢掉它，
 * 但评论已经发出去了 —— 这正是 Issue #62 要解决的噪音。
 *
 * 测试盯着两件事：
 * 1. skip=true 时有一个反应步骤（gh api reactions）
 * 2. skip=true 时没有任何评论步骤（gh issue comment / gh pr comment）
 */

const milesWorkflow = readFileSync(path.join(ROOT, '.github', 'workflows', 'qwen-miles.yml'), 'utf8');

test('skip 路径有反应步骤', () => {
  // 找到 skip=true 的步骤
  const skipStepMatch = milesWorkflow.match(/if:\s*\|?-?\s*\n\s*\$\{\{\s*steps\.context\.outputs\.skip\s*==\s*'true'\s*\}\}/);
  assert.ok(skipStepMatch, 'qwen-miles.yml 里找不到 skip=true 的步骤');

  // 该步骤应当调用 gh api reactions
  const afterSkip = milesWorkflow.slice(skipStepMatch.index);
  const nextStep = afterSkip.indexOf('\n      - name:');
  const skipStepContent = nextStep > -1 ? afterSkip.slice(0, nextStep) : afterSkip.slice(0, 500);
  assert.ok(
    skipStepContent.includes('gh api') && skipStepContent.includes('reactions'),
    'skip=true 的步骤应当调用 gh api reactions，而不是发评论',
  );
});

test('skip 路径没有评论步骤', () => {
  // 找到所有 skip=true 的步骤
  const skipPattern = /if:\s*\|?-?\s*\n\s*\$\{\{\s*steps\.context\.outputs\.skip\s*==\s*'true'\s*\}\}/g;
  const skipMatches = [...milesWorkflow.matchAll(skipPattern)];

  for (const match of skipMatches) {
    // 取这个步骤的内容（到下一个步骤或文件结尾）
    const afterMatch = milesWorkflow.slice(match.index);
    const nextStep = afterMatch.indexOf('\n      - name:', 10);
    const stepContent = nextStep > -1 ? afterMatch.slice(0, nextStep) : afterMatch.slice(0, 1000);

    // 这个步骤不应当发评论
    assert.ok(
      !stepContent.includes('gh issue comment') && !stepContent.includes('gh pr comment'),
      'skip=true 的步骤不应当发评论，否则就是 Issue #62 的噪音',
    );
  }
});

test('context 之后的关键步骤都有 skip!=true 条件', () => {
  // context 步骤决定 skip，之后的步骤如果可能产出内容（checkout 分支、run agent 等）
  // 都应当有 skip!=true 条件。context 之前的 checkout 是无条件的（需要代码才能跑 context）。
  const lines = milesWorkflow.split('\n');
  
  // 找到 context 步骤的位置
  const contextLine = lines.findIndex((l) => l.includes("id: 'context'"));
  assert.ok(contextLine > -1, '找不到 context 步骤');
  
  // 只检查 context 之后的步骤
  const afterContext = lines.slice(contextLine);
  const criticalSteps = ['Checkout existing branch', 'Put merging', 'Run agent', 'Clean up'];

  for (const stepName of criticalSteps) {
    const stepLine = afterContext.findIndex((l) => l.includes(`name: '${stepName}`) || l.includes(`name: "${stepName}`));
    if (stepLine === -1) continue;

    // 往下找 if 条件（最多 5 行）
    let hasSkipCondition = false;
    for (let i = stepLine; i < Math.min(stepLine + 5, afterContext.length); i++) {
      if (afterContext[i].includes("skip != 'true'") || afterContext[i].includes('skip != "true"')) {
        hasSkipCondition = true;
        break;
      }
      if (afterContext[i].includes('run:')) break; // 到 run 了还没找到条件
    }

    assert.ok(
      hasSkipCondition,
      `步骤 "${stepName}" 可能产出内容，但没有 skip!=true 条件，skip 时仍会执行`,
    );
  }
});

// ───────────────────── 包装器装在哪一轮 ─────────────────────

const claraWorkflow = readFileSync(path.join(ROOT, '.github', 'workflows', 'qwen-clara.yml'), 'utf8');

test('顾清那轮也装 gh 包装器：她有 issues: write，能改标签', () => {
  // 停手标签只归叶澜；顾清与陈实是仅有的两个「有 issues: write 又被装了包装器」的角色。
  assert.match(claraWorkflow, /no-merge-gh/);
  assert.match(claraWorkflow, /qwen-no-merge/);
});

test('陈实那轮末端检查不再按「谁合的」放行，改按本轮开始时间', () => {
  // 人自己合也会放松一次合并条件，所以不再有 [bot] 豁免；判的是合并时间。
  assert.doesNotMatch(milesWorkflow, /mergedBy/);
  assert.match(milesWorkflow, /mergedAt/);
  assert.match(milesWorkflow, /STARTED_AT/);
});

test('本轮开始时间已作为 work 的输出暴露给 gate', () => {
  assert.ok(
    milesWorkflow.includes("started_at: '${{ steps.before.outputs.started_at }}'"),
    'work 的 outputs 里没有 started_at，gate 取到的是空串',
  );
  assert.ok(
    milesWorkflow.includes('needs.work.outputs.started_at'),
    '末端检查没有取 started_at，没法判断合并发生在这一轮之前还是之中',
  );
});
