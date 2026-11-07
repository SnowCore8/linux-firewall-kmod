/**
 * 合并闸门的测试。
 *
 * 这个脚本唯一的工作就是「说不行」。判错的代价不对称：放过一次 = 把没批准的、检查红的
 * 代码合进主干；多拦一次 = 有人多点一下。所以每条判据都要有一条测试盯着，尤其是
 * 「什么情况下必须拦」。
 *
 * 前两条是实测发生过的事故，不是假想：
 *   PR #38 —— 「浏览器端到端测试」判 FAILURE，陈实照样合并。
 *   PR #39 —— 批准挂在 447ff12a，他在 b2763785 上合并。
 *
 *   /usr/bin/node --test .github/scripts/merge-gate.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { evaluateMerge, failedCheckNames, isPending, checkState, STOP_LABELS } from './merge-gate.mjs';

const NOW = Date.now();
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString();

const checks = (items) => items.map(([name, conclusion]) => ({ name, status: 'COMPLETED', conclusion }));
const running = () => [{ name: '单元测试', status: 'IN_PROGRESS', conclusion: null }];

const approveOn = (oid, submittedAt = ago(20)) => ({
  state: 'APPROVED', body: '', submittedAt, commit: { oid },
});
const rejectOn = (oid, submittedAt = ago(10)) => ({
  state: 'CHANGES_REQUESTED', body: '', submittedAt, commit: { oid },
});

/** 一个本来就该合的 PR：带批准、检查全绿。各条测试只改自己关心的那一项。 */
const pr = (over = {}) => ({
  number: 39,
  headRefName: 'qwen-fix-21',
  headRefOid: 'b2763785',
  baseRefName: 'master',
  baseRefOid: 'base111',
  isDraft: false,
  mergeable: 'MERGEABLE',
  labels: [],
  statusCheckRollup: checks([['单元测试', 'SUCCESS']]),
  reviews: [approveOn('b2763785')],
  ...over,
});

const rule = (result, id) => result.rules.find((r) => r.id === id);

// ───────────────────────── 两个真实事故 ─────────────────────────

test('#38：e2e 判失败就拦下，报出是哪个检查', () => {
  // 真实形状：批准在 head 上，只有「浏览器端到端测试」红了
  const result = evaluateMerge({
    pr: pr({ statusCheckRollup: checks([['单元测试', 'SUCCESS'], ['浏览器端到端测试', 'FAILURE']]) }),
    preexisting: [],
  });

  assert.equal(result.ok, false);
  assert.deepEqual(result.blocking, ['浏览器端到端测试']);
  assert.deepEqual(result.tolerated, []);
  assert.equal(rule(result, 'checks').ok, false);
  assert.match(rule(result, 'checks').detail, /浏览器端到端测试/);
});

test('#38：主干上同样红时才放行，并记进 tolerated', () => {
  // 主干本来就红——这才是 #38 的真实处境，但他当时没落这个证据
  const result = evaluateMerge({
    pr: pr({ statusCheckRollup: checks([['单元测试', 'SUCCESS'], ['浏览器端到端测试', 'FAILURE']]) }),
    preexisting: ['浏览器端到端测试'],
  });

  assert.equal(result.ok, true, '主干同样失败的检查不该把每个 PR 都锁死');
  assert.deepEqual(result.tolerated, ['浏览器端到端测试']);
  assert.deepEqual(result.blocking, []);
  assert.match(rule(result, 'checks').detail, /主干上同样失败/);
});

test('#39：批准挂在旧提交上就拦下', () => {
  // 真实形状：e8fcb58b 被驳回 → 447ff12a 批准 → dfb9d847、b2763785 又推了两次
  const result = evaluateMerge({
    pr: pr({
      headRefOid: 'b2763785',
      reviews: [rejectOn('e8fcb58b'), approveOn('447ff12a')],
      statusCheckRollup: checks([['单元测试', 'SUCCESS']]),
    }),
  });

  assert.equal(result.ok, false);
  assert.equal(rule(result, 'approval-at-head').ok, false);
  assert.match(rule(result, 'approval-at-head').detail, /b2763785/);
});

test('#39：批准在 head 上、且比驳回新，才放行', () => {
  const result = evaluateMerge({
    pr: pr({ headRefOid: 'b2763785', reviews: [rejectOn('e8fcb58b'), approveOn('b2763785')] }),
  });

  assert.equal(result.ok, true);
  assert.equal(rule(result, 'approval-at-head').ok, true);
});

test('同一 head 上先批准又要求修改，算没有批准', () => {
  const result = evaluateMerge({
    pr: pr({ reviews: [approveOn('b2763785', ago(60)), rejectOn('b2763785', ago(5))] }),
  });

  assert.equal(rule(result, 'approval-at-head').ok, false);
});

test('没有评审就拦下', () => {
  const result = evaluateMerge({ pr: pr({ reviews: [] }) });
  assert.equal(rule(result, 'approval-at-head').ok, false);
});

// ───────────────────────── 人放的闸 ─────────────────────────

test('带 do-not-merge 就拦下', () => {
  const result = evaluateMerge({ pr: pr({ labels: [{ name: 'do-not-merge' }] }) });
  assert.equal(result.ok, false);
  assert.equal(rule(result, 'no-stop-label').ok, false);
});

test('带 manual-review 就拦下', () => {
  const result = evaluateMerge({ pr: pr({ labels: [{ name: 'manual-review' }] }) });
  assert.equal(rule(result, 'no-stop-label').ok, false);
});

test('别的标签不拦', () => {
  const result = evaluateMerge({
    pr: pr({ labels: [{ name: 'bug' }, { name: 'good first issue' }] }),
  });
  assert.equal(result.ok, true);
});

test('STOP_LABELS 与提示词、巡检用的是同一组', () => {
  assert.deepEqual(STOP_LABELS, ['do-not-merge', 'manual-review']);
});

// ───────────────────────── 草稿与冲突 ─────────────────────────

test('草稿拦下', () => {
  const result = evaluateMerge({ pr: pr({ isDraft: true }) });
  assert.equal(result.ok, false);
  assert.equal(rule(result, 'not-draft').ok, false);
});

test('CONFLICTING 拦下', () => {
  const result = evaluateMerge({ pr: pr({ mergeable: 'CONFLICTING' }) });
  assert.equal(result.ok, false);
  assert.equal(rule(result, 'not-conflicting').ok, false);
});

test('mergeable=UNKNOWN 不拦（GitHub 懒计算，刚推完就是 UNKNOWN）', () => {
  const result = evaluateMerge({ pr: pr({ mergeable: 'UNKNOWN' }) });
  assert.equal(rule(result, 'not-conflicting').ok, true);
});

// ───────────────────────── 检查状态折算 ─────────────────────────

test('还在跑就拦下', () => {
  const result = evaluateMerge({ pr: pr({ statusCheckRollup: [...checks([['单元测试', 'SUCCESS']]), ...running()] }) });
  assert.equal(result.ok, false);
  assert.equal(rule(result, 'checks').ok, false);
});

test('一个检查都没有不算拦（这个仓库可能没配）', () => {
  const result = evaluateMerge({ pr: pr({ statusCheckRollup: [] }) });
  assert.equal(result.ok, true);
  assert.equal(rule(result, 'checks').ok, true);
});

test('SKIPPED 与 NEUTRAL 不算失败', () => {
  const result = evaluateMerge({
    pr: pr({ statusCheckRollup: checks([['a', 'SKIPPED'], ['b', 'NEUTRAL'], ['c', 'SUCCESS']]) }),
  });
  assert.equal(result.ok, true);
});

test('老式 StatusContext 的 FAILURE 必须认出来', () => {
  // statusCheckRollup 里混着 StatusContext（有 state、没有 conclusion）；
  // 只看 conclusion 会把这种红的说成绿的
  const context = { context: 'ci/external', state: 'FAILURE' };
  assert.equal(checkState(context), 'FAILURE');

  const result = evaluateMerge({ pr: pr({ statusCheckRollup: [context] }) });
  assert.equal(result.ok, false);
  assert.deepEqual(result.blocking, ['ci/external']);
});

test('老式 StatusContext 的 PENDING 算没跑完', () => {
  const result = evaluateMerge({
    pr: pr({ statusCheckRollup: [{ context: 'ci/external', state: 'PENDING' }] }),
  });
  assert.equal(rule(result, 'checks').ok, false);
});

test('TIMED_OUT / CANCELLED / ACTION_REQUIRED 都算失败', () => {
  const result = evaluateMerge({
    pr: pr({ statusCheckRollup: checks([['a', 'TIMED_OUT'], ['b', 'CANCELLED'], ['c', 'ACTION_REQUIRED']]) }),
  });
  assert.equal(result.ok, false);
  assert.deepEqual(result.blocking.sort(), ['a', 'b', 'c']);
});

test('失败项没名字也要报一条，不能空着', () => {
  assert.deepEqual(failedCheckNames({ statusCheckRollup: [{ status: 'COMPLETED', conclusion: 'FAILURE' }] }), [
    '(未命名检查)',
  ]);
});

test('isPending 只看状态，不看结论', () => {
  assert.equal(isPending(pr()), false);
  assert.equal(isPending(pr({ statusCheckRollup: running() })), true);
  assert.equal(isPending(pr({ statusCheckRollup: [] })), false);
});

// ───────────────────────── 多条同时不满足 ─────────────────────────

test('多条不满足时全部列出，不是只报第一条', () => {
  const result = evaluateMerge({
    pr: pr({
      isDraft: true,
      mergeable: 'CONFLICTING',
      labels: [{ name: 'do-not-merge' }],
      reviews: [],
      statusCheckRollup: checks([['浏览器端到端测试', 'FAILURE']]),
    }),
  });

  assert.equal(result.ok, false);
  assert.deepEqual(
    result.rules.filter((r) => !r.ok).map((r) => r.id),
    ['approval-at-head', 'no-stop-label', 'not-draft', 'not-conflicting', 'checks'],
  );
});
