/**
 * 巡检规则的测试。
 *
 * 这些规则决定「没人叫的时候该不该主动叫醒一个人」，写错的代价是双向的：
 * 叫错人 = 每小时烧一次模型；该叫的人不叫 = 一件已经批准的事一直躺在那里没人合。
 * 所以每条判据都要有一条测试盯着，尤其是「什么情况下不该叫」。
 *
 *   /usr/bin/node --test .github/scripts/patrol.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  rollupState,
  approvedAtHead,
  pickForMiles,
  pickForFrank,
  pickForNora,
  noraCandidate,
} from './patrol.mjs';

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString();

const checks = (conclusions) => conclusions.map((conclusion) => ({ status: 'COMPLETED', conclusion }));
const running = () => [{ status: 'IN_PROGRESS', conclusion: null }];

const pr = (over = {}) => ({
  number: 1,
  headRefName: 'qwen-fix-7',
  headRefOid: 'aaa111',
  isDraft: false,
  mergeable: 'MERGEABLE',
  body: '',
  createdAt: ago(120),
  updatedAt: ago(30),
  labels: [],
  statusCheckRollup: checks(['SUCCESS']),
  reviews: [],
  ...over,
});

const approveOn = (oid, submittedAt = ago(20)) => ({
  state: 'APPROVED', body: '', submittedAt, commit: { oid },
});

// ───────────────────────── check 状态折算 ─────────────────────────

test('没有检查项时不算失败，算「无检查」', () => {
  assert.equal(rollupState([]), '');
  assert.equal(rollupState(undefined), '');
});

test('有一项还在跑就是 PENDING，不管别的成没成', () => {
  assert.equal(rollupState([...checks(['SUCCESS']), ...running()]), 'PENDING');
});

test('SKIPPED 不算失败', () => {
  // dispatch 里 clara / nora / miles 三个 job 正常就是 SKIPPED
  assert.equal(rollupState(checks(['SUCCESS', 'SKIPPED', 'NEUTRAL'])), 'SUCCESS');
});

test('失败、超时、取消都算 FAILURE', () => {
  for (const c of ['FAILURE', 'TIMED_OUT', 'CANCELLED', 'ERROR']) {
    assert.equal(rollupState(checks(['SUCCESS', c])), 'FAILURE', `${c} 应该算失败`);
  }
});

// ───────────────────────── 批准是否仍然成立 ─────────────────────────

test('批准挂在当前提交上才算数', () => {
  assert.equal(approvedAtHead(pr({ reviews: [approveOn('aaa111')] })), true);
  // 评审挂在旧提交上：作者又推了新代码，旧批准不再覆盖它
  assert.equal(approvedAtHead(pr({ reviews: [approveOn('old999')] })), false);
});

test('App 批准不了自己开的 PR 时，正文标记也算批准', () => {
  const marked = { state: 'COMMENTED', body: '结论：可以合并\n<!-- qwen:verdict=approve -->', submittedAt: ago(20), commit: { oid: 'aaa111' } };
  assert.equal(approvedAtHead(pr({ reviews: [marked] })), true);
});

test('新的驳回压过旧的批准', () => {
  const rejected = {
    state: 'CHANGES_REQUESTED', body: '', submittedAt: ago(5), commit: { oid: 'aaa111' },
  };
  assert.equal(approvedAtHead(pr({ reviews: [approveOn('aaa111', ago(60)), rejected] })), false);
});

test('驳回之后又批准回来，算批准', () => {
  const rejected = {
    state: 'CHANGES_REQUESTED', body: '', submittedAt: ago(60), commit: { oid: 'aaa111' },
  };
  assert.equal(approvedAtHead(pr({ reviews: [rejected, approveOn('aaa111', ago(5))] })), true);
});

// ───────────────────────── 陈实：该合并 / 检查红了 ─────────────────────────

test('已批准且检查通过 → 叫陈实合并', () => {
  const [found] = pickForMiles([pr({ reviews: [approveOn('aaa111')] })], { now: NOW });
  assert.equal(found.pr.number, 1);
  assert.match(found.reason, /该合并了/);
});

test('已批准但和主干冲突 → 叫陈实解决冲突', () => {
  const [found] = pickForMiles(
    [pr({ mergeable: 'CONFLICTING', reviews: [approveOn('aaa111')] })], { now: NOW },
  );
  assert.match(found.reason, /冲突/);
});

test('mergeable 是 UNKNOWN 时仍然叫陈实 —— 实测 GitHub 常返回 unknown，按 MERGEABLE 判会永远漏掉已批准的 PR', () => {
  // 真实数据：PR #19 连查三次 mergeable 都是 UNKNOWN
  const [found] = pickForMiles(
    [pr({ mergeable: 'UNKNOWN', reviews: [approveOn('aaa111')] })], { now: NOW },
  );
  assert.ok(found, '已批准且检查通过就该叫，不管 mergeable 算没算出来');
  assert.match(found.reason, /该合并了/);
});

test('检查红了 → 叫陈实，哪怕还没批准', () => {
  const [found] = pickForMiles([pr({ statusCheckRollup: checks(['FAILURE']) })], { now: NOW });
  assert.match(found.reason, /检查没通过/);
});

test('没批准、检查也没红 → 不叫（周正还没看完，不轮到陈实）', () => {
  assert.deepEqual(pickForMiles([pr()], { now: NOW }), []);
});

test('检查还在跑 → 不叫，等它跑完', () => {
  assert.deepEqual(
    pickForMiles([pr({ statusCheckRollup: running(), reviews: [approveOn('aaa111')] })], { now: NOW }),
    [],
  );
});

test('别人的分支一律不碰', () => {
  assert.deepEqual(
    pickForMiles([pr({ headRefName: 'fix/someone-elses', reviews: [approveOn('aaa111')] })], { now: NOW }),
    [],
  );
});

test('草稿不叫', () => {
  assert.deepEqual(
    pickForMiles([pr({ isDraft: true, reviews: [approveOn('aaa111')] })], { now: NOW }),
    [],
  );
});

test('人放了 do-not-merge 或 manual-review 就不叫 —— 巡检不能绕过人的闸', () => {
  for (const name of ['do-not-merge', 'manual-review']) {
    assert.deepEqual(
      pickForMiles(
        [pr({ labels: [{ name }], reviews: [approveOn('aaa111')] })], { now: NOW },
      ),
      [],
      `${name} 应该挡住巡检`,
    );
  }
});

test('刚动过的不催：15 分钟内还在正常干活', () => {
  assert.deepEqual(
    pickForMiles([pr({ updatedAt: ago(3), reviews: [approveOn('aaa111')] })], { now: NOW }),
    [],
  );
});

test('好几个候选时，等得最久的先处理', () => {
  const picked = pickForMiles([
    pr({ number: 3, updatedAt: ago(20), reviews: [approveOn('aaa111')] }),
    pr({ number: 5, updatedAt: ago(90), reviews: [approveOn('aaa111')] }),
    pr({ number: 4, updatedAt: ago(45), reviews: [approveOn('aaa111')] }),
  ], { now: NOW });
  assert.deepEqual(picked.map((p) => p.pr.number), [5, 4, 3]);
});

// ───────────────────────── 周正：没人评审 ─────────────────────────

test('开了很久、当前提交没有评审 → 叫周正', () => {
  const [found] = pickForFrank([pr({ createdAt: ago(180) })], { now: NOW });
  assert.match(found.reason, /还没有评审/);
});

test('当前提交已经评审过 → 不叫，哪怕评审结论是要求修改', () => {
  assert.deepEqual(
    pickForFrank(
      [pr({ createdAt: ago(180), reviews: [{ state: 'CHANGES_REQUESTED', submittedAt: ago(30), commit: { oid: 'aaa111' } }] })],
      { now: NOW },
    ),
    [],
  );
});

test('评审过的是上一版 → 叫周正重新看当前提交', () => {
  const [found] = pickForFrank(
    [pr({ createdAt: ago(180), reviews: [{ state: 'APPROVED', submittedAt: ago(30), commit: { oid: 'old999' } }] })],
    { now: NOW },
  );
  assert.equal(found.pr.number, 1);
});

test('刚开的 PR 不催评审', () => {
  assert.deepEqual(pickForFrank([pr({ createdAt: ago(10) })], { now: NOW }), []);
});

test('草稿和带闸标签的 PR 不叫周正', () => {
  assert.deepEqual(pickForFrank([pr({ createdAt: ago(180), isDraft: true })], { now: NOW }), []);
  assert.deepEqual(
    pickForFrank([pr({ createdAt: ago(180), labels: [{ name: 'manual-review' }] })], { now: NOW }),
    [],
  );
});

// ───────────────────────── 叶澜：停在中间 ─────────────────────────

const issue = (over = {}) => ({
  number: 9, title: '某件事', labels: [], updatedAt: ago(60 * 30), ...over,
});

test('停了很久、没有任何回复 → 叫叶澜定', () => {
  const [found] = pickForNora([issue()], { now: NOW });
  assert.match(found.reason, /还没有任何回复/);
});

test('别人已经接下活了 → 不叫叶澜', () => {
  const comments = new Map([[9, [{ body: '这件事我来做\n<!-- qwen:handoff=miles reason=改一下 -->' }]]]);
  assert.deepEqual(pickForNora([issue()], { now: NOW, commentsByIssue: comments }), []);
});

test('叶澜已经说过话 → 不再说一遍', () => {
  const comments = new Map([[9, [{ body: '决定：做。\n<!-- qwen:role=nora -->' }]]]);
  assert.deepEqual(pickForNora([issue()], { now: NOW, commentsByIssue: comments }), []);
});

test('已经有开着的 PR 在做 → 不叫叶澜再定一次', () => {
  const openPrs = [{ number: 12, body: '修掉 #9 说的问题' }];
  assert.deepEqual(pickForNora([issue()], { now: NOW, openPrs }), []);
});

test('#9 不该被 #90 的 PR 顶掉', () => {
  const openPrs = [{ number: 12, body: '顺手修 #90 的问题' }];
  assert.equal(pickForNora([issue({ number: 9 })], { now: NOW, openPrs }).length, 1);
});

test('还在等顾清分类的 Issue 不抢', () => {
  assert.deepEqual(
    pickForNora([issue({ labels: [{ name: 'status/needs-triage' }] })], { now: NOW }),
    [],
  );
});

test('刚动过的 Issue 不催', () => {
  assert.deepEqual(pickForNora([issue({ updatedAt: ago(60) })], { now: NOW }), []);
});

// ───────────────────── 预筛：不看评论就能排除的，别去取评论 ─────────────────────

test('预筛能挡掉带闸标签、太新、已有 PR 在做的 Issue', () => {
  assert.equal(noraCandidate(issue(), { now: NOW }), true);
  assert.equal(noraCandidate(issue({ labels: [{ name: 'status/needs-triage' }] }), { now: NOW }), false);
  assert.equal(noraCandidate(issue({ labels: [{ name: 'manual-review' }] }), { now: NOW }), false);
  assert.equal(noraCandidate(issue({ updatedAt: ago(60) }), { now: NOW }), false);
  assert.equal(
    noraCandidate(issue(), { now: NOW, openPrs: [{ number: 12, body: '修 #9' }] }),
    false,
  );
});

test('预筛不排除空评论的 Issue —— 那正需要叶澜开口', () => {
  assert.equal(noraCandidate(issue(), { now: NOW, openPrs: [] }), true);
});
