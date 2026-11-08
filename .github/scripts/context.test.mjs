/**
 * 「这一轮该不该跑」那几条判据的测试。
 *
 * 它们决定的是「跳过还是不跳过」。错了不会报错 —— 该跑的没跑（一批 Issue 没人看）、
 * 不该跑的跑了（已合并的 PR 上又改一遍、别人的 PR 被动了）。两种都不会在日志里
 * 留下异常，所以每条判据都要有一条测试盯着。
 *
 *   /usr/bin/node --test .github/scripts/context.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  OWNED_BRANCH_PREFIX,
  isOwnedBranch,
  parseBatchLimit,
  prepareClara,
  prepareNora,
  prepareMiles,
  prepareFrank,
} from './context.mjs';

// ───────────────────────── 顾清：挑 Issue ─────────────────────────

test('给了编号就只处理那一条', () => {
  const r = prepareClara({ issueNumber: '42' });
  assert.equal(r.handled, true);
  assert.equal(r.mode, 'single');
  assert.equal(r.targets, '42');
});

test('定时巡检把「无标签」和「待分诊」并起来，去重后按数字排序', () => {
  // 字符串排序会把 100 排在 99 前面，批量时先处理的就成了大编号
  const r = prepareClara({ unlabeled: ['100', '9'], needsTriage: ['9', '11'] });
  assert.equal(r.handled, true);
  assert.equal(r.mode, 'batch');
  assert.equal(r.targets, '9,11,100');
});

test('两个来源都空时不跑模型', () => {
  const r = prepareClara({ unlabeled: [], needsTriage: [] });
  assert.equal(r.handled, false);
  assert.equal(r.targets, '');
});

test('批量上限真的截断，且截的是最小的那几个', () => {
  const r = prepareClara({ unlabeled: ['5', '3', '7', '1'], batchLimit: 2 });
  assert.equal(r.targets, '1,3');
});

test('非数字的取回值被丢掉，不会拼进 TARGETS', () => {
  // gh 失败时会返回空行或报错文本；拼进去会让模型去读一个不存在的编号
  const r = prepareClara({ unlabeled: ['', 'abc', '12'], needsTriage: [] });
  assert.equal(r.targets, '12');
});

test('批量上限为 0 时一条都不取', () => {
  const r = prepareClara({ unlabeled: ['1', '2'], batchLimit: 0 });
  assert.equal(r.handled, false);
});

// ───────────────────────── parseBatchLimit：校验输入 ─────────────────────────

test('空串回落默认值 5', () => {
  assert.equal(parseBatchLimit(''), 5);
});

test('undefined 回落默认值 5', () => {
  assert.equal(parseBatchLimit(undefined), 5);
});

test('合法正整数原样返回', () => {
  assert.equal(parseBatchLimit('10'), 10);
  assert.equal(parseBatchLimit(3), 3);
});

test('非数字字符串抛错', () => {
  assert.throws(() => parseBatchLimit('abc'), /必须是正整数/);
});

test('负数抛错', () => {
  assert.throws(() => parseBatchLimit('-1'), /必须是正整数/);
});

test('零抛错', () => {
  assert.throws(() => parseBatchLimit('0'), /必须是正整数/);
});

test('小数抛错', () => {
  assert.throws(() => parseBatchLimit('3.5'), /必须是正整数/);
});

// ───────────────────────── 叶澜：目标还开着吗 ─────────────────────────

test('目标关着就不做产品决策', () => {
  assert.equal(prepareNora({ number: 7, issue: { state: 'closed' } }).proceed, false);
});

test('取不到状态时不硬跑', () => {
  // 取不到与「关着」要同样处理：宁可这一轮什么都不做，也不要对着未知状态改标签
  assert.equal(prepareNora({ number: 7, issue: null }).proceed, false);
});

test('目标开着就正常跑', () => {
  assert.equal(prepareNora({ number: 7, issue: { state: 'open' } }).proceed, true);
});

// ───────────────────────── 陈实：模式和分支 ─────────────────────────

const pull = (over = {}) => ({
  headRef: `${OWNED_BRANCH_PREFIX}21`,
  baseRef: 'master',
  state: 'open',
  ...over,
});

test('修 Issue：分支名由编号推出来，Base 用默认分支', () => {
  const r = prepareMiles({ number: 21, issue: { state: 'open' }, defaultBranch: 'master' });
  assert.equal(r.skip, false);
  assert.equal(r.mode, 'fix-issue');
  assert.equal(r.headRef, 'qwen-fix-21');
  assert.equal(r.baseBranch, 'master');
  assert.equal(r.previousHead, '', '新分支没有「上一轮起点」，不能编一个出来');
});

test('响应 PR：改动落在那个 PR 自己的分支上', () => {
  const r = prepareMiles({ number: 33, onPr: true, pull: pull({ headRef: 'qwen-fix-21' }) });
  assert.equal(r.skip, false);
  assert.equal(r.mode, 'respond-pr');
  assert.equal(r.headRef, 'qwen-fix-21');
  assert.equal(r.prNumber, '33');
  assert.equal(r.issueNumber, '21', 'Issue 编号从分支名推出来');
  assert.equal(r.previousHead, 'qwen-fix-21');
});

test('别人的 PR 一律不动', () => {
  const r = prepareMiles({ number: 33, onPr: true, pull: pull({ headRef: 'feature/foo' }) });
  assert.equal(r.skip, true);
  assert.match(r.skipReason, /不是我方创建/);
});

test('已合并的 PR 不再动', () => {
  const r = prepareMiles({ number: 33, onPr: true, pull: pull({ state: 'closed' }) });
  assert.equal(r.skip, true);
  assert.match(r.skipReason, /已关闭或已合并/);
});

test('PR 编号以对象本身为准，不信任另传的值', () => {
  const r = prepareMiles({ number: 33, onPr: true, prNumber: '99', pull: pull() });
  assert.equal(r.prNumber, '33');
});

test('取不到 PR 时不动手 —— 不能当成「没有 PR」继续走修 Issue 那条路', () => {
  const r = prepareMiles({ number: 33, onPr: true, pull: null });
  assert.equal(r.skip, true);
});

test('Issue 关着就不动手', () => {
  const r = prepareMiles({ number: 21, issue: { state: 'closed' } });
  assert.equal(r.skip, true);
  assert.match(r.skipReason, /已关闭/);
});

test('取不到 Issue 时不动手', () => {
  assert.equal(prepareMiles({ number: 21, issue: null }).skip, true);
});

test('分支前缀只有一份定义', () => {
  assert.equal(OWNED_BRANCH_PREFIX, 'qwen-fix-');
  assert.equal(isOwnedBranch('qwen-fix-1'), true);
  assert.equal(isOwnedBranch('qwen-fix-'), true);
  assert.equal(isOwnedBranch('feature/qwen-fix-1'), false);
  assert.equal(isOwnedBranch(''), false);
});

// ───────────────────────── 周正：这次评审多余吗 ─────────────────────────

const frankPull = (over = {}) => ({
  headRef: `${OWNED_BRANCH_PREFIX}21`,
  headSha: 'b2763785',
  state: 'open',
  draft: false,
  isFork: false,
  ...over,
});

test('正常 PR 要评审', () => {
  const r = prepareFrank({ prNumber: 39, pull: frankPull() });
  assert.equal(r.skip, false);
  assert.equal(r.isOwnPr, true);
});

test('草稿与已关闭的 PR 不评审', () => {
  assert.equal(prepareFrank({ prNumber: 39, pull: frankPull({ draft: true }) }).skip, true);
  assert.equal(prepareFrank({ prNumber: 39, pull: frankPull({ state: 'merged' }) }).skip, true);
});

test('fork 的 PR 不评审', () => {
  assert.equal(prepareFrank({ prNumber: 39, pull: frankPull({ isFork: true }) }).skip, true);
});

test('当前提交上已有评审、且这次是机器人叫醒 → 跳过', () => {
  // 同一件事被安排两遍：PR 打开叫了一次，陈实又写了一条交接评论
  const r = prepareFrank({
    prNumber: 39,
    pull: frankPull(),
    reviews: [{ commitId: 'b2763785', state: 'APPROVED' }],
    senderIsBot: true,
  });
  assert.equal(r.skip, true);
  assert.equal(r.repeated, true);
  assert.match(r.skipReason, /重复叫醒/);
});

test('人明确叫周正再看一次，哪怕当前提交上已有评审也要评', () => {
  const r = prepareFrank({
    prNumber: 39,
    pull: frankPull(),
    reviews: [{ commitId: 'b2763785', state: 'APPROVED' }],
    senderIsBot: false,
  });
  assert.equal(r.skip, false, '人写「再看看」是他明确要看');
});

test('评审挂在旧提交上不算重复', () => {
  const r = prepareFrank({
    prNumber: 39,
    pull: frankPull({ headSha: 'newsha00' }),
    reviews: [{ commitId: 'oldsha11', state: 'APPROVED' }],
    senderIsBot: true,
  });
  assert.equal(r.skip, false);
});

test('取不到 PR 时不评审', () => {
  assert.equal(prepareFrank({ prNumber: 39, pull: null }).skip, true);
});

test('多个跳过原因都要列出来，不是只报第一条', () => {
  const r = prepareFrank({ prNumber: 39, pull: frankPull({ draft: true, isFork: true }) });
  assert.match(r.skipReason, /草稿/);
  assert.match(r.skipReason, /fork/);
});
