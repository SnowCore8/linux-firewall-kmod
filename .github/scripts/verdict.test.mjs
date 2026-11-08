/**
 * 周正这一轮的结论怎么算。
 *
 * 关键在于「批准」有两种形态：真的 `APPROVED` 评审，以及 `COMMENTED` 正文里带
 * `<!-- qwen:verdict=approve -->` 标记。后者是四个人共用一个 App 时的唯一出路 ——
 * GitHub 不允许 App 批准自己开的 PR，README 与 QWEN.md 都把这条路写成了正式做法。
 * 只看 `state` 会把那种批准读成 `comment`，日志与闸门的判断就对不上了。
 *
 *   /usr/bin/node --test .github/scripts/verdict.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { verdictFrom } from './verdict.mjs';

const HEAD = 'b2763785';

const review = (over = {}) => ({
  state: 'COMMENTED',
  body: '',
  submittedAt: '2026-11-08T06:00:00Z',
  commit: { oid: HEAD },
  ...over,
});

test('真的 APPROVED 评审算批准', () => {
  assert.equal(verdictFrom([review({ state: 'APPROVED' })], HEAD).verdict, 'approve');
});

test('COMMENTED 加正文标记也算批准 —— 共用 App 时唯一能提交的形态', () => {
  const r = verdictFrom([review({ body: '结论：批准。\n\n<!-- qwen:verdict=approve -->' })], HEAD);
  assert.equal(r.verdict, 'approve');
  assert.equal(r.state, 'COMMENTED', 'state 仍然是 COMMENTED，但结论是批准');
});

test('正文里的 request-changes 标记算要求修改', () => {
  const r = verdictFrom([review({ body: '这里要改。\n\n<!-- qwen:verdict=request-changes -->' })], HEAD);
  assert.equal(r.verdict, 'request-changes');
});

test('真的 CHANGES_REQUESTED 算要求修改', () => {
  assert.equal(verdictFrom([review({ state: 'CHANGES_REQUESTED' })], HEAD).verdict, 'request-changes');
});

test('只留了意见，既不是批准也不是驳回', () => {
  assert.equal(verdictFrom([review({ body: '看过了，写点看法。' })], HEAD).verdict, 'comment');
});

test('挂在旧提交上的批准不算这一轮的结论', () => {
  const old = review({ state: 'APPROVED', commit: { oid: 'oldsha11' } });
  assert.equal(verdictFrom([old], HEAD).verdict, 'comment');
});

test('当前提交上没有评审时记为 comment', () => {
  assert.equal(verdictFrom([], HEAD).verdict, 'comment');
});

test('同一提交上后写的意见覆盖先前的批准', () => {
  const reviews = [
    review({ state: 'APPROVED', submittedAt: '2026-11-08T06:00:00Z' }),
    review({ body: '又看了一遍，还是要改。\n<!-- qwen:verdict=request-changes -->', submittedAt: '2026-11-08T07:00:00Z' }),
  ];
  assert.equal(verdictFrom(reviews, HEAD).verdict, 'request-changes');
});

test('正文里引用了标记但不独占一行，不算', () => {
  // 「等绿了我再写 <!-- qwen:verdict=approve -->」是一条明说「现在不行」的评审
  const r = verdictFrom([review({ body: 'CI 还是红的，等绿了我再写 <!-- qwen:verdict=approve -->。' })], HEAD);
  assert.equal(r.verdict, 'comment');
});

test('围栏里贴出来的标记不算', () => {
  const r = verdictFrom([review({ body: '格式长这样：\n```\n<!-- qwen:verdict=approve -->\n```\n' })], HEAD);
  assert.equal(r.verdict, 'comment');
});
