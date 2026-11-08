/**
 * 评审语义与人工闸标签的测试。
 *
 * 这两样以前分散在 patrol.mjs 与 merge-gate.mjs 里各写一遍，而它们恰好是
 * 「能不能合」与「要不要叫人」共同依赖的判断。写错的代价是拿旧提交上的批准
 * 合新代码，或者某个角色看不见人放的闸。所以每条都要钉住。
 *
 *   /usr/bin/node --test .github/scripts/review.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  STOP_LABELS,
  hasStopLabel,
  latestReview,
  isApprove,
  isReject,
  approvedAtHead,
} from './review.mjs';

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString();

const review = (over = {}) => ({
  state: 'APPROVED',
  body: '',
  submittedAt: ago(10),
  commit: { oid: 'aaa111' },
  ...over,
});

const pr = (over = {}) => ({
  headRefOid: 'aaa111',
  reviews: [],
  ...over,
});

// ───────────────────────── 人工闸标签 ─────────────────────────

test('闸标签就是这两个，多一个少一个都会让某层看不见某道闸', () => {
  assert.deepEqual(STOP_LABELS, ['do-not-merge', 'manual-review']);
});

test('带任一闸标签就算有人放了闸', () => {
  assert.equal(hasStopLabel([{ name: 'do-not-merge' }]), true);
  assert.equal(hasStopLabel([{ name: 'manual-review' }]), true);
  assert.equal(hasStopLabel([{ name: 'bug' }, { name: 'manual-review' }]), true);
});

test('没有闸标签、没有标签、标签是 undefined 都不算放闸', () => {
  assert.equal(hasStopLabel([{ name: 'bug' }]), false);
  assert.equal(hasStopLabel([]), false);
  assert.equal(hasStopLabel(undefined), false);
});

test('标签名要精确匹配，带前后缀的不算', () => {
  assert.equal(hasStopLabel([{ name: 'do-not-merge-please' }]), false);
  assert.equal(hasStopLabel([{ name: 'manual-review-later' }]), false);
});

// ───────────────────────── 单条评审的语义 ─────────────────────────

test('APPROVE 与正文里的批准标记都算批准', () => {
  assert.equal(isApprove(review()), true);
  assert.equal(isApprove(review({ state: 'COMMENTED', body: '<!-- qwen:verdict=approve -->' })), true);
  assert.equal(isApprove(review({ state: 'COMMENTED', body: '' })), false);
});

test('REQUEST_CHANGES 与正文里的驳回标记都算驳回', () => {
  assert.equal(isReject(review({ state: 'CHANGES_REQUESTED' })), true);
  assert.equal(isReject(review({ state: 'COMMENTED', body: '<!-- qwen:verdict=request-changes -->' })), true);
  assert.equal(isReject(review()), false);
});

test('提到标记不算写标记：一条明说「现在不行」的评审不能放行合并', () => {
  // 这两条判的是能不能合，`contains` 会把「等绿了我再写 X」读成 X。
  const hedged = review({
    state: 'COMMENTED',
    body: 'CI 还是红的，等绿了我再写 <!-- qwen:verdict=approve -->。现在不行。',
  });
  assert.equal(isApprove(hedged), false);
  assert.equal(approvedAtHead({ headRefOid: 'aaa111', reviews: [hedged] }), false);

  const hedgedReject = review({
    state: 'COMMENTED',
    body: '如果这条没修，我会写 <!-- qwen:verdict=request-changes -->。',
  });
  assert.equal(isReject(hedgedReject), false);
});

test('代码里的标记不算数：引用一段不构成结论', () => {
  const inline = review({ state: 'COMMENTED', body: '规则是 `<!-- qwen:verdict=approve -->` 这一行' });
  assert.equal(isApprove(inline), false);

  const fenced = review({
    state: 'COMMENTED',
    body: '格式长这样：\n```\n<!-- qwen:verdict=approve -->\n```\n',
  });
  assert.equal(isApprove(fenced), false);

  const quoted = review({ state: 'COMMENTED', body: '> <!-- qwen:verdict=approve -->' });
  assert.equal(isApprove(quoted), false, '引用块是别人的话');
});

test('独占一行才认：前导空白容忍，行内混杂不认', () => {
  assert.equal(isApprove(review({ state: 'COMMENTED', body: '结论。\n  <!-- qwen:verdict=approve -->\n' })), true);
  assert.equal(isApprove(review({ state: 'COMMENTED', body: '结论。<!-- qwen:verdict=approve -->' })), false);
  // 前后带别的字也不行 —— 那已经不是标记本身了
  assert.equal(isApprove(review({ state: 'COMMENTED', body: 'x <!-- qwen:verdict=approve --> y' })), false);
});

test('真实评审的形态仍然认：结论 + 末尾一行标记', () => {
  // 历史 42 条标记都是这个形状，收紧判据不能漏认
  const body = '## 评审结论：批准\n\n- 改动只涉及注释\n- 变更说明与 diff 一致\n\n<!-- qwen:verdict=approve -->';
  assert.equal(isApprove(review({ state: 'COMMENTED', body })), true);
});

test('latestReview 按提交时间取最新，且不改原数组', () => {
  const old = review({ submittedAt: ago(60), body: 'old' });
  const fresh = review({ submittedAt: ago(1), body: 'fresh' });
  const input = [old, fresh];
  assert.equal(latestReview(input).body, 'fresh');
  assert.equal(input[0].body, 'old', '排序不能就地改调用方的数组');
});

test('没有评审时 latestReview 返回 undefined 而不是抛错', () => {
  assert.equal(latestReview([]), undefined);
  assert.equal(latestReview(undefined), undefined);
});

// ───────────────────────── 当前提交上有没有成立的批准 ─────────────────────────

test('批准挂在当前提交上才算数', () => {
  assert.equal(approvedAtHead(pr({ reviews: [review()] })), true);
});

test('批准挂在旧提交上不算 —— 拿旧批准合新代码是最危险的一步', () => {
  assert.equal(approvedAtHead(pr({ reviews: [review({ commit: { oid: 'old999' } })] })), false);
});

test('没有 head 哈希时一律不认', () => {
  assert.equal(approvedAtHead(pr({ headRefOid: '', reviews: [review()] })), false);
  assert.equal(approvedAtHead(pr({ headRefOid: undefined, reviews: [review()] })), false);
});

test('同一提交上更新的驳回会盖掉更早的批准', () => {
  const reviews = [
    review({ submittedAt: ago(30) }),
    review({ state: 'CHANGES_REQUESTED', submittedAt: ago(5) }),
  ];
  assert.equal(approvedAtHead(pr({ reviews })), false);
});

test('驳回之后又重新批准，以最新的为准', () => {
  const reviews = [
    review({ state: 'CHANGES_REQUESTED', submittedAt: ago(30) }),
    review({ submittedAt: ago(5) }),
  ];
  assert.equal(approvedAtHead(pr({ reviews })), true);
});

test('旧提交上的驳回不影响当前提交上的批准', () => {
  const reviews = [
    review({ state: 'CHANGES_REQUESTED', submittedAt: ago(5), commit: { oid: 'old999' } }),
    review({ submittedAt: ago(10) }),
  ];
  assert.equal(approvedAtHead(pr({ reviews })), true);
});

test('只有驳回、没有批准时不算成立', () => {
  assert.equal(approvedAtHead(pr({ reviews: [review({ state: 'CHANGES_REQUESTED' })] })), false);
});

test('只有 COMMENTED 时不算批准', () => {
  assert.equal(approvedAtHead(pr({ reviews: [review({ state: 'COMMENTED', body: '' })] })), false);
});
