/**
 * 路由规则的测试。
 *
 * 这段逻辑原本是 qwen-dispatch.yml 里的 300 多行内联 JS，错了的表现是
 * **什么也不发生** —— 被取消的运行 jobs 为空，日志里一个字都不留。
 * 所以每条判据都要有一条测试盯着，尤其是「什么情况下不派活」和「派给谁」。
 *
 *   /usr/bin/node --test .github/scripts/route.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ROLES,
  PEOPLE,
  asPerson,
  isOwnedBranch,
  issueNumberOfBranch,
  parseHandoff,
  parseCall,
  isCommentEvent,
  recentBotComments,
  countRecentHandoffs,
  recentCalls,
  minutesSinceLastCall,
  route,
  handoffLimitMessage,
} from './route.mjs';

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString();

const HANDOFF = (role, reason = '接着做') => `我先做到这里。\n\n<!-- qwen:handoff=${role} reason=${reason} -->`;
const CALL = (role) => `有空看一眼。\n\n<!-- qwen:to=${role} -->`;

/** 一个会被正常派活的基线：成员在自家 Issue 上 @ 了机器人 */
const base = () => ({
  eventName: 'issue_comment',
  action: 'created',
  payload: { issueNumber: 7, issueIsPr: false, commentBody: '@qwencoder 这个报错麻烦看下' },
  senderType: 'User',
  authorAssociation: 'MEMBER',
  actor: 'qwencoder[bot]',
  mention: '@qwencoder',
  gates: { now: NOW },
});

/** payload 是嵌套的，单独合一次，免得每次都要写全 */
const ev = (payloadOver = {}, over = {}) => {
  const baseInput = base();
  return { ...baseInput, ...over, payload: { ...baseInput.payload, ...payloadOver } };
};

const botComment = (over = {}) => ({
  user: { type: 'Bot' },
  created_at: ago(5),
  body: '',
  ...over,
});

// ────────────────────────── 名字与映射 ──────────────────────────

test('四个名字都认，旧职称也认', () => {
  assert.equal(asPerson('clara'), 'clara');
  assert.equal(asPerson('CLARA'), 'clara');
  assert.equal(asPerson('triager'), 'clara');
  assert.equal(asPerson('product'), 'nora');
  assert.equal(asPerson('engineer'), 'miles');
  assert.equal(asPerson('reviewer'), 'frank');
  assert.equal(asPerson('nobody'), null);
  assert.equal(asPerson(''), null);
  assert.equal(asPerson(undefined), null);
});

test('角色与中文名一一对得上', () => {
  assert.deepEqual(ROLES, ['clara', 'nora', 'miles', 'frank']);
  for (const role of ROLES) assert.ok(PEOPLE[role], `${role} 缺中文名`);
});

test('分支约定：只有 qwen-fix-<n> 算我方', () => {
  assert.equal(isOwnedBranch('qwen-fix-7'), true);
  assert.equal(isOwnedBranch('feature/qwen-fix-7'), false);
  assert.equal(isOwnedBranch(''), false);
  assert.equal(isOwnedBranch(undefined), false);
  assert.equal(issueNumberOfBranch('qwen-fix-7'), '7');
  assert.equal(issueNumberOfBranch('qwen-fix-'), '');
  assert.equal(issueNumberOfBranch('main'), '');
});

test('标记解析：交接带理由，点名不带', () => {
  assert.deepEqual(parseHandoff(HANDOFF('miles', '代码改完了')), { role: 'miles', reason: '代码改完了' });
  assert.deepEqual(parseHandoff(HANDOFF('engineer')), { role: 'miles', reason: '接着做' });
  assert.equal(parseHandoff('没有标记'), null);
  assert.equal(parseHandoff(HANDOFF('nobody')), null);
  assert.deepEqual(parseCall(CALL('frank')), { role: 'frank' });
  assert.deepEqual(parseCall(CALL('reviewer')), { role: 'frank' });
  assert.equal(parseCall('没有标记'), null);
});

test('reason 里带 > 也不会让整条交接丢掉', () => {
  // 旧正则用 [^>]*? 收尾，reason 里一个 `>` 就整条匹配不上，交接被静默丢弃。
  const parsed = parseHandoff('<!-- qwen:handoff=miles reason=a > b -->');
  assert.equal(parsed.role, 'miles');
  assert.equal(parsed.reason, 'a > b');
});

test('只有两种评论事件算评论', () => {
  assert.equal(isCommentEvent('issue_comment'), true);
  assert.equal(isCommentEvent('pull_request_review_comment'), true);
  assert.equal(isCommentEvent('pull_request_review'), false);
  assert.equal(isCommentEvent('issues'), false);
});

// ────────────────────────── 计数与闸门 ──────────────────────────

test('只数 24 小时内的机器人评论，人类的不算', () => {
  const comments = [
    botComment({ body: HANDOFF('miles') }),
    botComment({ created_at: ago(60 * 30), body: HANDOFF('frank') }),
    { user: { type: 'User' }, created_at: ago(1), body: HANDOFF('nora') },
    { user: { type: 'Bot' }, created_at: 'not-a-date', body: HANDOFF('clara') },
  ];
  const recent = recentBotComments(comments, NOW);
  assert.equal(recent.length, 1);
  assert.equal(countRecentHandoffs(recent), 1);
});

test('交接与点名分开计数', () => {
  const recent = recentBotComments(
    [botComment({ body: HANDOFF('miles') }), botComment({ body: CALL('frank') }), botComment({ body: '闲聊' })],
    NOW,
  );
  assert.equal(countRecentHandoffs(recent), 1);
  assert.equal(recentCalls(recent).length, 1);
});

test('从没点过名时等待时间是无穷大，不是 0', () => {
  assert.equal(minutesSinceLastCall([], NOW), Infinity);
  assert.equal(minutesSinceLastCall([botComment({ created_at: ago(30) })], NOW), 30);
});

// ────────────────────────── 手动触发 ──────────────────────────

test('手动触发：不认识的接手人直接失败', () => {
  const result = route(ev({}, { eventName: 'workflow_dispatch', manual: { number: 7, role: 'nobody' } }));
  assert.equal(result.kind, 'fail');
  assert.match(result.why, /不认识的接手人/);
});

test('手动触发：Issue 直接派，不需要查 PR', () => {
  const result = route(ev({}, { eventName: 'workflow_dispatch', manual: { number: 7, role: 'nora' } }));
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'nora');
  assert.equal(result.issueNumber, 7);
  assert.equal(result.prNumber, '');
  assert.equal(result.onPr, false);
});

test('手动触发：PR 要先查分支名，查到后补齐 prNumber', () => {
  const input = ev({ issueIsPr: true }, { eventName: 'workflow_dispatch', manual: { number: 9, role: 'frank' } });
  assert.equal(route(input).kind, 'need-pull');

  const result = route({ ...input, pull: { headRef: 'qwen-fix-7' } });
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'frank');
  assert.equal(result.prNumber, 9);
  assert.equal(result.headRef, 'qwen-fix-7');
});

// ────────────────────────── 自言自语与信任边界 ──────────────────────────

test('机器人评论既没交接也没点名 → 忽略', () => {
  const result = route(ev({ commentBody: '收到。' }, { senderType: 'Bot' }));
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /自言自语|既没有交接也没有点名/);
});

test('机器人评论带交接 → 派活，不被自言自语闸门拦掉', () => {
  const result = route(ev({ commentBody: HANDOFF('nora', '范围要定') }, { senderType: 'Bot' }));
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'nora');
});

test('机器人提交评审不带标记 → 不当成自言自语，仍然派活', () => {
  const result = route(
    ev(
      { issueNumber: 9, prNumber: 9, prHeadRef: 'qwen-fix-7', reviewBody: '改完了，可以合', reviewState: 'approved' },
      { eventName: 'pull_request_review', action: 'submitted', senderType: 'Bot' },
    ),
  );
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'miles');
  assert.equal(result.reason, '收到评审：approved');
});

test('机器人在他人 PR 上评审 → 忽略，不跟', () => {
  const result = route(
    ev(
      { issueNumber: 9, prNumber: 9, prHeadRef: 'someone-else/feature', reviewBody: '没问题' },
      { eventName: 'pull_request_review', action: 'submitted', senderType: 'Bot' },
    ),
  );
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /他人的 PR/);
});

test('陌生人 @ 机器人 → 忽略', () => {
  const result = route(ev({}, { authorAssociation: 'NONE' }));
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /无权限/);
});

test('CONTRIBUTOR 也不算可信来源', () => {
  assert.equal(route(ev({}, { authorAssociation: 'CONTRIBUTOR' })).kind, 'ignore');
});

test('这三个关联度的人都算可信', () => {
  for (const assoc of ['OWNER', 'MEMBER', 'COLLABORATOR']) {
    assert.equal(route(ev({}, { authorAssociation: assoc })).kind, 'assign', assoc);
  }
});

test('陌生人的交接不当指令', () => {
  const result = route(ev({ commentBody: HANDOFF('miles') }, { authorAssociation: 'NONE' }));
  assert.equal(result.kind, 'ignore');
});

// ────────────────────────── 交接 ──────────────────────────

test('交接优先于点名：两个标记同时出现时按交接走', () => {
  const result = route(ev({ commentBody: `${HANDOFF('frank')}\n${CALL('nora')}` }));
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'frank');
});

test('交接不区分人类还是机器人', () => {
  for (const senderType of ['User', 'Bot']) {
    const result = route(ev({ commentBody: HANDOFF('clara') }, { senderType }));
    assert.equal(result.role, 'clara', senderType);
  }
});

test('机器人第 21 次交接 → 超限，不再派人', () => {
  const result = route(
    ev({ commentBody: HANDOFF('miles') }, { senderType: 'Bot', gates: { now: NOW, recentHandoffs: 21, maxHandoffs: 20 } }),
  );
  assert.equal(result.kind, 'handoff-limit');
  assert.equal(result.role, 'miles');
  assert.equal(result.recent, 21);
  assert.equal(result.max, 20);
});

test('机器人第 20 次交接 → 仍然派，边界用 > 不用 >=', () => {
  const result = route(
    ev({ commentBody: HANDOFF('miles') }, { senderType: 'Bot', gates: { now: NOW, recentHandoffs: 20, maxHandoffs: 20 } }),
  );
  assert.equal(result.kind, 'assign');
});

test('人写的交接永远放行，不受额度限制', () => {
  const result = route(ev({ commentBody: HANDOFF('miles') }, { gates: { now: NOW, recentHandoffs: 999 } }));
  assert.equal(result.kind, 'assign');
});

test('PR 上交接：先要分支名，拿到后把在办的 Issue 填进 issueNumber', () => {
  const input = ev({ issueNumber: 9, issueIsPr: true, commentBody: HANDOFF('frank') });
  assert.equal(route(input).kind, 'need-pull');

  const result = route({ ...input, pull: { headRef: 'qwen-fix-7' } });
  assert.equal(result.issueNumber, '7');
  assert.equal(result.prNumber, 9);
  assert.equal(result.onPr, true);
});

test('在 PR 上交接但分支不是 qwen-fix-* → issueNumber 留空，不瞎猜', () => {
  const result = route({
    ...ev({ issueNumber: 9, issueIsPr: true, commentBody: HANDOFF('frank') }),
    pull: { headRef: 'someone-else/feature' },
  });
  assert.equal(result.issueNumber, '');
  assert.equal(result.prNumber, 9);
});

// ────────────────────────── 点名 ──────────────────────────

test('机器人点名有冷却', () => {
  const input = ev(
    { commentBody: CALL('nora') },
    { senderType: 'Bot', gates: { now: NOW, calls: [botComment({ created_at: ago(5) })], cooldownMinutes: 10 } },
  );
  const result = route(input);
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /冷却/);
});

test('冷却过了就放行', () => {
  const result = route(
    ev(
      { commentBody: CALL('nora') },
      { senderType: 'Bot', gates: { now: NOW, calls: [botComment({ created_at: ago(30) })], cooldownMinutes: 10 } },
    ),
  );
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'nora');
});

test('机器人点名有每日上限', () => {
  const calls = Array.from({ length: 40 }, () => botComment({ created_at: ago(60 * 20) }));
  const result = route(
    ev({ commentBody: CALL('nora') }, { senderType: 'Bot', gates: { now: NOW, calls, maxCalls: 40 } }),
  );
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /上限/);
});

test('人点名不看冷却也不看额度', () => {
  const calls = Array.from({ length: 999 }, () => botComment({ created_at: ago(1) }));
  const result = route(ev({ commentBody: CALL('nora') }, { gates: { now: NOW, calls } }));
  assert.equal(result.kind, 'assign');
});

// ────────────────────────── 事件分派 ──────────────────────────

test('新 Issue 和重开都归顾清', () => {
  for (const action of ['opened', 'reopened']) {
    const result = route(ev({ issueNumber: 3, issueBody: '有个问题' }, { eventName: 'issues', action }));
    assert.equal(result.role, 'clara', action);
    assert.equal(result.issueNumber, 3);
    assert.equal(result.onPr, false);
  }
});

test('Issue 上的其他动作不归任何人', () => {
  const result = route(ev({ issueNumber: 3 }, { eventName: 'issues', action: 'labeled' }));
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /issues\.labeled/);
});

test('指派给本次动作者 → 陈实接手', () => {
  const result = route(
    ev({ issueNumber: 3, assignee: 'qwencoder[bot]' }, { eventName: 'issues', action: 'assigned' }),
  );
  assert.equal(result.role, 'miles');
  assert.equal(result.issueNumber, 3);
});

test('指派给别人 → 忽略，不抢活', () => {
  const result = route(ev({ issueNumber: 3, assignee: 'human' }, { eventName: 'issues', action: 'assigned' }));
  assert.equal(result.kind, 'ignore');
});

test('新 PR 归周正，headRef 从载荷里取', () => {
  for (const action of ['opened', 'ready_for_review']) {
    const result = route(ev({ prNumber: 9, prHeadRef: 'qwen-fix-7', prIsFork: false }, { eventName: 'pull_request', action }));
    assert.equal(result.role, 'frank', action);
    assert.equal(result.prNumber, 9);
    assert.equal(result.headRef, 'qwen-fix-7');
    assert.equal(result.onPr, true);
  }
});

test('fork 来的 PR 不自动评审', () => {
  const result = route(ev({ prNumber: 9, prIsFork: true }, { eventName: 'pull_request', action: 'opened' }));
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /fork/);
});

test('自家 PR 上的评审 → 陈实处理意见', () => {
  const result = route(
    ev(
      { prNumber: 9, prHeadRef: 'qwen-fix-7', reviewState: 'changes_requested' },
      { eventName: 'pull_request_review', action: 'submitted' },
    ),
  );
  assert.equal(result.role, 'miles');
  assert.equal(result.issueNumber, '7');
  assert.equal(result.prNumber, 9);
  assert.match(result.reason, /changes_requested/);
});

// ────────────────────────── 评论 ──────────────────────────

test('自家 Issue 上被 @ → 顾清', () => {
  const result = route(ev({ issueNumber: 3, issueBody: '普通 Issue' }));
  assert.equal(result.role, 'clara');
  assert.equal(result.issueNumber, 3);
  assert.equal(result.onPr, false);
});

test('自家 Issue 上不 @ 也跟进：正文带我方标记', () => {
  const body = `<!-- qwen:opened-by=agent -->\n现状是这样`;
  const result = route(ev({ issueNumber: 3, issueBody: body, commentBody: '再补一句' }));
  assert.equal(result.role, 'clara');
  assert.match(result.reason, /我方 Issue/);
});

test('自家 Issue 上不 @ 也跟进：评论带角色标记', () => {
  const result = route(
    ev({ issueNumber: 3, commentBody: '<!-- qwen:role=nora --> 范围就定到这里' }),
  );
  assert.equal(result.role, 'clara');
});

test('别人的 Issue 上不 @ → 忽略，不乱插话', () => {
  const result = route(ev({ issueNumber: 3, issueBody: '别人的 Issue', commentBody: '路人甲发言' }));
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /未提及我方/);
});

test('mention 为空时不能把每条评论都当成被提及', () => {
  const result = route(ev({ issueNumber: 3, commentBody: '路人甲发言' }, { mention: '' }));
  assert.equal(result.kind, 'ignore', '`includes("")` 恒真会让机器人对每条评论都开口');
});

test('@ 不区分大小写', () => {
  const result = route(ev({ issueNumber: 3, commentBody: '@QWENCODER 帮看下' }, { mention: '@QwenCoder' }));
  assert.equal(result.role, 'clara');
});

test('自家 PR 上评论、没给分支名 → 先要分支名', () => {
  const result = route(ev({ issueNumber: 9, issueIsPr: true, commentBody: '这里要改' }));
  assert.equal(result.kind, 'need-pull');
});

test('自家 PR 上评论 → 陈实，且不许被「他人 PR」分支误判', () => {
  const result = route({
    ...ev({ issueNumber: 9, issueIsPr: true, commentBody: '这里要改' }),
    pull: { headRef: 'qwen-fix-7' },
  });
  assert.equal(result.role, 'miles');
  assert.equal(result.issueNumber, '7');
  assert.equal(result.prNumber, 9);
  assert.match(result.reason, /我方 PR/);
});

test('他人 PR 上被 @ → 周正只给意见', () => {
  const result = route({
    ...ev({ issueNumber: 9, issueIsPr: true, commentBody: '@qwencoder 这样写行吗' }),
    pull: { headRef: 'someone-else/feature' },
  });
  assert.equal(result.role, 'frank');
  assert.equal(result.prNumber, 9);
  assert.equal(result.issueNumber, '');
});

test('他人 PR 上没 @ → 忽略', () => {
  const result = route({
    ...ev({ issueNumber: 9, issueIsPr: true, commentBody: '写得不错' }),
    pull: { headRef: 'someone-else/feature' },
  });
  assert.equal(result.kind, 'ignore');
});

test('行内评审评论和普通评论走同一套', () => {
  const result = route(
    ev(
      { issueNumber: 9, issueIsPr: true, commentBody: '@qwencoder 这行有问题' },
      { eventName: 'pull_request_review_comment', pull: { headRef: 'someone-else/feature' } },
    ),
  );
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'frank');
});

test('没处理的事件也留原因，方便在日志里看出漏了什么', () => {
  const result = route(ev({}, { eventName: 'push', action: 'push' }));
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /push\.push/);
});

// ────────────────────────── 超限说明 ──────────────────────────

test('超限说明用中文名，且不带交接标记（否则会再触发一轮）', () => {
  const text = handoffLimitMessage({ role: 'miles', recent: 21, max: 20 });
  assert.match(text, /陈实/);
  assert.match(text, /21 次/);
  assert.match(text, /20 次/);
  assert.equal(parseHandoff(text), null);
  assert.equal(parseCall(text), null);
  assert.match(text, /<!-- qwen:role=dispatch -->/);
});
