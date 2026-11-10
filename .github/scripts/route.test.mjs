/**
 * 路由规则的测试。
 *
 * 这段逻辑错了的表现是**什么也不发生** —— 被取消的运行 jobs 为空，日志里一个字
 * 都不留。所以每条判据都要有一条测试盯着，尤其是「什么情况下不派活」和「派给谁」。
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
  turnsLimitMessage,
} from './route.mjs';

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString();

const HANDOFF = (role, reason = '接着做') => `我先做到这里。\n\n<!-- qwen:handoff=${role} reason=${reason} -->`;
const CALL = (role) => `有空看一眼。\n\n<!-- qwen:to=${role} -->`;

/** 一个会被正常派活的基线：成员在自家 Issue 上 @ 了机器人 */
const base = () => ({
  eventName: 'issue_comment',
  action: 'created',
  payload: { issueNumber: 7, issueIsPr: false, topicClosed: false, commentBody: '@qwencoder 这个报错麻烦看下' },
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

test('代码里的标记不认：贴一段示例不是在要求它生效', () => {
  // 行内代码
  assert.equal(parseHandoff('一条 `<!-- qwen:handoff=miles reason=试试 -->` 的评论'), null);
  // 围栏块，反引号与波浪线两种
  assert.equal(parseHandoff('日志如下\n```\n<!-- qwen:handoff=miles reason=试试 -->\n```\n'), null);
  assert.equal(parseHandoff('~~~\n<!-- qwen:to=frank -->\n~~~\n'), null);
});

test('代码外面还有真标记时照认', () => {
  const text = '示例 `<!-- qwen:handoff=nora reason=不是这条 -->`\n\n<!-- qwen:handoff=miles reason=这条才是 -->';
  assert.deepEqual(parseHandoff(text), { role: 'miles', reason: '这条才是' });
});

test('围栏没闭合时，后面的标记一并当引用', () => {
  // Markdown 也这么渲染。宁可漏认一条交接，也不要在引用块里认出一条指令。
  assert.equal(parseHandoff('```\n<!-- qwen:handoff=miles reason=x -->\n'), null);
});

test('数历史交接时也不数代码里的', () => {
  assert.equal(countRecentHandoffs([{ body: '贴一段：\n```\n<!-- qwen:handoff=frank reason=x -->\n```' }]), 0);
  assert.equal(recentCalls([{ body: '`<!-- qwen:to=nora -->`' }]).length, 0);
  // 同一条评论里代码内外都有时，只认外面那个
  assert.equal(countRecentHandoffs([{ body: '`<!-- qwen:handoff=frank reason=x -->`\n<!-- qwen:handoff=miles reason=y -->' }]), 1);
});

test('PR 描述里贴出交接标记，不会把这条 PR 从周正手里抢走', () => {
  // 真的踩到过：描述里为了说明「这条评论带了交接标记」把标记原样贴进行内代码，
  // 这条 PR 打开时就被派给了陈实，周正压根没被叫去评审。
  const input = ev(
    { prNumber: 47, issueIsPr: true, prBody: '改法：\n\n`<!-- qwen:handoff=miles reason=试试 -->`\n' },
    { eventName: 'pull_request', action: 'opened' },
  );
  const result = route(input);
  assert.equal(result.role, 'frank');
  assert.equal(result.prNumber, 47);
});

test('描述里真写了交接（不在代码里）照旧认', () => {
  const input = ev(
    { prNumber: 48, issueIsPr: true, prBody: '<!-- qwen:handoff=miles reason=先跑一遍 -->' },
    { eventName: 'pull_request', action: 'opened' },
  );
  const result = route({ ...input, pull: { headRef: 'qwen-fix-48' } });
  assert.equal(result.role, 'miles');
  assert.equal(result.reason, '交接：先跑一遍');
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

// ────────────────────────── 机器人状态评论 ──────────────────────────
//
// 机器人用评论请人接手，必须带交接或点名标记；没有标记的只是状态说明。
// 不区分的话，「Issue 回复归顾清」「我方 PR 回复归陈实」会让机器人自己叫醒
// 自己：陈实在 Issue 收尾会叫醒顾清，在自家 PR 写合并申请会再叫醒陈实。

test('机器人评论不带交接、点名或提及 → 只是状态说明，不叫醒任何人', () => {
  for (const commentBody of ['收到。', '<!-- qwen:role=miles --> 改完了，PR #9']) {
    const result = route(ev({ commentBody }, { senderType: 'Bot' }));
    assert.equal(result.kind, 'ignore');
    assert.match(result.why, /状态说明/);
  }
});

test('机器人评论 @ 了我们 → 仍按话题归谁派活', () => {
  const onIssue = route(ev({ commentBody: '@qwencoder 这里还要看一眼' }, { senderType: 'Bot' }));
  assert.equal(onIssue.role, 'clara');

  const onOwnedPr = route({
    ...ev(
      { issueNumber: 9, prNumber: 9, issueIsPr: true, commentBody: '@qwencoder 这里还要看一眼' },
      { senderType: 'Bot' },
    ),
    pull: { headRef: 'qwen-fix-7' },
  });
  assert.equal(onOwnedPr.role, 'miles');
});

// ────────────────────────── 终止条件：话题关闭 ──────────────────────────

test('话题关闭后机器人不再往下接 —— 收尾那句不该再叫醒一轮', () => {
  const result = route(
    ev(
      { topicClosed: true, commentBody: '已合并、已关闭。\n\n<!-- qwen:role=miles -->' },
      { senderType: 'Bot' },
    ),
  );
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /话题已关闭/);
});

test('关闭的话题上带交接标记也不派 —— 关掉就是这件事做完了', () => {
  const result = route(
    ev({ topicClosed: true, commentBody: HANDOFF('miles', '还有个小尾巴') }, { senderType: 'Bot' }),
  );
  assert.equal(result.kind, 'ignore');
});

test('关闭的话题上人说话仍然派活 —— 他大概是要重开或再问一句', () => {
  const result = route(ev({ topicClosed: true, commentBody: '@qwencoder 这个又出现了' }));
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'clara');
});

// ────────────────────────── 保险丝：机器人轮次上限 ──────────────────────────
//
// 话题还开着的时候就靠这条兜底，只拦「自己开的话题上反复说话」这种跑飞。
// 它不是主判据：真活干到一半不该被它截住。

test('机器人自己在 Issue 上写状态评论不再叫醒自己', () => {
  const result = route(
    ev(
      { issueNumber: 3, issueBody: '别人的 Issue', commentBody: '<!-- qwen:role=clara --> 我看过了' },
      { senderType: 'Bot' },
    ),
  );
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /状态说明/);
});

test('机器人发言到 24 小时上限就不叫醒 —— 话题一直不关时只剩这条保险丝', () => {
  const result = route(
    ev({ commentBody: HANDOFF('miles', '继续') }, { senderType: 'Bot', gates: { now: NOW, recentBotComments: 60 } }),
  );
  assert.equal(result.kind, 'turns-limit');
  assert.equal(result.recent, 60);
  assert.equal(result.max, 60);
});

test('差一次到上限时仍然派活，别把边界判错一轮', () => {
  const result = route(
    ev({ commentBody: HANDOFF('miles', '继续') }, { senderType: 'Bot', gates: { now: NOW, recentBotComments: 59 } }),
  );
  assert.equal(result.kind, 'assign');
});

test('机器人状态评论不占轮次上限，也不会触发超限说明', () => {
  const result = route(
    ev({ commentBody: '接着说' }, { senderType: 'Bot', gates: { now: NOW, recentBotComments: 60 } }),
  );
  assert.equal(result.kind, 'ignore');
  assert.match(result.why, /状态说明/);
});

test('轮次上限只管机器人，人写的评论不受限', () => {
  const result = route(
    ev({ commentBody: '@qwencoder 再看看' }, { gates: { now: NOW, recentBotComments: 999, maxTurns: 60 } }),
  );
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'clara');
});

test('轮次上限说明用中文，不带交接或点名标记', () => {
  const text = turnsLimitMessage({ recent: 60, max: 60 });
  assert.match(text, /60 次/);
  assert.match(text, /上限/);
  assert.equal(parseHandoff(text), null);
  assert.equal(parseCall(text), null);
  assert.match(text, /<!-- qwen:role=dispatch -->/);
});

test('轮次上限刚好达到时返回 turns-limit，带 number', () => {
  const result = route(
    ev(
      { issueNumber: 5, commentBody: HANDOFF('miles', '继续') },
      { senderType: 'Bot', gates: { now: NOW, recentBotComments: 60, maxTurns: 60 } },
    ),
  );
  assert.equal(result.kind, 'turns-limit');
  assert.equal(result.number, 5);
  assert.equal(result.recent, 60);
  assert.equal(result.max, 60);
});

test('轮次上限在 PR 上也带 number', () => {
  const result = route(
    ev(
      { issueNumber: 9, prNumber: 9, issueIsPr: true, commentBody: CALL('frank') },
      { senderType: 'Bot', gates: { now: NOW, recentBotComments: 60, maxTurns: 60 } },
    ),
  );
  assert.equal(result.kind, 'turns-limit');
  assert.equal(result.number, 9);
});

test('轮次上限只管机器人，人写的评论不受限 —— 真人发言永远不被拦', () => {
  const result = route(
    ev({ commentBody: '@qwencoder 再看看' }, { gates: { now: NOW, recentBotComments: 999, maxTurns: 60 } }),
  );
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'clara');
});

test('机器人评论带交接 → 派给被交接的人', () => {
  const result = route(ev({ commentBody: HANDOFF('nora', '范围要定') }, { senderType: 'Bot' }));
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'nora');
});

test('机器人提交评审不带标记 → 仍然派活', () => {
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

test('24 小时内已有 21 次交接 → 超限，不再派人', () => {
  const result = route(
    ev({ commentBody: HANDOFF('miles') }, { senderType: 'Bot', gates: { now: NOW, recentHandoffs: 21, maxHandoffs: 20 } }),
  );
  assert.equal(result.kind, 'handoff-limit');
  assert.equal(result.role, 'miles');
  assert.equal(result.recent, 21);
  assert.equal(result.max, 20);
});

test('24 小时内刚好 20 次交接 → 这次是第 21 次，停下', () => {
  // 计数的语义是「本次之前发生过几次」，所以 20 次历史意味着这一条就超了。
  // 早先这里用 >，靠的是「本次这条也数在里面」—— 与点名冷却失效同源，见 dispatch.mjs。
  const result = route(
    ev({ commentBody: HANDOFF('miles') }, { senderType: 'Bot', gates: { now: NOW, recentHandoffs: 20, maxHandoffs: 20 } }),
  );
  assert.equal(result.kind, 'handoff-limit');
});

test('24 小时内 19 次交接 → 还能派，额度没被提前收紧', () => {
  const result = route(
    ev({ commentBody: HANDOFF('miles') }, { senderType: 'Bot', gates: { now: NOW, recentHandoffs: 19, maxHandoffs: 20 } }),
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
    ev(
      { issueNumber: 3, assignee: 'qwencoder[bot]', assigneeType: 'Bot' },
      { eventName: 'issues', action: 'assigned' },
    ),
  );
  assert.equal(result.role, 'miles');
  assert.equal(result.issueNumber, 3);
});

test('指派给别人 → 忽略，不抢活', () => {
  const result = route(ev({ issueNumber: 3, assignee: 'human' }, { eventName: 'issues', action: 'assigned' }));
  assert.equal(result.kind, 'ignore');
});

test('人把 Issue 指派给 AI 账号 → 陈实接手', () => {
  // 真实形态：assignee 是机器人、触发事件的是那个人。早先的判据拿 assignee
  // 和触发者比，两者永远不相等，这条规则因此从来没生效过。
  const result = route(
    ev(
      { issueNumber: 42, assignee: 'qwencoder-clara[bot]', assigneeType: 'Bot' },
      { eventName: 'issues', action: 'assigned', senderType: 'User' },
    ),
  );
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'miles');
  assert.equal(result.issueNumber, 42);
  assert.equal(result.onPr, false);
});

test('人把 PR 指派给 AI 账号 → 当成 PR 派下去，不是当成 Issue', () => {
  // GitHub 对 PR 也发 issues.assigned。当成 Issue 派下去，陈实会去读一个
  // 没有 checkout 分支的 PR。
  const result = route(
    ev(
      { issueNumber: 51, issueIsPr: true, assignee: 'qwencoder-miles[bot]', assigneeType: 'Bot' },
      { eventName: 'issues', action: 'assigned', senderType: 'User' },
    ),
  );
  assert.equal(result.kind, 'need-pull', '要先知道分支名才能判它是不是我方 PR');

  const withPull = route({
    ...ev(
      { issueNumber: 51, issueIsPr: true, assignee: 'qwencoder-miles[bot]', assigneeType: 'Bot' },
      { eventName: 'issues', action: 'assigned', senderType: 'User' },
    ),
    pull: { headRef: 'qwen-fix-42' },
  });
  assert.equal(withPull.onPr, true);
  assert.equal(withPull.prNumber, 51);
  assert.equal(withPull.issueNumber, '42', 'qwen-fix-42 对应 42 号 Issue');
  assert.equal(withPull.headRef, 'qwen-fix-42');
});

test('人把 Issue 指派给另一个人 → 仍然忽略', () => {
  const result = route(
    ev(
      { issueNumber: 42, assignee: 'teammate', assigneeType: 'User' },
      { eventName: 'issues', action: 'assigned', senderType: 'User' },
    ),
  );
  assert.equal(result.kind, 'ignore');
});

test('取消指派（assignee 为空）不会被当成派活', () => {
  // unassigned 走的是另一个 action；但载荷缺 assignee 时也不能误派
  const result = route(
    ev({ issueNumber: 42, assignee: '', assigneeType: '' }, { eventName: 'issues', action: 'assigned' }),
  );
  assert.equal(result.kind, 'ignore');
});

test('机器人把 Issue 指派给自己 → 不当指令，否则是一轮接一轮的无限跑', () => {
  const result = route(
    ev(
      { issueNumber: 42, assignee: 'qwencoder-miles[bot]', assigneeType: 'Bot' },
      { eventName: 'issues', action: 'assigned', senderType: 'Bot' },
    ),
  );
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

test('自家 Issue 上不 @ 也跟进：正文写什么都不影响', () => {
  const body = `现状是这样`;
  const result = route(ev({ issueNumber: 3, issueBody: body, commentBody: '再补一句' }));
  assert.equal(result.role, 'clara');
  assert.match(result.reason, /Issue 上有新回复/);
});

test('自家 Issue 上不 @ 也跟进：评论带角色标记', () => {
  const result = route(
    ev({ issueNumber: 3, commentBody: '<!-- qwen:role=nora --> 范围就定到这里' }),
  );
  assert.equal(result.role, 'clara');
});

test('别人开的 Issue 上不 @ 也交给顾清 —— 真人的单和机器人的单一样处理', () => {
  const result = route(ev({ issueNumber: 3, issueBody: '别人的 Issue', commentBody: '这个还是红的' }));
  assert.equal(result.role, 'clara');
  assert.equal(result.issueNumber, 3);
  assert.equal(result.onPr, false);
  assert.match(result.reason, /Issue 上有新回复/);
});

test('mention 为空时不能把每条评论都当成被提及', () => {
  const result = route(ev({ issueNumber: 3, commentBody: '路人甲发言' }, { mention: '' }));
  assert.equal(result.role, 'clara', '不 @ 也会叫醒顾清');
  assert.doesNotMatch(result.reason, /被提及/, '`includes("")` 恒真会让日志谎称有人 @ 了我们');
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

test('他人 PR 上没 @ 也交给周正 —— 只出意见，边界在职责里', () => {
  const result = route({
    ...ev({ issueNumber: 9, issueIsPr: true, commentBody: '写得不错' }),
    pull: { headRef: 'someone-else/feature' },
  });
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'frank');
  assert.equal(result.onPr, true);
  assert.match(result.reason, /仅提供评审意见/);
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
