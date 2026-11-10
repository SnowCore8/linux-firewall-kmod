#!/usr/bin/env node
/**
 * `<!-- qwen:… -->` 标记的判据测试。
 *
 * 这份文件测的是「哪些写法算数」这条边界本身，而边界两边各有一套判据：
 *
 *   宽松（独占一行与否都认）—— `handoff` / `to`
 *   严格（必须独占一行）      —— `verdict` / `merge-request`
 *   严格（标记必须完整）      —— `role`
 *
 * 错的方向各不相同，所以用例分成三组写，而不是混成一张清单：抹平它们的差别，
 * 就等于把「贴一段引用」和「提出要求」看成一回事。
 *
 *   node --test .github/scripts/markers.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  hasApproveMarker,
  hasCall,
  hasHandoff,
  hasMergeRequest,
  hasRejectMarker,
  hasRole,
  parseCall,
  parseHandoff,
} from './markers.mjs';

// ────────────────────── 交接 handoff（宽松） ──────────────────────

test('交接：独占一行', () => {
  assert.deepEqual(parseHandoff('<!-- qwen:handoff=miles reason=检查没通过 -->'), {
    to: 'miles',
    reason: '检查没通过',
  });
});

test('交接：出现在句子中间也认', () => {
  // 强度是刻意的：漏认的代价是「该接手的人一直没人叫」，比多跑一轮更糟
  const text = '我这边做完了，接下来 <!-- qwen:handoff=frank reason=请你评审 --> 请周正看一眼。';
  assert.deepEqual(parseHandoff(text), { to: 'frank', reason: '请你评审' });
});

test('交接：reason 里的换行原样保留', () => {
  const text = '<!-- qwen:handoff=nora reason=第一行\n第二行 -->';
  assert.equal(parseHandoff(text).reason, '第一行\n第二行');
});

test('交接：名字大小写不敏感，统一成小写', () => {
  assert.equal(parseHandoff('<!-- qwen:handoff=Miles reason=x -->').to, 'miles');
});

test('交接：围栏里的引用不算', () => {
  const text = '格式长这样：\n\n```\n<!-- qwen:handoff=miles reason=示例 -->\n```\n';
  assert.equal(parseHandoff(text), null);
  assert.equal(hasHandoff(text), false);
});

test('交接：行内代码里的引用不算', () => {
  assert.equal(hasHandoff('写 `<!-- qwen:handoff=miles reason=x -->` 就能交接。'), false);
});

test('交接：没有标记返回 null', () => {
  assert.equal(parseHandoff('就是一句普通的话'), null);
});

test('交接：没有 reason 不算交接', () => {
  // `reason=` 是格式的一部分，缺了它就不是这条语法
  assert.equal(parseHandoff('<!-- qwen:handoff=miles -->'), null);
});

test('交接：中文名解析不出来', () => {
  // 机器里认的只有英文名。中文名只用在给人看的地方，所以中文名写进标记不会被认，
  // 也不会被误拼成一个不存在的角色 —— 认不出来就当没写，由 route 那边统一处理。
  assert.equal(parseHandoff('<!-- qwen:handoff=陈实 reason=x -->'), null);
});

// ────────────────────── 点名 to（宽松） ──────────────────────

test('点名：独占一行', () => {
  assert.equal(parseCall('<!-- qwen:to=frank -->'), 'frank');
});

test('点名：出现在句子里也认', () => {
  assert.equal(parseCall('这条给 <!-- qwen:to=nora --> 看，不要求动手。'), 'nora');
});

test('点名：行内代码里的引用不算', () => {
  assert.equal(hasCall('要叫人就写 `<!-- qwen:to=frank -->`。'), false);
});

test('点名：没有标记返回 null', () => {
  assert.equal(parseCall('普通评论'), null);
});

test('点名：大小写统一成小写', () => {
  assert.equal(parseCall('<!-- qwen:to=FRANK -->'), 'frank');
});

// ────────────────────── 合并申请（严格） ──────────────────────

test('合并申请：独占一行算', () => {
  assert.equal(hasMergeRequest('结论：可以合。\n\n<!-- qwen:merge-request -->\n'), true);
});

test('合并申请：行首行尾空白不影响', () => {
  assert.equal(hasMergeRequest('  <!-- qwen:merge-request -->  \n'), true);
});

test('合并申请：夹在句子里不算', () => {
  // 这条最危险：一句「暂不申请，等 CI 绿了再写 <!-- qwen:merge-request -->」如果不
  // 独占一行就不该被读成申请
  assert.equal(hasMergeRequest('等 CI 绿了我再写 <!-- qwen:merge-request --> 这一行。'), false);
});

test('合并申请：围栏里的示例不算', () => {
  const text = '```html\n<!-- qwen:merge-request -->\n```\n';
  assert.equal(hasMergeRequest(text), false);
});

test('合并申请：行内代码里的引用不算', () => {
  assert.equal(hasMergeRequest('写 `<!-- qwen:merge-request -->` 就是申请。'), false);
});

test('合并申请：拼错的不算', () => {
  assert.equal(hasMergeRequest('<!-- qwen:merge-requests -->'), false);
});

// ────────────────────── 评审结论（严格） ──────────────────────

test('评审：批准独占一行算', () => {
  assert.equal(hasApproveMarker('看过，没问题。\n\n<!-- qwen:verdict=approve -->\n'), true);
});

test('评审：批准夹在句子里不算', () => {
  assert.equal(hasApproveMarker('CI 还是红的，等绿了我再写 <!-- qwen:verdict=approve -->'), false);
});

test('评审：批准在围栏里不算', () => {
  assert.equal(hasApproveMarker('```\n<!-- qwen:verdict=approve -->\n```'), false);
});

test('评审：request-changes 独占一行算', () => {
  assert.equal(hasRejectMarker('\n<!-- qwen:verdict=request-changes -->\n'), true);
});

test('评审：request-changes 夹在句子里不算', () => {
  assert.equal(hasRejectMarker('不是 approve 也不是 <!-- qwen:verdict=request-changes --> 的写法'), false);
});

test('评审：approve 不能当成 request-changes', () => {
  assert.equal(hasRejectMarker('<!-- qwen:verdict=approve -->'), false);
  assert.equal(hasApproveMarker('<!-- qwen:verdict=request-changes -->'), false);
});

test('评审：多余的等号写法不算', () => {
  assert.equal(hasApproveMarker('<!-- qwen:verdict=approve=yes -->'), false);
});

// ────────────────────── 签名 role（严格） ──────────────────────

test('签名：完整标记算', () => {
  assert.equal(hasRole('结论如上。\n\n<!-- qwen:role=nora -->', 'nora'), true);
});

test('签名：前缀相同的别的名字不算', () => {
  // `nora-extra` 不可能是签名，判错了等于把没发生的发言当成发生了
  assert.equal(hasRole('<!-- qwen:role=nora-extra -->', 'nora'), false);
});

test('签名：别人的签名不算', () => {
  assert.equal(hasRole('<!-- qwen:role=miles -->', 'nora'), false);
});

test('签名：围栏里的示例不算', () => {
  assert.equal(hasRole('```\n<!-- qwen:role=nora -->\n```', 'nora'), false);
});

test('签名：句中出现的签名仍然算', () => {
  // 签名是要认出来的，它只表示「这个人发过话」，不需要独占一行
  assert.equal(hasRole('我的意见是…… <!-- qwen:role=frank -->', 'frank'), true);
});

// ────────────────────── 剥代码的共同前提 ──────────────────────

test('未闭合的围栏：剩余部分全部不算', () => {
  // 与 Markdown 渲染一致：宁可漏认，也不要在引用块里认出一条不存在的指令
  const text = '说明：\n```\n<!-- qwen:merge-request -->';
  assert.equal(hasMergeRequest(text), false);
});

test('波浪号围栏同样剥掉', () => {
  assert.equal(hasMergeRequest('~~~\n<!-- qwen:merge-request -->\n~~~'), false);
});

test('包围栏关不掉波浪号围栏', () => {
  assert.equal(hasMergeRequest('~~~\n<!-- qwen:merge-request -->\n```\n~~~'), false);
});

test('围栏外的标记不受影响', () => {
  const text = '```\n<!-- qwen:merge-request -->\n```\n\n真正申请：\n\n<!-- qwen:merge-request -->\n';
  assert.equal(hasMergeRequest(text), true);
});

test('空输入不抛异常', () => {
  assert.equal(hasHandoff(undefined), false);
  assert.equal(hasCall(null), false);
  assert.equal(hasMergeRequest(''), false);
  assert.equal(hasApproveMarker(undefined), false);
  assert.equal(hasRole('', 'nora'), false);
  assert.equal(parseHandoff(undefined), null);
  assert.equal(parseCall(undefined), null);
});
