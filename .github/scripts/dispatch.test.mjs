/**
 * dispatch 的搬运层测试。
 *
 * route.mjs 再怎么对，只要这里把字段名搬错了，route() 拿到的就是 undefined，
 * 结果是「安静地什么都不派」—— 没有报错，没有日志，只剩没人处理的事件。
 * 所以字段映射、闸门取数的时机、输出格式各要一条测试。
 *
 *   /usr/bin/node --test .github/scripts/dispatch.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { buildInput, outputLines, formatOutput, numberOfEvent } from './dispatch.mjs';
import { route, parseHandoff } from './route.mjs';

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const ENV = {
  GITHUB_REPOSITORY: 'owner/repo',
  QWEN_MENTION: '@QwenCoder',
  AGENT_MAX_HANDOFFS: '20',
  AGENT_MAX_CALLS: '40',
  AGENT_CALL_COOLDOWN_MINUTES: '10',
  ACTOR: 'qwencoder[bot]',
  DISPATCH_NOW: String(NOW),
};
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString();

const issueEvent = (over = {}) => ({
  action: 'created',
  sender: { type: 'User' },
  issue: {
    number: 7,
    body: '有个报错',
    author_association: 'MEMBER',
    ...over.issue,
  },
  comment: { body: '@qwencoder 看下', ...over.comment },
  ...over,
});

const prEvent = (over = {}) => ({
  action: 'opened',
  sender: { type: 'User' },
  pull_request: {
    number: 9,
    body: '改动说明',
    head: { ref: 'qwen-fix-7', repo: { fork: false } },
    author_association: 'MEMBER',
    ...over.pull_request,
  },
  ...over,
});

/** 默认不让测试碰网络：没显式给的依赖一被调用就报错 */
const noIo = (deps = {}) => ({
  isPull: () => {
    throw new Error('不该在这里问是不是 PR');
  },
  commentsOf: () => {
    throw new Error('不该在这里取评论');
  },
  ...deps,
});

// ────────────────────────── 字段搬运 ──────────────────────────

test('Issue 评论：字段搬对，route 能派给顾清', () => {
  const input = buildInput({ event: issueEvent(), eventName: 'issue_comment', env: ENV, deps: noIo() });
  assert.equal(input.payload.issueNumber, 7);
  assert.equal(input.payload.issueIsPr, false);
  assert.equal(input.payload.commentBody, '@qwencoder 看下');
  assert.equal(input.authorAssociation, 'MEMBER');
  assert.equal(input.mention, '@qwencoder', '触发词应当已被小写化');
  assert.equal(input.actor, 'qwencoder[bot]');

  const result = route(input);
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'clara');
  assert.equal(result.issueNumber, 7);
});

test('PR 打开：分支名从 pull_request.head.ref 取到，不用再问一次', () => {
  const input = buildInput({ event: prEvent(), eventName: 'pull_request', env: ENV, deps: noIo() });
  assert.equal(input.payload.prNumber, 9);
  assert.equal(input.payload.prHeadRef, 'qwen-fix-7');

  const result = route(input);
  assert.equal(result.role, 'frank');
  assert.equal(result.headRef, 'qwen-fix-7');
  assert.equal(result.prNumber, 9);
});

test('fork 标记搬对：fork 的 PR 不评审', () => {
  const event = prEvent({ pull_request: { head: { ref: 'their/fix', repo: { fork: true } } } });
  const input = buildInput({ event, eventName: 'pull_request', env: ENV, deps: noIo() });
  assert.equal(input.payload.prIsFork, true);
  assert.equal(route(input).kind, 'ignore');
});

test('评审：state 与作者关联都搬对', () => {
  const event = {
    ...prEvent({ action: 'submitted' }),
    review: { state: 'approved', author_association: 'MEMBER' },
  };
  const input = buildInput({ event, eventName: 'pull_request_review', env: ENV, deps: noIo() });
  assert.equal(input.payload.reviewState, 'approved');
  assert.equal(input.authorAssociation, 'MEMBER');

  const result = route(input);
  assert.equal(result.role, 'miles');
  assert.equal(result.issueNumber, '7');
});

test('指派：assignee 搬对', () => {
  const event = issueEvent({ action: 'assigned', assignee: { login: 'qwencoder[bot]' } });
  const input = buildInput({ event, eventName: 'issues', env: ENV, deps: noIo() });
  assert.equal(input.payload.assignee, 'qwencoder[bot]');
  assert.equal(route(input).role, 'miles');
});

test('手动触发：问一次它是不是 PR，不问分支名', () => {
  const asked = [];
  const input = buildInput({
    event: { inputs: { number: '9', role: 'frank' } },
    eventName: 'workflow_dispatch',
    env: ENV,
    deps: noIo({
      isPull: (n) => {
        asked.push(n);
        return true;
      },
    }),
  });
  assert.deepEqual(asked, ['9']);
  assert.equal(input.payload.issueIsPr, true);
  assert.equal(input.manual.number, '9');
  assert.equal(input.manual.role, 'frank');

  // PR 上派活需要分支名，这一步由 main() 补；route 这里先要
  assert.equal(route(input).kind, 'need-pull');
  assert.equal(route({ ...input, pull: { headRef: 'qwen-fix-7' } }).role, 'frank');
});

test('作者关联从 comment / review / issue / PR 任一处取到', () => {
  const cases = [
    ['issue_comment', issueEvent()],
    ['pull_request_review', prEvent({ review: { state: 'approved', author_association: 'OWNER' } })],
    ['issues', issueEvent({ comment: undefined })],
    ['pull_request', prEvent()],
  ];
  for (const [eventName, event] of cases) {
    const input = buildInput({ event, eventName, env: ENV, deps: noIo() });
    assert.notEqual(input.authorAssociation, '', `${eventName} 没取到作者关联`);
  }
});

// ────────────────────────── 闸门取数的时机 ──────────────────────────

test('人类写的交接：不去数评论，也就不付那几十次调用', () => {
  const event = issueEvent({ comment: { body: '<!-- qwen:handoff=miles reason=做吧 -->' } });
  const input = buildInput({ event, eventName: 'issue_comment', env: ENV, deps: noIo() });
  assert.equal(input.gates.recentHandoffs, undefined);
  assert.equal(route(input).kind, 'assign');
});

test('机器人写的交接：数一次评论，额度带进闸门', () => {
  let read = 0;
  const event = issueEvent({
    sender: { type: 'Bot' },
    comment: { body: '<!-- qwen:handoff=miles reason=做吧 -->' },
  });
  const comments = [
    { user: { type: 'Bot' }, created_at: ago(5), body: '<!-- qwen:handoff=frank reason=x -->' },
    { user: { type: 'Bot' }, created_at: ago(6), body: '<!-- qwen:to=nora -->' },
    { user: { type: 'User' }, created_at: ago(7), body: '<!-- qwen:handoff=nora reason=y -->' },
  ];
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => (read++, comments) }),
  });
  assert.equal(read, 1);
  assert.equal(input.gates.recentHandoffs, 1, '人类的交接不该被算进机器人的额度');
  assert.equal(input.gates.calls.length, 1);

  assert.equal(route(input).kind, 'assign');
});

test('机器人第 21 次交接：从真实评论数出来就超限', () => {
  const event = issueEvent({
    sender: { type: 'Bot' },
    comment: { body: '<!-- qwen:handoff=miles reason=做吧 -->' },
  });
  // 21 条历史交接 + 本次这条，共 22 条
  const comments = Array.from({ length: 21 }, (_, i) => ({
    user: { type: 'Bot' },
    created_at: ago(i + 1),
    body: '<!-- qwen:handoff=frank reason=x -->',
  }));
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => comments }),
  });
  const result = route(input);
  assert.equal(result.kind, 'handoff-limit');
  assert.equal(result.recent, 21);
});

test('评论取不到就抛，不伪装成「没有评论」', () => {
  const event = issueEvent({
    sender: { type: 'Bot' },
    comment: { body: '<!-- qwen:handoff=miles reason=做吧 -->' },
  });
  assert.throws(
    () => buildInput({
      event,
      eventName: 'issue_comment',
      env: ENV,
      deps: noIo({
        commentsOf: () => {
          throw new Error('403');
        },
      }),
    }),
    /403/,
    '静默当成没有评论会让防打转闸门失效',
  );
});

test('额度默认值与 README 一致', () => {
  const event = issueEvent({
    sender: { type: 'Bot' },
    comment: { body: '<!-- qwen:handoff=miles reason=做吧 -->' },
  });
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: { DISPATCH_NOW: String(NOW) },
    deps: noIo({ commentsOf: () => [] }),
  });
  assert.equal(input.gates.maxHandoffs, 20);
  assert.equal(input.gates.maxCalls, 40);
  assert.equal(input.gates.cooldownMinutes, 10);
  assert.equal(input.mention, '@qwencoder');
});

// ────────────────────────── 输出 ──────────────────────────

test('输出用 heredoc，reason 带换行也不会截断', () => {
  const text = formatOutput('reason', '第一行\n第二行');
  assert.equal(text, 'reason<<__END__\n第一行\n第二行\n__END__\n');
  assert.ok(!/reason=/.test(text), '别用 key=value 形式，多行会被 GitHub 拒掉');
});

test('派活时七个键齐全', () => {
  const lines = outputLines({
    kind: 'assign',
    role: 'miles',
    number: 9,
    onPr: true,
    reason: '收到评审：approved',
    issueNumber: '7',
    prNumber: 9,
    headRef: 'qwen-fix-7',
  });
  const text = lines.join('');
  for (const key of ['role', 'number', 'on_pr', 'reason', 'issue_number', 'pr_number', 'head_ref']) {
    assert.match(text, new RegExp(`^${key}<<__END__`, 'm'), `缺 ${key}`);
  }
  assert.match(text, /on_pr<<__END__\ntrue\n/);
});

test('不派活时只写一个空 role，下游四个 job 都不成立', () => {
  const lines = outputLines({ kind: 'ignore', why: '别人家的 Issue' });
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^role<<__END__\n\n__END__\n$/);
});

test('超限也不派活', () => {
  const lines = outputLines({ kind: 'handoff-limit', role: 'miles', number: 7, recent: 21, max: 20 });
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^role<<__END__\n\n__END__\n$/);
});

test('多页评论必须合并成一维再数，不能把 `[[...],[...]]` 当成评论列表', () => {
  // gh api --paginate 默认把每页拼在一起，超过 100 条评论时 JSON.parse 直接抛。
  // commentsOf 用 --slurp 拿 [[...],[...]]，这里模拟它 flatten 之后的结果。
  const page1 = Array.from({ length: 3 }, (_, i) => ({
    user: { type: 'Bot' },
    created_at: ago(i + 1),
    body: '<!-- qwen:handoff=frank reason=p1 -->',
  }));
  const page2 = Array.from({ length: 2 }, () => ({
    user: { type: 'Bot' },
    created_at: ago(10),
    body: '<!-- qwen:to=nora -->',
  }));
  const event = issueEvent({
    sender: { type: 'Bot' },
    comment: { body: '<!-- qwen:handoff=miles reason=做吧 -->' },
  });
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => [page1, page2].flat() }),
  });
  assert.equal(input.gates.recentHandoffs, 3);
  assert.equal(input.gates.calls.length, 2);
});

test('输出里不会出现交接标记，否则自己又触发一轮', () => {
  const text = outputLines({
    kind: 'assign', role: 'miles', number: 7, onPr: false, reason: '交接：做吧',
  }).join('');
  assert.equal(parseHandoff(text), null);
});

test('取数失败时也能从事件里拿到编号，report-failure 才有地方说明', () => {
  assert.equal(numberOfEvent({ issue: { number: 20 } }), 20);
  assert.equal(numberOfEvent({ pull_request: { number: 21 } }), 21);
  assert.equal(numberOfEvent({ inputs: { number: '20' } }), 20);
  assert.equal(numberOfEvent({}), '');
});
