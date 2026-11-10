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
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildInput, outputLines, formatOutput, numberOfEvent, commentsOf, hasExistingTurnsLimitNotice } from './dispatch.mjs';
import { route, parseHandoff } from './route.mjs';

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'dispatch.mjs');

const NOW = new Date('2026-11-07T12:00:00Z').getTime();
const ENV = {
  GITHUB_REPOSITORY: 'owner/repo',
  QWEN_MENTION: '@QwenCoder',
  AGENT_MAX_HANDOFFS: '20',
  AGENT_MAX_CALLS: '40',
  AGENT_MAX_TURNS: '60',
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
  const event = issueEvent({ action: 'assigned', assignee: { login: 'qwencoder[bot]', type: 'Bot' } });
  const input = buildInput({ event, eventName: 'issues', env: ENV, deps: noIo() });
  assert.equal(input.payload.assignee, 'qwencoder[bot]');
  // 类型也要搬：判「是不是我方账号」看的是它，漏搬就永远判不出来
  assert.equal(input.payload.assigneeType, 'Bot');
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

test('不带任何标记的机器人评论也要数 —— 保险丝数的是「说过多少话」', () => {
  let read = 0;
  const event = issueEvent({ sender: { type: 'Bot' }, comment: { body: '收到。' } });
  const comments = [
    { user: { type: 'Bot' }, created_at: ago(3), body: '已合并' },
    { user: { type: 'Bot' }, created_at: ago(9), body: '<!-- qwen:role=frank --> 可以合' },
    { user: { type: 'User' }, created_at: ago(12), body: '收到' },
  ];
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => (read++, comments) }),
  });
  assert.equal(read, 1);
  assert.equal(input.gates.recentBotComments, 2, '两条机器人评论都要数，带不带标记无关');
});

test('人写的评论完全不数 —— 轮次上限只管机器人，也就不付那几十次调用', () => {
  let read = 0;
  const event = issueEvent({ comment: { body: '接着说' } });
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({
      commentsOf: () => {
        read++;
        return [];
      },
    }),
  });
  assert.equal(read, 0);
  assert.equal(input.gates.recentBotComments, undefined);
});

test('话题关没关要搬对：路由靠它判断该不该停', () => {
  const open = buildInput({ event: issueEvent(), eventName: 'issue_comment', env: ENV, deps: noIo() });
  assert.equal(open.payload.topicClosed, false);

  // 关闭的 Issue 一样会收到 issue_comment，所以只能看 state，不能看事件名
  const closed = buildInput({
    event: issueEvent({ issue: { state: 'closed' } }),
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo(),
  });
  assert.equal(closed.payload.topicClosed, true);

  const merged = buildInput({
    event: prEvent({ pull_request: { state: 'closed' } }),
    eventName: 'pull_request',
    env: ENV,
    deps: noIo(),
  });
  assert.equal(merged.payload.topicClosed, true);
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

// ───────────────── 触发本轮的那条评论不算「历史」 ─────────────────
//
// GitHub 的评论列表里一定包含触发本次运行的那一条。把它当成历史，
// 「距上次点名」就恒为 0，冷却永远不满足，机器人之间的点名一次都发不出去。
// 下面两条喂的是真实形状：同一个数组里既有历史，也有触发的那条（带 id）。

test('真实形状：触发本轮的机器人点名不算进冷却，点名能发出去', () => {
  const trigger = {
    id: 1002,
    user: { type: 'Bot' },
    created_at: ago(0),
    body: '这条给周正看\n\n<!-- qwen:to=frank -->',
  };
  const history = {
    id: 1001,
    user: { type: 'Bot' },
    created_at: ago(45),
    body: '上一次点名\n\n<!-- qwen:to=nora -->',
  };
  const event = issueEvent({ sender: { type: 'Bot' }, comment: trigger });

  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    // 顺序模仿 gh：老的在前
    deps: noIo({ commentsOf: () => [history, trigger] }),
  });

  assert.equal(input.gates.calls.length, 1, '只剩那条 45 分钟前的历史点名');
  const result = route(input);
  assert.equal(result.kind, 'assign', '冷却已过，这次点名该派下去');
  assert.equal(result.role, 'frank');
});

test('触发本轮的交接同样不算进额度：刚好卡在额度上时仍能派一次', () => {
  const trigger = {
    id: 2001,
    user: { type: 'Bot' },
    created_at: ago(0),
    body: '<!-- qwen:handoff=miles reason=接力 -->',
  };
  const history = Array.from({ length: 19 }, (_, i) => ({
    id: 3000 + i,
    user: { type: 'Bot' },
    created_at: ago(i + 10),
    body: '<!-- qwen:handoff=frank reason=x -->',
  }));
  const event = issueEvent({ sender: { type: 'Bot' }, comment: trigger });

  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => [...history, trigger] }),
  });

  assert.equal(input.gates.recentHandoffs, 19, '19 条历史，不含触发这条');
  assert.equal(route(input).kind, 'assign', '第 20 次，还没到上限');
});

test('评论没有 id 时（旧形状）不误删历史', () => {
  const trigger = { user: { type: 'Bot' }, created_at: ago(0), body: '<!-- qwen:to=frank -->' };
  const history = { user: { type: 'Bot' }, created_at: ago(120), body: '<!-- qwen:to=nora -->' };
  const event = issueEvent({ sender: { type: 'Bot' }, comment: trigger });

  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => [history, trigger] }),
  });

  // 没有 id 就无从剔除，退回旧行为：两条都算。冷却因此会拦下这次（120 分钟前的那条
  // 不构成阻塞，但触发这条自己构成），这是保守的一侧 —— 拦住一次点名，而不是乱派活。
  assert.equal(input.gates.calls.length, 2);
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
  assert.equal(input.gates.maxTurns, 60);
  assert.equal(input.gates.cooldownMinutes, 10);
  assert.equal(input.mention, '@qwencoder');
});

// ────────────────────────── 输出 ──────────────────────────

test('输出用 heredoc，reason 带换行也不会截断', () => {
  const text = formatOutput('reason', '第一行\n第二行');
  assert.equal(text, 'reason<<__END__\n第一行\n第二行\n__END__\n');
  assert.ok(!/reason=/.test(text), '别用 key=value 形式，多行会被 GitHub 拒掉');
});

test('派活时八个键齐全', () => {
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
  for (const key of ['role', 'who', 'number', 'on_pr', 'reason', 'issue_number', 'pr_number', 'head_ref']) {
    assert.match(text, new RegExp(`^${key}<<__END__`, 'm'), `缺 ${key}`);
  }
  assert.match(text, /on_pr<<__END__\ntrue\n/);
  // 出错说明那条评论要写给人看，中文名从 route.mjs 带出来，别在 yml 里另抄一张表
  assert.match(text, /who<<__END__\n陈实\n/);
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

test('多页评论要合并成一维再数，不能只数到第一页', () => {
  // commentsOf 用 `--paginate --jq '.[]'`，gh 对每页分别跑 jq、把数组摊成一行一个
  // 对象，跨页累加；ghLines 逐行解析后本来就是一条扁平列表。这里喂的就是那个形状：
  // 两页的评论合在一起，数出来的应当是全量。
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
    deps: noIo({ commentsOf: () => [...page1, ...page2] }),
  });
  assert.equal(input.gates.recentHandoffs, 3);
  assert.equal(input.gates.calls.length, 2);
});

test('commentsOf 真的问 gh 要全部页，且不用只有新版 gh 才有的 --slurp', () => {
  // 上面几条都把 commentsOf 换成假函数，真实实现一次都没跑过 —— `--slurp` 就是这么
  // 漏进来的：它只在较新的 gh 里存在，本机 `gh version 2.46.0` 直接报 unknown flag，
  // 而 README 教的本地验证正是走这条路。所以这条用一个假 gh 把真实实现跑起来，
  // 既断言参数里没有 --slurp，也断言多行 NDJSON 能被跨页拼成一条列表。
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qwen-fake-gh-'));
  const arglog = path.join(dir, 'args.txt');
  const fake = path.join(dir, 'gh');
  fs.writeFileSync(
    fake,
    [
      '#!/usr/bin/env bash',
      // 参数原样记下来，好让测试断言实际传了什么
      'printf "%s\\n" "$@" > "$FAKE_GH_ARGS"',
      // gh 对每页跑一次 jq；这里模拟两页、各摊成一行一个对象
      "printf '%s\\n' '{\"id\":1,\"body\":\"第一页\"}' '{\"id\":2,\"body\":\"第二页\"}'",
      '',
    ].join('\n'),
    { mode: 0o755 },
  );

  const oldPath = process.env.PATH;
  const oldArgs = process.env.FAKE_GH_ARGS;
  process.env.PATH = `${dir}${path.delimiter}${oldPath}`;
  process.env.FAKE_GH_ARGS = arglog;
  try {
    const comments = commentsOf(7);
    assert.deepEqual(comments.map((c) => c.id), [1, 2], '两页都要取到');
    assert.equal(comments[1].body, '第二页');

    const args = fs.readFileSync(arglog, 'utf8').split('\n').filter(Boolean);
    assert.ok(args.includes('--paginate'), '要分页');
    assert.ok(args.includes('.[]'), "要摊成 NDJSON，否则多页拼起来没法解析");
    assert.ok(
      !args.includes('--slurp'),
      '--slurp 在 gh 2.46 上不存在，会让 README 教的本地验证直接报 unknown flag',
    );
  } finally {
    process.env.PATH = oldPath;
    if (oldArgs === undefined) delete process.env.FAKE_GH_ARGS;
    else process.env.FAKE_GH_ARGS = oldArgs;
    fs.rmSync(dir, { recursive: true, force: true });
  }
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

test('这一轮自己判失败时也要写编号，否则 report-failure 不出面', () => {
  // route() 判「配置有误」时手里没有编号，而 report-failure 的 if 是
  // `needs.route.outputs.number != ''`：编号空着它就不发说明，失败只在
  // Actions 里留一行红叉。role 仍然留空 —— 失败的一轮不该顺手把活派给谁。
  const text = outputLines({ kind: 'fail', why: '不认识的接手人：bogus' }, 44).join('');
  assert.match(text, /^role<<__END__\n\n__END__$/m, 'role 必须留空');
  assert.match(text, /^number<<__END__\n44\n__END__$/m, '缺编号时下游没人能说明');
});

// ────────────────────────── 轮次上限 ──────────────────────────

test('机器人发言到上限：buildInput 数出评论数，route 返回 turns-limit', () => {
  const comments = Array.from({ length: 60 }, (_, i) => ({
    user: { type: 'Bot' },
    created_at: ago(i + 1),
    body: '<!-- qwen:role=clara --> 又说了',
  }));
  const event = issueEvent({
    sender: { type: 'Bot' },
    comment: { body: '<!-- qwen:handoff=clara reason=继续 --> 再说一句' },
  });
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => comments }),
  });
  const result = route(input);
  assert.equal(result.kind, 'turns-limit');
  assert.equal(result.recent, 60);
  assert.equal(result.max, 60);
  assert.equal(result.number, 7);
});

test('turns-limit 也不派活，但输出编号（与 fail 同理，report-failure 要靠它找到话题）', () => {
  const lines = outputLines({ kind: 'turns-limit', number: 7, recent: 60, max: 60 });
  assert.equal(lines.length, 2);
  assert.match(lines[0], /^role<<__END__\n\n__END__\n$/);
  assert.match(lines[1], /^number<<__END__\n7\n__END__\n$/);
});

test('差一次到上限时仍然派活，turns-limit 不误触', () => {
  const comments = Array.from({ length: 59 }, (_, i) => ({
    user: { type: 'Bot' },
    created_at: ago(i + 1),
    body: '说了一句',
  }));
  const event = issueEvent({
    sender: { type: 'Bot' },
    comment: { body: '<!-- qwen:handoff=clara reason=继续 --> 再说一句' },
  });
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => comments }),
  });
  const result = route(input);
  assert.equal(result.kind, 'assign');
});

test('真人发言不受轮次上限拦，即使机器人已说满', () => {
  const comments = Array.from({ length: 999 }, (_, i) => ({
    user: { type: 'Bot' },
    created_at: ago(i < 500 ? i + 1 : i * 100),
    body: '机器人说的',
  }));
  // 只取最近 24 小时的
  const recentComments = comments.slice(0, 60);
  const event = issueEvent({
    comment: { body: '@qwencoder 再看看' },
  });
  const input = buildInput({
    event,
    eventName: 'issue_comment',
    env: ENV,
    deps: noIo({ commentsOf: () => recentComments }),
  });
  // 真人触发时不数评论
  const result = route(input);
  assert.equal(result.kind, 'assign');
  assert.equal(result.role, 'clara');
});

test('编号不是正整数时不写出去，免得 report-failure 去评论一个不存在的话题', () => {
  for (const bad of ['', 'abc', undefined, null, '0', '-1']) {
    const lines = outputLines({ kind: 'fail', why: 'x' }, bad);
    assert.equal(lines.length, 1, `${JSON.stringify(bad)} 不该产生 number`);
  }
});

// ────────────────────────── 轮次上限去重 ──────────────────────────

test('hasExistingTurnsLimitNotice：空评论列表返回 false，第一次触发应当发帖', () => {
  assert.equal(hasExistingTurnsLimitNotice([]), false);
  assert.equal(hasExistingTurnsLimitNotice(undefined), false);
});

test('hasExistingTurnsLimitNotice：没有匹配的评论返回 false', () => {
  const comments = [
    { user: { type: 'Bot' }, body: '机器人说的其他话' },
    { user: { type: 'User' }, body: '机器人发言已达 24 小时上限 <!-- qwen:role=dispatch -->' },
    { user: { type: 'Bot' }, body: '机器人发言已达 24 小时上限' }, // 缺 role 标记
    { user: { type: 'Bot' }, body: '<!-- qwen:role=dispatch -->' }, // 缺关键文字
  ];
  assert.equal(hasExistingTurnsLimitNotice(comments), false);
});

test('hasExistingTurnsLimitNotice：找到匹配的评论返回 true，第二次触发不发帖', () => {
  const comments = [
    { user: { type: 'Bot' }, body: '其他评论' },
    {
      user: { type: 'Bot' },
      body: '机器人发言已达 24 小时上限：最近 24 小时在这个话题上机器人已发言 60 次，达到上限 60 次，不再自动叫醒。\n\n<!-- qwen:role=dispatch -->',
    },
    { user: { type: 'Bot' }, body: '又说了什么' },
  ];
  assert.equal(hasExistingTurnsLimitNotice(comments), true);
});

test('hasExistingTurnsLimitNotice：只认 Bot 用户的评论，人发的不算', () => {
  const comments = [
    {
      user: { type: 'User' },
      body: '机器人发言已达 24 小时上限：最近 24 小时在这个话题上机器人已发言 60 次，达到上限 60 次，不再自动叫醒。\n\n<!-- qwen:role=dispatch -->',
    },
  ];
  assert.equal(hasExistingTurnsLimitNotice(comments), false, '人发的同类说明不该被当成去重依据');
});

test('turns-limit 的 outputLines 输出编号，确保 report-failure 能拿到', () => {
  const lines = outputLines({ kind: 'turns-limit', number: 42, recent: 60, max: 60 });
  const numberLine = lines.find((l) => l.startsWith('number<<__END__'));
  assert.ok(numberLine, '应该有 number 输出行');
  assert.match(numberLine, /42/);
});

// ────────────────────────── 退出码 ──────────────────────────

/**
 * 跑一遍真脚本，看它退了几。环境变量故意留空事件原文，让它走到「取数失败」。
 *
 * 这里只认「2」：1 在别的脚本里是「判定为否，结论已经说明了」，而 dispatch 失败时
 * 什么都没说明 —— 用 1 会让人把它读成一次正常的「不归任何人」。
 */
test('取不到事件原文时退出码是 2，不是 1', () => {
  const res = spawnSync(process.execPath, [SCRIPT], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_EVENT_PATH: '', GITHUB_REPOSITORY: 'owner/repo' },
  });
  assert.equal(res.status, 2, `退出码应为 2，实际 ${res.status}；stderr: ${res.stderr}`);
  assert.match(res.stderr, /dispatch 自己出错了/);
});

test('事件原文不是合法 JSON 时退出码是 2', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dispatch-exit-'));
  const file = path.join(dir, 'event.json');
  fs.writeFileSync(file, '{ 这不是 JSON');
  try {
    const res = spawnSync(process.execPath, [SCRIPT], {
      encoding: 'utf8',
      env: { ...process.env, GITHUB_EVENT_PATH: file, GITHUB_REPOSITORY: 'owner/repo' },
    });
    assert.equal(res.status, 2, `退出码应为 2，实际 ${res.status}；stderr: ${res.stderr}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
