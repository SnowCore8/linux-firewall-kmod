/**
 * 合并闸门的测试。
 *
 * 这个脚本唯一的工作就是「说不行」。判错的代价不对称：放过一次 = 把没批准的、检查红的
 * 代码合进主干；多拦一次 = 有人多点一下。所以每条判据都要有一条测试盯着，尤其是
 * 「什么情况下必须拦」。
 *
 * 最贵的两种失误各有一条判据盯着：
 *   检查红了照样合并 —— 主干上从此多一段没人验过的代码。
 *   批准挂在旧提交上却合了新提交 —— 批准的不是真正合进去的那一版。
 *
 *   /usr/bin/node --test .github/scripts/merge-gate.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  evaluateMerge,
  failedCheckNames,
  isPending,
  checkState,
  STOP_LABELS,
  withoutOwnRun,
  tickIssueChecklist,
} from './merge-gate.mjs';

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

// ───────────────────────── 检查与批准 ─────────────────────────

test('检查判失败就拦下，并报出是哪个检查', () => {
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

test('主干上同样红的检查不拦，并记进 tolerated', () => {
  const result = evaluateMerge({
    pr: pr({ statusCheckRollup: checks([['单元测试', 'SUCCESS'], ['浏览器端到端测试', 'FAILURE']]) }),
    preexisting: ['浏览器端到端测试'],
  });

  assert.equal(result.ok, true, '主干同样失败的检查不该把每个 PR 都锁死');
  assert.deepEqual(result.tolerated, ['浏览器端到端测试']);
  assert.deepEqual(result.blocking, []);
  assert.match(rule(result, 'checks').detail, /主干上同样失败/);
});

test('批准挂在旧提交上就拦下', () => {
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

test('批准在 head 上、且比驳回新，才放行', () => {
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

test('主干红着、另有一项还在跑 → 仍然拦下，不能借「主干也红」放过去', () => {
  // 主干红的时候 PR 会继承那项红的，另一项（比如刚被评审事件叫起来的 route）
  // 还在跑。按「先看失败是不是主干已有」的顺序判，这一版会被放行 ——
  // 合并说明里只写「主干也红」，而「检查全部跑完」这条判据根本没生效。
  const result = evaluateMerge({
    pr: pr({
      statusCheckRollup: [...checks([['单元测试', 'FAILURE']]), ...running()],
    }),
    preexisting: ['单元测试'],
  });

  assert.equal(result.ok, false, '有检查还在跑就不该合');
  assert.equal(rule(result, 'checks').ok, false);
  assert.match(rule(result, 'checks').detail, /检查在跑/);
  // tolerated 仍然照记，只是这一次不能拿来放行
  assert.deepEqual(result.tolerated, ['单元测试']);
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

// ───────────────────────── 自己这次运行 ─────────────────────────
// 闸门跑在陈实那次运行里，那次运行本身就是 PR 上的检查项。不剔掉的话，闸门先白等满
// MILES_CI_WAIT_MINUTES，再以「还有检查在跑」把自己拦下来 —— 每张 PR 都合不了。
const checkRun = (name, runId, over = {}) => ({
  name,
  status: 'IN_PROGRESS',
  conclusion: null,
  detailsUrl: `https://github.com/o/r/actions/runs/${runId}/job/${runId}01`,
  ...over,
});

test('剔掉自己这次运行产生的检查项', () => {
  const kept = withoutOwnRun(
    [
      checkRun('miles / work', '42407645741'),
      checkRun('route', '42407645741', { status: 'COMPLETED', conclusion: 'SUCCESS' }),
      checkRun('浏览器端到端测试', '42399000000', { status: 'COMPLETED', conclusion: 'SUCCESS' }),
    ],
    '42407645741',
  );
  assert.deepEqual(kept.map((c) => c.name), ['浏览器端到端测试']);
});

test('自己那次运行是唯一的检查项时，等于没有检查，不该拦', () => {
  const pr42 = pr({
    statusCheckRollup: withoutOwnRun([checkRun('miles / work', '42407645741')], '42407645741'),
  });
  assert.equal(rule(evaluateMerge({ pr: pr42 }), 'checks').ok, true);
  assert.equal(isPending(pr42), false);
});

test('没有 GITHUB_RUN_ID（本地跑）时一个都不剔', () => {
  const all = [checkRun('miles / work', '42407645741'), checkRun('单元测试', '42407645741')];
  assert.deepEqual(withoutOwnRun(all, ''), all);
  assert.deepEqual(withoutOwnRun(all, undefined), all);
});

test('别的运行还在跑，照样算没跑完', () => {
  const mixed = withoutOwnRun(
    [checkRun('miles / work', '42407645741'), checkRun('单元测试', '42407000000')],
    '42407645741',
  );
  assert.equal(isPending({ statusCheckRollup: mixed }), true);
});

// ───────────────────────── 合并之后勾 checklist ─────────────────────────
// QWEN.md 的合并规范要求「把 Issue 里的 checklist 勾完」。这条以前只有文档，
// 没有代码 —— 清单会一直空着。下面两条把命令接线也验上：纯函数对了，
// 但把 `issue edit` 写成别的子命令一样等于没做。

/** 造一个只认两个子命令的 gh：`issue view` 回固定正文，`issue edit` 把参数记下来。 */
function fakeGh(body) {
  const dir = mkdtempSync(join(tmpdir(), 'merge-gate-gh-'));
  const bin = join(dir, 'gh');
  const log = join(dir, 'args.txt');
  writeFileSync(join(dir, 'body.json'), JSON.stringify({ body }));
  writeFileSync(
    bin,
    [
      '#!/usr/bin/env bash',
      'printf "%s\\n" "$@" > "$FAKE_GH_LOG"',
      'if [ "$1 $2" = "issue view" ]; then cat "$FAKE_GH_BODY"; exit 0; fi',
      'exit 0',
      '',
    ].join('\n'),
  );
  chmodSync(bin, 0o755);
  return { dir, log };
}

function withFakeGh(body, fn) {
  const { dir, log } = fakeGh(body);
  const old = { PATH: process.env.PATH, LOG: process.env.FAKE_GH_LOG, BODY: process.env.FAKE_GH_BODY };
  process.env.PATH = `${dir}:${old.PATH}`;
  process.env.FAKE_GH_LOG = log;
  process.env.FAKE_GH_BODY = join(dir, 'body.json');
  try {
    return fn(log);
  } finally {
    process.env.PATH = old.PATH;
    process.env.FAKE_GH_LOG = old.LOG;
    process.env.FAKE_GH_BODY = old.BODY;
    rmSync(dir, { recursive: true, force: true });
  }
}

test('合并后真的去勾 Issue 的 checklist', () => {
  const body = ['- [ ] 改完自检', '- [x] 早就完了', '', '```', '- [ ] 示例', '```'].join('\n');
  withFakeGh(body, (log) => {
    assert.equal(tickIssueChecklist(7, 'owner/name'), 1);

    const args = readFileSync(log, 'utf8');
    assert.match(args, /^issue\nedit\n7\n--repo\nowner\/name\n--body$/m, `调用的命令不对：\n${args}`);
    assert.match(args, /- \[x\] 改完自检/, '回写时没把那一项勾上');
    assert.match(args, /- \[ \] 示例/, '围栏里的示例被改动了');
  });
});

test('checklist 一项都没勾到时不去回写', () => {
  withFakeGh('- [x] 全都做完了', (log) => {
    assert.equal(tickIssueChecklist(7, 'owner/name'), 0);
    assert.doesNotMatch(readFileSync(log, 'utf8'), /edit/, '没有要改的东西，不该发写请求');
  });
});

test('取不到 Issue 时不崩，返回 0 —— 合并已经发生，这时候失败只会误导', () => {
  const dir = mkdtempSync(join(tmpdir(), 'merge-gate-gh-'));
  const bin = join(dir, 'gh');
  writeFileSync(bin, '#!/usr/bin/env bash\necho "GraphQL: Could not resolve" >&2\nexit 1\n');
  chmodSync(bin, 0o755);

  const oldPath = process.env.PATH;
  process.env.PATH = `${dir}:${oldPath}`;
  let ticked;
  try {
    ticked = tickIssueChecklist(7, 'owner/name');
  } finally {
    process.env.PATH = oldPath;
    rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(ticked, 0);
});

// ───────────────────────── 退出码 ─────────────────────────
// 0 合并了、1 条件没满足、2 闸门自己没跑完。1 和 2 混用是最坏的错法：取数失败
// （令牌权限不够、接口报错）会被读成「闸门判过了，只是拦下了」，没人会去查。
test('取数失败时退出码是 2，不是 1', () => {
  const dir = mkdtempSync(join(tmpdir(), 'merge-gate-'));
  const bin = join(dir, 'gh');
  writeFileSync(bin, '#!/usr/bin/env bash\necho "GraphQL: Resource not accessible by integration" >&2\nexit 1\n');
  chmodSync(bin, 0o755);

  const res = spawnSync(
    process.execPath,
    [fileURLToPath(new URL('./merge-gate.mjs', import.meta.url)), '39', '--repo', 'owner/name'],
    { encoding: 'utf8', env: { ...process.env, PATH: `${dir}:${process.env.PATH}` } },
  );
  rmSync(dir, { recursive: true, force: true });

  assert.equal(res.status, 2, `退出码应为 2，实际 ${res.status}；stderr: ${res.stderr}`);
  assert.match(res.stderr, /判据没跑完/);
});
