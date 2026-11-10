/**
 * 四份角色工作流提示词之间的契约。
 *
 * 这一层出错的形状和 agent-contract 一样安静：某一段话少了、某个标记改了名字，
 * 工作流照样跑绿，只是那个行为再也不发生。所以这里把「四份必须一致」与
 * 「每个标记归属于谁」钉成测试。
 *
 *   node --test .github/scripts/prompt-contract.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const SCRIPTS = {
  clara: '.qwen/workflows/clara-triage.js',
  nora: '.qwen/workflows/nora-decide.js',
  miles: '.qwen/workflows/miles-fix.js',
  frank: '.qwen/workflows/frank-review.js',
};

const src = (role) => readFileSync(path.join(ROOT, SCRIPTS[role]), 'utf8');

test('四份都带同一套共用块与自己的签名', () => {
  for (const role of Object.keys(SCRIPTS)) {
    const s = src(role);
    for (const block of ['## 说话、点名、交接', '## 没什么要说的时候', '## 红线（不可越）']) {
      assert.ok(s.includes(block), `${role} 少了共用块「${block}」`);
    }
    assert.ok(s.includes('qwen:handoff='), `${role} 的提示词里没有交接标记`);
    assert.ok(s.includes('qwen:to='), `${role} 的提示词里没有点名标记`);
    assert.ok(s.includes(`<!-- qwen:role=${role} -->`), `${role} 没写自己的评论签名`);
    assert.ok(s.includes('连续失败两次'), `${role} 的红线里没有统一的失败停手口径`);
    assert.ok(s.includes('读不到 checks'), `${role} 没写清 CI 由闸门核、自己读不到 checks`);
  }
});

test('过期写法与无人解析的标记不回来', () => {
  for (const role of Object.keys(SCRIPTS)) {
    const s = src(role);
    assert.ok(!s.includes('别出现 `>`'), `${role} 又写回了「reason 禁 >」的过期规则`);
    assert.ok(!s.includes('verdict=comment'), `${role} 又在用解析器不认识的 verdict=comment`);
    assert.ok(!s.includes('检查还红着'), `${role} 又让陈实依据读不到的 checks 决定停手`);
  }
});

test('独行标记只出现在用得着的那一份里', () => {
  assert.ok(src('miles').includes('qwen:merge-request'), 'miles 没有合并申请标记，闸门永远收不到申请');
  assert.ok(src('frank').includes('qwen:verdict=approve'), 'frank 没有等效批准标记');
  assert.ok(src('frank').includes('qwen:verdict=request-changes'), 'frank 没有等效要求修改标记');

  for (const role of ['clara', 'nora', 'frank']) {
    assert.ok(!src(role).includes('qwen:merge-request'), `${role} 不该出现合并申请标记`);
  }
  for (const role of ['clara', 'nora', 'miles']) {
    assert.ok(!src(role).includes('qwen:verdict='), `${role} 不该出现评审结论标记`);
  }
});

test('核对按 token 扫全部评论判签名', () => {
  for (const role of ['clara', 'nora']) {
    const s = src(role);
    assert.ok(
      s.includes(`contains("<!-- qwen:role=${role} -->")`),
      `${role} 的核对没有扫全部评论找签名，可能又退回只看最后一条`,
    );
    assert.ok(s.includes('--paginate'), `${role} 的核对没有翻页取全部评论`);
  }
});
