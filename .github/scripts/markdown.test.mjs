/**
 * 正文处理的两件事：哪些是引用、哪些是写给人看的话。
 *
 * `tickCheckboxes` 在合并时把 Issue 的清单勾上（QWEN.md 的合并规范要求这一条）。
 * 判错的代价有两种，都不是报错：漏勾一项，清单看起来没做完；多勾一项，就把人家
 * 贴的示例改掉了。后者更糟 —— 引用被改动这件事没有痕迹。
 *
 *   /usr/bin/node --test .github/scripts/markdown.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { tickCheckboxes } from './markdown.mjs';

const lines = (...rows) => rows.join('\n');

test('没勾的勾上，并报出勾了几项', () => {
  const { body, ticked } = tickCheckboxes(lines('- [ ] 第一件', '- [ ] 第二件'));
  assert.equal(body, lines('- [x] 第一件', '- [x] 第二件'));
  assert.equal(ticked, 2);
});

test('已经勾过的不算这一次勾的', () => {
  const { body, ticked } = tickCheckboxes(lines('- [x] 早做完了', '- [ ] 还没做'));
  assert.equal(body, lines('- [x] 早做完了', '- [x] 还没做'));
  assert.equal(ticked, 1, '只勾了一项，说明里就该写一项');
});

test('围栏里贴的示例不动', () => {
  // 真实形状：Issue 里为了说明「任务列表长这样」贴一段围栏
  const src = lines(
    '正文：',
    '',
    '- [ ] 真的要做',
    '',
    '格式长这样：',
    '',
    '```markdown',
    '- [ ] 这是示例，别动',
    '```',
  );
  const { body, ticked } = tickCheckboxes(src);
  assert.equal(ticked, 1);
  assert.match(body, /- \[x\] 真的要做/);
  assert.match(body, /- \[ \] 这是示例，别动/, '围栏里那一行被改动了');
});

test('围栏关掉之后的照常勾', () => {
  const src = lines('~~~', '- [ ] 示例', '~~~', '- [ ] 真的');
  const { body, ticked } = tickCheckboxes(src);
  assert.equal(ticked, 1);
  assert.match(body, /- \[ \] 示例/);
  assert.match(body, /- \[x\] 真的/);
});

test('嵌套项与有序列表也算任务列表', () => {
  const { body, ticked } = tickCheckboxes(lines('  - [ ] 嵌套', '1. [ ] 有序', '* [ ] 星号', '+ [ ] 加号'));
  assert.equal(ticked, 4);
  assert.equal(body, lines('  - [x] 嵌套', '1. [x] 有序', '* [x] 星号', '+ [x] 加号'));
});

test('不是任务列表的写法一个字都不动', () => {
  // GitHub 只认 `[ ]` 后面跟空白或行尾；这三种都不是任务列表
  const src = lines('- [] 空的', '- [ ]夹着字', '[ ] 不在列表里', '- [  ] 两个空格');
  const { body, ticked } = tickCheckboxes(src);
  assert.equal(ticked, 0);
  assert.equal(body, src);
});

test('没有 checkbox 时不动正文，也不去回写', () => {
  const src = lines('只有一段说明。', '', '没有清单。');
  assert.deepEqual(tickCheckboxes(src), { body: src, ticked: 0 });
});

test('空正文不崩', () => {
  assert.deepEqual(tickCheckboxes(''), { body: '', ticked: 0 });
  assert.deepEqual(tickCheckboxes(undefined), { body: '', ticked: 0 });
});

test('围栏没闭合时剩余部分一律不动', () => {
  // 与 stripCode 同一条取舍：宁可漏勾，也不要在别人引用的原文里乱改
  const src = lines('- [ ] 真的', '```', '- [ ] 之后全都算示例');
  const { body, ticked } = tickCheckboxes(src);
  assert.equal(ticked, 1);
  assert.equal(body, lines('- [x] 真的', '```', '- [ ] 之后全都算示例'));
});
