/**
 * `--perms` 解析的测试。
 *
 * 这段逻辑决定每个身份拿多大权限。错了的表现不是报错，而是**App 建出来了、权限比该有的宽**
 * —— 顾清能推代码、周正能改 Issue，而这两件事在职责表里都是明确的「不干什么」。
 * 权限放宽之后没有任何地方会报错，所以只能靠测试盯住。
 *
 *   /usr/bin/node --test .github/scripts/app-perms.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { MENU_LABEL, describePerms, normalizeLevel, parsePerms } from './app-perms.mjs';

test('给级别就按级别算', () => {
  assert.deepEqual(parsePerms('contents:read,issues:write'), [
    { name: 'contents', level: 'read' },
    { name: 'issues', level: 'write' },
  ]);
});

test('不给级别默认 write —— 老的 --perms contents,issues 行为不能变', () => {
  assert.deepEqual(parsePerms('contents,issues,pull_requests'), [
    { name: 'contents', level: 'write' },
    { name: 'issues', level: 'write' },
    { name: 'pull_requests', level: 'write' },
  ]);
});

test('四个身份的矩阵都能写出来', () => {
  // 顾清、叶澜
  const writer = parsePerms('contents:read,issues:write,pull_requests:read');
  assert.deepEqual(describePerms(writer), 'contents=read issues=write pull_requests=read');

  // 周正
  const reviewer = parsePerms('contents:read,issues:read,pull_requests:write');
  assert.deepEqual(describePerms(reviewer), 'contents=read issues=read pull_requests=write');

  // 陈实
  const engineer = parsePerms('contents:write,issues:write,pull_requests:write,workflows:write');
  assert.equal(engineer.length, 4);
});

test('级别认别名、不分大小写', () => {
  assert.equal(normalizeLevel('Read-Only'), 'read');
  assert.equal(normalizeLevel('ro'), 'read');
  assert.equal(normalizeLevel('RW'), 'write');
  assert.equal(normalizeLevel('no-access'), 'none');
  assert.equal(normalizeLevel('read_write'), null);
});

test('空白不影响结果', () => {
  assert.deepEqual(parsePerms('  contents : read , issues:write  '), [
    { name: 'contents', level: 'read' },
    { name: 'issues', level: 'write' },
  ]);
});

test('逗号尾巴不当成一项', () => {
  assert.deepEqual(parsePerms('issues:write,'), [{ name: 'issues', level: 'write' }]);
});

test('级别写错要报错，不能悄悄按 write 建出来', () => {
  assert.throws(() => parsePerms('contents:reed'), /不认识的级别/);
  assert.throws(() => parsePerms('contents:'), /不认识的级别/);
});

test('同一项写两遍要报错', () => {
  assert.throws(() => parsePerms('issues:read,issues:write'), /重复/);
});

test('缺名字要报错', () => {
  assert.throws(() => parsePerms(':read'), /缺少名字/);
});

test('空字符串要报错', () => {
  assert.throws(() => parsePerms(''), /至少给一项/);
  assert.throws(() => parsePerms('  ,  '), /至少给一项/);
});

test('菜单文案覆盖三个级别', () => {
  assert.equal(MENU_LABEL.none, 'No access');
  assert.equal(MENU_LABEL.read, 'Read-only');
  assert.equal(MENU_LABEL.write, 'Read and write');
});
