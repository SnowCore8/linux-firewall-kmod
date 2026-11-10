/**
 * bootstrap.mjs 的测试：复制计划、角色权限、参数解析、gitignore 幂等、dry-run 不落手。
 *
 * 引导脚本的错误方向是「悄悄少做一步」：漏复制一档权限、把私钥目录混在一起、
 * 重复跑长出两份 gitignore 块。这些都不会报错，所以每条都要钉住。
 *
 *   /usr/bin/node --test .github/scripts/bootstrap.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  COPY_ENTRIES,
  GITIGNORE_BLOCK,
  ROLE_ORDER,
  ROLE_SPECS,
  SOURCE_ROOT,
  copyInto,
  copyPlan,
  findConflicts,
  gitignoreHasBlock,
  gitignoreWithBlock,
  mergeRoles,
  parseAppSlug,
  parseOnly,
  parseResume,
  resumeHint,
  roleDownloadDir,
  runBootstrap,
  setupArgs,
  shouldCopy,
} from './bootstrap.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bootstrap-test-'));

test('复制清单覆盖四份工作流、岗位说明与文档，且不含本仓库版本史', () => {
  const rels = copyPlan(SOURCE_ROOT).map((e) => e.rel);
  for (const rel of ['.github', '.qwen', 'docs', 'QWEN.md', 'CONTRIBUTING.md', 'package.json']) {
    assert.ok(rels.includes(rel), `复制清单缺 ${rel}`);
  }
  assert.equal(rels.includes('CHANGELOG.md'), false);
  assert.equal(shouldCopy('.github/CODEOWNERS'), false);
});

test('本机与敏感文件不复制', () => {
  for (const rel of [
    '.qwen/settings.json',
    '.qwen/skills/auto-skill-abc/SKILL.md',
    'node_modules/pkg/index.js',
    'qwen-artifacts/stdout.log',
    '.playwright-mcp/page.png',
    'keys/app.pem',
    'gha-creds-123.json',
  ]) {
    assert.equal(shouldCopy(rel), false, `${rel} 不该被复制`);
  }
  for (const rel of ['.github/workflows/qwen-ci.yml', '.qwen/workflows/miles-fix.js', 'docs/merge-gate.md']) {
    assert.equal(shouldCopy(rel), true, `${rel} 该被复制`);
  }
});

test('四个角色的权限按职责给，不是一律 write', () => {
  assert.equal(ROLE_SPECS.clara.perms, 'contents:read,issues:write,pull_requests:read');
  assert.equal(ROLE_SPECS.nora.perms, 'contents:read,issues:write,pull_requests:read');
  assert.equal(ROLE_SPECS.frank.perms, 'contents:read,issues:read,pull_requests:write');
  assert.equal(ROLE_SPECS.miles.perms, 'contents:write,issues:write,pull_requests:write,workflows:write');
  assert.deepEqual(Object.keys(ROLE_SPECS), ROLE_ORDER);
});

test('--only 去重、按固定顺序，不认识的直接报错', () => {
  assert.deepEqual(parseOnly('miles,clara,miles'), ['clara', 'miles']);
  assert.deepEqual(parseOnly(undefined), ['clara', 'nora', 'frank', 'miles']);
  assert.throws(() => parseOnly('alice'), /不认识的 --only/);
  assert.throws(() => parseOnly(','), /空列表/);
});

test('--resume 解析与角色合并', () => {
  const resume = parseResume(['frank=app-frank-abc', 'miles=app-miles']);
  assert.equal(resume.get('frank'), 'app-frank-abc');
  assert.deepEqual(mergeRoles(['clara'], resume), ['clara', 'frank', 'miles']);
  assert.throws(() => parseResume(['frank']), /<角色>=<slug>/);
  assert.throws(() => parseResume(['alice=x']), /<角色>=<slug>/);
});

test('每个角色用独立的私钥目录', () => {
  assert.equal(roleDownloadDir('/tmp/keys', 'clara'), '/tmp/keys/clara');
  assert.notEqual(roleDownloadDir('/tmp/keys', 'clara'), roleDownloadDir('/tmp/keys', 'miles'));
});

test('新建 App 带 --perms，续跑改用 --app 且不重设权限', () => {
  const created = setupArgs('miles', { repo: 'o/r', cdp: 'http://127.0.0.1:9222', downloadDir: '/tmp/keys/miles' });
  assert.ok(created.includes('--name'));
  assert.ok(created.includes('app-miles'));
  assert.ok(created.includes('--perms'));
  assert.ok(created.includes(ROLE_SPECS.miles.perms));

  const resumed = setupArgs('miles', {
    repo: 'o/r',
    cdp: 'http://127.0.0.1:9222',
    downloadDir: '/tmp/keys/miles',
    resumeSlug: 'app-miles-abcd',
  });
  assert.ok(resumed.includes('--app'));
  assert.ok(resumed.includes('app-miles-abcd'));
  assert.equal(resumed.includes('--perms'), false);
});

test('能从 setup-app 的输出里读出 slug，并拼出续跑命令', () => {
  const output = '已创建：https://github.com/settings/apps/app-frank-abcd\n完成。';
  assert.equal(parseAppSlug(output), 'app-frank-abcd');
  assert.equal(parseAppSlug('没有链接'), '');

  const hint = resumeHint('frank', 'app-frank-abcd', {
    repo: 'o/r',
    target: '/tmp/target',
    cdp: 'http://127.0.0.1:9222',
    downloadDir: '/tmp/keys',
  });
  assert.match(hint, /--resume frank=app-frank-abcd/);
  assert.match(hint, /--skip-copy --skip-labels/);
});

test('.gitignore 标记块只追加一次', () => {
  assert.equal(gitignoreHasBlock('node_modules/\n'), false);
  const once = gitignoreWithBlock('node_modules/\n');
  assert.ok(once.includes(GITIGNORE_BLOCK));
  assert.ok(once.startsWith('node_modules/\n'));
  assert.equal(gitignoreWithBlock(once), once);

  const empty = gitignoreWithBlock('');
  assert.ok(empty.startsWith(GITIGNORE_BLOCK));
  assert.ok(empty.endsWith('\n'));
});

test('复制会跳过敏感文件，冲突只认内容不同的已存在文件', () => {
  const source = tmp();
  const target = tmp();
  fs.mkdirSync(path.join(source, '.github', 'workflows'), { recursive: true });
  fs.mkdirSync(path.join(source, '.qwen'), { recursive: true });
  fs.mkdirSync(path.join(source, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(source, '.github', 'workflows', 'qwen-ci.yml'), 'name: ci\n');
  fs.writeFileSync(path.join(source, '.github', 'CODEOWNERS'), '* @someone\n');
  fs.writeFileSync(path.join(source, '.qwen', 'settings.json'), '{}\n');
  fs.writeFileSync(path.join(source, '.qwen', 'workflows.js'), 'ok\n');
  fs.writeFileSync(path.join(source, 'docs', 'architecture.md'), '# 架构\n');
  fs.writeFileSync(path.join(source, 'QWEN.md'), '# 守则\n');
  fs.writeFileSync(path.join(source, 'keys.pem'), 'secret\n');

  assert.deepEqual(findConflicts(source, target), []);
  copyInto(source, target);

  assert.equal(fs.existsSync(path.join(target, '.github', 'workflows', 'qwen-ci.yml')), true);
  assert.equal(fs.existsSync(path.join(target, '.github', 'CODEOWNERS')), false);
  assert.equal(fs.existsSync(path.join(target, '.qwen', 'settings.json')), false);
  assert.equal(fs.existsSync(path.join(target, '.qwen', 'workflows.js')), true);
  assert.equal(fs.existsSync(path.join(target, 'keys.pem')), false);

  // 内容相同算幂等，不同才是冲突
  assert.deepEqual(findConflicts(source, target), []);
  fs.writeFileSync(path.join(target, 'docs', 'architecture.md'), '# 改过的\n');
  assert.deepEqual(findConflicts(source, target), ['docs/architecture.md']);
});

test('dry-run 不调用任何外部命令、不写磁盘', () => {
  const target = path.join(tmp(), 'not-created');
  let called = 0;
  const code = runBootstrap(
    { repo: 'owner/name', target, dryRun: true },
    {
      spawn: () => {
        called += 1;
        throw new Error('dry-run 不该调用外部命令');
      },
      log: () => {},
      error: () => {},
    },
  );
  assert.equal(code, 0);
  assert.equal(called, 0);
  assert.equal(fs.existsSync(target), false);
});

test('--repo 写错在预检就停，不启动任何角色', () => {
  let called = 0;
  const code = runBootstrap(
    { repo: 'not-a-repo', target: '/tmp/whatever' },
    { spawn: () => { called += 1; return { status: 0 }; }, log: () => {}, error: () => {} },
  );
  assert.equal(code, 2);
  assert.equal(called, 0);
});
