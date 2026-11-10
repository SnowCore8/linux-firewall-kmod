import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import MarkdownIt from 'markdown-it';
import { headingAnchors, lintMarkdown, slugify } from './docs-check.mjs';

const dir = mkdtempSync(join(tmpdir(), 'docs-check-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const DOC = join(dir, 'doc.md');
const messages = (text, file = DOC) => lintMarkdown(text, file).map((p) => p.message);

test('合规的一篇没有问题', () => {
  const text = ['# 标题', '', '一句话。', '', '## 一、小节', '', '正文。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('围栏代码块缺语言标记', () => {
  const text = ['# 标题', '', '```', 'x', '```', ''].join('\n');
  assert.deepEqual(messages(text), ['代码块缺语言标记']);
});

test('缩进代码块标不了语言，要改围栏', () => {
  const text = ['# 标题', '', '    indented', ''].join('\n');
  assert.deepEqual(messages(text), ['缩进代码块标不了语言，改用围栏代码块']);
});

test('代码块里的行尾空白与制表符是内容，不报', () => {
  const text = ['# 标题', '', '```text', 'a   ', '\tb', '```', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('代码块外的行尾空白与制表符照报', () => {
  const text = ['# 标题', '', '正文   ', '', '正文\t中间', ''].join('\n');
  assert.deepEqual(messages(text), ['行尾有多余空白', '出现制表符']);
});

test('setext 下划线也按标题算，跳级逃不掉', () => {
  const text = ['# 标题', '', '另起一段', '', 'Sub', '===', ''].join('\n');
  assert.deepEqual(messages(text), ['一级标题应恰好一个，实际 2 个']);
});

test('ATX 跳级照报', () => {
  const text = ['# 标题', '', '### 跳了一级', ''].join('\n');
  assert.deepEqual(messages(text), ['标题从 h1 跳到 h3']);
});

test('行内代码里的井号不是标题', () => {
  const text = ['# 标题', '', '用 `## 二级` 表示二级标题。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('frontmatter 不被读成标题', () => {
  const text = ['---', 'name: demo', 'description: 说明', '---', '', '# 标题', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('链接文字里的 URL 不算裸 URL', () => {
  const text = ['# 标题', '', '见 [https://example.invalid](https://example.invalid)。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('行内代码里的 URL 不算裸 URL', () => {
  const text = ['# 标题', '', '例如 `https://example.invalid/x` 这样。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('正文裸 URL 要报，行号落在那一行', () => {
  const text = ['# 标题', '', '第一行。', '见 https://example.invalid 这段。', ''].join('\n');
  assert.deepEqual(lintMarkdown(text, DOC), [
    { line: 4, message: '正文里有裸 URL，包成链接或行内代码' },
  ]);
});

test('相对链接指得到就不报', () => {
  const target = join(dir, '存在.md');
  writeFileSync(target, '# 存在\n');
  const text = ['# 标题', '', '见 [这份](./存在.md)。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('相对链接指不到要报', () => {
  const text = ['# 标题', '', '见 [那份](./不存在.md)。', ''].join('\n');
  assert.deepEqual(messages(text), ['链接指向的文件不存在：./不存在.md']);
});

test('图片路径也要检查', () => {
  const text = ['# 标题', '', '![图](./无此图.png)', ''].join('\n');
  assert.deepEqual(messages(text), ['链接指向的文件不存在：./无此图.png']);
});

test('纯锚点与站外链接不查文件', () => {
  const text = ['# 标题', '', '[本节](#标题) 与 [外站](https://example.invalid)。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('引用式定义里的相对路径也要检查', () => {
  const text = ['# 标题', '', '见 [那份][1]。', '', '[1]: ./不见了.md', ''].join('\n');
  assert.deepEqual(messages(text), ['链接指向的文件不存在：./不见了.md']);
});

test('表格列数与表头不一致要报', () => {
  const text = ['# 标题', '', '| 甲 | 乙 |', '|---|---|', '| 1 | 2 | 3 |', ''].join('\n');
  assert.deepEqual(messages(text), ['表格行 3 列，表头 2 列']);
});

test('表格里的行内代码与转义管道不算列', () => {
  const text = ['# 标题', '', '| 甲 | 乙 |', '|---|---|', '| `a|b` | x \\| y |', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('连续空行与末尾缺换行', () => {
  assert.deepEqual(messages('# 标题\n\n\n正文\n'), ['连续空行超过一行']);
  assert.deepEqual(messages('# 标题\n\n正文'), ['文件末尾缺换行']);
});

test('一级标题缺失或多于一个', () => {
  assert.deepEqual(messages('## 只有二级\n'), ['一级标题应恰好一个，实际 0 个']);
  assert.deepEqual(messages('# 甲\n\n# 乙\n'), ['一级标题应恰好一个，实际 2 个']);
});

test('PR 模板不要求一级标题', () => {
  const text = ['<!-- 模板从注释开始 -->', '', '## 改了什么', ''].join('\n');
  assert.deepEqual(messages(text, join(dir, 'PULL_REQUEST_TEMPLATE.md')), []);
});

// 下面几条对着 GitHub 的真实渲染校准过：拿 v1.2.0 的 7 份文件比对，
// 83 个锚点与线上 id 逐个相同。
test('slug：emoji 去掉，留下的空格变连字符', () => {
  assert.equal(slugify('✅ 验证改动'), '-验证改动');
  assert.equal(slugify('🔒 安全'), '-安全');
});

test('slug：全角括号、点、斜杠、反引号、星号都不留', () => {
  assert.equal(slugify('2. 配置 Coding Plan（订阅制）'), '2-配置-coding-plan订阅制');
  assert.equal(slugify('改了某一个人的工作流脚本（`.qwen/workflows/*.js`）'), '改了某一个人的工作流脚本qwenworkflowsjs');
});

test('slug：下划线与连字符保留，英文转小写', () => {
  assert.equal(slugify('README_lint 与 merge-gate'), 'readme_lint-与-merge-gate');
});

test('slug：标题里的行内代码与加粗取文字', () => {
  const text = ['# 标题', '', '## 用 `gh pr view` 看', '', '## **加粗**的标题', ''].join('\n');
  assert.deepEqual([...headingAnchors(new MarkdownIt().parse(text, {}))], [
    '标题',
    '用-gh-pr-view-看',
    '加粗的标题',
  ]);
});

test('同名标题按 GitHub 的规矩追加 -1', () => {
  const text = ['# 标题', '', '## 甲', '', '## 甲', '', '## 甲', ''].join('\n');
  assert.deepEqual([...headingAnchors(new MarkdownIt().parse(text, {}))], ['标题', '甲', '甲-1', '甲-2']);
});

test('同文件锚点指得到就不报', () => {
  const text = ['# 标题', '', '## 一、形状', '', '见 [形状](#一形状)。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('同文件锚点不存在要报', () => {
  const text = ['# 标题', '', '## 一、形状', '', '见 [分层](#二分层)。', ''].join('\n');
  assert.deepEqual(messages(text), ['锚点不存在：#二分层']);
});

test('跨文件锚点指得到就不报', () => {
  const target = join(dir, '被引用.md');
  writeFileSync(target, '# 目标\n\n## 二、分层\n');
  const text = ['# 标题', '', '见 [分层](./被引用.md#二分层)。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('跨文件锚点不存在要报', () => {
  const target = join(dir, '被引用2.md');
  writeFileSync(target, '# 目标\n\n## 二、分层\n');
  const text = ['# 标题', '', '见 [形状](./被引用2.md#一形状)。', ''].join('\n');
  assert.deepEqual(messages(text), ['锚点不存在：./被引用2.md#一形状']);
});

test('百分号编码的中文锚点按解码后比对', () => {
  const target = join(dir, '编码.md');
  writeFileSync(target, '# 目标\n\n## 三、凭据\n');
  const text = ['# 标题', '', '见 [凭据](./编码.md#%E4%B8%89%E5%87%AD%E6%8D%AE)。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('指到非 md 文件的片段不查锚点', () => {
  const target = join(dir, 'LICENSE');
  writeFileSync(target, 'MIT\n');
  const text = ['# 标题', '', '见 [许可](./LICENSE#任意片段)。', ''].join('\n');
  assert.deepEqual(messages(text), []);
});

test('文件不存在时只报文件，不连带报锚点', () => {
  const text = ['# 标题', '', '见 [那份](./不存在2.md#某节)。', ''].join('\n');
  assert.deepEqual(messages(text), ['链接指向的文件不存在：./不存在2.md#某节']);
});
