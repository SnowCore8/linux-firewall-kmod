#!/usr/bin/env node

/**
 * 文档规范自查，规则写在 docs/style.md。
 *
 * 用 markdown-it 把文件真解析一遍，判断走 token —— 缩进代码块、setext 标题、
 * 行内代码里的 `#`、链接文字里的 URL，正则容易看错，AST 不会。
 *
 * 依赖 markdown-it（唯一的开发依赖，跑之前 `npm ci`）。运行时代码不用它。
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import MarkdownIt from 'markdown-it';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const SKIP_DIRS = new Set(['node_modules', 'qwen-artifacts', '.git', 'worktrees']);

const md = new MarkdownIt({ html: true, linkify: false });

/** 收集所有 `.md`，跳过不参与评审的目录。 */
function collect(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) collect(full, out);
    else if (name.endsWith('.md')) out.push(full);
  }
  return out;
}

/**
 * frontmatter 不是正文。换成等量空行，行号因此不用偏移 —— 也避免 `---` 被
 * 当成 setext 标题的下划线，把 `name: x` 读成一级标题。
 */
function blankFrontMatter(text) {
  const m = /^---\r?\n[\s\S]*?\r?\n---[ \t]*\r?\n/.exec(text);
  if (!m) return text;
  return m[0].replace(/[^\n]/g, '') + text.slice(m[0].length);
}

const tokLine = (t) => (t.map ? t.map[0] + 1 : 1);

/** 代码块占据的行（0 基）。这些行里的空白与制表符是内容，不算排版问题。 */
function codeLines(tokens) {
  const set = new Set();
  for (const t of tokens) {
    if ((t.type !== 'fence' && t.type !== 'code_block') || !t.map) continue;
    for (let i = t.map[0]; i < t.map[1]; i++) set.add(i);
  }
  return set;
}

/** 标题的可见文字：行内代码与图片的替代文字都算，HTML 标签不算。 */
function headingText(inline) {
  let out = '';
  for (const c of inline?.children ?? []) {
    if (c.type === 'text' || c.type === 'code_inline' || c.type === 'image') out += c.content;
    else if (c.type === 'html_inline') out += c.content.replace(/<[^>]*>/g, '');
    else if (c.type === 'softbreak' || c.type === 'hardbreak') out += ' ';
  }
  return out;
}

/**
 * GitHub 的锚点规则：转小写，只留字母、数字、组合符、`-`、`_` 和空格，其余一律删
 * （emoji、全角括号、点、斜杠、反引号都在删的行列），空格变 `-`。
 *
 * 注意不能先 trim：`## ✅ 验证改动` 删掉 emoji 后仍留着那个空格，锚点是
 * `-验证改动`，不是 `验证改动`。README 的目录就是按这个写的。
 */
export function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\p{M}\-_ ]/gu, '')
    .replace(/ /g, '-');
}

/** 一份文档里所有可用的锚点，重名的按 GitHub 的规矩追加 `-1`、`-2`。 */
export function headingAnchors(tokens) {
  const seen = new Map();
  const out = new Set();
  tokens.forEach((t, i) => {
    if (t.type !== 'heading_open') return;
    const base = slugify(headingText(tokens[i + 1]));
    if (!base) return;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.add(n === 0 ? base : `${base}-${n}`);
  });
  return out;
}

/** 按需解析目标文件的锚点并缓存 —— 18 份文件互相引用，不缓存会反复解析。 */
const anchorCache = new Map();

function anchorsOf(file) {
  const abs = resolve(file);
  if (anchorCache.has(abs)) return anchorCache.get(abs);
  let anchors = null;
  try {
    anchors = headingAnchors(md.parse(blankFrontMatter(readFileSync(abs, 'utf8')), {}));
  } catch {
    anchors = null;
  }
  anchorCache.set(abs, anchors);
  return anchors;
}

/**
 * 核一份文档。`filePath` 只用于解析相对链接，文件不必真的在磁盘上。
 * 返回 `[{ line, message }]`，空数组表示没问题。
 */
export function lintMarkdown(text, filePath = join(ROOT, 'inline.md')) {
  const out = [];
  const report = (line, message) => out.push({ line, message });

  const base = filePath.slice(filePath.lastIndexOf('/') + 1).replace(/\.md$/, '');
  const lines = text.split('\n');
  const env = {};
  const tokens = md.parse(blankFrontMatter(text), env);

  const skipBlank = codeLines(tokens);

  if (!text.endsWith('\n')) report(lines.length, '文件末尾缺换行');
  const triple = text.indexOf('\n\n\n');
  if (triple !== -1) report(text.slice(0, triple).split('\n').length, '连续空行超过一行');
  lines.forEach((line, i) => {
    if (skipBlank.has(i)) return;
    if (/[ \t]$/.test(line)) report(i + 1, '行尾有多余空白');
    if (line.includes('\t')) report(i + 1, '出现制表符');
  });

  const headings = tokens.filter((t) => t.type === 'heading_open');
  const h1 = headings.filter((t) => t.tag === 'h1');
  if (!base.startsWith('PULL_REQUEST_TEMPLATE') && h1.length !== 1) {
    report(h1[0] ? tokLine(h1[0]) : 1, `一级标题应恰好一个，实际 ${h1.length} 个`);
  }
  let prev = 0;
  for (const t of headings) {
    const level = Number(t.tag.slice(1));
    if (prev && level > prev + 1) report(tokLine(t), `标题从 h${prev} 跳到 h${level}`);
    prev = level;
  }

  for (const t of tokens) {
    if (t.type === 'fence' && !t.info.trim()) report(tokLine(t), '代码块缺语言标记');
    if (t.type === 'code_block') report(tokLine(t), '缩进代码块标不了语言，改用围栏代码块');
  }

  // 自身的锚点先入缓存：同一份文件里的 `#小节` 不必再读一遍盘。
  anchorCache.set(resolve(filePath), headingAnchors(tokens));

  // 同一个目标只报一次：引用式定义与指向它的链接会各出现一遍，报两遍是噪音。
  const reported = new Set();
  const decode = (s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  };
  const checkTarget = (line, target) => {
    if (!target) return;
    if (/^(https?:|mailto:|\/\/)/.test(target)) return;
    const hash = target.indexOf('#');
    const path = hash === -1 ? target : target.slice(0, hash);
    const frag = hash === -1 ? '' : target.slice(hash + 1);
    const shown = decode(target);
    if (reported.has(shown)) return;

    const absTarget = path ? resolve(dirname(filePath), decode(path)) : resolve(filePath);
    if (path && !existsSync(absTarget)) {
      reported.add(shown);
      report(line, `链接指向的文件不存在：${shown}`);
      return;
    }
    if (!frag || !absTarget.endsWith('.md')) return;
    const anchors = anchorsOf(absTarget);
    if (!anchors || anchors.has(decode(frag))) return;
    reported.add(shown);
    report(line, `锚点不存在：${shown}`);
  };

  for (const t of tokens) {
    if (t.type !== 'inline') continue;
    let line = tokLine(t);
    let inLink = 0;
    for (const c of t.children ?? []) {
      if (c.type === 'softbreak' || c.type === 'hardbreak') {
        line += 1;
        continue;
      }
      if (c.type === 'link_open') {
        inLink += 1;
        checkTarget(line, c.attrGet('href'));
      } else if (c.type === 'link_close') {
        inLink -= 1;
      } else if (c.type === 'image') {
        checkTarget(line, c.attrGet('src'));
      } else if (c.type === 'text' && inLink === 0 && /https?:\/\//.test(c.content)) {
        report(line, '正文里有裸 URL，包成链接或行内代码');
      }
      if (typeof c.content === 'string') line += (c.content.match(/\n/g) ?? []).length;
    }
  }
  for (const ref of Object.values(env.references ?? {})) {
    checkTarget(ref.map ? ref.map[0] + 1 : 1, ref.href);
  }

  // 表格列数只能回原文数：解析器会先把不齐的行补齐再交出来，
  // 补齐恰好把要报的错盖掉了。
  const count = (s) =>
    s
      .replace(/`[^`]*`/g, '')
      .replace(/\\\|/g, '')
      .trim()
      .replace(/^\||\|$/g, '')
      .split('|').length;
  for (const t of tokens) {
    if (t.type !== 'table_open' || !t.map) continue;
    const [start, end] = t.map;
    const expect = count(lines[start] ?? '');
    for (let i = start + 1; i < end; i++) {
      const got = count(lines[i] ?? '');
      if (got !== expect) report(i + 1, `表格行 ${got} 列，表头 ${expect} 列`);
    }
  }

  return out;
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  const files = collect(ROOT);
  const problems = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    for (const { line, message } of lintMarkdown(text, file)) {
      problems.push(`${relative(ROOT, file)}:${line} ${message}`);
    }
  }

  if (problems.length === 0) {
    console.log(`文档自查通过：${files.length} 份文件，0 处问题`);
    process.exit(0);
  }
  console.error(`文档自查发现 ${problems.length} 处问题：\n`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
