#!/usr/bin/env node
/**
 * 一次登录后的引导：复制可移植文件、建标签、按角色建 App 并写入凭据。
 *
 * 它只做编排，不替代 setup-app.mjs：登录、2FA、密钥值始终由人处理，
 * 这里不读、不打印任何密钥。
 *
 * 用法：
 *   node .github/scripts/bootstrap.mjs --repo owner/name --target /path/to/repo \
 *     [--cdp http://127.0.0.1:9222] [--download-dir /tmp/qwen-bootstrap-keys] \
 *     [--only clara,nora,miles,frank] [--resume <role>=<slug>] \
 *     [--skip-copy] [--skip-labels] [--skip-apps] [--force] [--dry-run]
 *
 * 退出码：0 全部完成；1 有角色失败（其余继续，并打印续跑命令）；2 预检或用法错误。
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const SOURCE_ROOT = path.resolve(HERE, '../..');

// 建 App 的顺序是固定的：先建只读身份，最后建权限最大的陈实。
export const ROLE_ORDER = ['clara', 'nora', 'frank', 'miles'];

export const ROLE_SPECS = {
  clara: {
    name: 'app-clara',
    varName: 'APP_ID_CLARA',
    secretName: 'APP_PRIVATE_KEY_CLARA',
    perms: 'contents:read,issues:write,pull_requests:read',
  },
  nora: {
    name: 'app-nora',
    varName: 'APP_ID_NORA',
    secretName: 'APP_PRIVATE_KEY_NORA',
    perms: 'contents:read,issues:write,pull_requests:read',
  },
  frank: {
    name: 'app-frank',
    varName: 'APP_ID_FRANK',
    secretName: 'APP_PRIVATE_KEY_FRANK',
    perms: 'contents:read,issues:read,pull_requests:write',
  },
  miles: {
    name: 'app-miles',
    varName: 'APP_ID_MILES',
    secretName: 'APP_PRIVATE_KEY_MILES',
    perms: 'contents:write,issues:write,pull_requests:write,workflows:write',
  },
};

export const COPY_ENTRIES = [
  '.github',
  '.qwen',
  'docs',
  'QWEN.md',
  'CONTRIBUTING.md',
  'SUPPORT.md',
  'CODE_OF_CONDUCT.md',
  'package.json',
  'package-lock.json',
  '.markdownlint-cli2.jsonc',
];

export const LABELS = [
  { name: 'do-not-merge', description: '叶澜掌管的停手闸：先别合并', color: 'B60205' },
  { name: 'manual-review', description: '叶澜掌管的停手闸：需要复核', color: 'D93F0B' },
];

export const GITIGNORE_BLOCK = `# Qwen Code settings (keep custom workflows, hand-picked skills and team memory in repo)
.qwen/*
!.qwen/skills/
!.qwen/workflows/
.qwen/skills/auto-skill-*/
# Shared team memory lives in the repo so every collaborator reads the same file
!.qwen/team-memory/
!.qwen/team-memory/**

# GitHub App credentials
gha-creds-*.json`;

/**
 * 哪些路径不复制进目标仓库。
 *
 * 都是「只属于本机或本仓库史」的东西：本地设置、自动抓取的技能、私钥与
 * gh 的凭据缓存、构建产物，以及本仓库自己的版本记录。CODEOWNERS 不在移植包里，
 * 目标仓库要不要自己的那份由它决定。
 */
export function shouldCopy(relPath) {
  const rel = relPath.split(path.sep).join('/');
  if (!rel) return true;
  const base = path.posix.basename(rel);
  if (rel === 'CHANGELOG.md') return false;
  if (rel === '.github/CODEOWNERS') return false;
  if (rel === '.qwen/settings.json') return false;
  if (rel.startsWith('.qwen/skills/auto-skill-')) return false;
  if (base.endsWith('.pem') || base.startsWith('gha-creds-')) return false;
  const segments = rel.split('/');
  if (segments.some((s) => ['node_modules', 'qwen-artifacts', '.playwright-mcp'].includes(s))) return false;
  return true;
}

/** 要复制的顶层条目（源仓库里实际存在的）。 */
export function copyPlan(sourceRoot = SOURCE_ROOT) {
  return COPY_ENTRIES.filter((rel) => fs.existsSync(path.join(sourceRoot, rel))).map((rel) => {
    const from = path.join(sourceRoot, rel);
    return { rel, from, kind: fs.statSync(from).isDirectory() ? 'dir' : 'file' };
  });
}

function collectSourceFiles(sourceRoot, rel, out = []) {
  if (!shouldCopy(rel)) return out;
  const abs = path.join(sourceRoot, rel);
  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    for (const name of fs.readdirSync(abs)) collectSourceFiles(sourceRoot, path.posix.join(rel, name), out);
  } else {
    out.push(rel);
  }
  return out;
}

/**
 * 目标仓库里「已经存在且内容不同」的文件。
 *
 * 只比对会被复制的那部分：目标自己多出来的文件不碰，相同内容算幂等。
 * 有冲突就必须显式 --force，避免一次手滑把别人的改动盖掉。
 */
export function findConflicts(sourceRoot, targetRoot) {
  if (!fs.existsSync(targetRoot)) return [];
  const conflicts = [];
  for (const entry of copyPlan(sourceRoot)) {
    for (const rel of collectSourceFiles(sourceRoot, entry.rel)) {
      const dst = path.join(targetRoot, rel);
      if (!fs.existsSync(dst)) continue;
      const srcStat = fs.statSync(path.join(sourceRoot, rel));
      const dstStat = fs.statSync(dst);
      if (srcStat.isDirectory() !== dstStat.isDirectory()) {
        conflicts.push(rel);
      } else if (srcStat.isFile() && !fs.readFileSync(path.join(sourceRoot, rel)).equals(fs.readFileSync(dst))) {
        conflicts.push(rel);
      }
    }
  }
  return conflicts;
}

export function copyInto(sourceRoot, targetRoot) {
  for (const entry of copyPlan(sourceRoot)) {
    fs.cpSync(entry.from, path.join(targetRoot, entry.rel), {
      recursive: true,
      force: true,
      filter: (src) => shouldCopy(path.relative(sourceRoot, src)),
    });
  }
}

export function gitignoreHasBlock(text) {
  return (
    text.includes('# Qwen Code settings (keep custom workflows, hand-picked skills and team memory in repo)') &&
    text.includes('gha-creds-*.json')
  );
}

/** 追加一次即可；已有标记块就原样返回，重复跑不会长出第二份。 */
export function gitignoreWithBlock(text) {
  if (gitignoreHasBlock(text)) return text;
  const prefix = text && !text.endsWith('\n') ? `${text}\n` : text;
  const separator = prefix && !prefix.endsWith('\n\n') ? '\n' : '';
  return `${prefix}${separator}${GITIGNORE_BLOCK}\n`;
}

/** --only 的取值：逗号分隔，去重，按固定顺序建 App。 */
export function parseOnly(value) {
  if (!value) return [...ROLE_ORDER];
  const wanted = new Set(
    String(value)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );
  if (!wanted.size) throw new Error('--only 不能是空列表');
  const unknown = [...wanted].filter((role) => !ROLE_ORDER.includes(role));
  if (unknown.length) throw new Error(`不认识的 --only：${unknown.join(', ')}（可选 ${ROLE_ORDER.join(' / ')}）`);
  return ROLE_ORDER.filter((role) => wanted.has(role));
}

/** --resume 的取值：可重复，写成 <角色>=<slug>。 */
export function parseResume(values) {
  const map = new Map();
  for (const raw of values || []) {
    const at = String(raw).indexOf('=');
    const role = at > 0 ? String(raw).slice(0, at).trim() : '';
    const slug = at > 0 ? String(raw).slice(at + 1).trim() : '';
    if (!ROLE_ORDER.includes(role) || !slug) {
      throw new Error(`--resume 要写成 <角色>=<slug>：${raw}`);
    }
    map.set(role, slug);
  }
  return map;
}

/** 显式续跑的角色也算进这一轮，仍然按固定顺序。 */
export function mergeRoles(only, resume) {
  const set = new Set(only);
  for (const role of ROLE_ORDER) if (resume.has(role)) set.add(role);
  return ROLE_ORDER.filter((role) => set.has(role));
}

export const roleDownloadDir = (baseDir, role) => path.join(baseDir, role);

export function setupArgs(role, { repo, cdp, downloadDir, resumeSlug = '' }) {
  const spec = ROLE_SPECS[role];
  const args = resumeSlug
    ? ['--app', resumeSlug]
    : ['--name', spec.name, '--perms', spec.perms];
  args.push('--repo', repo, '--var', spec.varName, '--secret', spec.secretName, '--cdp', cdp, '--download-dir', downloadDir);
  return args;
}

export function parseAppSlug(output) {
  const match = String(output).match(/\/settings\/apps\/([A-Za-z0-9-]+)/);
  return match ? match[1] : '';
}

export function resumeHint(role, slug, { repo, target, cdp, downloadDir }) {
  const parts = [
    'node .github/scripts/bootstrap.mjs',
    `--repo ${repo}`,
    `--target ${target}`,
    `--only ${role}`,
    `--resume ${role}=${slug}`,
    `--cdp ${cdp}`,
    `--download-dir ${downloadDir}`,
    '--skip-copy --skip-labels',
  ];
  return parts.join(' ');
}

const quote = (value) => (/^[A-Za-z0-9_./:=@-]+$/.test(String(value)) ? String(value) : `'${String(value).replace(/'/g, `'\\''`)}'`);

function printHelp(log) {
  log(`用法：
  node .github/scripts/bootstrap.mjs --repo <owner/name> --target <仓库路径> \\
    [--cdp http://127.0.0.1:9222] [--download-dir /tmp/qwen-bootstrap-keys] \\
    [--only clara,nora,miles,frank] [--resume <角色>=<slug>] \\
    [--skip-copy] [--skip-labels] [--skip-apps] [--force] [--dry-run]

它顺序做四件事：复制可移植文件 → 写 .gitignore 标记块 → 建停手标签 → 按角色建 App
并写入 Variable / Secret。每个角色用独立的 --download-dir，失败后按打印的
--resume 命令续跑。

仍需人做的一次性步骤：先 gh auth login；在带 --remote-debugging-port 的 Chrome 里
登录一次 GitHub（密码与 2FA 由你输入）；生成 QWEN_API_KEY。脚本不读、不打印任何密钥值。
--dry-run 只打印计划，不碰 gh、不写磁盘。`);
}

/**
 * 执行引导。deps 预留给测试：spawn 用来断言 dry-run 不会调用外部命令。
 */
export function runBootstrap(opts, deps = {}) {
  const spawn = deps.spawn || spawnSync;
  const log = deps.log || console.log;
  const warn = deps.error || console.error;
  const {
    repo,
    target,
    cdp = 'http://127.0.0.1:9222',
    downloadDir = '/tmp/qwen-bootstrap-keys',
    skipCopy = false,
    skipLabels = false,
    skipApps = false,
    force = false,
    dryRun = false,
    sourceRoot = SOURCE_ROOT,
  } = opts;

  if (!repo || !/^[^/\s]+\/[^/\s]+$/.test(repo)) {
    warn('缺少或写错了 --repo：要 <owner/name>');
    return 2;
  }
  if (!target) {
    warn('缺少 --target：要指向要安装的仓库路径');
    return 2;
  }

  const targetRoot = path.resolve(target);
  const sourceReal = fs.realpathSync(sourceRoot);
  const targetReal = fs.existsSync(targetRoot) ? fs.realpathSync(targetRoot) : targetRoot;
  if (targetReal === sourceReal) {
    warn('--target 就是源仓库本身，换个目录');
    return 2;
  }

  const only = parseOnly(opts.only);
  const resume = parseResume(opts.resume);
  const roles = mergeRoles(only, resume);

  if (dryRun) {
    log('[dry-run] 只打印计划，不调用 gh、不写磁盘。');
    log(`角色：${roles.join(' → ')}`);
    if (!skipCopy) {
      const conflicts = findConflicts(sourceRoot, targetRoot);
      log(`复制：${copyPlan(sourceRoot).map((e) => e.rel).join(' / ')}`);
      log(`冲突：${conflicts.length ? conflicts.join('\n  ') : '无'}${conflicts.length && !force ? '（正式跑会被拦下，需 --force）' : ''}`);
    }
    if (!skipLabels) log(`标签：${LABELS.map((l) => l.name).join(' / ')}`);
    if (!skipApps) {
      for (const role of roles) {
        const args = setupArgs(role, {
          repo,
          cdp,
          downloadDir: roleDownloadDir(downloadDir, role),
          resumeSlug: resume.get(role) || '',
        });
        log(`  ${quote('node')} ${[path.join(sourceRoot, '.github/scripts/setup-app.mjs'), ...args].map(quote).join(' ')}`);
      }
    }
    return 0;
  }

  // ── 预检 ──
  if (!skipApps || !skipLabels) {
    const auth = spawn('gh', ['auth', 'status'], { stdio: 'ignore' });
    if (auth.status !== 0) {
      warn('gh 没有登录。先跑 gh auth login，再重试（或加 --skip-apps --skip-labels）。');
      return 2;
    }
  }

  if (!skipCopy) {
    if (!fs.existsSync(targetRoot)) {
      warn(`--target 不存在：${targetRoot}`);
      return 2;
    }
    const git = spawn('git', ['-C', targetRoot, 'rev-parse', '--is-inside-work-tree'], { encoding: 'utf8' });
    if (git.status !== 0 || String(git.stdout || '').trim() !== 'true') {
      warn(`--target 不是 git 工作区：${targetRoot}`);
      return 2;
    }
    if (!force) {
      const status = spawn('git', ['-C', targetRoot, 'status', '--porcelain'], { encoding: 'utf8' });
      if (String(status.stdout || '').trim()) {
        warn('目标仓库有未提交的改动。先提交或 stash，确认后再跑；要覆盖就加 --force。');
        return 2;
      }
    }
    const conflicts = findConflicts(sourceRoot, targetRoot);
    if (conflicts.length && !force) {
      warn(`这些文件已存在且内容不同，没有 --force 不覆盖：\n  ${conflicts.join('\n  ')}`);
      return 2;
    }
  }

  const failures = [];

  // ── 复制 ──
  if (!skipCopy) {
    copyInto(sourceRoot, targetRoot);
    log(`已复制：${copyPlan(sourceRoot).map((e) => e.rel).join(' / ')}`);

    const gitignorePath = path.join(targetRoot, '.gitignore');
    const existing = fs.existsSync(gitignorePath) ? fs.readFileSync(gitignorePath, 'utf8') : '';
    if (!gitignoreHasBlock(existing)) {
      fs.writeFileSync(gitignorePath, gitignoreWithBlock(existing));
      log('已追加 .gitignore 的 Qwen 标记块');
    } else {
      log('.gitignore 里的 Qwen 标记块已存在，跳过');
    }
  }

  // ── 标签 ──
  if (!skipLabels) {
    for (const label of LABELS) {
      const r = spawn(
        'gh',
        ['label', 'create', label.name, '--repo', repo, '--description', label.description, '--color', label.color, '--force'],
        { stdio: 'inherit' },
      );
      if (r.status === 0) log(`标签 ${label.name} 已就绪`);
      else failures.push(`label:${label.name}`);
    }
  }

  // ── App ──
  if (!skipApps) {
    const setupApp = path.join(sourceRoot, '.github/scripts/setup-app.mjs');
    for (const role of roles) {
      const spec = ROLE_SPECS[role];
      if (!force) {
        const vars = spawn('gh', ['variable', 'list', '--repo', repo], { encoding: 'utf8' });
        const secrets = spawn('gh', ['secret', 'list', '--repo', repo], { encoding: 'utf8' });
        const hasVar = vars.status === 0 && String(vars.stdout).includes(spec.varName);
        const hasSecret = secrets.status === 0 && String(secrets.stdout).includes(spec.secretName);
        if (hasVar && hasSecret) {
          log(`${role}：${spec.varName} / ${spec.secretName} 已存在，跳过（--force 可重做）`);
          continue;
        }
      }

      const args = setupArgs(role, {
        repo,
        cdp,
        downloadDir: roleDownloadDir(downloadDir, role),
        resumeSlug: resume.get(role) || '',
      });
      log(`\n── ${role}：创建并安装 App ──`);
      const r = spawn(process.execPath, [setupApp, ...args], { encoding: 'utf8' });
      const output = `${r.stdout || ''}${r.stderr || ''}`;
      if (output) log(output.trimEnd());
      if (r.status === 0) {
        log(`${role}：完成`);
        continue;
      }

      failures.push(`app:${role}`);
      const slug = parseAppSlug(output);
      if (slug) {
        warn(`\n${role} 没走完。用这条续跑（不会重复创建）：`);
        warn(resumeHint(role, slug, { repo, target: targetRoot, cdp, downloadDir }));
      } else {
        warn(`\n${role} 没走完，也没从输出里读到 slug。去 Settings → Developer settings → GitHub Apps 找到它，再用 --resume ${role}=<slug> 续跑。`);
      }
    }
  }

  // ── 收尾 ──
  log(`\n仍需人工一次性完成（脚本不接触任何密钥值）：`);
  log(`  1. gh auth login（若还没登录）`);
  log(`  2. 在 Chrome 里登录 GitHub 一次（密码与 2FA 由你输入）`);
  log(`  3. gh secret set QWEN_API_KEY --repo ${repo}`);
  log(`  4. gh variable set QWEN_BASE_URL --repo ${repo} --body '<Coding Plan 的 base URL>'`);
  log(`  5. gh variable set QWEN_MODEL --repo ${repo} --body '<模型名>'`);
  log(`  6. gh variable set QWEN_CLI_VERSION --repo ${repo} --body 'latest'`);
  log(`  7. 确认工作流跑通后删掉私钥目录：rm -rf ${quote(downloadDir)}`);

  if (failures.length) {
    warn(`\n未完成：${failures.join(', ')}。其余步骤已经做完，按上面的 --resume 续跑即可。`);
    return 1;
  }
  log('\n引导完成。');
  return 0;
}

function main(argv = process.argv.slice(2)) {
  if (argv.includes('--help') || argv.includes('-h') || argv.length === 0) {
    printHelp(console.log);
    return 0;
  }

  const value = (name, fallback = '') => {
    const eq = argv.find((a) => a.startsWith(`--${name}=`));
    if (eq) return eq.slice(name.length + 3);
    const i = argv.indexOf(`--${name}`);
    return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : fallback;
  };
  const resume = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--resume' && argv[i + 1] && !argv[i + 1].startsWith('--')) {
      resume.push(argv[i + 1]);
      i += 1;
    } else if (argv[i].startsWith('--resume=')) {
      resume.push(argv[i].slice('--resume='.length));
    }
  }

  try {
    return runBootstrap({
      repo: value('repo'),
      target: value('target'),
      cdp: value('cdp', 'http://127.0.0.1:9222'),
      downloadDir: value('download-dir', '/tmp/qwen-bootstrap-keys'),
      only: value('only'),
      resume,
      skipCopy: argv.includes('--skip-copy'),
      skipLabels: argv.includes('--skip-labels'),
      skipApps: argv.includes('--skip-apps'),
      force: argv.includes('--force'),
      dryRun: argv.includes('--dry-run'),
    });
  } catch (error) {
    console.error(`\n✗ ${error.message}`);
    return 2;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
