#!/usr/bin/env node
/**
 * 自动把一个 GitHub App 配好：创建 → 生成私钥 → 装到仓库 → 写入 Variable/Secret。
 *
 * 前置：本机有一个**已登录 GitHub** 的 Chrome，且以 --remote-debugging-port 启动。
 * 脚本不碰密码、不碰 2FA、不读 cookie —— 它只是驱动你自己那个已登录的浏览器。
 *
 * 用法：
 *   node .github/scripts/setup-app.mjs \
 *     --name snowcore8-frank \
 *     --repo SnowCore8/linux-firewall-kmod \
 *     --var APP_ID_FRANK \
 *     --secret APP_PRIVATE_KEY_FRANK \
 *     --perms contents:read,issues:read,pull_requests:write \
 *     [--cdp http://127.0.0.1:9222] \
 *     [--dry-run]
 *
 * 权限按身份给，别一律给 write —— 该给哪几档见 QWEN.md 里每人的职责边界。
 * 所以新建时 `--perms` 是必填项，没有默认值可退：漏写只能停下，不能猜。
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { MENU_LABEL, describePerms, parsePerms } from './app-perms.mjs';

// ---------- 参数 ----------
const argv = process.argv.slice(2);
const arg = (k, d = null) => {
  const i = argv.indexOf(`--${k}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : d;
};
const flag = (k) => argv.includes(`--${k}`);

const APP_NAME = arg('name');
const RESUME_SLUG = arg('app');
const REPO = arg('repo');
const VAR_NAME = arg('var');
const SECRET_NAME = arg('secret');
const CDP = arg('cdp', 'http://127.0.0.1:9222');
const DRY = flag('dry-run');
const PERMS_RAW = arg('perms');
const DOWNLOAD_DIR = arg('download-dir', '/tmp/app-keys');
const EXISTING_KEY = arg('key');

if (!REPO || !VAR_NAME || !SECRET_NAME || (!APP_NAME && !RESUME_SLUG)) {
  if (flag('help') || argv.length === 0) {
    console.log(`用法：
  新建 App：
  node .github/scripts/setup-app.mjs \\
    --name <App 名称> \\
    --repo <owner/repo> \\
    --var <APP_ID 变量名> \\
    --secret <私钥 Secret 名> \\
    --perms contents:read,issues:write,pull_requests:read \\
    [--cdp http://127.0.0.1:9222] \\
    [--download-dir /tmp/app-keys] \\
    [--dry-run]

  已有 App 只补私钥/安装/凭据（上次中途失败时用这个，不会重复创建）：
  node .github/scripts/setup-app.mjs \\
    --app <App slug> \\
    --repo <owner/repo> \\
    --var <APP_ID 变量名> \\
    --secret <私钥 Secret 名>

前置：一个已登录 GitHub 的 Chrome，以 --remote-debugging-port=9222 启动。
脚本不读 cookie、不代填密码与 2FA。`);
    process.exit(0);
  }
  console.error('缺少参数。需要 --repo --var --secret，加 --name（新建）或 --app（续跑），加 --help 看用法。');
  process.exit(2);
}

const die = (msg) => {
  console.error(`\n✗ ${msg}`);
  process.exit(1);
};
const step = (msg) => console.log(`\n→ ${msg}`);
const ok = (msg) => console.log(`  ✓ ${msg}`);

// 参数写错时要在碰浏览器之前就停，别等到建到一半才发现级别拼错了
//
// 新建时 `--perms` 必填。给个「都一样 write」的默认值，就等于把代码里这句劝告
// 变成执行时反着做 —— 顾清能推代码、周正能改 Issue，都不报错，也就没人发现。
// 续跑（--app）改的是已有 App 的其它项，不重设权限，所以不要这一项。
let PERMS = [];
if (PERMS_RAW) {
  try {
    PERMS = parsePerms(PERMS_RAW);
  } catch (e) {
    die(`${e.message}（当前 --perms ${PERMS_RAW}）`);
  }
} else if (!RESUME_SLUG) {
  die(`新建 App 要给 --perms，没有默认值：不写就是每一项都 write，等于把权限开满。
  按 QWEN.md 里每人的职责边界挑级别，例 --perms contents:read,issues:write,pull_requests:read`);
}

// ---------- 极简 CDP 客户端 ----------
class CDPClient {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString());
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
      }
    });
  }

  static async connect(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', () => rej(new Error(`连不上 ${wsUrl}`)), { once: true });
    });
    return new CDPClient(ws);
  }

  send(method, params = {}, sessionId) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`${method} 超时`));
        }
      }, 60000);
    });
  }

  close() {
    this.ws.close();
  }
}

// 在页面里执行表达式，取回可序列化结果
async function evaluate(cli, sessionId, expression) {
  const r = await cli.send(
    'Runtime.evaluate',
    { expression, returnByValue: true, awaitPromise: true, userGesture: true },
    sessionId,
  );
  if (r.exceptionDetails) {
    throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  }
  return r.result?.value;
}

async function goto(cli, sessionId, url) {
  await cli.send('Page.enable', {}, sessionId).catch(() => {});
  await cli.send('Page.navigate', { url }, sessionId);
  await waitFor(cli, sessionId, `document.readyState === 'complete'`, 30000);
}

async function waitFor(cli, sessionId, expr, timeoutMs = 20000, intervalMs = 300) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await evaluate(cli, sessionId, expr).catch(() => false)) return true;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}

// ---------- 主流程 ----------
async function main() {
  // 0. 连浏览器
  step(`连接 ${CDP}`);
  const version = await fetch(`${CDP}/json/version`).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }).catch(() => null);
  if (!version) {
    die(`连不上 ${CDP}。请用带 --remote-debugging-port 的方式启动已登录的 Chrome（见 README）。`);
  }
  ok(`浏览器 ${version.Browser}`);

  const tabs = await fetch(`${CDP}/json/list`).then((r) => r.json());
  const page = tabs.find((t) => t.type === 'page');
  if (!page) die('没有可用的标签页');

  const cli = await CDPClient.connect(page.webSocketDebuggerUrl);
  const { sessionId } = await cli.send('Target.attachToTarget', { targetId: page.id, flatten: true });

  // 1. 确认登录态
  step('确认 GitHub 登录态');
  await goto(cli, sessionId, 'https://github.com/settings/apps');
  const loggedIn = await evaluate(cli, sessionId, `!location.pathname.startsWith('/login')`);
  if (!loggedIn) {
    die('浏览器未登录 GitHub。请在这个 Chrome 里登录后重试；脚本不代填密码与 2FA。');
  }
  const who = await evaluate(
    cli,
    sessionId,
    `(document.querySelector('meta[name="user-login"]')?.content) || document.title`,
  );
  ok(`已登录：${who}`);

  let appUrl;
  if (RESUME_SLUG) {
    // 已有 App：跳过创建，直接进设置页
    appUrl = `https://github.com/settings/apps/${RESUME_SLUG}`;
    step(`续跑已有 App：${RESUME_SLUG}`);
    await goto(cli, sessionId, `https://github.com/settings/apps/${RESUME_SLUG}`);
    const exists = await waitFor(
      cli,
      sessionId,
      `location.pathname === '/settings/apps/${RESUME_SLUG}' && /App ID/i.test(document.body.innerText)`,
      30000,
    );
    if (!exists) die(`打不开 https://github.com/settings/apps/${RESUME_SLUG}（slug 不对或无权访问）`);
    ok(`已打开 ${RESUME_SLUG}`);
  } else {
    // 2. 创建 App
    step(`创建 App：${APP_NAME}`);
    await goto(cli, sessionId, 'https://github.com/settings/apps/new');
    if (await evaluate(cli, sessionId, `!!document.querySelector('#integration_name')`) === false) {
      die('没打开创建页（可能被重定向）');
    }

    // 名称、主页、描述
    const homepage = `https://github.com/${REPO}`;
    await evaluate(cli, sessionId, `(() => {
      const set = (sel, v) => {
        const el = document.querySelector(sel);
        if (!el) return false;
        el.focus(); el.value = v;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      };
      set('#integration_name', ${JSON.stringify(APP_NAME)});
      set('#integration_url', ${JSON.stringify(homepage)});
      set('#integrator_description', 'AI 团队里某位同事的独立身份');
      return true;
    })()`);
    ok(`名称 ${APP_NAME}，主页 ${homepage}`);

    // 关掉 webhook
    await evaluate(cli, sessionId, `(() => {
      const cb = document.querySelector('input[type=checkbox][name="integration[hook_attributes][active]"]');
      if (cb && cb.checked) { cb.click(); return '已取消'; }
      return '本来就未勾选';
    })()`);
    ok('Webhook 已关闭');

    // 逐项按身份设权限：每档对应菜单里的一项，选完回读 hidden input 确认
    ok(`权限：${describePerms(PERMS)}`);
    for (const { name, level } of PERMS) {
      const label = MENU_LABEL[level];

      const opened = await evaluate(cli, sessionId, `(() => {
        const hidden = document.querySelector('input[name="integration[default_permissions][${name}]"]');
        if (!hidden) return '未找到该权限项';
        const details = hidden.closest('details');
        if (details && !details.open) details.querySelector('summary').click();

        const group = hidden.closest('focus-group');
        const btn = group && group.querySelector('button[popovertarget]');
        if (!btn) return '未找到权限按钮';
        btn.scrollIntoView({ block: 'center' });
        btn.click();
        return 'ok';
      })()`);
      if (opened !== 'ok') die(`权限 ${name} 打不开下拉：${opened}`);

      const picked = await evaluate(cli, sessionId, `(() => {
        const hidden = document.querySelector('input[name="integration[default_permissions][${name}]"]');
        const group = hidden.closest('focus-group');
        const btn = group.querySelector('button[popovertarget]');
        const overlay = document.getElementById(btn.getAttribute('popovertarget'));
        if (!overlay) return '菜单未出现';
        const opt = [...overlay.querySelectorAll('button[role=menuitemradio]')]
          .find((b) => b.innerText.trim() === ${JSON.stringify(label)});
        if (!opt) return '没有这一档';
        opt.click();
        return 'ok';
      })()`);
      if (picked !== 'ok') {
        die(`权限 ${name} 选不到「${label}」：${picked}。这一项可能只有别的档位，改成它支持的。`);
      }

      const value = await evaluate(
        cli,
        sessionId,
        `document.querySelector('input[name="integration[default_permissions][${name}]"]').value`,
      );
      if (value !== level) die(`权限 ${name} 设置失败（要 ${level}，当前 ${value}）`);
      ok(`${name} = ${level}`);
    }

    if (DRY) {
      ok('--dry-run：停在这里，未提交创建');
      cli.close();
      return;
    }

    // 3. 提交创建
    step('提交创建');
    await evaluate(cli, sessionId, `(() => {
      const btn = [...document.querySelectorAll('input[type=submit], button[type=submit]')]
        .find((b) => /Create GitHub App/i.test(b.value || b.innerText || ''));
      if (!btn) return 'no-button';
      btn.scrollIntoView({ block: 'center' });
      btn.click();
      return 'clicked';
    })()`);

    const created = await waitFor(cli, sessionId, `location.pathname.startsWith('/settings/apps/') && !location.pathname.endsWith('/new')`, 60000);
    if (!created) die('创建后没有跳转到 App 设置页');
    appUrl = await evaluate(cli, sessionId, `location.href`);
    ok(`已创建：${appUrl}`);
  }

  // 4. 读 App ID
  step('读取 App ID');
  // GitHub 是渐进渲染：导航完成的那一刻 innerText 可能还是空的，先等它出现再匹配
  const idShown = await waitFor(
    cli,
    sessionId,
    `/App ID/i.test(document.body?.innerText || '')`,
    30000,
  );
  if (!idShown) die(`App 设置页没出现「App ID」字样：${appUrl}`);
  const appId = await evaluate(cli, sessionId, `(() => {
    const t = document.body.innerText;
    const m = t.match(/App ID[^\\d]{0,40}(\\d{4,})/i);
    return m ? m[1] : null;
  })()`);
  if (!appId) die('读不到 App ID');
  ok(`App ID = ${appId}`);

  // 5. 生成私钥
  step('生成私钥');
  let pemPath = EXISTING_KEY;
  let pem;
  if (EXISTING_KEY) {
    if (!fs.existsSync(EXISTING_KEY)) die(`--key 指定的文件不存在：${EXISTING_KEY}`);
    pem = fs.readFileSync(EXISTING_KEY, 'utf8');
    if (!pem.includes('BEGIN RSA PRIVATE KEY') && !pem.includes('BEGIN PRIVATE KEY')) {
      die(`--key 指定的不是私钥：${EXISTING_KEY}`);
    }
    ok(`复用已有私钥（${pem.length} 字节）`);
  } else {
    fs.mkdirSync(DOWNLOAD_DIR, { recursive: true });
    const before = new Set(fs.readdirSync(DOWNLOAD_DIR));

    await cli.send('Browser.setDownloadBehavior', { behavior: 'allowAndName', downloadPath: DOWNLOAD_DIR });

    await goto(cli, sessionId, `${appUrl}/key_pairs`);
    await waitFor(cli, sessionId, `document.body.innerText.includes('New key')`, 20000);

    const keyClicked = await evaluate(cli, sessionId, `(() => {
      const el = [...document.querySelectorAll('span.Button-label, button, a')]
        .find((e) => (e.innerText || '').trim() === 'New key');
      if (!el) return 'no-button';
      (el.closest('button') || el).click();
      return 'clicked';
    })()`);
    if (keyClicked !== 'clicked') die('找不到「New key」按钮');

    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const now = fs.readdirSync(DOWNLOAD_DIR).filter((f) => !before.has(f));
      if (now.length) {
        pemPath = path.join(DOWNLOAD_DIR, now[0]);
        break;
      }
    }
    if (!pemPath) die('私钥没有下载成功');
    pem = fs.readFileSync(pemPath, 'utf8');
    if (!pem.includes('BEGIN RSA PRIVATE KEY') && !pem.includes('BEGIN PRIVATE KEY')) {
      die('下载到的不是私钥');
    }
    ok(`私钥已下载（${pem.length} 字节）`);
  }

  // 6. 安装到仓库
  step('安装到仓库');
  await goto(cli, sessionId, `${appUrl}/installations`);
  // 这页也是渐进渲染：先等账户列表出现，再判断是「装过」还是「该装」
  const pickable = await waitFor(
    cli,
    sessionId,
    `/Install|Installed|Configure/i.test(document.body?.innerText || '')`,
    30000,
  );
  if (!pickable) die(`安装页没有出现账户列表：${appUrl}/installations`);

  const installHref = await evaluate(cli, sessionId, `(() => {
    const a = [...document.querySelectorAll('a')]
      .find((el) => /^Install$/.test((el.innerText || '').trim()) && (el.getAttribute('href') || '').includes('/installations/new'));
    return a ? a.getAttribute('href') : null;
  })()`);

  // 装过的账户后面挂的是 Installed 徽标，配置入口是 Configure；两者都算已安装
  const alreadyInstalled = await evaluate(
    cli,
    sessionId,
    `/\\b(Installed|Configure)\\b/i.test(document.body.innerText)`,
  );

  if (!installHref && !alreadyInstalled) die('找不到 Install 链接，也看不出已安装');
  if (!installHref) {
    ok('检测到已有安装，跳过安装步骤');
  } else {
    await goto(cli, sessionId, new URL(installHref, 'https://github.com').href);
    await waitFor(cli, sessionId, `!!document.querySelector('input[type=radio][name=install_target]')`, 20000);

    // 选 only select repositories
    await evaluate(cli, sessionId, `document.querySelector('input[type=radio][name=install_target][value=selected]').click()`);
    await new Promise((r) => setTimeout(r, 1200));

    // 展开选择器
    await evaluate(cli, sessionId, `(() => {
      const s = [...document.querySelectorAll('summary')].find((e) => /Select repositories/.test(e.innerText));
      if (s) s.click();
      return true;
    })()`);
    await waitFor(cli, sessionId, `!!document.getElementById('repository-menu-list')`, 15000);

    // 列表不会自己出来，一直停在 Loading —— 必须先在搜索框里打字才会去拉
    const repoName = REPO.split('/')[1];
    const typed = await evaluate(cli, sessionId, `(() => {
      const i = [...document.querySelectorAll('input[type=text],input[type=search]')]
        .find((el) => /search for a repositor/i.test(el.placeholder || ''));
      if (!i) return 'no-search';
      i.focus();
      i.value = ${JSON.stringify(repoName)};
      i.dispatchEvent(new Event('input', { bubbles: true }));
      i.dispatchEvent(new Event('change', { bubbles: true }));
      return 'typed';
    })()`);
    if (typed !== 'typed') die(`找不到仓库搜索框：${typed}`);

    let picked = 'no-list';
    for (let i = 0; i < 40; i++) {
      picked = await evaluate(cli, sessionId, `(() => {
        const list = document.getElementById('repository-menu-list');
        if (!list) return 'no-list';
        const btns = [...list.querySelectorAll('button')];
        if (!btns.length) return 'not-ready';
        const hit = btns.find((b) => (b.innerText || '').includes('/${repoName}'));
        if (!hit) return 'not-found:' + btns.length;
        hit.click();
        return 'ok';
      })()`);
      if (picked === 'ok') break;
      await new Promise((r) => setTimeout(r, 500));
    }
    if (picked !== 'ok') die(`选择仓库失败：${picked}`);

    // 等隐藏域真的写进去（Install 按钮在此之前是禁用态）
    const repoSelected = await waitFor(
      cli,
      sessionId,
      `document.querySelectorAll('input[name="repository_ids[]"]').length > 0`,
      15000,
    );
    if (!repoSelected) die('仓库没有被选中');
    const chosen = await evaluate(
      cli,
      sessionId,
      `[...document.querySelectorAll('input[name="repository_ids[]"]')].map(i => i.value)`,
    );
    ok(`已选仓库 id: ${JSON.stringify(chosen)}`);

    // 提交安装
    await waitFor(
      cli,
      sessionId,
      `[...document.querySelectorAll('button[type=submit]')].some((b) => b.innerText.trim() === 'Install' && !b.disabled)`,
      20000,
    );
    await evaluate(cli, sessionId, `(() => {
      const btn = [...document.querySelectorAll('button[type=submit]')].find((b) => b.innerText.trim() === 'Install');
      if (!btn) return 'no-install';
      btn.scrollIntoView({ block: 'center' });
      btn.click();
      return 'clicked';
    })()`);
    const installed = await waitFor(
      cli,
      sessionId,
      `location.pathname.startsWith('/settings/installations/') || document.body.innerText.includes('was installed')`,
      60000,
    );
    if (!installed) die('安装没有完成');
    ok('已安装');
  }

  cli.close();

  // 7. 写凭据
  step('写入仓库凭据');
  const run = (cmd, args, input) => {
    const r = spawnSync(cmd, args, { input, encoding: 'utf8' });
    if (r.status !== 0) die(`${cmd} 失败：${r.stderr || r.stdout}`);
    return r.stdout.trim();
  };

  run('gh', ['variable', 'set', VAR_NAME, '--repo', REPO, '--body', appId]);
  ok(`Variable ${VAR_NAME} = ${appId}`);

  run('gh', ['secret', 'set', SECRET_NAME, '--repo', REPO], pem);
  ok(`Secret ${SECRET_NAME} 已写入`);

  // 8. 校验
  step('校验');
  const vars = run('gh', ['variable', 'list', '--repo', REPO]);
  const secrets = run('gh', ['secret', 'list', '--repo', REPO]);
  ok(vars.includes(VAR_NAME) ? `${VAR_NAME} 存在` : `${VAR_NAME} 缺失！`);
  ok(secrets.includes(SECRET_NAME) ? `${SECRET_NAME} 存在` : `${SECRET_NAME} 缺失！`);

  // 私钥只留在磁盘，立刻提醒清理
  console.log(`\n私钥文件：${pemPath}`);
  console.log('确认 workflow 跑通后请删除它：rm -f ' + pemPath);
  console.log(`\n完成。App ID ${appId}，slug 见 ${appUrl}`);
}

main().catch((e) => die(e.stack || e.message));
