/**
 * 四份角色工作流、共享 action、引擎配置之间的契约。
 *
 * 这一层出错的形状全都一样：**不报错，只是某件事不再发生**。
 *   - 角色名写错 → 找不到 `.github/agents/<role>.json`，那一轮停在第一步；
 *   - settings 里写了一个 v0.18.0 不存在的 MCP 工具 → docker 起得来、工具没有，
 *     模型调它时报错，而人看到的是「模型绕路了」；
 *   - 工作流里写了 `uses: ./.github/actions/run-agent` 却没传某个必填 input →
 *     调用时 job 直接失败，但报错在 runner 里，本地看不出来；
 *   - 某个角色少了一份配置 → 只有那一个人不能用，其他三个人照跑，很容易漏很久。
 *
 * 所以这里把三样东西一起核：配置存在且合法、工具名真实存在、必填 input 都传了。
 *
 *   /usr/bin/node --test .github/scripts/agent-contract.test.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** 四个角色。加人时只改这一行，下面每一条检查都会自动覆盖新角色。 */
const ROLES = ['clara', 'nora', 'miles', 'frank'];

const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');
const settingsPath = (role) => `.github/agents/${role}.json`;
const workflowPath = (role) => `.github/workflows/qwen-${role}.yml`;

const settingsOf = (role) => JSON.parse(read(settingsPath(role)));

/**
 * github-mcp-server v0.18.0 认识的全部工具名。
 *
 * 从上游 README 抄下来而不是当场查：测试要在没有网络的 CI 里跑。代价是升级镜像
 * 版本时这份清单会过时 —— 所以下面还有一条测试盯着「镜像版本变了就提醒」。
 */
const KNOWN_TOOLS = new Set([
  'add_issue_comment', 'add_sub_issue', 'assign_copilot_to_issue', 'create_issue',
  'get_issue', 'get_issue_comments', 'list_issue_types', 'list_issues', 'list_label',
  'list_sub_issues', 'remove_sub_issue', 'reprioritize_sub_issue', 'search_issues',
  'update_issue',
  'pull_request_read', 'get_file_contents', 'search_code', 'list_commits', 'get_commit',
]);

// ───────────────────────── 配置存在且合法 ─────────────────────────

test('每个角色都有一份引擎配置', () => {
  for (const role of ROLES) {
    assert.ok(existsSync(path.join(ROOT, settingsPath(role))), `${settingsPath(role)} 不存在，${role} 跑不起来`);
  }
});

test('每份配置都是合法 JSON，且是对象', () => {
  for (const role of ROLES) {
    const cfg = settingsOf(role); // 解析失败会在这里抛，报错带文件内容
    assert.equal(typeof cfg, 'object');
    assert.ok(cfg && !Array.isArray(cfg), `${role} 的配置应当是一个对象`);
  }
});

test('每份配置都关了自动记忆与遥测', () => {
  // 这两项开着会让同一轮的行为不可复现，而那正是告警与重试最难查的一类
  for (const role of ROLES) {
    const cfg = settingsOf(role);
    assert.equal(cfg.memory?.enableManagedAutoMemory, false, `${role} 没关自动记忆`);
    assert.equal(cfg.memory?.enableManagedAutoDream, false, `${role} 没关自动做梦`);
    assert.equal(cfg.telemetry?.enabled, false, `${role} 没关遥测`);
  }
});

test('每份配置都给 shell 工具，但也只给这一个', () => {
  // core 只取工具名，括号里写的命令名不起作用，所以白名单里多写等于多开
  for (const role of ROLES) {
    assert.deepEqual(settingsOf(role).tools?.core, ['run_shell_command'], `${role} 的 tools.core 不对`);
  }
});

test('轮次预算是正整数，且没有一个是无限制', () => {
  for (const role of ROLES) {
    const turns = settingsOf(role).model?.maxSessionTurns;
    assert.ok(Number.isInteger(turns) && turns > 0, `${role} 的 maxSessionTurns 不是正整数：${turns}`);
  }
});

// ───────────────────────── MCP 工具名真实存在 ─────────────────────────

test('配置里引用的每个 MCP 工具都是 v0.18.0 认识的', () => {
  for (const role of ROLES) {
    const tools = settingsOf(role).mcpServers?.github?.includeTools || [];
    for (const name of tools) {
      assert.ok(KNOWN_TOOLS.has(name), `${role} 引用了不存在的 MCP 工具：${name}（模型调它时会失败）`);
    }
  }
});

test('MCP 一律用 docker 拉固定版本，不用 latest', () => {
  for (const role of ROLES) {
    const server = settingsOf(role).mcpServers?.github;
    if (!server) continue;
    assert.equal(server.command, 'docker', `${role} 的 MCP 不是 docker 起的`);
    const image = (server.args || []).find((a) => String(a).includes('github-mcp-server'));
    assert.ok(image, `${role} 的 MCP 没有指定镜像`);
    assert.match(image, /:v\d+\.\d+\.\d+$/, `${role} 的镜像没钉住版本：${image}`);
  }
});

test('镜像版本与上面那份工具清单是同一条线', () => {
  // KNOWN_TOOLS 是照 v0.18.0 抄的。谁把镜像升级了，这条会红，提醒去核工具名。
  const versions = new Set(
    ROLES.map((role) => {
      const server = settingsOf(role).mcpServers?.github;
      const image = (server?.args || []).find((a) => String(a).includes('github-mcp-server')) || '';
      return (image.match(/:v(\d+\.\d+\.\d+)$/) || [])[1];
    }),
  );
  assert.deepEqual([...versions], ['0.18.0'], '镜像版本变了，KNOWN_TOOLS 要照新版本重新核一遍');
});

test('四个人的 MCP 凭证都从 GITHUB_TOKEN 注入，不写死值', () => {
  for (const role of ROLES) {
    const server = settingsOf(role).mcpServers?.github;
    if (!server) continue;
    assert.equal(server.env?.GITHUB_PERSONAL_ACCESS_TOKEN, '${GITHUB_TOKEN}', `${role} 的 MCP 凭证变量写法不对`);
    assert.ok((server.args || []).includes('-e'), `${role} 的 MCP 没把凭证变量透进容器`);
  }
});

// ───────────────────────── 工作流确实用了这些配置 ─────────────────────────

test('四份工作流都通过共享 action 跑模型，而不是自己内联 settings', () => {
  for (const role of ROLES) {
    const yml = read(workflowPath(role));
    assert.match(yml, /uses: '\.\/\.github\/actions\/run-agent'/, `${role} 没走共享 action`);
    assert.doesNotMatch(yml, /^\s+settings: \|-/m, `${role} 里还留着内联 settings`);
    assert.doesNotMatch(yml, /mcpServers/, `${role} 里还留着内联的 MCP 配置`);
  }
});

test('传给共享 action 的角色名就是配置文件名', () => {
  for (const role of ROLES) {
    const yml = read(workflowPath(role));
    assert.match(yml, new RegExp(`^\\s+role: '${role}'$`, 'm'), `${role} 传给 action 的 role 与文件名对不上`);
  }
});

test('共享 action 的必填 input 在四份工作流里都传了', () => {
  const action = read('.github/actions/run-agent/action.yml');
  // 只取 inputs: 块里 required: true 的那几个
  const required = [...action.matchAll(/^ {2}([a-z_]+):\n(?: {4}.*\n)*? {4}required: true$/gm)].map((m) => m[1]);
  assert.ok(required.length >= 4, `没能从 action.yml 里取到必填 input，取到的：${required.join(', ')}`);

  for (const role of ROLES) {
    const yml = read(workflowPath(role));
    const withBlock = yml.slice(yml.indexOf("uses: './.github/actions/run-agent'"));
    for (const key of required) {
      assert.match(withBlock, new RegExp(`^\\s+${key}: `, 'm'), `${role} 没传必填 input：${key}`);
    }
  }
});

test('共享 action 的 role input 说明里列的角色与这里核的四个一致', () => {
  // 加第五个人时提醒去改文档与这份清单
  const action = read('.github/actions/run-agent/action.yml');
  for (const role of ROLES) {
    assert.ok(action.includes(role), `action.yml 的 role 说明里没提到 ${role}`);
  }
});

// ───────────────── 工作流脚本：args 与脚本读的字段对上 ─────────────────
//
// 四个人的这一轮都搬进了 .qwen/workflows/<role>-*.js。这一层错起来和 context.mjs
// 那条一样安静：工作流拼了一个 `headref`，脚本读的是 `headRef`，拿到的是 undefined，
// 于是脚本开头那条必填检查直接把整轮抛掉 —— 或者更糟，拼出一个空分支名推上去、
// 把一批 Issue 读成空。
//
// 所以两侧都从源码里取：工作流那个 JSON 里的键，脚本里 `args?.<键>` 的键。

/** 角色 → 工作流脚本。加人时只改这一行。 */
const WORKFLOW_SCRIPTS = {
  clara: '.qwen/workflows/clara-triage.js',
  nora: '.qwen/workflows/nora-decide.js',
  miles: '.qwen/workflows/miles-fix.js',
  frank: '.qwen/workflows/frank-review.js',
};

/** 工作流脚本的命令名：来自文件名，不是 meta.name。 */
const commandOf = (script) => `/${path.basename(script, '.js')}`;

/** 工作流那个 prompt 里 JSON 的键。 */
function argsProvidedBy(role) {
  const yml = read(workflowPath(role));
  const at = yml.indexOf(`${commandOf(WORKFLOW_SCRIPTS[role])} {`);
  assert.ok(at >= 0, `${role} 的 prompt 里没有 ${commandOf(WORKFLOW_SCRIPTS[role])} 调用`);
  // 取到这一行的结尾（prompt 是单行 YAML，用 >- 折叠）
  const line = yml.slice(at, yml.indexOf('\n', at));
  return [...new Set([...line.matchAll(/"([a-zA-Z]+)":/g)].map((m) => m[1]))];
}

/** 脚本里从 args 读的键。 */
function argsReadBy(role) {
  const src = read(WORKFLOW_SCRIPTS[role]);
  return [...new Set([...src.matchAll(/args\?\.([a-zA-Z]+)/g)].map((m) => m[1]))];
}

/** 脚本开头那句 throw 里要求的键。 */
function argsRequiredBy(role) {
  const src = read(WORKFLOW_SCRIPTS[role]);
  const hit = src.match(/throw new Error\(\s*'args 需要 \{([^}]*)\}/);
  if (!hit) return [];
  return hit[1].split(',').map((s) => s.trim()).filter(Boolean);
}

test('工作流传的每个参数，脚本都读得到', () => {
  for (const role of ROLES) {
    const provided = argsProvidedBy(role);
    const read_ = argsReadBy(role);
    assert.ok(provided.length >= 2, `${role} 没从 prompt 里取到参数键，取到的：${provided.join(', ')}`);
    assert.ok(read_.length >= 2, `${role} 没从脚本里取到读取的键，取到的：${read_.join(', ')}`);

    for (const key of provided) {
      assert.ok(read_.includes(key), `${role} 传了 ${key}，脚本里没人读它 —— 白传`);
    }
  }
});

test('脚本要的必填参数，工作流都传了', () => {
  // 脚本开头那句 throw 是硬要求：少一个就整轮失败。单独核一遍，
  // 是因为「传了但拼错大小写」在上一测试里看不出来（键名不同就各算一个）。
  for (const role of ROLES) {
    const required = argsRequiredBy(role);
    assert.ok(required.length, `${role} 的脚本开头没有那句「args 需要 {…}」，这条检查对它等于没做`);
    const provided = argsProvidedBy(role);
    for (const key of required) {
      assert.ok(provided.includes(key), `${role} 的脚本必需 ${key}，工作流的 args 里没有`);
    }
  }
});

test('脚本读的每个参数，工作流都传了', () => {
  // 反方向：脚本读 `args?.x`，工作流没传 → 拿到 undefined。带默认值的（`|| ''`）不算
  // 漏传，所以只在脚本里那一行没有默认值时才算错。
  for (const role of ROLES) {
    const provided = argsProvidedBy(role);
    const src = read(WORKFLOW_SCRIPTS[role]);
    for (const key of argsReadBy(role)) {
      const line = src.split('\n').find((l) => l.includes(`args?.${key}`)) || '';
      if (/\|\|/.test(line)) continue; // 有默认值，不传也不会 undefined
      assert.ok(provided.includes(key), `${role} 的脚本读 ${key} 且没有默认值，工作流却没传 —— 会拿到 undefined`);
    }
  }
});

test('每个工作流脚本都在仓库里，且开头合法', () => {
  // 这些脚本原先在 .qwen/workflows 下被 .gitignore 排除，CI checkout 里根本没有：
  // 本地跑得好好的，runner 上斜杠命令找不到定义，整轮直接失败。
  for (const role of ROLES) {
    const script = WORKFLOW_SCRIPTS[role];
    assert.ok(existsSync(path.join(ROOT, script)), `${script} 不在仓库里，CI 读不到`);

    const src = read(script);
    const meta = src.match(/^export const meta = \{[\s\S]*?\n\};/m);
    assert.ok(meta, `${script} 开头没有 export const meta`);
    assert.match(meta[0], /name: '[^']+'/, `${script} 的 meta 没有 name`);
    assert.match(meta[0], /phases: \[/, `${script} 的 meta 没有 phases`);

    // 沙箱里没有这些：用了会被拒，而且是在所有代理跑之前就拒
    assert.doesNotMatch(src, /\bDate\.(now|parse|UTC)\b|new Date\(|\bMath\.random\(/, `${script} 用了 Date / Math.random，沙箱会直接拒绝`);
    assert.doesNotMatch(src, /^\s*import\s/m, `${script} 不能 import`);
    // 顶层 return 是工作流脚本的返回值；反过来写进函数里才算错，这里不管。
    assert.match(src, /^return \{/m, `${script} 没有返回值，这一轮的结果取不到`);
  }
});

test('工作流的 prompt 指向同名脚本，两边名字对得上', () => {
  // 命令名来自文件名。提示词里写成 /clara 而文件叫 clara-triage.js，那一条命令不存在，
  // 而 CLI 对「找不到命令」的表现是把整句当普通文本回一句 —— 退出码仍是 0。
  for (const role of ROLES) {
    const command = commandOf(WORKFLOW_SCRIPTS[role]);
    const yml = read(workflowPath(role));
    assert.match(
      yml,
      new RegExp(`^\\s+prompt: >-\\n\\s+${command.replace('/', '\\/')} \\{`, 'm'),
      `${role} 的 prompt 没指向 ${command}（命令名取自 ${WORKFLOW_SCRIPTS[role]} 的文件名）`,
    );
  }
});

test('四个人的工作流都打开了动态工作流，并把墙钟放开', () => {
  // 不开这条，`/clara-triage {…}` 只是普通命令，工作流脚本根本不执行 —— 而 CLI 不会报错。
  // 墙钟不放开（默认 30 分钟）会在最后一拍把核对砍掉，那一拍才是发现「说做了但没做」的地方。
  for (const role of ROLES) {
    const yml = read(workflowPath(role));
    assert.match(yml, /^\s+QWEN_CODE_ENABLE_WORKFLOWS: '1'$/m, `${role} 没打开动态工作流，脚本不会执行`);
    assert.match(
      yml,
      /^\s+QWEN_CODE_MAX_WORKFLOW_SECONDS: '86400'$/m,
      `${role} 的墙钟没放开，默认 30 分钟会砍掉最后那一拍`,
    );
  }
});

test('四个人都有「工作流没跑完就判失败」那一步', () => {
  // CLI 在工作流抛错时仍然退出 0，只把「Workflow failed: …」写进工具的返回内容。
  // 缺了这一步，一次什么都没做的运行看起来是绿的 —— 这是这一层最坏的形状。
  for (const role of ROLES) {
    const yml = read(workflowPath(role));
    assert.match(yml, /node \.github\/scripts\/workflow-run\.mjs/, `${role} 没有 workflow-run.mjs 那一步`);
    assert.match(
      yml,
      new RegExp(`^\\s+ROLE: '${role}'$`, 'm'),
      `${role} 的 workflow-run 那一步没把 ROLE 传对，报错会指向别人`,
    );
  }
});

// ───────────────── 脚本与本地 action 必须先 checkout ─────────────────
//
// 判据从「内联 JS」搬成「工作区里的 .mjs」之后，步骤的位置就成了判据的一部分：
// checkout 之前工作区是空的，node 报 Cannot find module。真出过一次 —— 周正那份
// 工作流的 context 步骤排在 checkout 之前，PR 一打开那一轮直接失败。
//
// 反过来还有一个陷阱：原先 checkout 的 `if` 引用了 context 的 skip 输出。位置一换，
// 依赖就成环了，所以 checkout 必须无条件执行。

/** 按 `- name:` 切出每个步骤（四份工作流里 steps 都缩进 6 格）。 */
function stepBlocks(yml) {
  const lines = yml.split('\n');
  const starts = [];
  lines.forEach((line, i) => {
    if (/^ {6}- name:/.test(line)) starts.push(i);
  });
  return starts.map((start, k) => {
    const end = k + 1 < starts.length ? starts[k + 1] : lines.length;
    const block = lines.slice(start, end).join('\n');
    const name = (block.match(/^ {6}- name: '([^']*)'/m) || [])[1] || `第 ${k + 1} 个步骤`;
    return { name, block };
  });
}

/** 这一步骤是否要用工作区里的文件：本地 action，或 .github/scripts/ 下的脚本。 */
// 注释要剥掉：说明文字里也会提到 .github/scripts/context.mjs，那不是真的调用。
const needsWorkspace = (block) => {
  const code = block
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
  return /uses: '\.\//.test(code) || /\.github\/scripts\/[a-z-]+\.mjs/.test(code);
};

const isCheckout = (block) => /uses: 'actions\/checkout@/.test(block);

test('用工作区文件的步骤都排在 checkout 之后', () => {
  for (const role of ROLES) {
    const steps = stepBlocks(read(workflowPath(role)));
    const checkoutAt = steps.findIndex((s) => isCheckout(s.block));
    assert.ok(checkoutAt >= 0, `${role} 没有 checkout 步骤`);

    steps.forEach((step, i) => {
      if (!needsWorkspace(step.block)) return;
      assert.ok(
        i > checkoutAt,
        `${role} 的「${step.name}」要用工作区里的文件，却排在 checkout 之前（会报 Cannot find module）`,
      );
    });
  }
});

test('checkout 不依赖判断步骤的输出 —— 那会成环', () => {
  for (const role of ROLES) {
    const steps = stepBlocks(read(workflowPath(role)));
    const checkout = steps.find((s) => isCheckout(s.block));
    assert.ok(checkout, `${role} 没有 checkout 步骤`);
    assert.doesNotMatch(
      checkout.block,
      /steps\.context\.outputs/,
      `${role} 的 checkout 用到了 context 的输出，而 context 需要先 checkout`,
    );
  }
});

// ───────────────── 脚本读的变量名，工作流必须真的传 ─────────────────
//
// 这类错误一次都不会报：脚本读到 undefined，判据恒为假，日志里看起来一切正常。
// 真出过一次 —— 工作流传 SENDER_TYPE，脚本读 SENDER_IS_BOT，「机器人重复叫醒
// 就不评」这条判据在 CI 里从未生效。纯函数单测抓不到，因为传进去的是测例自己
// 造的对象；只有把两边的名字放在一起比对才看得见。

/** 从 context.mjs 里按 runXxx 函数切段，取出每段读的 process.env 变量名。 */
function envReadBy(role) {
  const src = read('.github/scripts/context.mjs');
  const fn = `function run${role[0].toUpperCase()}${role.slice(1)}(`;
  const start = src.indexOf(fn);
  assert.ok(start >= 0, `context.mjs 里找不到 ${fn}`);
  const rest = src.slice(start + fn.length);
  const end = rest.search(/^function /m);
  const body = end >= 0 ? rest.slice(0, end) : rest;
  // main() 里读的 REPOSITORY 是四人共用的，这里只看角色自己的那段
  return [...new Set([...body.matchAll(/process\.env\.([A-Z_][A-Z0-9_]*)/g)].map((m) => m[1]))];
}

/** 工作流里那个 context.mjs 步骤的 env 块给了哪些键。 */
function envProvidedBy(role) {
  const yml = read(workflowPath(role));
  const marker = `node .github/scripts/context.mjs ${role}`;
  const at = yml.indexOf(marker);
  assert.ok(at >= 0, `${role} 的工作流里没有 ${marker}`);
  // 往回找到这个步骤的开头（- name:），取到 run: 之前
  const head = yml.lastIndexOf('\n      - name:', at);
  const step = yml.slice(head, at);
  const envAt = step.indexOf('env:');
  const envBlock = envAt >= 0 ? step.slice(envAt) : '';
  return [...new Set([...envBlock.matchAll(/^ {10}([A-Z_][A-Z0-9_]*):/gm)].map((m) => m[1]))];
}

test('context.mjs 每个角色读的环境变量，工作流都传了', () => {
  for (const role of ROLES) {
    const provided = envProvidedBy(role);
    for (const key of envReadBy(role)) {
      // GITHUB_OUTPUT 由 runner 给，不用工作流声明
      if (key === 'GITHUB_OUTPUT') continue;
      assert.ok(
        provided.includes(key),
        `${role} 的 context 步骤没传 ${key}，脚本读到的是 undefined（判据会恒为假且不报错）`,
      );
    }
  }
});

test('这条检查本身不是空转：两侧都真的取到了东西', () => {
  // 比对为空集也会「通过」，所以要证明每侧都取到了非空的名字集合
  for (const role of ROLES) {
    assert.ok(envReadBy(role).length > 0, `${role} 没取到任何环境变量名，这条检查对它等于没做`);
    assert.ok(envProvidedBy(role).length > 0, `${role} 的工作流没取到任何 env 键，这条检查对它等于没做`);
  }
  // 那个真出过事的键，两侧都要在
  assert.ok(envReadBy('frank').includes('SENDER_TYPE'), `runFrank 里没读 SENDER_TYPE，取到的：${envReadBy('frank').join(', ')}`);
  assert.ok(envProvidedBy('frank').includes('SENDER_TYPE'), 'frank 的 context 步骤没传 SENDER_TYPE');
});

// ─────────────────── 闸门那三档权限：搬了 job 也别漏 ───────────────────
//
// 闸门要读 statusCheckRollup，需要 actions / checks / statuses 三档 read。
// 它现在在 qwen-miles.yml 里是独立的 gate job（和模型那一轮各有各的超时），
// 权限写在 gate 里；而被调用工作流不能自己抬权限 —— 调用方少给一档，整次运行
// 就是 startup_failure：没有 job、没有日志、没有评论，只有一条失败记录。
//
// 所以两侧一起核：gate job 要声明这三档，每个调用 qwen-miles.yml 的 job 也要给。

const GATE_CHECK_SCOPES = ['actions', 'checks', 'statuses'];

/** 调用 qwen-miles.yml 的工作流（自己那份不含这行，天然被滤掉）。 */
const milesCallers = readdirSync(path.join(ROOT, '.github', 'workflows'))
  .filter((f) => f.endsWith('.yml'))
  .map((f) => path.join('.github', 'workflows', f))
  .filter((f) => read(f).includes("uses: './.github/workflows/qwen-miles.yml'"));

/** 一份工作流里，那个调用 qwen-miles.yml 的 job 的 permissions 块声明了哪些键。 */
function callerPermissionKeys(file) {
  const lines = read(file).split('\n');
  const callAt = lines.findIndex((line) => line.includes("uses: './.github/workflows/qwen-miles.yml'"));
  assert.notEqual(callAt, -1, `${file} 里找不到调用 qwen-miles.yml 的 job`);

  // 往回找 job 开头：2 空格缩进的 `名字:`
  let head = callAt;
  while (head > 0 && !/^ {2}[a-z][a-z0-9-]*:$/.test(lines[head])) head -= 1;
  assert.ok(head > 0, `${file} 里取不到调用 qwen-miles.yml 的 job 名`);

  // permissions: 写在 uses: 之后，往下找
  let i = callAt + 1;
  for (; i < lines.length; i += 1) if (lines[i] === '    permissions:') break;
  assert.ok(i < lines.length, `${file} 的 ${lines[head].trim()} 没有 permissions: 块`);

  const keys = [];
  for (let j = i + 1; j < lines.length; j += 1) {
    // 块内注释不能当成块结束，否则注释后面那几档会被漏掉
    if (/^ {6}#/.test(lines[j])) continue;
    // pull-requests 带连字符，字符类里得有 -
    const m = /^ {6}([a-z_-]+):/.exec(lines[j]);
    if (!m) break;
    keys.push(m[1]);
  }
  return keys;
}

test('gate job 自己声明了读检查项的那三档', () => {
  const lines = read(workflowPath('miles')).split('\n');
  const gateAt = lines.indexOf('  gate:');
  assert.notEqual(gateAt, -1, 'qwen-miles.yml 里没有独立的 gate job，闸门是不是又被塞回 work 里了');

  const block = lines.slice(gateAt).join('\n');
  const permAt = block.indexOf('    permissions:');
  assert.ok(permAt >= 0, 'gate job 没有 permissions: 块');
  const stepsAt = block.indexOf('    steps:', permAt);
  const perms = block.slice(permAt, stepsAt >= 0 ? stepsAt : undefined);

  for (const key of GATE_CHECK_SCOPES) {
    assert.match(
      perms,
      new RegExp(`^ {6}${key}: 'read'$`, 'm'),
      `gate job 少声明 ${key}: read，闸门查 statusCheckRollup 会报 Resource not accessible by integration`,
    );
  }
});

test('每个调用 qwen-miles.yml 的 job 都给全了那三档', () => {
  assert.ok(milesCallers.length >= 2, `只找到 ${milesCallers.length} 处调用，dispatch 与 patrol 应该都在`);

  for (const file of milesCallers) {
    const keys = callerPermissionKeys(file);
    for (const key of GATE_CHECK_SCOPES) {
      assert.ok(
        keys.includes(key),
        `${file} 少给 ${key}，被调用的工作流抬不了权限，整次运行 startup_failure`,
      );
    }
  }
});
