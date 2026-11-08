/**
 * dispatch 的路由规则：一条动静该由谁来处理。
 *
 * 为什么单独成文件：这套判断是整个系统最容易出错的一处 —— 判断错了会导致该处理的
 * 动静被静默丢弃（被取消的运行 jobs 为空，日志里什么都不留），或者两个人的活互相顶掉。
 * 这种规则必须能单测，所以它不能塞在 workflow 的内联脚本里。
 *
 * 这里只做**纯判断**：给同样的事件与数据，永远得到同样的结论。所有 I/O
 * （查 PR 分支、数评论、发「交接额度用完」的说明）都留在 workflow 里。
 * 调用方遵守一个约定：返回 `{ kind: 'need-pull' }` 时，去把 PR 的分支名查出来，
 * 带上 `pull` 再调一次 —— 这个函数没有副作用，重入是安全的。
 *
 * 测试：`node --test .github/scripts/route.test.mjs`
 */

import { stripCode } from './markdown.mjs';

export const ROLES = ['clara', 'nora', 'miles', 'frank'];

/** 写给人看的话里一律用中文名 */
export const PEOPLE = { clara: '顾清', nora: '叶澜', miles: '陈实', frank: '周正' };

/** 这几个别名来自更早的职称命名，仍会出现在最近的评论里：读的时候认下来，写一律用正式名 */
export const ALIASES = { triager: 'clara', product: 'nora', engineer: 'miles', reviewer: 'frank' };

export const asPerson = (token) => {
  const key = (token || '').toLowerCase();
  const id = ALIASES[key] ?? key;
  return ROLES.includes(id) ? id : null;
};

// reason 用 [\s\S]*? 而不是 [^>]*?：后者遇到 reason 里一个 `>` 就整条匹配不上，
// 交接被静默丢弃 —— 作者以为自己交出去了，实际谁也没被叫醒。宁可把 `>` 当普通字符。
const HANDOFF_RE = /<!--\s*qwen:handoff=([a-z]+)\s+reason=([\s\S]*?)\s*-->/i;
const CALL_RE = /<!--\s*qwen:to=([a-z]+)\s*-->/i;

export const OWN_MARKER = '<!-- qwen:opened-by=agent -->';
export const ROLE_MARKER = '<!-- qwen:role=';

export const isOwnIssue = (text) => (text || '').includes(OWN_MARKER);
export const isOwnComment = (text) => (text || '').includes(ROLE_MARKER);

/** 我方分支的命名约定：`qwen-fix-<issue 号>` */
export const OWNED_PREFIX = 'qwen-fix-';
export const isOwnedBranch = (ref) => String(ref || '').startsWith(OWNED_PREFIX);
export const issueNumberOfBranch = (ref) =>
  (isOwnedBranch(ref) ? String(ref).slice(OWNED_PREFIX.length) : '');

export const parseHandoff = (text) => {
  const m = HANDOFF_RE.exec(stripCode(text));
  if (!m) return null;
  const role = asPerson(m[1]);
  return role ? { role, reason: m[2].trim() } : null;
};

export const parseCall = (text) => {
  const m = CALL_RE.exec(stripCode(text));
  if (!m) return null;
  const role = asPerson(m[1]);
  return role ? { role } : null;
};

export const isCommentEvent = (eventName) =>
  eventName === 'issue_comment' || eventName === 'pull_request_review_comment';

const DAY = 24 * 60 * 60 * 1000;

/**
 * 最近 24 小时的机器人评论。只算机器人 —— 人类写的交接与点名是明确指令，
 * 不该被防打转闸门拦掉，否则机器人把额度用完之后人也叫不动人。
 */
export function recentBotComments(comments, now) {
  const since = now - DAY;
  return (comments || []).filter(
    (c) => c.user?.type === 'Bot' && Date.parse(c.created_at) > since,
  );
}

export const countRecentHandoffs = (botComments) =>
  (botComments || []).filter((c) => HANDOFF_RE.test(stripCode(c.body))).length;

export const recentCalls = (botComments) =>
  (botComments || []).filter((c) => CALL_RE.test(stripCode(c.body)));

/** 距离最近一次点名过了多久（分钟）。没有点过名返回 Infinity。 */
export function minutesSinceLastCall(calls, now) {
  const last = (calls || []).reduce((latest, c) => Math.max(latest, Date.parse(c.created_at) || 0), 0);
  return last ? (now - last) / 60000 : Infinity;
}

const ignore = (why) => ({ kind: 'ignore', why });
const assign = (role, number, onPr, reason, extra = {}) => ({
  kind: 'assign',
  role,
  number,
  onPr,
  reason,
  issueNumber: extra.issueNumber ?? '',
  prNumber: extra.prNumber ?? '',
  headRef: extra.headRef ?? '',
});

/**
 * 决定这条动静归谁。返回的 kind：
 *   assign          —— 派活，字段齐全
 *   ignore          —— 不归任何人（why 说明原因，会写进日志）
 *   fail            —— 配置或输入有误，应当让这次运行失败
 *   handoff-limit   —— 自动交接超限，调用方需要发一条说明再结束
 *   need-pull       —— 判断需要 PR 的分支名，调用方查来后带上 pull 重调
 */
export function route(input) {
  const {
    eventName,
    action,
    payload = {},
    senderType,
    authorAssociation,
    mention,
    pull,
    gates = {},
    manual = {},
  } = input;

  const trusted = ['OWNER', 'MEMBER', 'COLLABORATOR'];

  // ── 手动触发：完全由人指定，不做任何推断 ──
  if (eventName === 'workflow_dispatch') {
    const role = asPerson(manual.role);
    if (!role) return { kind: 'fail', why: `不认识的接手人：${manual.role}` };

    const number = Number(manual.number);
    const onPr = Boolean(payload.issueIsPr);
    if (onPr && !pull) return { kind: 'need-pull' };

    return assign(role, number, onPr, '手动在工作流界面指定', {
      issueNumber: onPr ? '' : number,
      prNumber: onPr ? number : '',
      headRef: pull?.headRef || '',
    });
  }

  // 事件正文：评论 / 评审用自己的正文，其余用 Issue 或 PR 的正文
  const body = isCommentEvent(eventName)
    ? payload.commentBody
    : eventName === 'pull_request_review'
      ? payload.reviewBody
      : payload.issueBody || payload.prBody;

  // 机器人在评论里既没交接也没点名，就是在自言自语：只在原地留个记录，不叫醒谁。
  // 这条闸门只针对评论类事件 —— 评审、开 PR 这些事件本身就带着明确意图，
  // 周正交 APPROVED 是要陈实来合并，正文里不会有交接标记。
  if (isCommentEvent(eventName) && senderType === 'Bot'
      && !parseHandoff(body) && !parseCall(body)) {
    return ignore('机器人的评论，既没有交接也没有点名，忽略');
  }

  if (senderType !== 'Bot' && !trusted.includes(authorAssociation)) {
    return ignore(`作者关联为 ${authorAssociation}，无权限，忽略`);
  }

  // ── 1. 交接优先：不区分人类还是机器人，只看评论里的标记 ──
  const handoff = parseHandoff(body);
  if (handoff) {
    const number = payload.issueNumber || payload.prNumber;

    // 防打转闸门只拦机器人自己发起的转交；人写的交接永远放行
    if (senderType === 'Bot') {
      const recent = gates.recentHandoffs ?? 0;
      // 用 >= 而不是 >：gates.recentHandoffs 数的是「本次之前」已经发生的交接
      // （dispatch.mjs 把触发本次运行的那条评论剔掉了），所以刚好用满 20 次时，
      // 这条就是第 21 次，该停下。早先这里写 >，靠的是「本次这条也算在计数里」——
      // 那个前提是点名冷却永远失效的同一个原因，一并改掉。
      if (recent >= (gates.maxHandoffs ?? 20)) {
        return {
          kind: 'handoff-limit',
          role: handoff.role,
          number,
          recent,
          max: gates.maxHandoffs ?? 20,
        };
      }
    }

    const onPr = Boolean(payload.issueIsPr || payload.prNumber);
    if (onPr && !pull) return { kind: 'need-pull' };
    const headRef = pull?.headRef || '';
    const linkedIssue = issueNumberOfBranch(headRef);

    return assign(handoff.role, number, onPr, `交接：${handoff.reason}`, {
      issueNumber: onPr ? linkedIssue : number,
      prNumber: onPr ? number : '',
      headRef,
    });
  }

  // ── 1.5 点名：叫醒对方来读，但不要求他动手 ──
  // 有冷却和每日上限，否则两个人互相点名能一直转下去。同样只约束机器人。
  const call = parseCall(body);
  if (call) {
    const number = payload.issueNumber || payload.prNumber;

    if (senderType === 'Bot') {
      const calls = gates.calls || [];
      const waited = minutesSinceLastCall(calls, gates.now ?? Date.now());

      if (calls.length >= (gates.maxCalls ?? 40)) {
        return ignore(`最近 24 小时已点名 ${calls.length} 次，达到上限 ${gates.maxCalls ?? 40}，不再叫醒`);
      }
      if (waited < (gates.cooldownMinutes ?? 10)) {
        return ignore(`距上次点名才 ${Math.round(waited)} 分钟，冷却 ${gates.cooldownMinutes ?? 10} 分钟，暂不叫醒`);
      }
    }

    const onPr = Boolean(payload.issueIsPr || payload.prNumber);
    if (onPr && !pull) return { kind: 'need-pull' };
    const headRef = pull?.headRef || '';
    const linkedIssue = issueNumberOfBranch(headRef);

    return assign(call.role, number, onPr, '同事点名让你看这条', {
      issueNumber: onPr ? linkedIssue : number,
      prNumber: onPr ? number : '',
      headRef,
    });
  }

  // ── 2. 新 Issue / 重开 → 顾清 ──
  if (eventName === 'issues' && ['opened', 'reopened'].includes(action)) {
    return assign('clara', payload.issueNumber, false, 'Issue 新建或重开', {
      issueNumber: payload.issueNumber,
    });
  }

  // ── 3. 指派给我方账号 → 陈实接手 ──
  // 真实用法是人把 Issue 指派给 AI 账号：assignee 是机器人、actor 是人，两者永远
  // 不相等 —— 早先拿 assignee 和 actor 比，这条规则因此从来没生效过，且安静到没人发现。
  //
  // 判「是不是我方」只看账号类型，不看登录名：四个角色各有自己的 App，登录名不在
  // 代码里；仓库里其它地方（isOwnIssue / isOwnComment）也是用标记而不是登录名。
  //
  // 但不接受机器人发起的指派：那等于「自己叫醒自己」，没有终止条件 —— 一次指派
  // 一轮模型运行，写错就是无限跑。角色之间交接有专门的标记，带冷却和每日上限。
  if (eventName === 'issues' && action === 'assigned') {
    const assignee = payload.assignee || '';
    if (payload.assigneeType !== 'Bot') {
      return ignore(`指派给 ${assignee || '(空)'}，不是我方账号，忽略`);
    }
    if (senderType === 'Bot') {
      return ignore(`机器人把 ${assignee} 指派给自己，不当指令（交接请用交接标记）`);
    }
    // PR 也会发 issues.assigned（GitHub 对 opened / assigned / labeled 这些 action
    // 同时发 issues 事件）。不分开看的话，指派一个 PR 会被当成 Issue 派下去 ——
    // 陈实会去读一个没有 checkout 分支的 PR。
    const onPr = Boolean(payload.issueIsPr);
    if (onPr && !pull) return { kind: 'need-pull' };
    const headRef = pull?.headRef || '';
    return assign('miles', payload.issueNumber, onPr, `被指派给 ${assignee}`, {
      issueNumber: onPr ? issueNumberOfBranch(headRef) : payload.issueNumber,
      prNumber: onPr ? payload.issueNumber : '',
      headRef,
    });
  }

  // ── 4. 新 PR → 周正 ──
  if (eventName === 'pull_request' && ['opened', 'ready_for_review'].includes(action)) {
    if (payload.prIsFork) return ignore('来自 fork 的 PR，不自动评审');
    return assign('frank', payload.prNumber, true, 'PR 打开或转正', {
      prNumber: payload.prNumber,
      headRef: pull?.headRef || payload.prHeadRef || '',
    });
  }

  // ── 5. 收到评审 → 我方 PR 交给陈实处理意见 ──
  // 判据是分支名：他人 PR 的评审结果不归我方跟进。
  if (eventName === 'pull_request_review') {
    const ref = pull?.headRef || payload.prHeadRef || '';
    if (!isOwnedBranch(ref)) return ignore('他人的 PR，评审结果不需要我方跟进');
    return assign('miles', payload.prNumber, true, `收到评审：${payload.reviewState}`, {
      issueNumber: issueNumberOfBranch(ref),
      prNumber: payload.prNumber,
      headRef: ref,
    });
  }

  // ── 6. 评论 / 行内评论 ──
  if (isCommentEvent(eventName)) {
    const number = payload.issueNumber;
    const onPr = Boolean(payload.issueIsPr);
    // mention 为空时 `includes('')` 永远为真，会把每一条评论都当成被提及。
    // workflow 那边有默认值兜着，这里也不留这个洞。
    const needle = (mention || '').toLowerCase();
    const mentioned = Boolean(needle) && (body || '').toLowerCase().includes(needle);

    if (onPr) {
      // 是不是我方 PR，只能看分支名；没有就请调用方取一次再来。
      // 放在 mentioned 之前：我方 PR 上的回复不管有没有 @ 都该由陈实处理。
      if (!pull) return { kind: 'need-pull' };
      const ref = pull.headRef || '';
      // 我方 PR 上的任何回复都由陈实处理
      if (isOwnedBranch(ref)) {
        return assign('miles', number, true, mentioned ? '被提及' : '我方 PR 上的回复', {
          issueNumber: issueNumberOfBranch(ref),
          prNumber: number,
          headRef: ref,
        });
      }
      if (mentioned) {
        return assign('frank', number, true, '在他人的 PR 上被询问，仅提供评审意见', {
          prNumber: number,
          headRef: ref,
        });
      }
      return ignore('他人 PR 上未提及我方，忽略');
    }

    // Issue 上：被 @ 了，或者这条 Issue/评论本身就是我方写的
    if (mentioned || isOwnIssue(payload.issueBody) || isOwnComment(body)) {
      return assign('clara', number, false, mentioned ? '被提及' : '我方 Issue 上的回复', {
        issueNumber: number,
      });
    }
    return ignore('未提及我方且不是我方 Issue，忽略');
  }

  return ignore(`未处理的动静：${eventName}.${action}`);
}

/**
 * 超限说明的正文。单独拎出来是因为它是一句给人看的话，
 * 措辞改起来不该动到路由逻辑。
 */
export function handoffLimitMessage({ role, recent, max }) {
  return [
    `自动转交暂停：最近 24 小时在这个话题上已经交接 ${recent} 次，超过上限 ${max} 次，这次交给${PEOPLE[role]}的活没有继续往下派人。`,
    '',
    '话题本身没有关掉 —— 直接在这里说要谁做、做什么，我会照办；需要连着推进更多轮，把 `AGENT_MAX_HANDOFFS` 调高即可。',
    '',
    '<!-- qwen:role=dispatch -->',
  ].join('\n');
}
