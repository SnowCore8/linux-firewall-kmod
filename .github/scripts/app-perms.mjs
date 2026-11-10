/**
 * 解析 `setup-app.mjs --perms` 的取值。
 *
 * 为什么要单独一档级别：四个身份的权限并不一样 —— 顾清与叶澜只需要 `issues: write`，
 * 周正需要 `pull_requests: write` 但只读 Issue，陈实才需要 `contents: write`。
 * 建 App 时一律点成 Read and write，等于给顾清开了一条她能推代码、周正能改 Issue 的路，
 * 而这些能力他们从来不用 —— 权限只该开到用得上的那一档。
 *
 * 写法：`名字` 或 `名字:级别`，逗号分隔。名字不带级别时默认 write，
 * 这样老的 `--perms contents,issues` 行为不变。级别不区分大小写，认几个常见别名。
 */

const LEVELS = {
  none: 'none',
  'no-access': 'none',
  read: 'read',
  ro: 'read',
  'read-only': 'read',
  write: 'write',
  rw: 'write',
  'read-write': 'write',
};

/** GitHub 建 App 页面上的菜单项文案，按 hidden input 的值对应。 */
export const MENU_LABEL = {
  none: 'No access',
  read: 'Read-only',
  write: 'Read and write',
};

export const normalizeLevel = (raw) => {
  const key = String(raw ?? '').trim().toLowerCase();
  return LEVELS[key] || null;
};

/**
 * @param {string} spec 例：`contents:read,issues:write,pull_requests:read`
 * @returns {{name: string, level: string}[]} 按给出的顺序
 * @throws 名字为空、级别不认识、同名项重复时抛错 —— 静默忽略会让人以为权限配上了
 */
export function parsePerms(spec) {
  const parts = String(spec ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (!parts.length) throw new Error('--perms 是空的：至少给一项，例 contents:read,issues:write');

  const seen = new Set();
  return parts.map((part) => {
    const at = part.indexOf(':');
    const name = (at < 0 ? part : part.slice(0, at)).trim();
    const rawLevel = at < 0 ? 'write' : part.slice(at + 1);

    if (!name) throw new Error(`权限项缺少名字：${JSON.stringify(part)}`);
    if (seen.has(name)) throw new Error(`权限项重复：${name}（写了两遍，不知道按哪个算）`);
    seen.add(name);

    const level = normalizeLevel(rawLevel);
    if (!level) {
      throw new Error(
        `不认识的级别：${name}:${rawLevel.trim()}（只能是 none / read / write）`,
      );
    }
    return { name, level };
  });
}

/** 拼成人看的说明，写进日志和交付里用。 */
export const describePerms = (perms) =>
  perms.map((p) => `${p.name}=${p.level}`).join(' ');
