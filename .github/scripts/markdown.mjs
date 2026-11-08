/**
 * 正文里的哪些部分是「写给人看的话」，哪些是「引用的代码」。
 *
 * 路由（route.mjs）和评审结论（review.mjs）都靠正文里的 `<!-- qwen:... -->` 标记
 * 做判断，而两处都踩过同一个坑：贴一段日志、一段 diff、一个命令是写描述的常规做法，
 * 那些片段里出现标记是因为作者在引用它，不是在要求它生效。
 *
 * 实际发生过：某条 PR 的描述里为了说明「这条评论带了交接标记」贴了一行行内代码，
 * 这条 PR 打开时就被从周正手里抢给了陈实 —— 贴证据的人并不想改路由。
 *
 * 所以两处都先过一遍这里再判断。
 */

const FENCE_LINE = /^ {0,3}(`{3,}|~{3,})/;

/**
 * 去掉正文里被代码包起来的部分（围栏块与行内代码），只留真正写给人看的话。
 *
 * 围栏未闭合时把剩余部分一并去掉，与 Markdown 的渲染一致 —— 宁可漏认一条标记，
 * 也不要在引用块里认出一条根本不存在的指令。
 */
export function stripCode(text) {
  const lines = [];
  let fence = null;
  for (const line of String(text || '').split('\n')) {
    const open = FENCE_LINE.exec(line);
    if (fence) {
      if (open && open[1][0] === fence[0] && open[1].length >= fence.length) fence = null;
      lines.push('');
    } else if (open) {
      fence = open[1];
      lines.push('');
    } else {
      lines.push(line);
    }
  }
  return lines.join('\n').replace(/(`+)([^\n]*?)\1/g, '');
}

// 没勾的 checkbox：列表项开头 + `[ ]`，后面必须是空白或行尾。
// 缩进（嵌套项）与有序列表（`1. [ ]`）都算，GitHub 两种都渲染成任务列表。
const UNCHECKED = /^([ \t]*(?:[-*+]|\d+[.)])[ \t]+)\[ \](?=[ \t]|$)/;

/**
 * 把没勾的 checkbox 勾上，围栏块里面的原样留着。
 *
 * 为什么不能直接全局替换：Issue 里贴一段「任务列表长这样」的围栏是常事，
 * 把那段里的 `- [ ]` 也勾掉，等于改写了人家引用的示例。这跟 stripCode 是同一条
 * 理由的两种用法 —— 那里的错法是认出一条不存在的指令，这里的错法是改掉一段
 * 别人引用的原文。
 *
 * 返回 `{ body, ticked }`：ticked 是这一次勾掉了几项，0 表示不用回写。
 */
export function tickCheckboxes(text) {
  const lines = [];
  let fence = null;
  let ticked = 0;
  for (const line of String(text || '').split('\n')) {
    const open = FENCE_LINE.exec(line);
    if (fence) {
      if (open && open[1][0] === fence[0] && open[1].length >= fence.length) fence = null;
      lines.push(line);
      continue;
    }
    if (open) {
      fence = open[1];
      lines.push(line);
      continue;
    }
    if (UNCHECKED.test(line)) {
      lines.push(line.replace(UNCHECKED, '$1[x]'));
      ticked += 1;
      continue;
    }
    lines.push(line);
  }
  return { body: lines.join('\n'), ticked };
}
