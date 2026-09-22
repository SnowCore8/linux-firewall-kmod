// 搜索关键词高亮：把文本中命中关键词的片段用 <mark> 包起来
//
// 用途：列表页搜索时高亮 IP / 理由 / Jail 名，让用户在长文本里快速定位命中位置。
//
// 安全与正确性要点：
//   1. 关键词必须做正则转义后再拼 RegExp —— IP 里的 `.`、CIDR 里的 `/`、
//      IPv6 里的 `:`、以及用户随手输入的 `(` 都会让裸拼的正则抛异常或误匹配。
//   2. 命中判断用「小写集合比对」而不是 RegExp.test —— 带 g 标志的正则实例
//      在 test() 之间会保留 lastIndex，连续调用会出现「隔一个漏一个」的经典坑。
//
// 控制台形态：命中使用主题的 primary-soft 底 + primary-strong 字（弱底色衬托，
// 不用荧光高亮抢夺视线），圆角 1px 与全局的 2px 圆角语言保持一致。
import { useMemo } from 'react'
import type { CSSProperties, ReactNode } from 'react'

export interface HighlightTextProps {
  /** 原始文本 */
  text: string
  /** 搜索关键词；支持空格分隔的多个词，全部命中即高亮 */
  query?: string
  className?: string
  style?: CSSProperties
}

/** 转义正则元字符，避免用户输入破坏正则结构 */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** 把文本切成「命中 / 未命中」的片段序列 */
function splitSegments(text: string, query: string | undefined): { text: string; hit: boolean }[] {
  const terms = (query ?? '')
    .trim()
    .split(/\s+/)
    .filter((term) => term.length > 0)

  if (terms.length === 0 || text.length === 0) return [{ text, hit: false }]

  // 命中判断用小写集合（未转义的原词），与正则拆分保持解耦
  const termSet = new Set(terms.map((term) => term.toLowerCase()))
  const pattern = new RegExp(`(${terms.map(escapeRegExp).join('|')})`, 'gi')

  return text
    .split(pattern) // 捕获组会把命中片段一并保留在结果里
    .filter((part) => part.length > 0)
    .map((part) => ({ text: part, hit: termSet.has(part.toLowerCase()) }))
}

export function HighlightText({ text, query, className, style }: HighlightTextProps) {
  const segments = useMemo(() => splitSegments(text, query), [text, query])

  // 无命中时直接返回纯文本节点，避免多包一层无意义的 span
  if (segments.length === 1 && !segments[0].hit) {
    return (
      <span className={className} style={style}>
        {text}
      </span>
    )
  }

  return (
    <span className={className} style={style}>
      {segments.map((segment, index): ReactNode =>
        segment.hit ? (
          <mark
            key={`${index}-${segment.text}`}
            style={{
              padding: '0 1px',
              borderRadius: 1,
              background: 'var(--fw-primary-soft)',
              color: 'var(--fw-primary-strong)',
              fontWeight: 600,
            }}
          >
            {segment.text}
          </mark>
        ) : (
          <span key={`${index}-${segment.text}`}>{segment.text}</span>
        ),
      )}
    </span>
  )
}

export default HighlightText
