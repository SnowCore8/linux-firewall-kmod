// 日志页（二级页，位于「更多」之下；控制台式高密度）
//
// 做什么：
//   1) 实时日志（tail -f）：本页**自己**维护一条 `GET /api/v1/logs/stream` 的 EventSource，
//      命名事件 `log` 推送的是日志文件的**原始行字符串**（后端不做 JSON 包装、不含行号），
//      因此本页自行编号（单调递增）并解析 JSON 行，渲染成「时间 + 级别 + 消息」。
//   2) 历史日志：`GET /api/v1/logs` 分页查询（page/page_size），支持关键词（后端按整行
//      小写包含匹配）与级别过滤（客户端按解析出的 level 字段过滤，见下方说明）。
//   3) 过滤起点：读取/写入配置项 `clear_logs_at`（`GET|PUT /api/v1/config`），
//      并把它作为本页默认的时间下限。
// 影响什么：只有「写入 / 取消过滤起点」是写操作（改守护进程配置并持久化）；其余均为只读。
//
// 设计约定（styles/global.css 的 fw-* 令牌 + components/console.tsx 的原语）：
//   · 日志正文等宽、行高取最小（消息 12px / 原文 10px / 元信息 10px），一屏尽量多行；
//   · 凡可点元素（返回、跟随开关、清空、过滤、翻页、写入按钮）一律 ≥44px 触摸目标，
//     与数据行的紧凑密度互不妥协；
//   · 状态用 [Badge]（LIVE / RETRY / PAUSED）表达，跟随/暂停语义直接写在按钮上。
//
// 断线重连策略（与 useSse 的全局流一致，但本页独立维护，互不影响）：
//   - 收到 onerror 后主动 close，避免浏览器自带重连与本模块的调度叠加；
//   - 指数退避 delay = min(2^attempt, 30) 秒；
//   - 每个连接周期一个 errorHandled 标志 + 「当前连接对象 === 触发者」检查，杜绝重入与迟到回调。
//
// 关于级别过滤为什么放在客户端（依据代码，不是猜测）：
//   后端 log_viewer.rs 的级别匹配条件是「行内含 `[LEVEL]` 或 ` LEVEL `」，
//   而当前守护进程写出的日志行是 JSON（形如 {"msg":"…","level":"WARN","ts":"…"}），
//   其中级别写作 `"level":"WARN"`（前后是引号与冒号，没有空格包围），
//   走 POST 级别的后端过滤会命中不到任何行。为保证功能可用，本页把 level 过滤
//   放在客户端按解析后的字段做，并把 `since` 同时传给后端与客户端各过滤一次
//   （后端按行首 19 字符字典序比较，对 JSON 行是无害的直通）。

import { useEffect, useMemo, useRef, useState } from 'react'
import { Dialog, PullToRefresh, SearchBar } from 'antd-mobile'
import { DeleteOutline } from 'antd-mobile-icons'
import { useNavigate } from 'react-router-dom'

import type { LogEntry, LogPageResponse, WebuiConfigResponse } from '../api/types'
import { LOG_STREAM_URL, getConfig, getLogs, updateConfig } from '../api/endpoints'
import { withAccessToken } from '../api/auth'
import { useAsync } from '../hooks/useAsync'
import { useToast } from '../hooks/useToast'
import {
  BackLink,
  Badge,
  InlineError,
  Note,
  Panel,
  PanelLoading,
  SegTabs,
  Toolbar,
  errorText,
} from '../components/console'
import type { Tone } from '../components/console'
import { EmptyState } from '../components/EmptyState'
import { HighlightText } from '../components/HighlightText'
import { PageHeader } from '../components/PageHeader'
import { formatDatetime, formatNumber } from '../lib/format'

/** 每页条数：后端上限 500，取 100 兼顾移动端渲染与请求耗时 */
const PAGE_SIZE = 100
/** 实时缓冲上限：超过后丢弃最旧的行，避免长时间挂机把内存吃满 */
const LIVE_BUFFER_LIMIT = 300

/** 流状态：connecting 首次连接 / live 已连接 / reconnecting 断开重连中 */
type StreamStatus = 'connecting' | 'live' | 'reconnecting'

/** 流状态 → Badge 文案 / 色调 / 中文说明（Badge 醒目 + 中文短句可读，两者并排） */
const STREAM_META: Record<StreamStatus, { badge: string; tone: Tone; hint: string }> = {
  connecting: { badge: 'CONNECT', tone: 'default', hint: '正在连接日志流' },
  live: { badge: 'LIVE', tone: 'success', hint: '实时接收中' },
  reconnecting: { badge: 'RETRY', tone: 'warning', hint: '已断开，重连中' },
}

/** 一条实时日志：seq 为本次会话内单调递增的编号，parsed 为入队时解析一次的结果 */
interface LiveLine {
  seq: number
  /** 解析结果：入队时解析一次，避免每次渲染/过滤都重解析整条缓冲 */
  parsed: ParsedLine
}

/** 解析后的日志行；非 JSON 行只有 raw 有值 */
interface ParsedLine {
  /** 级别字段（JSON 行的 "level"），解析失败为空串 */
  level: string
  /** 时间戳字段（JSON 行的 "ts"，ISO 8601），解析失败为空串 */
  ts: string
  /** 消息字段（JSON 行的 "msg"），解析失败为空串 */
  msg: string
  /** 原始行，始终保留，用于「原文」视图与复制 */
  raw: string
}

/** 解析一行日志：JSON 行取结构化字段，非 JSON 行回退为纯文本（不是错误，只是格式不同） */
function parseLine(raw: string): ParsedLine {
  try {
    const value: unknown = JSON.parse(raw)
    if (typeof value !== 'object' || value === null) {
      return { level: '', ts: '', msg: '', raw }
    }
    const record = value as Record<string, unknown>
    return {
      level: typeof record.level === 'string' ? record.level : '',
      ts: typeof record.ts === 'string' ? record.ts : '',
      msg: typeof record.msg === 'string' ? record.msg : '',
      raw,
    }
  } catch {
    // 非 JSON（例如进程启动横幅）按纯文本处理
    return { level: '', ts: '', msg: '', raw }
  }
}

/**
 * ISO 8601 字符串 → Unix 秒。
 * JS 的 Date 只认到毫秒，而守护进程写出的 ts 带纳秒（9 位小数），
 * 因此先把小数位截断到 3 位再解析；仍解析失败返回 0（展示层会显示 N/A）。
 */
function tsToUnixSeconds(ts: string): number {
  if (ts === '') return 0
  const normalized = ts.replace(/(\.\d{3})\d+/, '$1')
  const millis = Date.parse(normalized)
  return Number.isNaN(millis) ? 0 : Math.floor(millis / 1000)
}

/** 级别 → 语义色调（与后端级别命名一致，未知级别用默认色） */
function levelTone(level: string): Tone {
  switch (level.toUpperCase()) {
    case 'ERROR':
      return 'danger'
    case 'WARN':
      return 'warning'
    case 'INFO':
      return 'primary'
    default:
      return 'default'
  }
}

/** 级别过滤选项；value 为空串表示不过滤 */
const LEVEL_OPTIONS: ReadonlyArray<{ label: string; value: string }> = [
  { label: '全部', value: '' },
  { label: 'ERROR', value: 'ERROR' },
  { label: 'WARN', value: 'WARN' },
  { label: 'INFO', value: 'INFO' },
  { label: 'DEBUG', value: 'DEBUG' },
]

/**
 * 一条日志行：元信息（编号 / 级别 / 时间）一行 + 等宽正文。
 *
 * 行高取向：正文 12px、原文与元信息 10px，段间距只留 3px——日志页的价值在密度，
 * 但每行本身不可点，因此不受 44px 触摸目标约束（页内可点控件另行保证）。
 */
function LogRow({
  leading,
  level,
  ts,
  msg,
  raw,
  query,
  last,
}: {
  /** 行首编号：实时流用 `#序号`，历史用 `L行号` */
  leading: string
  level: string
  ts: string
  msg: string
  raw: string
  /** 关键词（用于高亮，与后端过滤一致） */
  query: string
  /** 是否为列表末行：末行不画分隔线，避免与面板边框叠成双线 */
  last?: boolean
}) {
  return (
    <div style={{ padding: '3px 6px', borderBottom: last ? 0 : '1px solid var(--fw-border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <span
          className="fw-mono"
          style={{ flexShrink: 0, fontSize: 10, color: 'var(--fw-text-3)' }}
        >
          {leading}
        </span>
        {level !== '' ? <Badge tone={levelTone(level)}>{level.toUpperCase()}</Badge> : null}
        {ts !== '' ? (
          <span className="fw-mono" style={{ fontSize: 10, color: 'var(--fw-text-3)' }}>
            {formatDatetime(tsToUnixSeconds(ts))}
          </span>
        ) : null}
      </div>
      {/* 主内容：有 msg 用 msg（可读），否则直接用原始行 */}
      <div
        className="fw-mono"
        style={{ fontSize: 12, lineHeight: 1.4, wordBreak: 'break-all', color: 'var(--fw-text)' }}
      >
        <HighlightText text={msg !== '' ? msg : raw} query={query} />
      </div>
      {/* JSON 行额外保留原文：结构化字段之外的细节（tracing target、附加字段）只能从这里核对 */}
      {msg !== '' ? (
        <div
          className="fw-mono"
          style={{
            fontSize: 10,
            lineHeight: 1.4,
            wordBreak: 'break-all',
            color: 'var(--fw-text-3)',
          }}
        >
          <HighlightText text={raw} query={query} />
        </div>
      ) : null}
    </div>
  )
}

export default function Logs() {
  const navigate = useNavigate()
  const toast = useToast()

  // ------------------------------ 实时日志流 ------------------------------
  const [streamStatus, setStreamStatus] = useState<StreamStatus>('connecting')
  const [attempt, setAttempt] = useState(0)
  const [streamError, setStreamError] = useState<string | null>(null)
  const [liveLines, setLiveLines] = useState<LiveLine[]>([])
  const [paused, setPaused] = useState(false)
  /** 暂停状态放进 ref：事件回调里读取，避免闭包拿到过期的 state */
  const pausedRef = useRef(false)
  pausedRef.current = paused
  /** 本次会话内单调递增的序号（只增不减，清屏也不回退） */
  const seqRef = useRef(0)

  useEffect(() => {
    // stopped：卸载后阻止迟到的定时器/回调继续动作
    let stopped = false
    /** 当前生效的连接：用于丢弃旧连接的迟到事件（防重入的关键） */
    let source: EventSource | null = null
    let retryTimer: number | null = null
    let failures = 0

    const detach = () => {
      if (source) {
        source.close()
        source = null
      }
    }

    /** 建立一次连接；函数声明提升，便于 scheduleRetry 互相引用 */
    function connect(): void {
      if (stopped) return
      if (retryTimer !== null) {
        window.clearTimeout(retryTimer)
        retryTimer = null
      }
      detach()
      setStreamStatus(failures === 0 ? 'connecting' : 'reconnecting')

      // 令牌走 query：EventSource 无法设置 Authorization 头（见 api/auth.ts）
      const es = new EventSource(withAccessToken(LOG_STREAM_URL))
      source = es
      // 本连接周期内 error 是否已处理：避免 onerror 连续触发导致重复调度
      let errorHandled = false

      es.onopen = () => {
        if (stopped || source !== es) return
        failures = 0
        setAttempt(0)
        setStreamError(null)
        setStreamStatus('live')
      }

      // 服务端连接确认事件（事件名 connected）
      es.addEventListener('connected', () => {
        if (stopped || source !== es) return
        failures = 0
        errorHandled = false
        setStreamError(null)
        setStreamStatus('live')
      })

      // 实时日志行：后端推的就是文件里的原始行，编号由前端生成
      es.addEventListener('log', (event: Event) => {
        if (stopped || source !== es) return
        if (!(event instanceof MessageEvent) || typeof event.data !== 'string') return
        if (pausedRef.current) return
        seqRef.current += 1
        // 解析一次即入队：原先存 raw、每次过滤时整条缓冲重解析（300 行 × 每条新行）
        const line: LiveLine = { seq: seqRef.current, parsed: parseLine(event.data) }
        setLiveLines((prev) => [line, ...prev].slice(0, LIVE_BUFFER_LIMIT))
      })

      // 服务端显式错误（无法打开/读取日志文件）——此时流会结束，随后触发 onerror 走重连
      es.addEventListener('error', (event: Event) => {
        if (stopped || source !== es) return
        if (event instanceof MessageEvent && typeof event.data === 'string') {
          setStreamError(event.data)
        }
      })

      // 连接层错误（网络断开、服务端 503 连接数超限）：主动断开并退避重连
      es.onerror = () => {
        if (stopped || source !== es || errorHandled) return
        errorHandled = true

        detach()
        failures += 1
        setStreamStatus('reconnecting')
        setAttempt(failures)

        // 指数退避：1、2、4、8、16、32 → 截断到 30 秒上限
        const delayMs = Math.min(2 ** Math.min(failures, 5), 30) * 1000
        retryTimer = window.setTimeout(connect, delayMs)
      }
    }

    connect()

    return () => {
      stopped = true
      if (retryTimer !== null) window.clearTimeout(retryTimer)
      detach()
    }
  }, [])

  // ------------------------------ 历史日志查询 ------------------------------
  const [level, setLevel] = useState('')
  const [keyword, setKeyword] = useState('')
  const [page, setPage] = useState(1)
  /** 本地清屏时间点（Unix 秒）；0 表示不限制。与配置中的过滤起点共同决定下限 */
  const [localCutoff, setLocalCutoff] = useState(0)
  /** 配置读写计数：写入过滤起点后触发重新拉取 */
  const [configNonce, setConfigNonce] = useState(0)

  const config = useAsync<WebuiConfigResponse>(() => getConfig(), [configNonce])

  /** 配置中的过滤起点（clear_logs_at）→ Unix 秒；未设置或非法值为 0 */
  const configCutoff = useMemo(
    () => (config.data?.clear_logs_at ? tsToUnixSeconds(config.data.clear_logs_at) : 0),
    [config.data],
  )
  /** 生效下限：本地清屏与配置起点取较晚者 */
  const cutoffSeconds = Math.max(localCutoff, configCutoff)

  /** 传给后端的 since：形如 2026-09-19T06:03:00（与后端「行首 19 字符」比较口径对齐） */
  const sinceParam = useMemo(() => {
    if (cutoffSeconds <= 0) return ''
    return formatDatetime(cutoffSeconds).replace(' ', 'T')
  }, [cutoffSeconds])

  // 空关键词 / 空 since 一律不传（undefined 会被 withQuery 跳过），
  // 与旧实现一致：避免 `keyword=` 这类空过滤条件白白进入查询串。
  const history = useAsync<LogPageResponse>(
    () =>
      getLogs({
        page,
        page_size: PAGE_SIZE,
        keyword: keyword.trim() === '' ? undefined : keyword.trim(),
        since: sinceParam === '' ? undefined : sinceParam,
      }),
    [page, keyword, sinceParam],
  )

  /** 关键词或时间下限变化时回到第 1 页，避免停留在越界页码上 */
  useEffect(() => {
    setPage(1)
  }, [keyword, sinceParam])

  /** 历史条目 → 解析结果，供过滤与渲染复用（避免每次渲染重复解析） */
  const parsedHistory = useMemo(
    () =>
      (history.data?.items ?? []).map((item: LogEntry) => ({
        ...parseLine(item.content),
        lineNumber: item.line_number,
      })),
    [history.data],
  )

  /** 客户端过滤：时间下限（按解析出的 ts）+ 级别；关键词已由后端过滤 */
  const filteredHistory = useMemo(() => {
    return parsedHistory.filter((line) => {
      if (cutoffSeconds > 0) {
        const seconds = tsToUnixSeconds(line.ts)
        // 无法解析时间戳的行（非 JSON）不参与时间过滤，避免被静默丢弃
        if (seconds > 0 && seconds < cutoffSeconds) return false
      }
      if (level !== '' && line.level.toUpperCase() !== level) return false
      return true
    })
  }, [parsedHistory, cutoffSeconds, level])

  /** 实时行同样受时间下限与级别过滤约束，保证「清空」后旧行不再回到视图 */
  const filteredLive = useMemo(() => {
    return liveLines
      .map((line) => ({ ...line.parsed, seq: line.seq }))
      .filter((line) => {
        if (cutoffSeconds > 0) {
          const seconds = tsToUnixSeconds(line.ts)
          if (seconds > 0 && seconds < cutoffSeconds) return false
        }
        if (level !== '' && line.level.toUpperCase() !== level) return false
        return true
      })
  }, [liveLines, cutoffSeconds, level])

  // ------------------------------ 操作 ------------------------------
  /** 清空当前视图：清掉实时缓冲并把时间下限设为现在（不回退已经生成的序号） */
  const clearView = () => {
    setLiveLines([])
    setLocalCutoff(Math.floor(Date.now() / 1000))
  }

  /** 把「现在」写入配置项 clear_logs_at（写操作，需确认） */
  const persistCutoff = async () => {
    const now = formatDatetime(Math.floor(Date.now() / 1000)).replace(' ', 'T')
    const confirmed = await Dialog.confirm({
      content: `把 ${now} 写入配置项 clear_logs_at？写入后守护进程会持久化该过滤起点，本页会把它作为默认时间下限。`,
      confirmText: '写入',
    })
    if (!confirmed) return
    try {
      await updateConfig({ clear_logs_at: now })
      toast.success('过滤起点已写入配置')
      setLocalCutoff(0)
      setConfigNonce((n) => n + 1)
    } catch (e) {
      toast.error(`写入失败：${errorText(e)}`)
    }
  }

  /** 取消配置中的过滤起点（写空字符串，后端语义 = 取消过滤） */
  const cancelPersistedCutoff = async () => {
    const confirmed = await Dialog.confirm({
      content: '取消配置中的过滤起点？取消后本页将重新显示全部历史日志。',
      confirmText: '取消过滤',
    })
    if (!confirmed) return
    try {
      await updateConfig({ clear_logs_at: '' })
      toast.success('已取消配置中的过滤起点')
      setLocalCutoff(0)
      setConfigNonce((n) => n + 1)
    } catch (e) {
      toast.error(`取消失败：${errorText(e)}`)
    }
  }

  const streamMeta = STREAM_META[streamStatus]
  const pageInfo = history.data
  const persistedCutoff = config.data?.clear_logs_at ?? null

  return (
    <>
      {/* 二级页头部：统一工具条（左端返回更多 + 本页流状态与跟随控制）。
          刷新走下拉手势，不设页内刷新按钮——全站一致 */}
      <Toolbar>
        <BackLink onClick={() => navigate('/more')} />
        <Badge tone={streamMeta.tone}>{streamMeta.badge}</Badge>
        <span
          style={{
            flex: 1,
            minWidth: 0,
            fontSize: 10,
            color: paused ? 'var(--fw-warning)' : 'var(--fw-text-3)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {paused ? '显示已暂停（连接保持）' : streamMeta.hint}
        </span>
        <button
          type="button"
          className="fw-cmd"
          aria-pressed={paused}
          onClick={() => setPaused((v) => !v)}
        >
          {paused ? '恢复跟随' : '暂停跟随'}
        </button>
        <button
          type="button"
          className="fw-iconbtn"
          aria-label="清空当前视图"
          onClick={clearView}
        >
          <DeleteOutline />
        </button>
      </Toolbar>

      {/* 页内区块标题：必须是 h2 且文本精确为「实时日志」—— 顶栏 h1 是「日志」，
          两者故意不同名，e2e 分别断言（level 2 + exact），改任一处都会红。
          视觉上隐藏（srOnly）：顶栏已标明这是日志页，第二行标题纯属重复 */}
      <PageHeader title="实时日志" srOnly />

      {/* 页头第二行：计数与重连计数（dim 小字，只占 10px 高） */}
      <div
        className="fw-mono fw-num"
        style={{ fontSize: 10, color: 'var(--fw-text-3)', marginBottom: 6 }}
      >
        已收 {formatNumber(seqRef.current, false)} 行 · 缓冲 {formatNumber(liveLines.length, false)}/
        {LIVE_BUFFER_LIMIT}
        {streamStatus === 'reconnecting'
          ? ` · 重连第 ${formatNumber(attempt, false)} 次（退避 ≤30s）`
          : ''}
        {filteredLive.length !== liveLines.length
          ? ` · 过滤后显示 ${formatNumber(filteredLive.length, false)} 行`
          : ''}
        {cutoffSeconds > 0 ? ` · 时间下限 ${formatDatetime(cutoffSeconds)}` : ''}
      </div>

      <PullToRefresh
        onRefresh={async () => {
          await Promise.all([history.reload(), config.reload()])
        }}
      >
        <div className="fw-page">
          {streamError !== null && (
            <div className="fw-banner fw-banner-danger" role="alert">
              日志流异常：{streamError}（将自动重连）
            </div>
          )}
          {streamStatus === 'reconnecting' && (
            <div className="fw-banner fw-banner-warning" role="status">
              实时日志流已断开，正在按指数退避重连。服务端日志流并发上限为 5，多个标签页同时打开会互相占满。
            </div>
          )}

          {/* ------------------------------ 实时输出 ------------------------------ */}
          <Panel
            title="实时输出"
            meta={`最新在上 · 显示 ${formatNumber(filteredLive.length, false)} / 缓冲 ${formatNumber(
              liveLines.length,
              false,
            )}`}
            padded={false}
          >
            {filteredLive.length === 0 ? (
              <EmptyState
                compact
                title="暂无实时日志"
                description="实时流只推送连接建立之后新写入的日志行；历史内容请查看下方「历史日志」"
              />
            ) : (
              filteredLive.map((line, index) => (
                <LogRow
                  key={line.seq}
                  leading={`#${line.seq}`}
                  level={line.level}
                  ts={line.ts}
                  msg={line.msg}
                  raw={line.raw}
                  query={keyword}
                  last={index === filteredLive.length - 1}
                />
              ))
            )}
          </Panel>

          {/* ------------------------------ 历史日志 ------------------------------ */}
          <Panel
            title="历史日志"
            meta={
              pageInfo === null
                ? '分页查询'
                : `匹配 ${formatNumber(pageInfo.total_lines, false)} 行 · 第 ${formatNumber(
                    pageInfo.page,
                    false,
                  )}/${formatNumber(Math.max(pageInfo.total_pages, 1), false)} 页`
            }
            padded={false}
          >
            {/* 过滤区：搜索 + 级别分段 + 时间下限说明 + 三个 44px 操作钮 */}
            <div style={{ padding: '5px 6px 0' }}>
              <SearchBar
                placeholder="关键词（后端按整行小写包含匹配）"
                value={keyword}
                onChange={setKeyword}
              />
              <div style={{ marginTop: 5 }}>
                <SegTabs label="级别过滤" items={LEVEL_OPTIONS} value={level} onChange={setLevel} />
              </div>
              <div
                style={{
                  marginTop: 4,
                  fontSize: 10,
                  lineHeight: 1.45,
                  color: 'var(--fw-text-3)',
                }}
              >
                时间下限：
                {cutoffSeconds > 0 ? formatDatetime(cutoffSeconds) : '未设置'}
                {configCutoff > 0 && configCutoff >= localCutoff ? '（来自配置 clear_logs_at）' : ''}
                {localCutoff > 0 && localCutoff > configCutoff ? '（来自本页清空）' : ''}
                ；配置中的过滤起点：{persistedCutoff === null ? '未设置' : persistedCutoff || '空（未过滤）'}
                <br />
                级别过滤在客户端按解析出的 level 字段执行：后端日志行为 JSON，级别写作
                {' "level":"WARN"'}，服务端的 [LEVEL] 匹配对它无效。
              </div>
              <div style={{ display: 'flex', gap: 4, marginTop: 5, flexWrap: 'wrap' }}>
                <button type="button" className="fw-cmd" onClick={() => void persistCutoff()}>
                  写入过滤起点
                </button>
                <button
                  type="button"
                  className="fw-cmd"
                  disabled={persistedCutoff === null}
                  onClick={() => void cancelPersistedCutoff()}
                >
                  取消配置起点
                </button>
                <button
                  type="button"
                  className="fw-cmd"
                  aria-label="刷新历史日志"
                  onClick={() => void history.reload()}
                >
                  刷新
                </button>
              </div>
            </div>

            {history.error !== null ? (
              <InlineError message={`历史日志加载失败：${history.error}`} onRetry={history.reload} />
            ) : pageInfo === null ? (
              <PanelLoading lines={5} />
            ) : filteredHistory.length === 0 ? (
              <EmptyState
                compact
                title="没有匹配的日志"
                description={
                  keyword.trim() === '' && level === '' && cutoffSeconds === 0
                    ? '日志文件为空，或尚未写入任何内容'
                    : '当前筛选条件下本页没有匹配行；可放宽关键词/级别，或翻到其它页'
                }
              />
            ) : (
              filteredHistory.map((line, index) => (
                <LogRow
                  key={line.lineNumber}
                  leading={`L${line.lineNumber}`}
                  level={line.level}
                  ts={line.ts}
                  msg={line.msg}
                  raw={line.raw}
                  query={keyword}
                  last={index === filteredHistory.length - 1}
                />
              ))
            )}

            {/* 分页控制：页码与总页数来自后端 LogPageResponse */}
            {pageInfo !== null && (
              <div style={{ padding: '5px 6px' }}>
                <div
                  className="fw-mono fw-num"
                  style={{ fontSize: 10, color: 'var(--fw-text-3)', marginBottom: 4 }}
                >
                  共 {formatNumber(pageInfo.total_lines, false)} 行 · 每页{' '}
                  {formatNumber(pageInfo.page_size, false)} 行 · 按时间下限与级别过滤后本页显示{' '}
                  {formatNumber(filteredHistory.length, false)} 行
                </div>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button
                    type="button"
                    className="fw-cmd"
                    style={{ flex: 1 }}
                    disabled={pageInfo.page <= 1}
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                  >
                    上一页
                  </button>
                  <button
                    type="button"
                    className="fw-cmd"
                    style={{ flex: 1 }}
                    disabled={pageInfo.page >= pageInfo.total_pages}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    下一页
                  </button>
                </div>
              </div>
            )}
          </Panel>

          {/* -------------------------------- 说明 -------------------------------- */}
          <Panel title="说明" padded={false}>
            <Note>
              行首编号：#N 是本次会话内的接收序号（后端只推原始行、不含行号），LN 才是日志文件中的行号。
            </Note>
            <Note>
              日志文件由守护进程按配置路径写入（默认 /var/log/firewall.log），本页只读不写文件。
            </Note>
            <Note>
              「清空」只清空本页视图并设本地时间下限，不删除文件内容；要把过滤起点持久化请用「写入过滤起点」。
            </Note>
          </Panel>
        </div>
      </PullToRefresh>
    </>
  )
}
