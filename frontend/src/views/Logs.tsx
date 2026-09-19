// 日志页（二级页，位于「更多」之下）
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
import { Button, Card, Dialog, List, NavBar, NoticeBar, SearchBar, Selector, Skeleton, Tag } from 'antd-mobile'
import type { SelectorOption } from 'antd-mobile'
import { DeleteOutline, FileOutline, LoopOutline, SearchOutline } from 'antd-mobile-icons'
import { useNavigate } from 'react-router-dom'
import type { LogEntry, LogPageResponse, UpdateConfigRequest, WebuiConfigResponse } from '../api/types'
import { LOG_STREAM_URL } from '../api/endpoints'
import { withAccessToken } from '../api/auth'
import { getJson, sendJson } from '../api/client'
import { useAsync } from '../hooks/useAsync'
import { useToast } from '../hooks/useToast'
import { PageHeader } from '../components/PageHeader'
import { EmptyState } from '../components/EmptyState'
import { HighlightText } from '../components/HighlightText'
import { formatDatetime, formatNumber } from '../lib/format'

/** 端点常量：与 handler.rs 的 build_router() 路由一一对应 */
const LOGS_URL = '/api/v1/logs'
const CONFIG_URL = '/api/v1/config'

/** 每页条数：后端上限 500，取 100 兼顾移动端渲染与请求耗时 */
const PAGE_SIZE = 100
/** 实时缓冲上限：超过后丢弃最旧的行，避免长时间挂机把内存吃满 */
const LIVE_BUFFER_LIMIT = 300

/** 次要说明文字样式 */
const MUTED = { color: 'var(--adm-color-text-secondary)', fontSize: 12 } as const
/** 日志正文样式：等宽 + 允许长行换行 */
const LOG_TEXT = {
  fontFamily: 'var(--fw-font-mono)',
  fontSize: 12,
  lineHeight: 1.5,
  wordBreak: 'break-all' as const,
} as const

/** 流状态：connecting 首次连接 / live 已连接 / reconnecting 断开重连中 */
type StreamStatus = 'connecting' | 'live' | 'reconnecting'

/** 流状态 → 用户可见文案与颜色 */
const STREAM_META: Record<StreamStatus, { text: string; color: 'success' | 'warning' | 'default' }> = {
  connecting: { text: '连接中', color: 'default' },
  live: { text: '实时接收中', color: 'success' },
  reconnecting: { text: '已断开，重连中', color: 'warning' },
}

/** 一条实时日志：seq 为本次会话内单调递增的编号，raw 为后端推送的原始行 */
interface LiveLine {
  seq: number
  raw: string
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

/** 级别 → Tag 颜色（与后端级别命名一致，未知级别用默认灰） */
function levelColor(level: string): 'danger' | 'warning' | 'primary' | 'default' {
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
const LEVEL_OPTIONS: SelectorOption<string>[] = [
  { label: '全部', value: '' },
  { label: 'ERROR', value: 'ERROR' },
  { label: 'WARN', value: 'WARN' },
  { label: 'INFO', value: 'INFO' },
  { label: 'DEBUG', value: 'DEBUG' },
]

/** 把任意抛出物转成可展示文案 */
function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
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
        const line: LiveLine = { seq: seqRef.current, raw: event.data }
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

  const config = useAsync<WebuiConfigResponse>(() => getJson<WebuiConfigResponse>(CONFIG_URL), [configNonce])

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

  const history = useAsync<LogPageResponse>(
    () =>
      getJson<LogPageResponse>(
        `${LOGS_URL}?page=${page}&page_size=${PAGE_SIZE}${
          keyword.trim() === '' ? '' : `&keyword=${encodeURIComponent(keyword.trim())}`
        }${sinceParam === '' ? '' : `&since=${encodeURIComponent(sinceParam)}`}`,
      ),
    [page, keyword, sinceParam],
  )

  /** 关键词或时间下限变化时回到第 1 页，避免停留在越界页码上 */
  useEffect(() => {
    setPage(1)
  }, [keyword, sinceParam])

  /** 历史条目 → 解析结果，供过滤与渲染复用（避免每次渲染重复解析） */
  const parsedHistory = useMemo(
    () => (history.data?.items ?? []).map((item: LogEntry) => ({ ...parseLine(item.content), lineNumber: item.line_number })),
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
      .map((line) => ({ ...parseLine(line.raw), seq: line.seq }))
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
      await sendJson<UpdateConfigRequest, WebuiConfigResponse>(CONFIG_URL, 'PUT', {
        clear_logs_at: now,
      })
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
      await sendJson<UpdateConfigRequest, WebuiConfigResponse>(CONFIG_URL, 'PUT', { clear_logs_at: '' })
      toast.success('已取消配置中的过滤起点')
      setLocalCutoff(0)
      setConfigNonce((n) => n + 1)
    } catch (e) {
      toast.error(`取消失败：${errorText(e)}`)
    }
  }

  const streamMeta = STREAM_META[streamStatus]
  const pageInfo = history.data

  return (
    <>
      {/* 二级页返回入口：回到收纳本页的「更多」 */}
      <NavBar onBack={() => navigate('/more')}>日志</NavBar>

      <PageHeader
        title="实时日志"
        subtitle={`本次会话已接收 ${formatNumber(seqRef.current, false)} 行，最多保留最近 ${LIVE_BUFFER_LIMIT} 行`}
        extra={
          <>
            <Button
              size="small"
              fill="none"
              style={{ minHeight: 44 }}
              onClick={() => setPaused((v) => !v)}
            >
              {paused ? '继续' : '暂停'}
            </Button>
            <Button size="small" fill="none" style={{ minHeight: 44 }} aria-label="清空当前视图" onClick={clearView}>
              <DeleteOutline fontSize={18} />
            </Button>
          </>
        }
      />

      <div style={{ paddingBottom: 7 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 5 }}>
          <Tag color={streamMeta.color} fill="outline">
            {streamMeta.text}
          </Tag>
          {streamStatus === 'reconnecting' && (
            <span style={MUTED}>第 {formatNumber(attempt, false)} 次重连，退避最长 30 秒</span>
          )}
          {paused && <Tag color="warning" fill="outline">显示已暂停（连接保持）</Tag>}
        </div>

        {streamError !== null && (
          <NoticeBar color="error" wrap content={`日志流异常：${streamError}（将自动重连）`} />
        )}

        {streamStatus === 'reconnecting' && (
          <NoticeBar
            color="alert"
            wrap
            content="实时日志流已断开，正在按指数退避自动重连。服务端日志流并发上限为 5，多个标签页同时打开会互相占满。"
          />
        )}

        {filteredLive.length === 0 ? (
          <Card>
            <EmptyState
              compact
              title="暂无实时日志"
              description="实时流只推送连接建立之后新写入的日志行；历史内容请查看下方「历史日志」"
            />
          </Card>
        ) : (
          <Card title="实时输出（最新在上）">
            {filteredLive.map((line) => (
              <div
                key={line.seq}
                style={{ padding: '4px 0', borderBottom: '1px solid var(--fw-border)' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={MUTED}>#{formatNumber(line.seq, false)}</span>
                  {line.level !== '' && (
                    <Tag color={levelColor(line.level)} fill="outline">
                      {line.level}
                    </Tag>
                  )}
                  {line.ts !== '' && <span style={MUTED}>{formatDatetime(tsToUnixSeconds(line.ts))}</span>}
                </div>
                <div style={LOG_TEXT}>
                  <HighlightText text={line.msg !== '' ? line.msg : line.raw} query={keyword} />
                </div>
                {/* 非 JSON 行没有 msg 字段，原文即上方内容；JSON 行额外保留原文供核对细节字段 */}
                {line.msg !== '' && (
                  <div style={{ ...LOG_TEXT, ...MUTED, marginTop: 1 }}>
                    <HighlightText text={line.raw} query={keyword} />
                  </div>
                )}
              </div>
            ))}
          </Card>
        )}

        {/* ------------------------------ 历史日志 ------------------------------ */}
        <Card
          title={
            <span>
              <FileOutline /> 历史日志
            </span>
          }
          style={{ marginTop: 10 }}
        >
          <SearchBar
            placeholder="关键词（后端按整行小写包含匹配）"
            value={keyword}
            onChange={setKeyword}
            style={{ '--height': '44px' }}
          />

          <div style={{ marginTop: 5 }}>
            <Selector options={LEVEL_OPTIONS} value={[level]} onChange={(v) => setLevel(v[0] ?? '')} />
          </div>

          <div style={{ ...MUTED, marginTop: 5 }}>
            级别过滤在客户端按解析出的 level 字段执行（后端日志行为 JSON，级别写作
            "level":"WARN"，服务端的 [LEVEL] 匹配对其无效）。
          </div>

          <div style={{ ...MUTED, marginTop: 4 }}>
            当前时间下限：
            {cutoffSeconds > 0 ? formatDatetime(cutoffSeconds) : '未设置'}
            {configCutoff > 0 && configCutoff >= localCutoff ? '（来自配置 clear_logs_at）' : ''}
            {localCutoff > 0 && localCutoff > configCutoff ? '（来自本页清空）' : ''}
            ；配置中的过滤起点：
            {config.data?.clear_logs_at ?? '未设置'}
          </div>

          <div style={{ display: 'flex', gap: 5, marginTop: 5, flexWrap: 'wrap' }}>
            <Button size="small" style={{ minHeight: 44 }} onClick={() => void persistCutoff()}>
              写入过滤起点
            </Button>
            <Button
              size="small"
              style={{ minHeight: 44 }}
              disabled={(config.data?.clear_logs_at ?? null) === null}
              onClick={() => void cancelPersistedCutoff()}
            >
              取消配置过滤起点
            </Button>
            <Button
              size="small"
              fill="none"
              style={{ minHeight: 44 }}
              aria-label="刷新历史日志"
              onClick={() => history.reload()}
            >
              <LoopOutline fontSize={18} />
            </Button>
          </div>

          {history.error !== null && (
            <NoticeBar
              color="error"
              wrap
              content={`历史日志加载失败：${history.error}`}
              extra={
                <a onClick={() => history.reload()} style={{ color: 'inherit', textDecoration: 'underline' }}>
                  重试
                </a>
              }
            />
          )}

          {history.data === null && history.error === null ? (
            <Skeleton.Paragraph lineCount={6} animated />
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
            <>
              {filteredHistory.map((line) => (
                <div
                  key={line.lineNumber}
                  style={{ padding: '4px 0', borderBottom: '1px solid var(--fw-border)' }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={MUTED}>第 {formatNumber(line.lineNumber, false)} 行</span>
                    {line.level !== '' && (
                      <Tag color={levelColor(line.level)} fill="outline">
                        {line.level}
                      </Tag>
                    )}
                    {line.ts !== '' && (
                      <span style={MUTED}>{formatDatetime(tsToUnixSeconds(line.ts))}</span>
                    )}
                  </div>
                  <div style={LOG_TEXT}>
                    <HighlightText text={line.msg !== '' ? line.msg : line.raw} query={keyword} />
                  </div>
                  {line.msg !== '' && (
                    <div style={{ ...LOG_TEXT, ...MUTED, marginTop: 1 }}>
                      <HighlightText text={line.raw} query={keyword} />
                    </div>
                  )}
                </div>
              ))}
            </>
          )}

          {/* 分页控制：页码与总页数来自后端 LogPageResponse */}
          {pageInfo !== null && (
            <>
              <div style={{ ...MUTED, marginTop: 5 }}>
                共匹配 {formatNumber(pageInfo.total_lines, false)} 行 · 第{' '}
                {formatNumber(pageInfo.page, false)} / {formatNumber(Math.max(pageInfo.total_pages, 1), false)} 页 ·
                每页 {formatNumber(pageInfo.page_size, false)} 行
              </div>
              <div style={{ display: 'flex', gap: 5, marginTop: 5 }}>
                <Button
                  block
                  style={{ minHeight: 44 }}
                  disabled={pageInfo.page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  上一页
                </Button>
                <Button
                  block
                  style={{ minHeight: 44 }}
                  disabled={pageInfo.page >= pageInfo.total_pages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  下一页
                </Button>
              </div>
            </>
          )}
        </Card>

        <List header="说明" style={{ marginTop: 7 }}>
          <List.Item>
            <SearchOutline /> 实时流序号是本次会话内的递增编号：后端只推送原始日志行，不含行号；
            历史视图显示的「第 N 行」才对应文件中的行号。
          </List.Item>
          <List.Item>日志文件由守护进程按配置路径写入（默认 /var/log/firewall.log），本页只读不写文件。</List.Item>
        </List>
      </div>
    </>
  )
}
