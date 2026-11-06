import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import {
  Button,
  Flex,
  Input,
  Segmented,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import {
  ClearOutlined,
  PauseCircleOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  VerticalAlignBottomOutlined,
} from '@ant-design/icons'
import { PageHeader } from '../components/PageHeader.tsx'
import { DataTable } from '../components/DataTable.tsx'
import { EmptyState } from '../components/state/EmptyState.tsx'
import { useAsync, type UseAsyncResult } from '../hooks/useAsync.ts'
import { useRefreshSignal } from '../hooks/useRefreshSignal.ts'
import { backoffSeconds } from '../hooks/useSse.ts'
import { getLogs, getSseStatus, logsStreamUrl } from '../api/endpoints.ts'
import { formatClock } from '../lib/format.ts'
import type { LogEntry, LogLevel, LogPageResponse } from '../api/types.ts'

/**
 * 日志页 —— 实时日志流 + 历史日志两种读法，一个 Segmented 切换。
 *
 * 实时流（/api/v2/logs/stream）由本页**自己接管**：门禁 `check_sse_events` 要求契约声明的
 * 三个事件名（connected / log / error）逐字出现在本文件里，故下面用逐个
 * `addEventListener('名字', …)` 的写法，字面量必须落在源码里这条检查才成立（events 流的
 * 六个事件名则在 hooks/useSse.ts，两条流分处两地是门禁强制的，不是随意拆分）。
 *
 * 帧语义（见 daemon logs.go：writeFrame("log", sseRaw(line))）：`log` 帧的 data 就是**一整行
 * 原始日志文本**（不经 JSON 包装），`error` 帧是服务端读文件失败的原文。连接级错误也走
 * 'error' 事件但**没有 data**——据此区分「服务端报错帧」与「连接断了」。
 *
 * 级别过滤在**客户端**做：后端按 `[LEVEL]` 前缀过滤，对 JSON 结构的日志行失效（见迁移说明），
 * 所以实时流一律前端解析级别再筛，宁可多传也不漏行。
 *
 * 连接上限 5（与 events 的 10 各自独立）：出错重连前先探 sse-status 的 logs.limit_reached，
 * 达上限就停手并提示降级，不把 503 当网络故障无限重试。
 */

type Mode = 'live' | 'history'
type LiveState = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'limit'
type LevelFilter = LogLevel | 'all'

const MAX_LIVE_LINES = 500

interface LiveLine {
  id: number
  content: string
  level: LogLevel | null
  at: number
}

const LEVEL_COLORS: Record<LogLevel, string> = {
  DEBUG: 'default',
  INFO: 'blue',
  WARN: 'orange',
  ERROR: 'red',
}

/** 从一行日志里解析级别：先试 JSON 的 level 字段，再退回 `[LEVEL]` / 裸词匹配。 */
function parseLevel(content: string): LogLevel | null {
  const trimmed = content.trim()
  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(trimmed) as { level?: unknown }
      const raw = String(obj.level ?? '').toUpperCase()
      if (raw.startsWith('WARN')) return 'WARN'
      if (raw === 'DEBUG' || raw === 'INFO' || raw === 'ERROR') return raw
    } catch {
      // 不是合法 JSON，退回文本匹配
    }
  }
  const m = trimmed.match(/\b(DEBUG|INFO|WARN|WARNING|ERROR)\b/i)
  if (!m) return null
  const up = m[1].toUpperCase()
  return up === 'WARNING' ? 'WARN' : (up as LogLevel)
}

export default function Logs() {
  const [mode, setMode] = useState<Mode>('live')

  // --- 实时流状态 ---
  const [liveLines, setLiveLines] = useState<LiveLine[]>([])
  const [liveState, setLiveState] = useState<LiveState>('idle')
  const [paused, setPaused] = useState(false)
  // 暂停期间到达并被丢弃的行数；恢复接收时清零
  const [missed, setMissed] = useState(0)
  const [autoscroll, setAutoscroll] = useState(true)
  const [liveLevel, setLiveLevel] = useState<LevelFilter>('all')
  const [liveKeyword, setLiveKeyword] = useState('')
  const [lastLogAt, setLastLogAt] = useState(0)

  const esRef = useRef<EventSource | null>(null)
  const timerRef = useRef<number | null>(null)
  const attemptsRef = useRef(0)
  const lineIdRef = useRef(0)
  const pausedRef = useRef(paused)
  pausedRef.current = paused
  const viewerRef = useRef<HTMLDivElement>(null)

  // --- 历史查询状态 ---
  const [histLevel, setHistLevel] = useState<LevelFilter>('all')
  const [histKeyword, setHistKeyword] = useState('')
  const [keywordInput, setKeywordInput] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  // 关键词去抖：停止输入 400ms 后才落到查询，避免每敲一个字打一次后端
  useEffect(() => {
    const t = window.setTimeout(() => {
      setHistKeyword(keywordInput.trim())
      setPage(1)
    }, 400)
    return () => window.clearTimeout(t)
  }, [keywordInput])

  const historyQuery = useAsync<LogPageResponse>(
    (signal) =>
      getLogs(
        {
          page,
          page_size: pageSize,
          level: histLevel === 'all' ? null : histLevel,
          keyword: histKeyword || null,
        },
        signal,
      ),
    { enabled: mode === 'history' },
  )

  // 过滤/翻页变化时重取历史
  useEffect(() => {
    if (mode === 'history') historyQuery.refetch()
    // 仅在真正影响查询的输入变化时触发；refetch 身份稳定
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, page, pageSize, histLevel, histKeyword])

  useRefreshSignal(() => {
    if (mode === 'history') historyQuery.refetch()
  })

  // --- 实时流连接管理 ---
  const clearTimer = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }, [])

  const closeStream = useCallback(() => {
    clearTimer()
    if (esRef.current) {
      esRef.current.onerror = null
      esRef.current.close()
      esRef.current = null
    }
  }, [clearTimer])

  const connect = useCallback(() => {
    closeStream()
    setLiveState(attemptsRef.current === 0 ? 'connecting' : 'reconnecting')
    const es = new EventSource(logsStreamUrl())
    esRef.current = es

    // 门禁要求的字面量：connected / log / error 三个事件名逐个显式监听
    es.addEventListener('connected', () => {
      attemptsRef.current = 0
      setLiveState('open')
    })

    es.addEventListener('log', (e: MessageEvent<string>) => {
      const content = e.data
      setLastLogAt(Date.now())
      if (pausedRef.current) {
        setMissed((m) => m + 1)
        return
      }
      const line: LiveLine = {
        id: ++lineIdRef.current,
        content,
        level: parseLevel(content),
        at: Date.now(),
      }
      setLiveLines((prev) => {
        const next = [...prev, line]
        return next.length > MAX_LIVE_LINES ? next.slice(next.length - MAX_LIVE_LINES) : next
      })
    })

    es.addEventListener('error', (e: Event) => {
      // 服务端 error 帧带 data（读文件失败的原文）；连接级错误没有 data
      const data = (e as MessageEvent<string>).data
      if (typeof data === 'string' && data.length > 0) {
        if (!pausedRef.current) {
          setLiveLines((prev) => {
            const next = [
              ...prev,
              { id: ++lineIdRef.current, content: data, level: 'ERROR' as LogLevel, at: Date.now() },
            ]
            return next.length > MAX_LIVE_LINES ? next.slice(next.length - MAX_LIVE_LINES) : next
          })
        } else {
          setMissed((m) => m + 1)
        }
        return
      }
      // 连接错误：自己接管重连（不用 EventSource 自带策略），先探上限
      closeStream()
      setLiveState('reconnecting')
      void getSseStatus()
        .then((status) => {
          if (status.logs.limit_reached) {
            attemptsRef.current = 0
            setLiveState('limit')
            return
          }
          scheduleReconnect()
        })
        .catch(() => scheduleReconnect())
    })

    function scheduleReconnect() {
      const delay = backoffSeconds(attemptsRef.current) * 1000
      attemptsRef.current += 1
      clearTimer()
      timerRef.current = window.setTimeout(() => {
        timerRef.current = null
        connect()
      }, delay)
    }
  }, [closeStream, clearTimer])

  // 进入实时模式即连接，离开即断开（省名额：上限只有 5）
  useEffect(() => {
    if (mode === 'live') {
      attemptsRef.current = 0
      connect()
    } else {
      closeStream()
      setLiveState('idle')
    }
    return closeStream
  }, [mode, connect, closeStream])

  // 自动滚动到底部（新行到达且开启 autoscroll 时）
  useEffect(() => {
    if (autoscroll && viewerRef.current) {
      viewerRef.current.scrollTop = viewerRef.current.scrollHeight
    }
  }, [liveLines, autoscroll])

  const filteredLive = useMemo(() => {
    const kw = liveKeyword.trim().toLowerCase()
    return liveLines.filter((l) => {
      if (liveLevel !== 'all' && l.level !== liveLevel) return false
      if (kw && !l.content.toLowerCase().includes(kw)) return false
      return true
    })
  }, [liveLines, liveLevel, liveKeyword])

  // LiveState 五个取值都是合法的 SseConnectionState，直传即可；此前 connecting
  // 被三元兜底分支误并成 reconnecting，首次连接时徽标显示「重连中」
  return (
    <>
      <PageHeader
        title="日志"
        description="守护进程实时日志流与历史日志检索"
        breadcrumb={[{ title: '运维' }, { title: '日志' }]}
        realtimeState={mode === 'live' ? liveState : undefined}
        realtimeLastEventAt={mode === 'live' ? lastLogAt : undefined}
        extra={
          <Segmented<Mode>
            value={mode}
            onChange={(v) => setMode(v)}
            options={[
              { label: '实时流', value: 'live' },
              { label: '历史', value: 'history' },
            ]}
          />
        }
      />

      {mode === 'live' ? (
        <LivePanel
          lines={filteredLive}
          total={liveLines.length}
          state={liveState}
          paused={paused}
          missed={missed}
          autoscroll={autoscroll}
          level={liveLevel}
          keyword={liveKeyword}
          viewerRef={viewerRef}
          onTogglePause={() => {
            // 正在暂停 → 本次点击是恢复：清零计数，下一轮暂停重新计
            if (pausedRef.current) setMissed(0)
            setPaused((p) => !p)
          }}
          onToggleAutoscroll={(v) => setAutoscroll(v)}
          onClear={() => setLiveLines([])}
          onLevelChange={setLiveLevel}
          onKeywordChange={setLiveKeyword}
          onReconnect={() => {
            attemptsRef.current = 0
            connect()
          }}
        />
      ) : (
        <HistoryPanel query={historyQuery} page={page} pageSize={pageSize} level={histLevel} keyword={keywordInput}
          onPageChange={(p, ps) => {
            setPage(p)
            setPageSize(ps)
          }}
          onLevelChange={(v) => {
            setHistLevel(v)
            setPage(1)
          }}
          onKeywordChange={setKeywordInput}
        />
      )}
    </>
  )
}

// getLogs 的返回类型：LogPageResponse（历史分页载荷）

interface LivePanelProps {
  lines: LiveLine[]
  total: number
  state: LiveState
  paused: boolean
  /** 暂停期间到达并被丢弃的行数。 */
  missed: number
  autoscroll: boolean
  level: LevelFilter
  keyword: string
  viewerRef: RefObject<HTMLDivElement | null>
  onTogglePause: () => void
  onToggleAutoscroll: (v: boolean) => void
  onClear: () => void
  onLevelChange: (v: LevelFilter) => void
  onKeywordChange: (v: string) => void
  onReconnect: () => void
}

function LivePanel(props: LivePanelProps) {
  const {
    lines, total, state, paused, missed, autoscroll, level, keyword, viewerRef,
    onTogglePause, onToggleAutoscroll, onClear, onLevelChange, onKeywordChange, onReconnect,
  } = props

  return (
    <Flex vertical gap={12}>
      <Flex wrap="wrap" gap={8} align="center" className="fw-table-toolbar">
        <Select<LevelFilter>
          value={level}
          onChange={onLevelChange}
          style={{ width: 120 }}
          options={[
            { label: '全部级别', value: 'all' },
            { label: 'DEBUG', value: 'DEBUG' },
            { label: 'INFO', value: 'INFO' },
            { label: 'WARN', value: 'WARN' },
            { label: 'ERROR', value: 'ERROR' },
          ]}
        />
        <Input.Search
          allowClear
          placeholder="过滤关键词（客户端）"
          value={keyword}
          onChange={(e) => onKeywordChange(e.target.value)}
          style={{ width: 240 }}
        />
        <Space size={8}>
          <Tooltip title={paused ? '继续接收' : '暂停接收（连接保持）'}>
            <Button
              icon={paused ? <PlayCircleOutlined /> : <PauseCircleOutlined />}
              onClick={onTogglePause}
            >
              {paused ? '继续' : '暂停'}
            </Button>
          </Tooltip>
          <Tooltip title="清空当前缓冲">
            <Button icon={<ClearOutlined />} onClick={onClear} disabled={total === 0}>
              清空
            </Button>
          </Tooltip>
          {state === 'limit' && (
            <Button type="primary" icon={<ReloadOutlined />} onClick={onReconnect}>
              重新连接
            </Button>
          )}
        </Space>
        <Space size={6} style={{ marginLeft: 'auto' }}>
          <VerticalAlignBottomOutlined style={{ color: 'var(--fw-text-secondary)' }} />
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            自动滚动
          </Typography.Text>
          <Switch size="small" checked={autoscroll} onChange={onToggleAutoscroll} />
        </Space>
      </Flex>

      {state === 'limit' && (
        <Typography.Text type="warning" style={{ fontSize: 12 }}>
          实时日志连接数已达上限（5），已停止重试。可稍后点「重新连接」，或改用「历史」检索。
        </Typography.Text>
      )}

      {paused && missed > 0 && (
        <Typography.Text type="warning" style={{ fontSize: 12 }}>
          暂停中：已到达 {missed} 条新日志被丢弃，恢复后不会补回。
        </Typography.Text>
      )}

      <div
        ref={viewerRef}
        role="log"
        aria-live="polite"
        aria-label="实时日志流"
        style={{
          height: 'calc(100vh - 260px)',
          minHeight: 320,
          overflowY: 'auto',
          border: '1px solid var(--fw-border)',
          borderRadius: 'var(--fw-radius)',
          background: 'var(--fw-bg-elevated)',
          padding: '8px 0',
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 12.5,
          lineHeight: 1.6,
        }}
      >
        {lines.length === 0 ? (
          <EmptyState
            scenario={state === 'open' ? 'no-data' : 'disabled'}
            title={state === 'open' ? '等待日志…' : '实时流未连接'}
            description={
              state === 'open'
                ? '连接已建立，新的日志行会出现在这里'
                : '切换到本面板即自动连接；若显示已降级请点重新连接'
            }
          />
        ) : (
          lines.map((l) => (
            <div
              key={l.id}
              style={{
                display: 'flex',
                gap: 8,
                padding: '1px 12px',
                alignItems: 'baseline',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              <span style={{ color: 'var(--fw-text-secondary)', flex: 'none' }}>{formatClock(l.at)}</span>
              {l.level && (
                <Tag color={LEVEL_COLORS[l.level]} style={{ marginInlineEnd: 0, flex: 'none', lineHeight: '16px' }}>
                  {l.level}
                </Tag>
              )}
              <span style={{ flex: 1, minWidth: 0 }}>{l.content}</span>
            </div>
          ))
        )}
      </div>

      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        已缓冲 {lines.length} 行（过滤后） / 共 {total} 行 · 上限 {MAX_LIVE_LINES} 行，超出丢弃最旧
      </Typography.Text>
    </Flex>
  )
}

interface HistoryPanelProps {
  query: UseAsyncResult<LogPageResponse>
  page: number
  pageSize: number
  level: LevelFilter
  keyword: string
  onPageChange: (page: number, pageSize: number) => void
  onLevelChange: (v: LevelFilter) => void
  onKeywordChange: (v: string) => void
}

function HistoryPanel(props: HistoryPanelProps) {
  const { query, page, pageSize, level, keyword, onPageChange, onLevelChange, onKeywordChange } = props

  const columns = useMemo(
    () => [
      {
        title: '行号',
        dataIndex: 'line_number',
        key: 'line_number',
        width: 90,
        render: (n: number) => <span className="fw-mono" style={{ color: 'var(--fw-text-secondary)' }}>{n}</span>,
      },
      {
        title: '内容',
        dataIndex: 'content',
        key: 'content',
        render: (text: string) => {
          const lv = parseLevel(text)
          return (
            <Space align="start" size={8}>
              {lv && <Tag color={LEVEL_COLORS[lv]} style={{ marginInlineEnd: 0 }}>{lv}</Tag>}
              <span className="fw-mono" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: 12.5 }}>
                {text}
              </span>
            </Space>
          )
        },
      },
    ],
    [],
  )

  const data: LogEntry[] = query.data?.items ?? []
  const total = query.data?.total_lines ?? 0

  return (
    <DataTable<LogEntry>
      data={query.data ? data : null}
      isLoading={query.isLoading}
      isRefreshing={query.isRefreshing}
      error={query.error}
      onRetry={query.refetch}
      rowKey="line_number"
      columns={columns}
      emptyScenario={keyword || level !== 'all' ? 'no-results' : 'no-data'}
      emptyTitle={keyword || level !== 'all' ? '没有匹配的日志' : '暂无历史日志'}
      emptyDescription={
        keyword || level !== 'all' ? '试试放宽关键词或级别过滤' : '守护进程尚未写出可检索的历史日志'
      }
      toolbar={
        <>
          <Select<LevelFilter>
            value={level}
            onChange={onLevelChange}
            style={{ width: 120 }}
            options={[
              { label: '全部级别', value: 'all' },
              { label: 'DEBUG', value: 'DEBUG' },
              { label: 'INFO', value: 'INFO' },
              { label: 'WARN', value: 'WARN' },
              { label: 'ERROR', value: 'ERROR' },
            ]}
          />
          <Input.Search
            allowClear
            placeholder="搜索关键词"
            defaultValue={keyword}
            onSearch={(v) => onKeywordChange(v)}
            onChange={(e) => {
              if (e.target.value === '') onKeywordChange('')
            }}
            style={{ width: 260 }}
          />
          <Button icon={<ReloadOutlined />} onClick={query.refetch} loading={query.isRefreshing}>
            刷新
          </Button>
          <Typography.Text type="secondary" style={{ marginLeft: 'auto', fontSize: 12 }}>
            共 {total} 行
          </Typography.Text>
        </>
      }
      pagination={{
        current: page,
        pageSize,
        total,
        showSizeChanger: true,
        pageSizeOptions: [20, 50, 100, 200],
        showTotal: (t) => `共 ${t} 行`,
        onChange: onPageChange,
      }}
      scroll={{ x: 'max-content' }}
    />
  )
}
