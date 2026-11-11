import type { ReactNode } from 'react'
import { Flex, Table, type TableProps } from 'antd'
import { LoadingState } from './state/LoadingState.tsx'
import { EmptyState, type EmptyScenario } from './state/EmptyState.tsx'
import { ErrorState } from './state/ErrorState.tsx'
import type { ApiError } from '../api/client.ts'

/**
 * 数据表格封装 —— 把 AntD Table 与全站统一的加载/空/错误态缝在一起。
 *
 * 每个列表页都要处理同样四件事（骨架、空态分场景、错误条、粘性表头 + 密度），若各页各写
 * 一遍，状态体验就会不一致（有的用转圈、有的用骨架，空态文案五花八门）。封装成一处后，
 * 页面只关心「数据 + 列 + 工具条」，四态自动就位。
 *
 * 分工：
 *   * 首屏无数据且加载中 → 表格骨架（不是转圈）；
 *   * 无数据且失败 → 错误块（带重试）；持有旧数据的失败走页级 stale 提示，不覆盖表格；
 *   * 有数据 → AntD Table，空数组时用 EmptyState 作为 locale.emptyText。
 */

export interface DataTableProps<T> extends Omit<TableProps<T>, 'dataSource' | 'loading'> {
  /** 当前数据；null 表示尚未取到（区别于空数组）。 */
  data: T[] | null
  isLoading?: boolean
  /** 前台取数中（首屏 / 手动刷新 / 翻页）；以表格 loading 遮罩呈现。后台轮询不传此位，避免遮罩挡住点击。 */
  isFetching?: boolean
  error?: ApiError | null
  onRetry?: () => void
  /** 空数组时展示的空态场景与文案。 */
  emptyScenario?: EmptyScenario
  emptyTitle?: string
  emptyDescription?: ReactNode
  emptyActionLabel?: string
  onEmptyAction?: () => void
  /** 表格上方的工具条（筛选、批量操作、刷新）。 */
  toolbar?: ReactNode
  /** 骨架行数。 */
  skeletonRows?: number
}

export function DataTable<T extends object>({
  data,
  isLoading = false,
  isFetching = false,
  error = null,
  onRetry,
  emptyScenario = 'no-data',
  emptyTitle,
  emptyDescription,
  emptyActionLabel,
  onEmptyAction,
  toolbar,
  skeletonRows = 6,
  ...tableProps
}: DataTableProps<T>) {
  const emptyNode = (
    <EmptyState
      scenario={emptyScenario}
      title={emptyTitle}
      description={emptyDescription}
      actionLabel={emptyActionLabel}
      onAction={onEmptyAction}
    />
  )

  const rowKey = tableProps.rowKey
  if (!rowKey && process.env.NODE_ENV === 'development') {
    console.warn('DataTable: rowKey is required, using "_index" as fallback')
  }

  let body: ReactNode
  if (isLoading && data == null) {
    body = <LoadingState variant="table" rows={skeletonRows} />
  } else if (error && data == null) {
    body = <ErrorState error={error} onRetry={onRetry} />
  } else {
    body = (
      <Table<T>
        {...tableProps}
        dataSource={data ?? []}
        loading={isFetching}
        sticky
        locale={{ emptyText: emptyNode }}
        rowKey={rowKey ?? '_index'}
      />
    )
  }

  return (
    <Flex vertical gap={12}>
      {toolbar && <div className="fw-table-toolbar">{toolbar}</div>}
      {body}
    </Flex>
  )
}
