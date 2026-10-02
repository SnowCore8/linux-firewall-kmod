/**
 * 仅存在于前端视图的查询参数类型。
 *
 * 这些名字对应的是「界面允许用户选择的排序方式」与「分页请求参数」，
 * 属于前端交互词汇而非后端契约字段，因此不进 `http_contract.ts`。
 * 其中 `sort_by` 的取值必须与服务端的排序键逐字一致。
 */

/** `GET /api/v1/bans` 的排序键；取值对应服务端的排序分支 */
export type BanSortKey =
  | 'banned_at_desc'
  | 'banned_at_asc'
  | 'ip_asc'
  | 'ip_desc'
  | 'jail_asc'
  | 'remaining_asc'
  | 'remaining_desc'

/** 分页请求参数；后端缺省 page=1、page_size=20，上限 page_size=100 */
export interface PaginationParams {
  page?: number
  page_size?: number
  sort_by?: BanSortKey
}
