/**
 * 后端接口契约的唯一入口。
 *
 * `contract/generated/http_contract.ts` 由 `contract/http.fwidl` 生成，
 * 路径、SSE 事件名与全部响应/请求结构都在那里定义。前端不得再手写这些字面量：
 * 需要新增或修改字段时，改 `.fwidl` 源文件并重新生成，本文件随之一并生效。
 *
 * 这里只做一次转出，好处是前端各处统一 `from '../api/contract'`，将来契约文件
 * 挪位置或拆分都不必逐个改引用点。
 *
 * 相对层数是三层：本文件在 `frontend/src/api/`，契约在仓库根的 `contract/`，
 * 途中要跨过 `api/`、`src/`、`frontend/` 三层；少一层会指向不存在的 `frontend/contract/`。
 */

export * from '../../../contract/generated/http_contract'
