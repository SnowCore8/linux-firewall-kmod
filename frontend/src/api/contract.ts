/**
 * 契约桥 —— 前端接触「生成物」的唯一入口。
 *
 * `contract/generated/http_contract.ts` 由 `contract/http.fwidl` 经 `gen.py` 生成，是路由
 * 路径、鉴权常量与 SSE 事件名的单一真相源。前端任何地方都不得手写 `/api/v2/...` 字面量：
 * `verify_http.py` 的 `check_frontend_route_literals` 会扫遍 `frontend/src`，只放行本文件与
 * `endpoints.ts`。于是「路径改没改」成了一道查表题——契约改名，这里跟着变，调用点一律通过
 * `ROUTES.<常量>` 取值，运行期不会再出现「页面照常跑、直到契约改名才 404」。
 *
 * 本文件只做**再导出**，不新增任何路径知识：值（ROUTES/API_BASE/AUTH）与类型（两个 SSE
 * 事件名联合）分别用 `export` 与 `export type` 转出（tsconfig 开了 verbatimModuleSyntax，
 * 两者必须分开写，否则 isolatedModules 下会报错）。
 */

export { API_BASE, AUTH, ROUTES } from '../../../contract/generated/http_contract'

export type {
  SseEventsApiV2Events,
  SseEventsApiV2LogsStream,
} from '../../../contract/generated/http_contract'
