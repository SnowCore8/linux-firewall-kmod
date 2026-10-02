/**
 * JSX 开发模式运行时入口。
 *
 * 编译器在 development 条件下从 `<jsxImportSource>/jsx-dev-runtime` 取 `jsxDEV`，
 * 该函数比 `jsx` 多出 source / self / isStaticChildren 三个参数，它们只服务于
 * React 的调试信息与热更新，本运行时不需要调试信息，一律忽略并转交 create。
 */

import { create } from './dom'
import type { CommonProps, ElementType } from './jsx-runtime'

export { Fragment } from './symbols'

export function jsxDEV(
  type: ElementType,
  props: CommonProps | null,
  key?: string | number,
  _isStaticChildren?: boolean,
  _source?: unknown,
  _self?: unknown,
): Node | null {
  return create(type, props, key)
}

export { jsx, jsxs, render } from './jsx-runtime'
