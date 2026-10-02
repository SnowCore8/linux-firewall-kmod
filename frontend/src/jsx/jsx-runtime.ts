/**
 * 无框架 JSX 运行时 —— JSX 只作为语法，求值结果直接是 DOM 节点。
 *
 * # 契约
 * `tsconfig.json` 的 `jsxImportSource` 指向本模块的包别名，编译器据此把
 * `<div />` 编译成 `jsx('div', { ... })`、`<A />` 编译成 `jsx(A, { ... })`。
 * 自动运行时要求具名导出 `jsx` / `jsxs` / `Fragment`；开发模式另需
 * `jsx-dev-runtime` 导出的 `jsxDEV`（见同目录 jsx-dev-runtime.ts）。
 *
 * # 返回值
 * 一律返回真实 DOM 节点（元素或 DocumentFragment）。函数组件的返回值就是它的
 * 渲染结果；返回 null 表示「不渲染任何内容」，由父级 appendChildren 跳过。
 *
 * # 为什么没有虚拟 DOM
 * 面板数据由 SSE 推送 + REST 回退驱动，刷新语义是「整棵子树重建」，没有高频局部
 * 更新，diff 的复杂度与运行时体积换不到收益。
 *
 * # 约定
 * - 属性名沿用 JSX 习惯（className / htmlFor / onXxx），内部统一翻译成 DOM API。
 * - `style` 接受对象或字符串；对象中以 `--` 开头的键走 setProperty（CSS 变量）。
 * - `key` 供调用方标识数据项，本运行时不参与 diff，也不写入 DOM。
 * - 事件属性注册 addEventListener，不覆盖同名 DOM 属性。
 */

import { appendChildren, create } from './dom'
import { Fragment } from './symbols'

/** 可渲染的子节点：节点、文本、数组/可迭代，以及表示「不渲染」的空值与假值 */
export type Child =
  | Node
  | string
  | number
  | boolean
  | null
  | undefined
  | Iterable<Child>
  | Child[]

/** CSS 属性值；数字原样写入（需要单位时由调用方自带） */
export type StyleValue = string | number | null | undefined

/** 内联样式表 */
export type StyleMap = Record<string, StyleValue>

/** 事件处理函数；具体事件类型由各 onXxx 属性声明 */
export type EventHandler<E extends Event = Event> = (event: E) => void

/** 所有元素共有、且值得写进类型的属性；其余属性经索引签名透传 */
export interface CommonProps {
  children?: Child
  key?: string | number
  /** 函数式 ref：节点挂载后回调一次 */
  ref?: (node: HTMLElement | SVGElement) => void
  class?: string
  className?: string
  style?: string | StyleMap
  id?: string
  title?: string
  role?: string
  tabIndex?: number
  hidden?: boolean
  disabled?: boolean
  onClick?: EventHandler<MouseEvent>
  onDoubleClick?: EventHandler<MouseEvent>
  onInput?: EventHandler<Event>
  onChange?: EventHandler<Event>
  onKeyDown?: EventHandler<KeyboardEvent>
  onKeyUp?: EventHandler<KeyboardEvent>
  onKeyPress?: EventHandler<KeyboardEvent>
  onSubmit?: EventHandler<Event>
  onFocus?: EventHandler<FocusEvent>
  onBlur?: EventHandler<FocusEvent>
  onScroll?: EventHandler<Event>
  onTouchStart?: EventHandler<TouchEvent>
  onTouchEnd?: EventHandler<TouchEvent>
  onAnimationEnd?: EventHandler<AnimationEvent>
  onLoad?: EventHandler<Event>
  onError?: EventHandler<Event>
  /** aria-* / data-* 与元素专有属性透传，值类型不做约束 */
  [attribute: string]: unknown
}

declare global {
  namespace JSX {
    /** 一次 JSX 求值的结果：真实 DOM 节点；null 表示不渲染 */
    type Element = Node | null
    interface ElementChildrenAttribute {
      children: {}
    }
    interface IntrinsicElements extends CommonProps {}
  }
}

/**
 * 片段标记。`<>…</>` 编译为 `jsx(Fragment, { children: [...] })`，
 * 求值为 DocumentFragment —— 挂载时子节点会被摊平进父级，本身不留痕迹。
 */
export { Fragment }

/** 组件契约：props 具体类型由各组件自行声明，运行时的收口类型见 create */
export type Component<P = CommonProps> = (props: P) => Node | null

/** JSX 元素类型：内置标签名、Fragment，或函数组件 */
export type ElementType = string | typeof Fragment | Component<never>

/**
 * 单子节点入口。children 放在 props.children，由 create 统一挂载。
 */
export function jsx(type: ElementType, props: CommonProps | null, key?: string | number): Node | null {
  return create(type, props, key)
}

/**
 * 多子节点入口。静态多子节点的 children 一定是数组，行为与 jsx 一致 ——
 * 分开只为对齐自动运行时约定，运行时不做区分。
 */
export function jsxs(type: ElementType, props: CommonProps | null, key?: string | number): Node | null {
  return create(type, props, key)
}

/**
 * 开发模式入口。source / self / isStaticChildren 只服务于 React 的调试信息，
 * 本运行时不需要，一律忽略。
 */
export function jsxDEV(
  type: ElementType,
  props: CommonProps | null,
  key?: string | number,
): Node | null {
  return create(type, props, key)
}

/**
 * 把节点挂到父级下，供入口与动态区域使用。
 *
 * 命名上区分于 appendChildren：render 是外部调用点的措辞，让 main.tsx 这类入口
 * 读起来是「挂载」而不是「拼接子节点」。
 */
export function render(parent: Node, child: Child): void {
  appendChildren(parent, child)
}
