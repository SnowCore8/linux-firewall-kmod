/**
 * JSX 运行时的 DOM 构建层。
 *
 * # 职责
 * 把 `create(标签名 | 组件, props, key)` 直接物化成真实 DOM 节点：无虚拟 DOM、
 * 无 diff、无调度。面板数据由 SSE 推送驱动，刷新语义是「整棵子树重建」，
 * 因此这里只需要「一次成型」。
 *
 * # 命名空间
 * `document.createElement` 建出的标签一律落在 HTML 命名空间，SVG 标签必须走
 * createElementNS，否则浏览器不会把它当图形处理。JSX 求值时拿不到父节点，无法
 * 像 HTML 解析器那样按父级继承命名空间，因而改用一份固定的 SVG 标签表判定。
 * 表里刻意不含 HTML/SVG 同名的 title / style / a / script，避免误伤 HTML 用法。
 *
 * # 属性
 * 属性名沿用 JSX 习惯：className、htmlFor 等少数别名做显式映射；SVG 元素上的
 * 驼峰名转连字符（viewBox 这类必须保序的名字见 SVG_CASE_ATTRS）；HTML 元素依赖
 * setAttribute 自身的大小写不敏感。事件属性走 addEventListener，不覆写 DOM 属性。
 * style 对象里以 `--` 开头的键按 CSS 变量处理，数字值默认补 px。
 */

import type { Child, CommonProps, Component, ElementType, StyleMap } from './jsx-runtime'
import { Fragment } from './symbols'

const SVG_NS = 'http://www.w3.org/2000/svg'

/**
 * 需要建进 SVG 命名空间的标签。JSX 侧只会用到图表那一小组，
 * 但表按 SVG 1.1/2 的常见元素补全，避免后续加图时再回来改。
 */
const SVG_TAGS = new Set<string>([
  'svg',
  'g',
  'defs',
  'symbol',
  'use',
  'path',
  'rect',
  'circle',
  'ellipse',
  'line',
  'polyline',
  'polygon',
  'text',
  'tspan',
  'textPath',
  'marker',
  'pattern',
  'clipPath',
  'mask',
  'linearGradient',
  'radialGradient',
  'stop',
  'filter',
  'feBlend',
  'feColorMatrix',
  'feComponentTransfer',
  'feComposite',
  'feFlood',
  'feGaussianBlur',
  'feMerge',
  'feMergeNode',
  'feOffset',
  'feTurbulence',
  'foreignObject',
  'image',
  'switch',
  'view',
])

/**
 * SVG 元素上必须保留驼峰大小写的属性名。其余驼峰名一律转连字符
 * （strokeWidth → stroke-width），因为 SVG 属性名是大小写敏感的。
 */
const SVG_CASE_ATTRS = new Set<string>([
  'viewBox',
  'preserveAspectRatio',
  'gradientUnits',
  'gradientTransform',
  'patternUnits',
  'patternContentUnits',
  'patternTransform',
  'clipPathUnits',
  'maskUnits',
  'maskContentUnits',
  'primitiveUnits',
  'filterUnits',
  'markerWidth',
  'markerHeight',
  'markerUnits',
  'refX',
  'refY',
  'spreadMethod',
  'startOffset',
  'textLength',
  'lengthAdjust',
  'attributeName',
  'attributeType',
  'repeatCount',
  'repeatDur',
  'calcMode',
  'pathLength',
  'stdDeviation',
  'baseFrequency',
  'numOctaves',
  'kernelMatrix',
  'kernelUnitLength',
  'tableValues',
  'keyTimes',
  'keySplines',
  'keyPoints',
  'requiredFeatures',
  'systemLanguage',
  'xChannelSelector',
  'yChannelSelector',
  'diffuseConstant',
  'specularConstant',
  'specularExponent',
  'surfaceScale',
  'pointsAtX',
  'pointsAtY',
  'pointsAtZ',
  'limitingConeAngle',
  'z',
  'in',
  'in2',
])

/** 无 props 时复用的空对象，避免每次求值新建 */
export const EMPTY_PROPS: CommonProps = Object.freeze(Object.create(null) as CommonProps)

/**
 * 元素/组件求值入口。key 只供调用方标识数据项，不参与构建。
 */
export function create(type: ElementType, props: CommonProps | null, _key?: string | number): Node | null {
  const resolved = props ?? EMPTY_PROPS

  if (type === Fragment) {
    return buildFragment(resolved)
  }
  if (typeof type === 'function') {
    return buildComponent(type as Component<CommonProps>, resolved)
  }
  if (typeof type === 'string') {
    return buildElement(type, resolved)
  }
  throw new TypeError(`不支持的 JSX 元素类型: ${String(type)}`)
}

/** 片段求值为 DocumentFragment，挂载时其子节点被摊平、本身不留痕迹 */
function buildFragment(props: CommonProps): DocumentFragment {
  const fragment = document.createDocumentFragment()
  appendChildren(fragment, props.children)
  return fragment
}

/** 函数组件的返回值即渲染结果；undefined 一律收敛成 null（不渲染） */
function buildComponent(component: Component<CommonProps>, props: CommonProps): Node | null {
  const rendered = component(props)
  return rendered === undefined ? null : rendered
}

/** 元素：建节点、落属性、递归挂子节点、最后回调 ref */
function buildElement(tag: string, props: CommonProps): Node {
  const isSvg = SVG_TAGS.has(tag)
  const element = isSvg ? document.createElementNS(SVG_NS, tag) : document.createElement(tag)

  applyProps(element, props, isSvg)
  appendChildren(element, props.children)

  const ref = props.ref
  if (typeof ref === 'function') {
    ref(element)
  }

  return element
}

/**
 * 把子节点挂到父级下。数组与可迭代对象按顺序摊平；null / undefined / boolean
 * 表示「不渲染」直接跳过。DocumentFragment 交给 appendChild 自行摊平。
 */
export function appendChildren(parent: Node, child: Child): void {
  if (child === null || child === undefined || typeof child === 'boolean') {
    return
  }
  if (typeof child === 'string' || typeof child === 'number') {
    parent.appendChild(document.createTextNode(String(child)))
    return
  }
  if (typeof Node !== 'undefined' && child instanceof Node) {
    parent.appendChild(child)
    return
  }
  if (isIterable(child)) {
    for (const item of child) {
      appendChildren(parent, item)
    }
    return
  }
  throw new TypeError(`不可渲染的子节点类型: ${describe(child)}`)
}

function isIterable(value: unknown): value is Iterable<Child> {
  return typeof value === 'object' && value !== null && Symbol.iterator in value
}

function describe(value: unknown): string {
  if (Array.isArray(value)) {
    return 'array'
  }
  if (value === null) {
    return 'null'
  }
  return typeof value
}

/**
 * JSX 习惯名 → 真实属性名的别名。只收「小写化之后不是真实属性名」的几个：
 * HTML 的 setAttribute 本身大小写不敏感，其余名字无需翻译。
 */
const ATTRIBUTE_ALIASES: Record<string, string> = {
  className: 'class',
  class: 'class',
  htmlFor: 'for',
  httpEquiv: 'http-equiv',
  acceptCharset: 'accept-charset',
}

/** 标准布尔属性：true 写空值，false 走删除（见 setProp） */
const BOOLEAN_ATTRS = new Set<string>([
  'hidden',
  'disabled',
  'selected',
  'required',
  'multiple',
  'autofocus',
  'open',
  'controls',
  'loop',
  'muted',
  'novalidate',
  'playsinline',
  'async',
  'defer',
  'inert',
  'reversed',
  'default',
])

/**
 * 只有写成 DOM 属性才生效的名字：表单控件的即时值不反映到 attribute 上，
 * `indeterminate` 甚至没有对应 attribute；`checked` 走属性可区分默认值与当前值。
 */
const PROPERTY_PROPS = new Set<string>(['value', 'checked', 'indeterminate', 'selectedIndex'])

/** onXxx → 事件类型名；只有大小写不成规则的几个需要显式映射，其余小写化即可 */
const EVENT_ALIASES: Record<string, string> = {
  onDoubleClick: 'dblclick',
}

/** 数字按无单位值写入的 CSS 属性，其余数字补 px */
const UNITLESS = new Set<string>([
  'opacity',
  'z-index',
  'flex',
  'flex-grow',
  'flex-shrink',
  'order',
  'line-height',
  'font-weight',
  'zoom',
  'aspect-ratio',
  'tab-size',
  'column-count',
  'columns',
  'grid-row',
  'grid-column',
  'grid-row-start',
  'grid-row-end',
  'grid-column-start',
  'grid-column-end',
  'animation-iteration-count',
  'scale',
  'fill-opacity',
  'stroke-opacity',
  'stroke-width',
  'stroke-dasharray',
  'stroke-dashoffset',
  'stroke-miterlimit',
])

/** HTML 与 SVG 元素在属性/样式写入上的公共类型 */
type DomElement = HTMLElement | SVGElement

/** 遍历 props 落属性：事件走监听器，style 单独处理，children/key/ref 不是属性 */
function applyProps(element: DomElement, props: CommonProps, isSvg: boolean): void {
  for (const name of Object.keys(props)) {
    if (name === 'children' || name === 'key' || name === 'ref' || name === 'style') {
      continue
    }
    const value = props[name]
    if (name.startsWith('on') && name.length > 2 && isUpperCode(name.charCodeAt(2))) {
      listen(element, name, value)
      continue
    }
    setProp(element, name, value, isSvg)
  }
  if (props.style !== undefined) {
    applyStyle(element, props.style)
  }
}

/** 单个属性的写入规则：假值删除、真值按布尔属性处理，其余转成字符串 */
function setProp(element: DomElement, name: string, value: unknown, isSvg: boolean): void {
  const attribute = resolveAttrName(name, isSvg)

  if (value === null || value === undefined || value === false) {
    element.removeAttribute(attribute)
    return
  }
  if (value === true) {
    element.setAttribute(attribute, BOOLEAN_ATTRS.has(attribute) ? '' : 'true')
    return
  }
  if (!isSvg && PROPERTY_PROPS.has(name)) {
    ;(element as unknown as Record<string, unknown>)[name] = value
    return
  }
  element.setAttribute(attribute, String(value))
}

/** SVG 属性名大小写敏感：需要保序的查表，其余驼峰转连字符；HTML 侧原样下传 */
function resolveAttrName(name: string, isSvg: boolean): string {
  const alias = ATTRIBUTE_ALIASES[name]
  if (alias !== undefined) {
    return alias
  }
  if (!isSvg || SVG_CASE_ATTRS.has(name)) {
    return name
  }
  return toKebab(name)
}

/** 事件属性注册监听器，不覆写同名 DOM 属性 */
function listen(element: DomElement, prop: string, value: unknown): void {
  if (typeof value !== 'function') {
    return
  }
  const type = EVENT_ALIASES[prop] ?? prop.slice(2).toLowerCase()
  element.addEventListener(type, value as EventListener)
}

/**
 * 内联样式：字符串整体写入；对象逐条 setProperty，`--` 前缀按 CSS 变量原样处理，
 * 空值删除该声明。
 */
function applyStyle(element: DomElement, style: string | StyleMap): void {
  if (typeof style === 'string') {
    element.setAttribute('style', style)
    return
  }

  const declarations = element.style
  for (const key of Object.keys(style)) {
    const value = style[key]
    if (key.startsWith('--')) {
      if (value === null || value === undefined || value === '') {
        declarations.removeProperty(key)
      } else {
        declarations.setProperty(key, String(value))
      }
      continue
    }

    const property = toKebab(key)
    if (value === null || value === undefined || value === '') {
      declarations.removeProperty(property)
      continue
    }
    const text = typeof value === 'number' && !UNITLESS.has(property) ? `${value}px` : String(value)
    declarations.setProperty(property, text)
  }
}

function toKebab(name: string): string {
  return name.replace(/[A-Z]/g, (ch) => `-${ch.toLowerCase()}`)
}

function isUpperCode(code: number): boolean {
  return code >= 65 && code <= 90
}
