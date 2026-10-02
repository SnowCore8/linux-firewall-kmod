/**
 * JSX 运行时共享标记。
 *
 * 单独成模块是为了断开 jsx-runtime（对外契约）与 dom（DOM 构建）之间的循环：
 * 两边都要用到 Fragment，而它必须是同一个值。
 */

/**
 * 片段标记。`<>…</>` 编译为 `jsx(Fragment, { children: [...] })`，
 * 求值为 DocumentFragment —— 挂载时子节点被摊平进父级，本身不留痕迹。
 */
export const Fragment: unique symbol = Symbol.for('firewall.jsx.fragment')
