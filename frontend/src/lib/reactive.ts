/**
 * 把渲染函数挂到 DOM 上。
 *
 * 没有虚拟 DOM，因此「局部更新」不是 diff 出来的：给定渲染函数，返回一个宿主
 * 元素，数据变化时清空宿主并重挂整棵子树。宿主用 display: contents，只作为
 * 重挂锚点存在，不生成盒子、不影响父级布局。
 *
 * 注意：宿主是真实元素，不能放在 <table>/<select>/<ul> 这类对子节点有严格约束的
 * 位置；需要时请把 reactive 提到这些元素外层。
 */

import { render, type Child } from '../jsx/jsx-runtime'
import { effect } from './signals'

export function reactive(renderChild: () => Child): Node {
  const host = document.createElement('div')
  host.style.display = 'contents'

  effect(() => {
    host.replaceChildren()
    render(host, renderChild())
  })

  return host
}
