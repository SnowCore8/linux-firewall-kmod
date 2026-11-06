import { useEffect, useRef } from 'react'

/**
 * 全局快捷键订阅 —— 命令面板（mod+k）、刷新（r）、切主题（mod+j）等共用一套解析。
 *
 * 组合键写法：`mod+k`（mod = macOS 的 ⌘ / 其余平台的 Ctrl）、`shift+?`、`alt+1`、`g d`
 * 这种「先按 g 再按 d」的序列暂不支持（保持简单，命令面板已覆盖多数跳转）。
 *
 * 默认在输入控件（input/textarea/contenteditable）里**不触发**单字母键，免得打字时误触；
 * 带 mod 的组合（如 mod+k）则始终触发——这是通用预期。`allowInInput` 可强制放开。
 */

export interface HotkeyOptions {
  /** 在输入框内也触发；默认 false（带 mod 的组合不受此限）。 */
  allowInInput?: boolean
  /** 为 false 时暂停监听。 */
  enabled?: boolean
  /** 触发后是否 preventDefault（默认 true，避免与浏览器默认行为冲突）。 */
  preventDefault?: boolean
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  const tag = target.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable
}

/**
 * 是否 macOS 系平台 —— mod 键解析与 UI 快捷键标签（⌘ vs Ctrl）的唯一判定来源。
 * 导出给外壳等需要显示「mod+K」实际按键的地方复用，避免各处各判一遍导致标签与行为不一致。
 */
export const IS_MAC =
  typeof navigator !== 'undefined' && /mac|iphone|ipad|ipod/i.test(navigator.platform || '')

/** 把 'mod+shift+k' 解析成 { key, ctrl, shift, alt, meta, needsMod }。 */
function parseCombo(combo: string) {
  const parts = combo.toLowerCase().split('+').map((p) => p.trim())
  const spec = { key: '', ctrl: false, shift: false, alt: false, meta: false, needsMod: false }
  for (const part of parts) {
    if (part === 'mod') {
      spec.needsMod = true
      if (IS_MAC) spec.meta = true
      else spec.ctrl = true
    } else if (part === 'ctrl' || part === 'control') spec.ctrl = true
    else if (part === 'meta' || part === 'cmd' || part === 'command') spec.meta = true
    else if (part === 'alt' || part === 'option') spec.alt = true
    else if (part === 'shift') spec.shift = true
    else spec.key = part
  }
  return spec
}

export function useHotkey(
  combo: string,
  handler: (e: KeyboardEvent) => void,
  options: HotkeyOptions = {},
): void {
  const { allowInInput = false, enabled = true, preventDefault = true } = options
  const handlerRef = useRef(handler)
  handlerRef.current = handler

  useEffect(() => {
    if (!enabled) return
    const spec = parseCombo(combo)

    const onKeyDown = (e: KeyboardEvent) => {
      const usesMod = spec.ctrl || spec.meta || spec.alt
      if (isEditableTarget(e.target) && !allowInInput && !usesMod) return

      const key = e.key.toLowerCase()
      const keyMatches =
        spec.key === key ||
        // '?' 需要 shift，e.key 直接就是 '?'；'/' 同理。用 code 兜底字母键。
        (spec.key.length === 1 && key === spec.key)
      if (!keyMatches) return
      if (spec.ctrl !== e.ctrlKey) return
      if (spec.meta !== e.metaKey) return
      if (spec.alt !== e.altKey) return
      if (spec.shift !== e.shiftKey && spec.key.length > 1) return

      if (preventDefault) e.preventDefault()
      handlerRef.current(e)
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [combo, enabled, allowInInput, preventDefault])
}
