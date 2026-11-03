import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './app/App.tsx'
import './global.css'

/**
 * 入口 —— 挂载 React 树 + 注册 Service Worker。
 *
 * StrictMode 保留：它在开发期双调用 effect，能提前暴露「SSE 连接没在卸载时清干净」
 * 「订阅没退订」这类副作用泄漏。生产构建不受影响。
 *
 * Service Worker 由守护进程在 `/sw.js`（带 Service-Worker-Allowed: /）提供，而非 /static/，
 * 这样作用域是根、能接管页面导航实现离线外壳。注册失败（如非安全上下文）静默忽略——
 * 面板的核心价值是实时数据，离线只是兜底，不该因 SW 注册失败而报错打断首屏。
 */
const container = document.getElementById('root')
if (!container) throw new Error('缺少 #root 挂载点')

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {
      // 离线能力是可选增强，注册失败不影响在线使用
    })
  })
}
