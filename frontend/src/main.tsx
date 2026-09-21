// 应用入口：挂载 React 根、装配全局 Provider
//
// 职责边界：本文件只做「挂载 + Provider 组合」，不包含任何路由或视图逻辑。
// Provider 组合顺序（固定，不要调整）：Theme → Toast → Auth → App。
//   - Theme 最外层：主题令牌要覆盖后续所有分支（含 Toast / Popup 等 portal 内容）
//   - Toast 在 Auth 之外：登录失败/成功提示需要 Toast
//   - Auth 在 App 之外：App 内的 AuthGate 据此决定渲染登录页还是主界面
//   - SseProvider 不在这里，而在 AuthGate 内部（App.tsx）：未认证时不得建立
//     SSE 连接，否则无令牌的 EventSource 会持续 401 并喂大服务端暴力破解计数
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { unstableSetRender } from 'antd-mobile'

// antd-mobile 全局样式（reset + --adm-* 变量）。从 'antd-mobile' 桶导入时也会带上，
// 这里显式声明依赖：即使将来组件改为按路径导入，全局样式也不会丢。
import 'antd-mobile/es/global'
import './styles/global.css'

import App from './App'
import { initAccessToken } from './api/auth'
import { ErrorBoundary } from './components/ErrorBoundary'
import { AuthProvider } from './hooks/useAuth'
import { ThemeProvider } from './hooks/useTheme'
import { ToastProvider } from './hooks/useToast'

// ---- React 19 兼容：给 antd-mobile 的命令式渲染器换上 createRoot ----
//
// antd-mobile v5 的 peer 只声明到 React 18；命令式 API（Dialog.confirm、Toast.show、
// Popup/Modal 的 imperative 调用）内部走 rc-util 的 render.js，而该模块**优先**取用
// 已被 React 19 删除的 `ReactDOM.render` / `unmountComponentAtNode`（它们的 `render`
// 现在从 `react-dom/client` 暴露）。结果是：点击一次 Toast/Dialog 就会抛
// `TypeError: <minified> is not a function`，提示与二次确认框全部不出现。
//
// antd-mobile 为此专门留了官方兼容开关 `unstableSetRender`，用它把命令式渲染换成
// `react-dom/client` 的 `createRoot`。必须在**任何** Toast/Dialog 调用之前执行，
// 故放在模块顶层、Provider 挂载之前。
unstableSetRender((node, container) => {
  const root = createRoot(container)
  root.render(node)
  // 返回卸载函数（契约要求 Promise<void>）；容器的移除由调用方 renderToBody 负责
  return async () => {
    root.unmount()
  }
})

// 认证令牌必须在任何请求发生前解析完成：把 URL 里的 `?access_token=`
// （或 sessionStorage 中上次登录留下的令牌）装载进 api/auth.ts 的缓存。
// 返回 null 表示未认证，AuthGate 会渲染登录页。
initAccessToken()

// 挂载点由后端 render_dashboard() 返回的 index.html 提供（<div id="root">）。
// 找不到就直接抛出可见错误，避免出现「白屏且无任何提示」的排查黑洞。
const container = document.getElementById('root')
if (!container) {
  throw new Error('挂载点 #root 不存在：index.html 可能被改动或未正确加载')
}

createRoot(container).render(
  <StrictMode>
    {/* 最外层兜底：Provider 自身抛错时也能看到错误信息，而不是白屏 */}
    <ErrorBoundary>
      <ThemeProvider>
        <ToastProvider>
          <AuthProvider>
            <App />
          </AuthProvider>
        </ToastProvider>
      </ThemeProvider>
    </ErrorBoundary>
  </StrictMode>,
)

// PWA Service Worker 注册。
//
// 注册地址是**根路径** `/sw.js` 而不是 `/static/sw.js`：脚本作用域由脚本 URL
// 决定，`/static/sw.js` 只能接管 `/static/` 下的资源，无法接管页面导航；
// 守护进程为此单独提供了 `/sw.js` 路由（带 `Service-Worker-Allowed: /`）。
//
// 安全上下文限制：浏览器只在 HTTPS 或 localhost 下暴露 `serviceWorker` API。
// 经 `http://<局域网IP>:9119` 访问时该 API 不存在，PWA 安装同样被拒——
// 这是浏览器的硬性约束，本应用无法绕过。此处静默跳过，不影响界面功能。
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((err: unknown) => {
      // 注册失败（http 下强行调用、响应头缺少 Service-Worker-Allowed 等）
      // 只降级为普通网页，不打扰用户
      console.warn('[PWA] Service Worker 注册失败，将以普通网页方式运行：', err)
    })
  })
}
