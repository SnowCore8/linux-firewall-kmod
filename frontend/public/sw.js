/**
 * Firewall 控制面板 Service Worker —— 手写、零依赖
 *
 * 设计约束（与守护进程的静态服务契约配套）：
 *   - 本文件由守护进程的 `GET /sw.js` 提供（带 Service-Worker-Allowed: /），
 *     而不是走 `/static/`，否则作用域会被限制在 `/static/`，无法接管页面导航。
 *   - 前端是 hash 路由，服务端对 7 个页面路径都返回同一份 index.html，
 *     因此离线外壳只需缓存其中一个路径即可。
 *
 * 缓存策略：
 *   1. 导航请求      —— 网络优先，失败回退缓存的外壳（断网仍可打开界面）
 *   2. `/static/*`   —— 网络优先，失败回退缓存（离线仍可用；见 networkFirstAsset 内注释）
 *   3. `/api/*`      —— 完全不拦截：实时封禁/统计/SSE 数据绝不能读缓存
 *   4. 其余同源 GET  —— 交给网络（如 /metrics、/health）
 *
 * 升级方式：改动本文件后把 CACHE_VERSION 加一，activate 阶段会自动清掉旧缓存。
 */

const CACHE_VERSION = 'v2'

// 应用外壳缓存（index.html）
const SHELL_CACHE = `firewall-shell-${CACHE_VERSION}`
// 构建产物缓存（app.js / style.css / icons / manifest.webmanifest …）
const ASSET_CACHE = `firewall-assets-${CACHE_VERSION}`

// 本版本保留的缓存白名单，其余（含旧版本）在 activate 时清理
const KEEP_CACHES = [SHELL_CACHE, ASSET_CACHE]

// 离线外壳使用的固定缓存键。用固定键而非 request.url，避免 `/` 与
// `/dashboard` 各存一份同样的 index.html。
const SHELL_URL = '/dashboard'

// 静态资源前缀（vite 配置 base: '/static/'）
const STATIC_PREFIX = '/static/'

// 实时数据前缀（绝不缓存）
const API_PREFIX = '/api/'

/**
 * 最后一次兜底的离线提示页：只有在外壳也没缓存到时才会返回。
 */
const OFFLINE_FALLBACK_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Firewall — 离线</title>
<style>
  body { margin: 0; min-height: 100vh; display: flex; align-items: center;
         justify-content: center; background: #0a0e14; color: #d7e0e6;
         font-family: system-ui, -apple-system, sans-serif; text-align: center; }
  main { padding: 24px; max-width: 20em; }
  h1 { font-size: 1.1rem; margin: 0 0 12px; color: #3d8b9a; }
  p { margin: 0; font-size: 0.875rem; line-height: 1.6; color: #8b9aa5; }
</style>
</head>
<body>
<main>
  <h1>界面尚未缓存</h1>
  <p>当前离线，且本机还没有成功加载过控制面板，因此无法显示缓存副本。请恢复网络后重试。</p>
</main>
</body>
</html>`

/**
 * 安装：立刻接管，并尽力预缓存应用外壳。
 *
 * 外壳预取失败不阻塞安装 —— 首次访问时 Basic Auth 可能尚未完成、
 * 或本机就处于离线状态，这两种情况都该留待首次成功导航时再填充缓存。
 */
self.addEventListener('install', (event) => {
  const precache = (async () => {
    try {
      const response = await fetch(SHELL_URL, {
        credentials: 'same-origin',
        cache: 'reload',
      })
      if (response && response.ok) {
        const cache = await caches.open(SHELL_CACHE)
        await cache.put(SHELL_URL, response.clone())
      }
    } catch (_) {
      // 离线 / 未鉴权：忽略，交给首次成功导航填充
    }
    await self.skipWaiting()
  })()
  event.waitUntil(precache)
})

/**
 * 激活：清理旧版本缓存 + 立即接管所有受控页面。
 */
self.addEventListener('activate', (event) => {
  const cleanup = (async () => {
    const names = await caches.keys()
    await Promise.all(
      names
        .filter((name) => !KEEP_CACHES.includes(name))
        .map((name) => caches.delete(name)),
    )
    await self.clients.claim()
  })()
  event.waitUntil(cleanup)
})

/**
 * 导航请求：网络优先，失败回退缓存的外壳。
 *
 * 成功响应同时写入外壳缓存，使离线时能打开界面（数据仍来自实时 SSE，
 * 离线期间自然为空，界面自身的离线横幅由应用层负责提示）。
 */
async function networkFirstShell(request) {
  try {
    const response = await fetch(request)
    if (response && response.ok) {
      const cache = await caches.open(SHELL_CACHE)
      await cache.put(SHELL_URL, response.clone())
    }
    return response
  } catch (_) {
    const cached = await caches.match(SHELL_URL)
    if (cached) {
      return cached
    }
    return new Response(OFFLINE_FALLBACK_HTML, {
      status: 503,
      statusText: 'Service Unavailable',
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    })
  }
}

/**
 * `/static/*`：网络优先，失败回退缓存。
 *
 * 为什么不是缓存优先：构建产物文件名是固定的（app.js / style.css，
 * 见 vite.config.ts 的 entryFileNames），而缓存版本标识埋在 app.js 内部。
 * 若缓存优先，守护进程升级后第一次加载会**把上一版的 JS 喂给新版 index.html**
 * ——表现为界面停留在旧样式、或新旧不匹配导致的运行期错误（本项目曾因此出现
 * 「调整后的界面看不到、API 全 401」），要等下一次刷新才自愈。
 * 守护进程对 `/static/*` 已声明 `Cache-Control: no-store`，因此回源本身
 * 不会被浏览器 HTTP 缓存拦下，网络优先是零额外代价的正确选择。
 *
 * 缓存仅作为离线兜底保留：断网时仍能加载已缓存的界面。
 */
async function networkFirstAsset(request) {
  const cache = await caches.open(ASSET_CACHE)
  try {
    const response = await fetch(request)
    if (response && response.ok) {
      await cache.put(request, response.clone())
    }
    return response
  } catch (_) {
    const cached = await cache.match(request)
    if (cached) {
      return cached
    }
    return new Response('', { status: 504, statusText: 'Gateway Timeout' })
  }
}

/**
 * fetch 分发：按路径与请求类型选择策略。
 */
self.addEventListener('fetch', (event) => {
  const request = event.request

  // 只处理 GET；POST/PUT/DELETE 一律直连网络
  if (request.method !== 'GET') {
    return
  }

  const url = new URL(request.url)

  // 跨源请求不介入
  if (url.origin !== self.location.origin) {
    return
  }

  // 实时数据：完全不拦截。封禁列表、统计、SSE 事件流都必须直连守护进程，
  // 任何缓存都可能展示过期的封禁状态。
  if (url.pathname.startsWith(API_PREFIX)) {
    return
  }

  // 页面导航：网络优先 + 离线回退外壳
  if (request.mode === 'navigate') {
    event.respondWith(networkFirstShell(request))
    return
  }

  // 构建产物：网络优先 + 离线回退缓存
  if (url.pathname.startsWith(STATIC_PREFIX)) {
    event.respondWith(networkFirstAsset(request))
    return
  }

  // 其余同源 GET（/metrics、/health 等）交给网络，不缓存
})
