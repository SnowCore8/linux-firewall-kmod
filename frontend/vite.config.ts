// Vite 构建配置 — 产物直接落到守护进程的 rust-embed 目录
//
// 关键约束（与 src/daemon/web_ui/mod.rs 的静态服务契约对齐，迁移前后不变）：
//   1. base = "/static/"：守护进程通过 `GET /static/*path` 提供资源，
//      因此 index.html 中的资源引用必须带 /static/ 前缀。
//   2. assetsDir = ""：资源平铺输出，文件名固定，便于 rust-embed 相对查找。
//   3. 守护进程只对 7 个页面路径返回 HTML、无 catch-all，故前端用 hash 路由。
//
// PWA 例外：service worker 需要根作用域才能接管页面导航，而 /static/ 下的
// 资源天然只有 /static/ 作用域，故 sw.js 由守护进程单独用 /sw.js 路由提供
// （见 src/daemon/http_exporter/handler.rs），这里只负责把它输出到 static/。
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],

  // 产物经 /static/*path 提供，必须带该前缀
  base: '/static/',

  build: {
    // 直接输出到守护进程嵌入目录（相对 frontend/）
    outDir: '../src/daemon/web_ui/static',
    emptyOutDir: true,
    target: 'es2020',
    // 资源平铺到输出根目录，避免 assets/ 子目录带来的相对路径差异
    assetsDir: '',
    // 单一 CSS 文件，减少请求数
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        // 固定入口文件名，index.html 引用稳定
        entryFileNames: 'app.js',
        chunkFileNames: 'chunk-[name].js',
        assetFileNames: '[name].[ext]',
      },
    },
  },

  server: {
    // 开发服务器端口与旧版保持一致；API/SSE 代理到守护进程
    port: 8080,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:9119',
        changeOrigin: true,
        // SSE 长连接需要禁用缓冲
        ws: false,
      },
    },
  },
})
