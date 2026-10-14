// Vite 构建配置 — 产物直接落到 Go 守护进程的嵌入目录（src/daemon/web_ui/static）
//
// 关键约束（与守护进程随二进制携带面板的契约对齐，迁移前后不变）：
//   1. base = "/static/"：守护进程对外提供 `GET /static/*path`，
//      因此 index.html 中的资源引用必须带 /static/ 前缀。
//   2. assetsDir = ""：资源平铺输出，文件名固定，便于 go:embed 按名查找。
//   3. 守护进程只对一组固定的页面路径返回 HTML、无 catch-all，故前端用 hash 路由。
//
// PWA 例外：service worker 需要根作用域才能接管页面导航，而 /static/ 下的
// 资源天然只有 /static/ 作用域，故 sw.js 由守护进程单独用 /sw.js 路由提供，
// 这里只负责把它输出到 static/。
//
// JSX 运行时：React 19 自动运行时（tsconfig 的 jsx = "react-jsx"、
// jsxImportSource = "react"）。@vitejs/plugin-react 负责把 .tsx 编译到
// `react/jsx-runtime` 并接上 Fast Refresh；这两处配置必须成对维护，否则 tsc 与
// 打包器会各自解析一份 JSX 实现（tsc 报类型不匹配、产物却跑另一套运行时）。
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],

  // 产物按 /static/*path 提供，必须带该前缀；文件名固定以便
  // 守护进程的 go:embed 按名查找（assets.go 位于 src/daemon/web_ui/static/assets.go）。
  base: '/static/',

  build: {
    // 直接输出到 Go 守护进程的嵌入目录（相对 frontend/）：src/daemon 是模块根，
    // 产物必须是 ../src/daemon/web_ui/static，与 go:embed 目录同名同层。
    outDir: '../src/daemon/web_ui/static',
    // 不能用 emptyOutDir：本目录里还有已入库的 assets.go（//go:embed 的持有文件），
    // vite 清空输出目录会连它一起删掉，随后 go build 就以「包内无 .go 文件」失败。
    // 陈旧面板文件的清理由 make frontend 的构建前置步骤完成（保留 assets.go）。
    emptyOutDir: false,
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
