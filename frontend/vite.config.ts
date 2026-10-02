// Vite 构建配置 — 产物直接落到 Go 守护进程的 go:embed 目录
//
// 关键约束（与 Go 守护进程 Web UI 的静态服务契约对齐，迁移前后不变）：
//   1. base = "/static/"：守护进程通过 `GET /static/*path` 提供资源，
//      因此 index.html 中的资源引用必须带 /static/ 前缀。
//   2. assetsDir = ""：资源平铺输出，文件名固定，便于 go:embed 相对查找。
//   3. 守护进程只对一组固定的页面路径返回 HTML、无 catch-all，故前端用 hash 路由。
//
// PWA 例外：service worker 需要根作用域才能接管页面导航，而 /static/ 下的
// 资源天然只有 /static/ 作用域，故 sw.js 由守护进程单独用 /sw.js 路由提供，
// 这里只负责把它输出到 static/。
//
// JSX 运行时：不使用 React。tsconfig 的 jsxImportSource 指向自研运行时，esbuild
// 会把 JSX 编译成 `import { jsx } from "@fw/jsx/jsx-runtime"` 这类裸标识符，
// 由下面的 alias 落到 src/jsx。tsconfig 的 paths 与本段 alias 必须成对维护，
// 否则 tsc 与打包器的解析结果会不一致（tsc 报找不到模块、打包器另找一份实现）。
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const jsxRuntime = fileURLToPath(new URL('./src/jsx', import.meta.url))

export default defineConfig({
  resolve: {
    alias: [
      { find: '@fw/jsx/jsx-runtime', replacement: `${jsxRuntime}/jsx-runtime.ts` },
      { find: '@fw/jsx/jsx-dev-runtime', replacement: `${jsxRuntime}/jsx-dev-runtime.ts` },
    ],
  },

  // 产物经 /static/*path 提供，必须带该前缀
  base: '/static/',

  build: {
    // 直接输出到 Go 守护进程的嵌入目录（相对 frontend/）
    outDir: '../src/daemon-go/web_ui/static',
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
