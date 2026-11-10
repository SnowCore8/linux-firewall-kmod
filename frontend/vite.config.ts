// Vite 构建配置 — 产物落到 build/obj/frontend（源码树之外）
//
// 中间产物与源码分离：Makefile 的 `make daemon` 在 go build 前把这里的内容临时
// 拷入 src/daemon/web_ui/static（go:embed 的输入），构建结束立即删除。
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
    // 中间产物写到 build/obj/frontend（相对 frontend/）。embed 目录不在源码树内，
    // 由 make daemon 临时同步，因此这里可以放心清空输出目录。
    outDir: '../build/obj/frontend',
    emptyOutDir: true,
    target: 'es2020',
    // 资源平铺到输出根目录，避免 assets/ 子目录带来的相对路径差异
    assetsDir: '',
    // 单一 CSS 文件，减少请求数
    cssCodeSplit: false,
    // vendor chunk（echarts/antd）体积大但可长期缓存，提高警告阈值避免噪音
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        // 固定入口文件名，index.html 引用稳定
        entryFileNames: 'app.js',
        chunkFileNames: 'chunk-[name].js',
        assetFileNames: '[name].[ext]',
        // 手动分割大依赖，避免单个 chunk 超过 500 kB 警告阈值
        manualChunks(id) {
          if (id.includes('node_modules')) {
            // ECharts 体积大且仅在图表页使用，独立 chunk 按需加载
            if (id.includes('echarts')) return 'vendor-echarts'
            // Ant Design 组件库独立，避免与业务代码混在一起
            if (id.includes('antd') || id.includes('@ant-design')) return 'vendor-antd'
            // React 核心稳定不变，长期缓存
            if (id.includes('react')) return 'vendor-react'
          }
        },
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
