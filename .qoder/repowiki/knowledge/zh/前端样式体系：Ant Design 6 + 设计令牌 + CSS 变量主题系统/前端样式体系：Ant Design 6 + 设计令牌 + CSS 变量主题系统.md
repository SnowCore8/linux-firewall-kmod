---
kind: frontend_style
name: 前端样式体系：Ant Design 6 + 设计令牌 + CSS 变量主题系统
category: frontend_style
scope:
    - '**'
source_files:
    - frontend/src/theme/tokens.ts
    - frontend/src/providers/ThemeProvider.tsx
    - frontend/src/global.css
    - frontend/vite.config.ts
    - frontend/package.json
    - frontend/src/components/StatCard.tsx
---

## 1. 采用的系统与工具

- **框架与构建**：React 19 + TypeScript + Vite 8，使用 `@vitejs/plugin-react`（React 19 自动 JSX 运行时，`jsx = "react-jsx"`）。
- **组件库**：Ant Design 6（`antd`），通过 `ConfigProvider` 注入 `ThemeConfig`；图标来自 `@ant-design/icons`。
- **图表**：ECharts 6 + `echarts-for-react`，通过独立的 `chartBaseTheme()` / `CHART_COLORS` 与 AntD token 保持同源。
- **PWA**：`public/manifest.webmanifest` + `public/sw.js`，由守护进程单独以 `/sw.js` 路由提供（Vite 仅输出到 static/）。
- **文档站点**：独立于面板的 HonKit/GitBook 站点（`docs/`），不在本风格范畴内。

## 2. 关键文件

- `frontend/src/theme/tokens.ts` — 设计令牌单一真相源（品牌色、语义色、威胁等级色阶、字体族、密度度量、`buildTheme()`、`chartBaseTheme()`）。
- `frontend/src/providers/ThemeProvider.tsx` — 主题 Provider，把 antd ThemeConfig 注入组件树，并把令牌写入 `:root` CSS 变量，维护 `data-theme` / `data-density` 属性。
- `frontend/src/global.css` — 全局样式层：CSS 变量兜底默认值、自绘微件（`.fw-dot`、`.fw-page-header`、`.fw-table-toolbar`）、滚动条、可访问性焦点环、`prefers-reduced-motion` 降级。
- `frontend/vite.config.ts` — 构建契约：`base = "/static/"`、`assetsDir = ""`、固定文件名 `app.js`，产物落 `build/obj/frontend`，供 Go `go:embed` 消费。
- `frontend/package.json` — 依赖声明（antd 6、echarts 6、react-router-dom 7、dayjs）。
- `frontend/src/components/StatCard.tsx` — 典型业务组件示例，展示如何消费 CSS 变量（`--fw-brand`、`--fw-success` 等）和 AntD Card。

## 3. 架构与约定

### 三层样式分工

1. **AntD Token 层**（`tokens.ts` → `buildTheme()`）：所有能走 ConfigProvider 的颜色、字体、圆角、控件高度、阴影都集中在这里。`buildTheme(mode, density)` 根据暗/亮模式与标准/紧凑密度选择 `darkAlgorithm`/`defaultAlgorithm` + `compactAlgorithm`，并覆盖 Layout/Menu/Table/Card/Button 等组件级 token。
2. **CSS 变量层**（`global.css` + `ThemeProvider` 写入 `:root`）：承载 AntD token 管不到的部分——纯 CSS 自绘元素、滚动条、页面标题区、表格工具条、数值淡入动画等。颜色一律通过 `var(--fw-*)` 引用，与 tokens 同源。
3. **业务组件层**：组件只消费 CSS 变量或 AntD 组件 API，不写死具体色值。

### 主题与密度

- 外观模式：`system | dark | light`，跟随系统时通过 `useMediaQuery('(prefers-color-scheme: dark)')` 解析。
- 信息密度：`standard | compact`，影响控件高度、圆角、字号、Table cell padding、Menu itemHeight 等。
- 偏好持久化：`localStorage` key 为 `firewall.theme.preference` 与 `firewall.theme.density`，跨标签同步（`usePersistentState`）。
- `ThemeProvider` 同时设置 `document.documentElement` 的 `data-theme` 与 `data-density` 属性，供 `[data-theme='dark']` 类选择器使用。

### 设计令牌规范

- 品牌主色：`#13aebf`（teal），沿用旧版 `--fw-primary-strong`，保持产品识别连续性。
- 语义色：`success=#2fbf71`、`warning=#f5a524`、`danger=#ff5561`、`info=#4a9eff`，与后端 ThreatLevel 一一对应。
- 威胁等级色阶：`safe→critical` 五档（绿→黄→橙→红），配套 `THREAT_LABELS` 中文标签与 `THREAT_RANK` 序数用于比较逻辑。
- 图表调色板：8 色中等明度数组 `CHART_COLORS`，通过 `chartColor(index)` 回绕取色，保证任意系列数都有稳定配色。
- 字体：正文 `IBM Plex Sans`，等宽 `JetBrains Mono`（IP/速率/计数列统一用 `tabular-nums` 对齐）。

### 响应式策略

- 桌面优先（package.json description 明确“桌面优先，响应式”）。
- 仅在 `max-width: 768px` 断点调整 `.fw-app-content` 的 padding。
- 侧边栏宽度通过 CSS 变量 `--fw-sider-width: 232px` / `--fw-sider-collapsed-width: 64px` 控制，而非硬编码。

### 可访问性与动效

- 键盘焦点环：`:focus-visible` 使用 `outline: 2px solid var(--fw-brand)`，鼠标点击不显示。
- 减少动效：`@media (prefers-reduced-motion: reduce)` 下关闭 `.fw-dot--pulse` 与 `.fw-fade-in` 动画，并将所有 transition-duration 强制为 `0.01ms`。
- 实时状态灯：`.fw-dot--pulse` 使用 `::after` 伪元素做向外扩散的同色光环动画。

## 4. 约定与约束

- **颜色/字体/圆角等能走 AntD ConfigProvider token 的一律走 token**，禁止在组件类里写死具体色值（`global.css` 顶部注释明确此分工约定）。
- **自绘元素一律引用 `var(--fw-*)`**，与 tokens 同源，切换主题自动跟随（`global.css` 注释要求）。
- **Vite 构建契约**（`vite.config.ts` 注释）：
  - `base = "/static/"`：守护进程对外提供 `GET /static/*path`，index.html 资源引用必须带 `/static/` 前缀。
  - `assetsDir = ""`：资源平铺输出，文件名固定，便于 go:embed 按名查找。
  - 固定入口文件名 `app.js`、`chunk-[name].js`、`[name].[ext]`，确保嵌入路径稳定。
  - `cssCodeSplit: false`：单一 CSS 文件，减少请求数。
  - 产物输出到 `build/obj/frontend`，由 Makefile 临时拷贝到 `src/daemon/web_ui/static` 后删除。
- **React 19 JSX 运行时**：`tsconfig` 的 `jsx = "react-jsx"` 与 `@vitejs/plugin-react` 必须成对维护，否则 tsc 与打包器会各自解析一份 JSX 实现（`vite.config.ts` 注释明确）。
- **AntD 语言**：全局通过 `ConfigProvider locale={zhCN}` 设置中文，dayjs 也 `locale('zh-cn')`，避免日期选择器出现英文月份（`ThemeProvider.tsx`）。
- **数据密度**：紧凑模式下 Table cellPaddingBlock/cellPaddingInline 减半、Menu itemHeight 从 42→36、Card paddingLG 从 20→14，保证安全运维控制台一屏容纳更多行（`tokens.ts`）。
- **威胁等级可视化**：所有威胁等级卡片统一使用 `THREAT_COLORS` 与 `THREAT_LABELS`，并通过 `threatRank()` 比较等级升降，禁止各视图自行定义映射（`tokens.ts` 注释说明其用途）。
- **图表主题**：ECharts 不走 ConfigProvider，需显式调用 `chartBaseTheme(mode)` 获取文字/轴线/背景色，并与 `CHART_COLORS` 搭配使用（`tokens.ts` 注释说明）。
- **PWA 作用域例外**：service worker 需要根作用域接管导航，而 `/static/` 下资源只有 `/static/` 作用域，故 sw.js 由守护进程单独路由提供（`vite.config.ts` 注释）。

## 5. 观察到的约束来源

- 上述约定大部分是代码注释中的设计约定（`tokens.ts`、`global.css`、`vite.config.ts` 头部注释），并非 lint 规则强制。
- 唯一可视为“强约束”的是 Vite 构建配置本身：`base`、`assetsDir`、`entryFileNames` 等字段直接决定产物布局，Go 端 `go:embed` 依赖这些固定命名，改动会破坏守护进程的静态资源加载。
- React 19 JSX 运行时的双配置（tsconfig + vite plugin）若不一致会导致类型检查与运行时行为分裂，属于构建期可检测的约束。