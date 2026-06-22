import { defineConfig, devices } from '@playwright/test';

/**
 * Firewall 项目 E2E 测试配置
 *
 * 测试目标：daemon 内置 Web UI（axum，默认 http://127.0.0.1:9119）
 * 运行前置：启动 daemon 进程并确保 Web UI 可访问
 */
export default defineConfig({
  // 测试目录：与现有 Rust 集成测试隔离，专门存放浏览器测试
  testDir: './tests/e2e',

  // 每次运行前清理测试产物目录
  fullyParallel: true,

  // CI 环境下禁用仅本地的行为（如 headed 模式），保持本地 / CI 一致性
  forbidOnly: !!process.env.CI,

  // 失败时不重试，避免掩盖 daemon 真实问题；需要时可调整为 2
  retries: process.env.CI ? 2 : 0,

  // 并行 worker 数量；CI 上收敛为 2 避免压垮 daemon
  workers: process.env.CI ? 2 : undefined,

  // 报告器：本地生成 HTML 报告；CI 追加 GitHub / List 输出
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['github'], ['list']]
    : [['html', { open: 'on-failure' }], ['list']],

  use: {
    // Web UI 默认监听 127.0.0.1:9119，可通过 BASE_URL 环境变量覆盖
    baseURL: process.env.BASE_URL ?? 'http://127.0.0.1:9119',

    // 失败时收集 trace，便于事后排查（HTML report 中直接查看）
    trace: 'on-first-retry',

    // 失败时截图，快速定位 UI 异常
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // 不在配置中启动 dev server —— daemon 是 Rust 二进制，
  // 由外部流程（Makefile / systemd / 手动）启动，Playwright 只负责连接
  // webServer: { ... },
});
