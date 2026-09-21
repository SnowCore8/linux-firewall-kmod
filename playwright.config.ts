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

  // 失败即失败，不重试：本套件含「无 console 错误/警告」与写操作回环两类硬断言，
  // 重试会把间歇性缺陷（偶发的控制台告警、偶发 503）洗成绿，违背「失败即阻塞合并」。
  retries: 0,

  // 单 worker 串行执行。
  //
  // 为什么不用并行：每个页面实例都会建立一条 `/api/v1/events` SSE 长连接
  // （前端的 SseProvider 挂在认证闸门内部），而守护进程对**管理流**的连接位有
  // 硬上限（见 src/daemon/api/sse.rs 的 SseStatus 与契约 http.fwidl）。多 worker
  // 叠加本地可能已在跑的控制台标签页，会随机触顶 503，表现为用例莫名失败。
  // 本套件用例数有限，串行换来确定性；要提速应先调大服务端连接位配额，
  // 而不是把不确定性带进 CI。
  workers: 1,

  // 报告器：本地生成 HTML 报告；CI 追加 GitHub / List 输出
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['github'], ['list']]
    : [['html', { open: 'on-failure' }], ['list']],

  use: {
    // Web UI 默认监听 127.0.0.1:9119，可通过 BASE_URL 环境变量覆盖
    baseURL: process.env.BASE_URL ?? 'http://127.0.0.1:9119',

    // 失败时收集 trace（不重试，故用 retain-on-failure 而非 on-first-retry）
    trace: 'retain-on-failure',

    // 失败时截图，快速定位 UI 异常
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // 不在配置中启动 dev server —— daemon 是 Rust 二进制。
  //
  // 为什么不用 Playwright 的 webServer：本套件需要的不是「一条命令」，而是
  // 「insmod 内核模块 → 生成临时配置 → 起守护进程 → 等 /health 就绪 → 收尾 rmmod」，
  // 其中 rmmod 是必需的（内核把单守护进程实现为 portid + 30 秒活动超时且无注销消息，
  // 不重载模块则下一次运行会被 Refused 拒绝）。Playwright 只能杀进程组，不会卸模块，
  // 故整条夹具独立为 scripts/e2e-daemon.sh，CI 与本地共用。
  // webServer: { ... },
});
