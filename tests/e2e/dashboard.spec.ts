import { test, expect } from '@playwright/test';

/**
 * Web UI 健康检查 — 验证 daemon 内置仪表盘可达
 *
 * 前置条件：daemon 进程已启动，Web UI 监听 127.0.0.1:9119
 * 可通过 BASE_URL 环境变量覆盖目标地址
 */
test.describe('Firewall Web UI', () => {
  test('dashboard 页面可加载', async ({ page }) => {
    const response = await page.goto('/dashboard');
    expect(response?.ok(), 'dashboard 应返回 2xx').toBeTruthy();

    // 验证页面包含预期标题或关键元素，避免静默失败
    await expect(page).toHaveTitle(/firewall/i);
  });

  test('health 端点返回健康状态', async ({ request }) => {
    const response = await request.get('/health');
    expect(response.status()).toBe(200);

    const body = await response.text();
    expect(body.length).toBeGreaterThan(0);
  });
});
