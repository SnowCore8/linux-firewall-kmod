/**
 * 登录页：在未持有访问令牌时收集 Basic 凭据。
 *
 * 与浏览器的原生认证弹窗相比，本页的优势是**行为确定**：
 * - 弹窗依赖顶层文档返回 401，而 SPA 外壳是公开路由（不返回 401），弹窗根本不会出现；
 * - 弹窗在移动端 Chrome / PWA 独立窗口中的表现不一致，而本页是普通表单，处处一致；
 * - 提交前先做一次校验，凭据错误时给出明确文案，而不是让整页 API 静默失败。
 *
 * 校验通过后把令牌交给 `api/auth.ts`（`setAccessToken`），由 `AuthGate` 切到应用界面。
 */

import { Button, Card, Form, Input, NoticeBar } from 'antd-mobile'
import { useState } from 'react'

import { encodeCredentials, setAccessToken } from '../api/auth'

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (): Promise<void> => {
    if (submitting) return
    setError(null)
    setSubmitting(true)

    try {
      // 先用待验证的凭据探测一个受保护端点，避免把错误凭据写进会话存储
      const candidate = encodeCredentials(username, password)
      const response = await fetch('/api/v1/stats', {
        headers: { Authorization: `Basic ${candidate}` },
        credentials: 'same-origin',
      })

      if (response.status === 401) {
        // 服务端连续失败 10 次后会锁定 60 秒，此时正确凭据同样返回 401，故一并提示
        setError('用户名或密码错误；若连续失败次数过多，请等待约 1 分钟后重试。')
        return
      }
      if (!response.ok) {
        setError(`服务端返回 HTTP ${response.status}，请稍后重试。`)
        return
      }

      // 校验通过：写入令牌，AuthGate 会随状态变化切换到主界面（notify=true 即触发）
      setAccessToken(username, password)
    } catch (err) {
      setError(`无法连接守护进程：${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100dvh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 10,
      }}
    >
      <Card title="Firewall 控制台" style={{ width: '100%', maxWidth: 420 }}>
        <div style={{ marginBottom: 7, color: 'var(--adm-color-weak)', fontSize: 12 }}>
          请输入 Web UI 的访问凭据（对应配置中的 metrics_username / metrics_password）。
        </div>

        {error ? (
          <NoticeBar color="alert" wrap content={error} style={{ marginBottom: 7 }} />
        ) : null}

        <Form
          layout="horizontal"
          footer={
            <Button block color="primary" loading={submitting} onClick={handleSubmit}>
              登录
            </Button>
          }
        >
          <Form.Item name="username" label="用户名">
            <Input
              placeholder="用户名"
              autoComplete="username"
              value={username}
              onChange={setUsername}
            />
          </Form.Item>
          <Form.Item name="password" label="密码">
            <Input
              type="password"
              placeholder="密码"
              autoComplete="current-password"
              value={password}
              onChange={setPassword}
              // 回车即提交，移动端键盘「前往」键同样触发
              onEnterPress={handleSubmit}
            />
          </Form.Item>
        </Form>
      </Card>
    </div>
  )
}

export default Login
