import { useEffect } from 'react'
import { Alert, Button, Card, Form, Input, Space, Typography, Flex } from 'antd'
import { LockOutlined, UserOutlined, SafetyOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../providers/AuthProvider.tsx'
import { AUTH_LOCKOUT_SECONDS } from '../api/auth.ts'
import { DEFAULT_PATH } from '../app/nav.ts'

/**
 * 登录页 —— 认证闸门。
 *
 * 体验要点（都是桌面控制台该有的，不是把移动登录页搬过来）：
 *   * 已登录直接跳概览，不让认证过的用户还停在登录页；
 *   * 连续失败逼近阈值时给「还可尝试 N 次」的预警，达阈值后按钮禁用 + 秒级倒计时，
 *     避免用户把账号越试越死（镜像守护进程的锁定窗口，见 AuthProvider）；
 *   * 错误文案透出后端 message（凭据错 / 锁定 / 服务不可达分类清楚）；
 *   * 用户名自动聚焦，Enter 提交；不展示任何默认凭据（凭据由管理员经环境变量下发，
 *     写进页面等于泄密）。
 */

interface LoginForm {
  username: string
  password: string
}

export default function Login() {
  const navigate = useNavigate()
  const { isAuthenticated, isLoggingIn, login, error, failCount, threshold, lockoutRemaining, clearError } =
    useAuth()

  // 已认证（含刷新后 sessionStorage 仍有令牌）→ 直接进概览
  useEffect(() => {
    if (isAuthenticated) navigate(DEFAULT_PATH, { replace: true })
  }, [isAuthenticated, navigate])

  const locked = lockoutRemaining > 0
  const remainingAttempts = Math.max(0, threshold - failCount)

  const onFinish = async (values: LoginForm): Promise<void> => {
    await login(values.username.trim(), values.password)
  }

  return (
    <Flex align="center" justify="center" style={{ minHeight: '100vh', padding: 24 }}>
      <div style={{ width: '100%', maxWidth: 400 }}>
        <Space direction="vertical" size={20} style={{ width: '100%' }}>
          <Space direction="vertical" size={6} align="center" style={{ width: '100%' }}>
            <SafetyOutlined style={{ fontSize: 40, color: 'var(--fw-brand)' }} />
            <Typography.Title level={3} style={{ margin: 0 }}>
              Firewall 控制台
            </Typography.Title>
            <Typography.Text type="secondary" style={{ fontSize: 13 }}>
              实时 IP 封禁防护系统
            </Typography.Text>
          </Space>

          <Card styles={{ body: { padding: 24 } }}>
            {error && (
              <Alert
                type={locked ? 'warning' : 'error'}
                message={error}
                showIcon
                closable
                onClose={clearError}
                style={{ marginBottom: 16 }}
                role="alert"
              />
            )}
            {!error && !locked && failCount > 0 && (
              <Alert
                type="warning"
                message={`还可尝试 ${remainingAttempts} 次，超过将锁定 ${AUTH_LOCKOUT_SECONDS} 秒`}
                showIcon
                style={{ marginBottom: 16 }}
              />
            )}

            <Form<LoginForm>
              layout="vertical"
              onFinish={onFinish}
              requiredMark={false}
              disabled={locked}
              autoComplete="on"
            >
              <Form.Item
                name="username"
                label="用户名"
                rules={[{ required: true, message: '请输入用户名' }]}
              >
                <Input
                  size="large"
                  prefix={<UserOutlined />}
                  placeholder="管理员用户名"
                  autoFocus
                  autoComplete="username"
                  aria-label="用户名"
                />
              </Form.Item>
              <Form.Item
                name="password"
                label="密码"
                rules={[{ required: true, message: '请输入密码' }]}
              >
                <Input.Password
                  size="large"
                  prefix={<LockOutlined />}
                  placeholder="密码"
                  autoComplete="current-password"
                  aria-label="密码"
                />
              </Form.Item>
              <Form.Item style={{ marginBottom: 0 }}>
                <Button
                  type="primary"
                  htmlType="submit"
                  size="large"
                  block
                  loading={isLoggingIn}
                  disabled={locked}
                >
                  {locked ? `已锁定（${lockoutRemaining}s）` : '登录'}
                </Button>
              </Form.Item>
            </Form>
          </Card>

          <Typography.Paragraph
            type="secondary"
            style={{ fontSize: 12, textAlign: 'center', margin: 0 }}
          >
            凭据由管理员通过环境变量 <span className="fw-mono">FIREWALL_METRICS_USERNAME / PASSWORD</span>{' '}
            下发。会话令牌仅保存在当前标签页，关闭即失效。
          </Typography.Paragraph>
        </Space>
      </div>
    </Flex>
  )
}
