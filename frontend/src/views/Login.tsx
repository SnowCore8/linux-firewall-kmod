/**
 * 登录页：在未持有访问令牌时收集 Basic 凭据。
 *
 * 与浏览器的原生认证弹窗相比，本页的优势是**行为确定**：
 * - 弹窗依赖顶层文档返回 401，而 SPA 外壳是公开路由（不返回 401），弹窗根本不会出现；
 * - 弹窗在移动端 Chrome / PWA 独立窗口中的表现不一致，而本页是普通表单，处处一致；
 * - 提交前先做一次校验，凭据错误时给出明确文案，而不是让整页 API 静默失败。
 *
 * 校验通过后把令牌交给 `api/auth.ts`（`setAccessToken`），由 `AuthGate` 切到应用界面。
 *
 * 版式（控制台式）：品牌方块 + 紧凑凭据面板，靠上排布；不再用「垂直居中 + 大卡片 + 大留白」。
 * 输入行高 44px（触摸目标下限），输入框本体 28px，保持控制台密度观感。
 */

import { useState } from 'react'

import { Panel, Rows } from '../components/console'
import { encodeCredentials, setAccessToken } from '../api/auth'

/** 错误 / 提示条的方框样式：fw-banner 只带下边框，这里补成完整一圈 */
const BANNER_BOX = {
  border: '1px solid var(--fw-border)',
  borderRadius: 'var(--fw-radius)',
  marginBottom: 'var(--fw-gap)',
} as const

/** 面板内的一行 dim 说明（10px 紧凑） */
const DIM_NOTE = {
  fontSize: 10,
  color: 'var(--fw-text-3)',
  lineHeight: 1.45,
  padding: '1px 0',
} as const

/**
 * 凭据输入行：标签（dim 固定列）+ 方框输入。
 *
 * 用 <label> 包住输入框：输入框本体 28px 高，可点区域由行高撑到 44px
 * （触摸目标下限），且点击行内空白即聚焦输入框（浏览器原生行为）。
 * 输入框字号 16px：小于该值会让 iOS Safari 聚焦时放大整页。
 */
function CredentialRow(props: {
  label: string
  type: 'text' | 'password'
  autoComplete: string
  value: string
  onChange: (value: string) => void
  onEnter: () => void
}) {
  const { label, type, autoComplete, value, onChange, onEnter } = props
  const [focused, setFocused] = useState(false)
  return (
    <label className="fw-row" style={{ minHeight: 44 }}>
      <span className="fw-row-label" style={{ width: 64, alignSelf: 'center' }}>
        {label}
      </span>
      <input
        aria-label={label}
        type={type}
        autoComplete={autoComplete}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        // 回车即提交，移动端键盘「前往」键同样触发
        onKeyDown={(e) => {
          if (e.key === 'Enter') onEnter()
        }}
        style={{
          flex: 1,
          minWidth: 0,
          height: 28,
          padding: '0 6px',
          fontSize: 16,
          color: 'var(--fw-text)',
          background: 'var(--fw-bg)',
          border: `1px solid ${focused ? 'var(--fw-primary-strong)' : 'var(--fw-border-strong)'}`,
          borderRadius: 'var(--fw-radius-sm)',
          outline: 'none',
        }}
      />
    </label>
  )
}

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
        background: 'var(--fw-bg)',
        // 靠上排布：控制台登录不需要垂直居中的大留白；只避开状态栏安全区
        padding: 'calc(var(--fw-safe-top) + 18px) 10px 18px',
        display: 'flex',
        justifyContent: 'center',
      }}
    >
      <div style={{ width: '100%', maxWidth: 420 }}>
        {/* 品牌行：终端标记（fw-mark）+ 应用名，替代原来的大卡片标题 */}
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 'var(--fw-gap)' }}>
          <span className="fw-mark" style={{ fontSize: 15 }}>
            ▌FW
          </span>
          <span style={{ flex: 1, minWidth: 0, fontSize: 11, letterSpacing: '0.1em', color: 'var(--fw-text-2)' }}>
            FIREWALL CONSOLE
          </span>
        </div>

        <Panel title="访问凭据" meta="BASIC AUTH">
          {error !== null ? (
            <div className="fw-banner fw-banner-danger" style={BANNER_BOX} role="alert">
              <span className="fw-banner-icon">!</span>
              <span style={{ flex: 1, minWidth: 0 }}>{error}</span>
            </div>
          ) : null}

          <Rows>
            <CredentialRow
              label="用户名"
              type="text"
              autoComplete="username"
              value={username}
              onChange={setUsername}
              onEnter={() => void handleSubmit()}
            />
            <CredentialRow
              label="密码"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={setPassword}
              onEnter={() => void handleSubmit()}
            />
          </Rows>

          <div style={{ display: 'flex', marginTop: 5 }}>
            <button
              type="button"
              className="fw-cmd"
              style={{
                flex: 1,
                color: 'var(--fw-primary-strong)',
                borderColor: 'var(--fw-primary-strong)',
                fontSize: 12,
              }}
              disabled={submitting}
              onClick={() => void handleSubmit()}
            >
              {submitting ? '验证中…' : '登录'}
            </button>
          </div>
        </Panel>

        <Panel title="说明">
          <div style={DIM_NOTE}>凭据对应守护进程配置中的 metrics_username / metrics_password。</div>
          <div style={DIM_NOTE}>令牌只保存在本次会话的 sessionStorage 中，关闭标签页即失效。</div>
          <div style={DIM_NOTE}>
            连续失败会触发服务端锁定（约 1 分钟），锁定期间即使凭据正确也会被拒绝。
          </div>
        </Panel>
      </div>
    </div>
  )
}

export default Login
