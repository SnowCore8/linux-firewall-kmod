// 渲染异常边界：捕获子树在「渲染 / 生命周期 / 构造函数」中抛出的异常
//
// 为什么需要：React 18+ 若某棵子树渲染抛错且无人接管，整棵树会被卸载成白屏，
// 控制台报错在手机上根本看不到。这里把异常降级为一个可见的卡片 + 堆栈，
// 并提供「重试」，让用户/运维能立刻知道是哪个组件坏了。
//
// 注意：ErrorBoundary 不能捕获事件回调、setTimeout、Promise 里的异常
// （那些走 useToast / 视图自己的 error 分支处理）。
import { Button } from 'antd-mobile'
import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'

export interface ErrorBoundaryProps {
  children: ReactNode
  /**
   * 该值变化时自动清除错误状态。
   * 典型用法：传当前路由 pathname —— 用户在错误页点了底部导航后，
   * 边界会复位，不会一直卡在上一页的错误卡片上。
   */
  resetKey?: string | number
  /** 自定义错误 UI；不传则使用内置卡片 */
  fallback?: (error: Error, reset: () => void) => ReactNode
}

interface ErrorBoundaryState {
  error: Error | null
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    // 返回新 state 触发一次重新渲染，渲染出 fallback UI
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // 控制台留痕：E2E 用例会断言「无 console error」，此处不做静默吞错
    console.error('[ErrorBoundary] 组件渲染异常：', error, info.componentStack)
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.error) this.reset()
  }

  /** 清空错误状态，重新渲染原子树（用于「重试」按钮） */
  private readonly reset = () => {
    this.setState({ error: null })
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children
    if (this.props.fallback) return this.props.fallback(error, this.reset)

    return (
      <div
        role="alert"
        style={{
          margin: 7,
          padding: 10,
          border: '1px solid var(--fw-danger)',
          borderRadius: 'var(--fw-radius)',
          background: 'var(--fw-surface)',
          color: 'var(--fw-text)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 5 }}>
          <span style={{ color: 'var(--fw-danger)', fontSize: 16, lineHeight: 1 }}>⚠</span>
          <strong style={{ fontSize: 14 }}>界面渲染出错</strong>
        </div>
        <p style={{ margin: '0 0 7px', fontSize: 12, color: 'var(--fw-text-2)', wordBreak: 'break-word' }}>
          {error.message || '未知错误'}
        </p>

        {/* 堆栈默认折叠：默认不刷屏，排查时展开即可 */}
        {error.stack ? (
          <details style={{ marginBottom: 7 }}>
            <summary style={{ fontSize: 12, color: 'var(--fw-text-3)', cursor: 'pointer' }}>
              查看堆栈信息
            </summary>
            <pre
              className="fw-mono"
              style={{
                margin: '5px 0 0',
                padding: 5,
                maxHeight: 200,
                overflow: 'auto',
                fontSize: 11,
                lineHeight: 1.5,
                color: 'var(--fw-text-2)',
                background: 'var(--fw-bg-alt)',
                borderRadius: 'var(--fw-radius-sm)',
              }}
            >
              {error.stack}
            </pre>
          </details>
        ) : null}

        <Button size="small" color="primary" fill="outline" onClick={this.reset}>
          重试
        </Button>
      </div>
    )
  }
}

// 同时提供默认导出与具名导出：使用方（各 view）两种写法都能引入
export default ErrorBoundary
