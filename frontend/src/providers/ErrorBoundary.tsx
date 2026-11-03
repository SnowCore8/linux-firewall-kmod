import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Button, Result, Typography } from 'antd'

/**
 * 全局错误边界 —— 兜住渲染期抛出的异常，避免白屏，给出一键复位。
 *
 * React 的错误边界只能是 class 组件（函数组件没有 componentDidCatch 等价物），这是全仓
 * 唯一一处刻意用 class 的地方。复位有两条路：`onReset` 回调（清空局部状态）优先，其次
 * 「重新加载」——因为渲染错误往往意味着某处的不变量已被破坏，重载是最干净的恢复。
 *
 * 边界只兜渲染错误，不兜事件处理器 / 异步回调里的异常（那些走各自的 try/catch 与
 * useAsync 的错误态）。
 */

interface ErrorBoundaryProps {
  children: ReactNode
  /** 复位回调；提供时优先于整页重载（用于只重置局部而非刷新浏览器）。 */
  onReset?: () => void
  /** 自定义兜底标题。 */
  title?: string
}

interface ErrorBoundaryState {
  error: Error | null
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // 仅本地日志：不接任何外部上报（无采集端点，也不该把堆栈发去第三方）
    console.error('[ErrorBoundary] 渲染异常', error, info.componentStack)
  }

  private handleReset = (): void => {
    if (this.props.onReset) {
      this.setState({ error: null })
      this.props.onReset()
    } else {
      window.location.reload()
    }
  }

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children

    return (
      <Result
        status="error"
        title={this.props.title ?? '页面出错了'}
        subTitle="渲染过程中发生异常。你可以尝试复位当前视图，或重新加载整个面板。"
        extra={[
          <Button key="reset" type="primary" onClick={this.handleReset}>
            {this.props.onReset ? '复位视图' : '重新加载'}
          </Button>,
        ]}
      >
        <Typography.Paragraph>
          <Typography.Text type="secondary" copyable style={{ fontFamily: 'var(--fw-font-mono)' }}>
            {error.message}
          </Typography.Text>
        </Typography.Paragraph>
      </Result>
    )
  }
}
