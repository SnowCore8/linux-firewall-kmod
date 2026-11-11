import { useState, type ReactNode } from 'react'
import { App, Button, Drawer, Form, Space, type FormInstance } from 'antd'

/**
 * 抽屉表单封装 —— 桌面范式下，「新建/编辑」不再是移动端的底部 Popup，而是右侧 Drawer + Form。
 *
 * 统一三件事，避免各页各写：
 *   1. 提交流程：校验 → 调 onSubmit → 成功关抽屉、失败留在原地并弹错误（不清空用户已填内容）；
 *   2. 脏检查：填了一半点关闭/遮罩时二次确认，防误触丢失输入（这是桌面表单的基本礼貌）；
 *   3. 危险动作二次确认：`confirmText` 存在时，提交前弹确认框（如「解封全部临时封禁」）。
 *
 * 表单实例由调用方用 `Form.useForm()` 建好后传入——这样调用方能在打开前 setFieldsValue、
 * 关闭后 resetFields，生命周期握在页面手里，封装只管渲染与提交编排。
 */

export interface DrawerFormProps<T> {
  open: boolean
  title: ReactNode
  form: FormInstance<T>
  onSubmit: (values: T) => Promise<void>
  onCancel: () => void
  children: ReactNode
  width?: number
  initialValues?: Partial<T>
  submitText?: string
  cancelText?: string
  /** 提交按钮为危险色（删除/解封类）。 */
  danger?: boolean
  /** 提交前二次确认的文案；缺省则直接提交。 */
  confirmText?: string
  confirmTitle?: string
  /** 关闭时若表单已改动则二次确认；默认 true。 */
  dirtyCheck?: boolean
  /** 表单布局；默认 vertical。 */
  layout?: 'horizontal' | 'vertical' | 'inline'
  extraFooter?: ReactNode
}

export function DrawerForm<T>({
  open,
  title,
  form,
  onSubmit,
  onCancel,
  children,
  width = 480,
  initialValues,
  submitText = '提交',
  cancelText = '取消',
  danger = false,
  confirmText,
  confirmTitle = '确认操作',
  dirtyCheck = true,
  layout = 'vertical',
  extraFooter,
}: DrawerFormProps<T>) {
  const [submitting, setSubmitting] = useState(false)
  // 用上下文感知的 modal 实例（随主题走），静态 Modal.confirm 在暗色下会渲染成亮色
  const { modal } = App.useApp()

  const doSubmit = async (): Promise<void> => {
    let values: T
    try {
      values = await form.validateFields()
    } catch {
      // 校验失败：AntD 已在字段上标红，滚动到首个错误由 Form 负责
      setSubmitting(false)
      return
    }
    try {
      await onSubmit(values)
      // 成功：调用方通常在此关闭抽屉；这里不强行关，交给 onSubmit 后的 onCancel/open 控制
    } catch {
      // 失败：错误提示由 onSubmit 内部负责（它有后端 message），抽屉保持打开、内容不丢
    } finally {
      setSubmitting(false)
    }
  }

  const handleSubmit = (): void => {
    if (submitting) return
    setSubmitting(true)
    if (confirmText) {
      modal.confirm({
        title: confirmTitle,
        content: confirmText,
        okText: '确认',
        okButtonProps: danger ? { danger: true } : undefined,
        cancelText: '再想想',
        onOk: doSubmit,
        // 取消确认弹窗时复位：submitting 已在 handleSubmit 入口置真，
        // 不复位会让提交按钮永久停在 loading 态。
        onCancel: () => setSubmitting(false),
      })
    } else {
      void doSubmit()
    }
  }

  const handleCancel = (): void => {
    if (dirtyCheck && form.isFieldsTouched()) {
      modal.confirm({
        title: '放弃未保存的修改？',
        content: '表单已改动但尚未提交，关闭后这些输入会丢失。',
        okText: '放弃',
        okButtonProps: { danger: true },
        cancelText: '继续编辑',
        onOk: onCancel,
      })
    } else {
      onCancel()
    }
  }

  return (
    <Drawer
      open={open}
      title={title}
      width={width}
      onClose={handleCancel}
      destroyOnHidden
      maskClosable={!submitting}
      keyboard={!submitting}
      footer={
        <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
          {extraFooter}
          <Button onClick={handleCancel} disabled={submitting}>
            {cancelText}
          </Button>
          <Button type="primary" danger={danger} loading={submitting} onClick={handleSubmit}>
            {submitText}
          </Button>
        </Space>
      }
    >
      <Form
        form={form}
        layout={layout}
        initialValues={initialValues}
        requiredMark
        scrollToFirstError
        onFinish={handleSubmit}
      >
        {children}
      </Form>
    </Drawer>
  )
}
