// 「更多」页（TabBar 一级页）
//
// 做什么：作为二级页的收纳入口，以控制台式紧凑行（44px 触摸目标 + 一行 dim 说明）
//        列出「Jail 管理 / 日志 / 设置」三个页面，避免用户在底部只有 5 个位置的一级
//        导航里迷路。
// 影响什么：本页**本身不发起任何请求、不产生任何写操作**，只做页内跳转（hash 路由）；
//          所有真实数据与写操作都在被跳转到的二级页里完成。
//
// 版式：不再用「大卡片 + 大内边距」的列表，而是「面板 + 发丝分隔的菜单行」——
//       行高仍是 44px（可点元素下限），只是每行的说明压成一行 10px dim 小字，
//       一屏可以同时看到全部入口与其职责。

import { FileOutline, HistogramOutline, SetOutline } from 'antd-mobile-icons'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

import { Panel, Rows } from '../components/console'
import { PageHeader } from '../components/PageHeader'

/** 二级入口定义：路径与 AppShell 的 MORE_CHILD_PATHS / PAGE_TITLES 保持一致 */
interface MoreEntry {
  /** 路由路径（与 App.tsx 的路由表一一对应） */
  path: string
  /** 入口名称 */
  title: string
  /** 一句话说明该页面做什么（一行内可读完，减少误点） */
  description: string
  /** 图标（全部取自 antd-mobile-icons 的有效导出） */
  icon: ReactNode
}

const ENTRIES: readonly MoreEntry[] = [
  {
    path: '/jails',
    title: 'Jail 管理',
    description: '阈值与运行时统计；启用或禁用单个 Jail；封禁时长推荐',
    icon: <HistogramOutline fontSize={16} />,
  },
  {
    path: '/logs',
    title: '日志',
    description: '实时跟踪内核与守护进程日志；关键词检索与历史翻页',
    icon: <FileOutline fontSize={16} />,
  },
  {
    path: '/settings',
    title: '设置',
    description: '速率与协议阈值、DDoS 检测开关、容量上限、日志过滤起点',
    icon: <SetOutline fontSize={16} />,
  },
]

/** 面板内的一行 dim 说明（10px 紧凑） */
const DIM_NOTE = {
  fontSize: 10,
  color: 'var(--fw-text-3)',
  lineHeight: 1.45,
  padding: '1px 0',
} as const

export default function More() {
  const navigate = useNavigate()

  return (
    <>
      {/* 区块标题（h2）：e2e 以 level-2 标题精确匹配本页，文案不可改 */}
      <PageHeader
        title="更多"
        srOnly
        subtitle="以下页面不在底部导航中；点击进入后可用左上角返回键回到本页"
      />

      <Panel title="二级页面" meta={`${ENTRIES.length} 项`} padded={false}>
        <Rows>
          {ENTRIES.map((entry, index) => (
            <button
              key={entry.path}
              type="button"
              className="fw-row"
              style={{
                width: '100%',
                minHeight: 44, // 可点行：不低于触摸目标下限
                alignItems: 'center',
                gap: 6,
                padding: '2px 6px',
                border: 0,
                // 末行不画分隔线，避免与面板边框叠成双线（Rows 已裁掉溢出）
                borderBottom: index === ENTRIES.length - 1 ? 'none' : '1px solid var(--fw-border)',
                borderRadius: 0,
                background: 'transparent',
                color: 'inherit',
                font: 'inherit',
                textAlign: 'left',
                cursor: 'pointer',
              }}
              onClick={() => navigate(entry.path)}
            >
              <span style={{ flexShrink: 0, display: 'flex', color: 'var(--fw-primary-strong)' }}>
                {entry.icon}
              </span>
              <span style={{ flex: 1, minWidth: 0 }}>
                <span style={{ display: 'block', fontSize: 12, color: 'var(--fw-text)' }}>
                  {entry.title}
                </span>
                <span style={{ display: 'block', fontSize: 10, color: 'var(--fw-text-3)' }}>
                  {entry.description}
                </span>
              </span>
              <span style={{ flexShrink: 0, color: 'var(--fw-text-3)' }}>›</span>
            </button>
          ))}
        </Rows>
      </Panel>

      {/* 使用说明：把「本页不写数据」讲清楚，避免用户以为这里也能改配置 */}
      <Panel title="说明">
        <div style={DIM_NOTE}>本页只做导航，不读取也不修改任何配置。</div>
        <div style={DIM_NOTE}>配置修改集中在「设置」；白名单与封禁管理在底部导航的一级页中。</div>
        <div style={DIM_NOTE}>进入二级页后用页面左上角的「更多」按钮回到本页。</div>
      </Panel>
    </>
  )
}
