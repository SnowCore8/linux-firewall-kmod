// 「更多」页（TabBar 一级页）
//
// 做什么：作为二级页的收纳入口，集中列出「Jail 管理 / 日志 / 设置」三个页面，
//        并解释每个页面负责什么，避免用户在底部只有 5 个位置的一级导航里迷路。
// 影响什么：本页**本身不发起任何请求、不产生任何写操作**，只做页内跳转（hash 路由）；
//          所有真实数据与写操作都在被跳转到的二级页里完成。
//
// 为什么用 List.Item + onClick 而不是 <a href>：应用是 hash 路由，点击必须走
// react-router 的 navigate，才能保持 TabBar 的选中态与浏览器历史一致。

import { List } from 'antd-mobile'
import { FileOutline, HistogramOutline, SetOutline } from 'antd-mobile-icons'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'

import { PageHeader } from '../components/PageHeader'

/** 二级入口定义：路径与 AppShell 的 MORE_CHILD_PATHS / PAGE_TITLES 保持一致 */
interface MoreEntry {
  /** 路由路径（与 App.tsx 的路由表一一对应） */
  path: string
  /** 入口名称 */
  title: string
  /** 一句话说明该页面做什么，减少误点 */
  description: string
  /** 图标（全部取自 antd-mobile-icons 的有效导出） */
  icon: ReactNode
}

const ENTRIES: readonly MoreEntry[] = [
  {
    path: '/jails',
    title: 'Jail 管理',
    description: '查看各 Jail 的阈值与运行时统计，启用或禁用单个 Jail，并查看封禁时长推荐',
    icon: <HistogramOutline fontSize={19} />,
  },
  {
    path: '/logs',
    title: '日志',
    description: '实时跟踪内核与守护进程日志，支持关键词检索、级别过滤与历史翻页',
    icon: <FileOutline fontSize={19} />,
  },
  {
    path: '/settings',
    title: '设置',
    description: '编辑速率与协议阈值、DDoS 检测开关、各表容量上限与日志视图过滤起点',
    icon: <SetOutline fontSize={19} />,
  },
]

/** 行高下限：触摸目标 ≥ 44px（List.Item 默认 48px，这里显式固化约束） */
const ROW_STYLE = { minHeight: 44 } as const

export default function More() {
  const navigate = useNavigate()

  return (
    <>
      <PageHeader
        title="更多"
        subtitle="以下页面不在底部导航中；点击进入后可用左上角返回键回到本页"
      />

      <div style={{ paddingBottom: 7 }}>
        <List>
          {ENTRIES.map((entry) => (
            <List.Item
              key={entry.path}
              clickable
              arrowIcon
              style={ROW_STYLE}
              prefix={entry.icon}
              description={entry.description}
              onClick={() => navigate(entry.path)}
            >
              {entry.title}
            </List.Item>
          ))}
        </List>

        {/* 使用说明：把「本页不写数据」讲清楚，避免用户以为这里也能改配置 */}
        <List header="说明" style={{ marginTop: 7 }}>
          <List.Item style={ROW_STYLE}>本页只做导航，不读取也不修改任何配置</List.Item>
          <List.Item style={ROW_STYLE}>
            配置修改集中在「设置」；白名单与封禁管理在底部导航的一级页中
          </List.Item>
        </List>
      </div>
    </>
  )
}
