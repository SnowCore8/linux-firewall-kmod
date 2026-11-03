import type { ComponentType, CSSProperties } from 'react'
import {
  DashboardOutlined,
  StopOutlined,
  SafetyCertificateOutlined,
  ClusterOutlined,
  ThunderboltOutlined,
  RadarChartOutlined,
  CloudDownloadOutlined,
  ExperimentOutlined,
  FileTextOutlined,
  SettingOutlined,
} from '@ant-design/icons'

/** 图标组件的最小 props 约定（AntD 图标都满足：接受 style/className）。 */
export type NavIcon = ComponentType<{ style?: CSSProperties; className?: string }>

/**
 * 信息架构（IA）—— 侧边栏分组、路由路径、页面标题/图标的单一真相源。
 *
 * 三处消费同一份配置，避免「菜单加了、命令面板没有、面包屑对不上」的漂移：
 *   1. AppShell 的侧边栏菜单（分组 + 图标 + 选中态）；
 *   2. CommandPalette（页面跳转项，模糊匹配 label/keywords）；
 *   3. 路由表（app/router.tsx）与 PageHeader 面包屑。
 *
 * 分组按运维心智模型：总览（一眼看态势）/ 防护（动手处置：封禁·白名单·越狱·DDoS）/
 * 智能（风险引擎·威胁情报·综合分析，多为只读洞察）/ 运维（日志·设置）。
 * 去掉旧版的 3D 地图页（three.js），攻击源地理分布并入分析页的只读视图。
 */

export interface NavItem {
  /** 路由路径（hash router，不含前缀 #）。 */
  path: string
  /** 菜单/标题文案。 */
  label: string
  /** 一句话说明（命令面板副标题、面包屑用）。 */
  description: string
  icon: NavIcon
  /** 命令面板模糊匹配的额外关键词。 */
  keywords?: string[]
  /** 需要后端 flag 开启才有内容；关时页面显示 disabled 空态。 */
  featureFlag?: 'risk_engine' | 'threat_feeds'
}

export interface NavGroup {
  title: string
  items: NavItem[]
}

export const NAV_GROUPS: NavGroup[] = [
  {
    title: '总览',
    items: [
      {
        path: '/dashboard',
        label: '概览',
        description: '威胁态势、实时速率、趋势与 Top 攻击源',
        icon: DashboardOutlined,
        keywords: ['dashboard', 'home', '首页', '态势', '总览'],
      },
    ],
  },
  {
    title: '防护',
    items: [
      {
        path: '/bans',
        label: '封禁管理',
        description: '查看、手工封禁、解封与批量处置',
        icon: StopOutlined,
        keywords: ['ban', '封禁', '拦截', '黑名单'],
      },
      {
        path: '/whitelist',
        label: '白名单',
        description: '永不封禁的可信地址与网段',
        icon: SafetyCertificateOutlined,
        keywords: ['whitelist', '白名单', 'allow', '可信'],
      },
      {
        path: '/jails',
        label: '越狱规则',
        description: '日志判定规则的启用状态与计数',
        icon: ClusterOutlined,
        keywords: ['jail', '越狱', '规则', 'fail2ban'],
      },
      {
        path: '/ddos',
        label: 'DDoS 监控',
        description: '速率、窗口、端口/协议分布与扫描探测',
        icon: ThunderboltOutlined,
        keywords: ['ddos', '速率', 'rate', '扫描', '流量'],
      },
    ],
  },
  {
    title: '智能',
    items: [
      {
        path: '/risk',
        label: '风险引擎',
        description: '多维风险向量与攻击事件（需开启 risk_engine）',
        icon: RadarChartOutlined,
        keywords: ['risk', '风险', '向量', '评分'],
        featureFlag: 'risk_engine',
      },
      {
        path: '/threat-feeds',
        label: '威胁情报',
        description: '外部情报源列表、同步状态与手动刷新',
        icon: CloudDownloadOutlined,
        keywords: ['threat', '情报', 'feed', 'ipsum', 'firehol'],
        featureFlag: 'threat_feeds',
      },
      {
        path: '/analysis',
        label: '综合分析',
        description: '预测、周期性、协同、复发、声誉与阈值推荐',
        icon: ExperimentOutlined,
        keywords: ['analysis', '分析', '预测', '异常', '统计'],
      },
    ],
  },
  {
    title: '运维',
    items: [
      {
        path: '/logs',
        label: '日志',
        description: '历史日志与实时日志流',
        icon: FileTextOutlined,
        keywords: ['log', '日志', '事件', 'stream'],
      },
      {
        path: '/settings',
        label: '设置',
        description: 'Web UI 配置、认证与运行时状态',
        icon: SettingOutlined,
        keywords: ['setting', '设置', '配置', 'config'],
      },
    ],
  },
]

/** 展平的全部导航项（命令面板、按路径查标题时用）。 */
export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((g) => g.items)

/** 按路径查导航项（含深链前缀匹配，如 /bans/1.2.3.4 → /bans）。 */
export function findNavItem(path: string): NavItem | undefined {
  return NAV_ITEMS.find((item) => item.path === path)
}

/** 默认落地页（登录成功后、根路径重定向目标）。 */
export const DEFAULT_PATH = '/dashboard'
