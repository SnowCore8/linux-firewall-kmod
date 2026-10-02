// 攻击地图页（3D 地球）：把封禁 IP 的地理分布画在一颗可自转、可拖拽的地球上
//
// 做什么：从 `GET /api/v1/stats/attack-geo` 取近 7 天封禁记录的城市级地理聚合，用
//   Three.js 在球面上打发光点（点径与颜色随封禁次数）。同一响应里的
//   `server_latitude` / `server_longitude` 给出本机坐标：两者都有值时，额外绘制
//   「本机」标记并从每个攻击源画一条弧线连到本机；任一缺失则只画点位、不画标记与弧线
//   （宁可缺，也不画到错误的位置上）。点位可悬停（鼠标）/ 点按（触摸）查看该地点的
//   国家、城市、封禁次数与唯一 IP 数。
// 影响什么：本页全部为只读展示，不触发任何写操作，不改变内核或守护进程状态。唯一的
//   额外网络请求是地球贴图 `/static/earth-night.webp`（随前端产物一起嵌入守护进程二进制）。
//
// 数据来源（真实端点，无占位假数据）：
//   GET /api/v1/stats/attack-geo → AttackGeoResponse（api/types.ts 中由 Rust 契约推导）
//   该域**没有** SSE 实时推送，因此按 usePollInterval（与 SSE 推送同源）轮询固定间隔，
//   页面切到后台时 useAsync 会自动暂停。
//
// 降级语义（与后端 src/daemon/history_snapshot/attack_geo.rs 一致）：
//   `geoip_enabled === false`（配置项 geoip_db_path 未设置或数据库缺失）时**不创建
//   WebGL 上下文**，直接以共享的 EmptyState 说明如何启用；地理解析不可用不影响封禁功能。
//
// 设计约定（styles/global.css 的 fw-* 令牌 + components/console.tsx 的原语）：
//   · 结构用 Panel 承载，3D 只占一块固定高度的画布，其余仍是控制台式数据行（可读、可复制）；
//   · 3D 用色不写死：都在运行期从 CSS 令牌（--fw-danger / --fw-warning / --fw-primary-strong 等）
//     的**计算值**解析，因此深浅主题切换后重读一次即可跟随，JS 里不存在第二套色板；
//   · 贴图取深色的 earth-night：与页面底色（--fw-bg 近黑）同调，发光点位与弧线自然成为
//     视觉主体；它是**唯一**一张贴图（曾试过的 day 版已删——不被任何代码引用，只会
//     白占产物体积），体积也小于常见的日间贴图，符合移动端优先。
//
// 页面内不渲染 h1（顶栏独占）；本页的 h2 由 PageHeader 承担。

import { PullToRefresh } from 'antd-mobile'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/addons/controls/OrbitControls.js'

import { getAttackGeo } from '../api/endpoints'
import type { AttackGeoResponse, GeoPoint } from '../api/types'
import {
  Badge,
  InlineError,
  Note,
  Panel,
  PanelLoading,
  Row,
  Rows,
  Tile,
  Tiles,
  Verdict,
} from '../components/console'
import type { Tone } from '../components/console'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { useAsync } from '../hooks/useAsync'
import { usePollInterval } from '../hooks/usePollInterval'
import { useTheme } from '../hooks/useTheme'
import { formatDatetime, formatNumber } from '../lib/format'

// ---------------------------------------------------------------------------
// 场景尺寸与视觉参数（世界单位以球半径为 1 归一，改这里的值即可整体调参）
// ---------------------------------------------------------------------------

/**
 * 地球贴图地址。
 *
 * 为什么用 `import.meta.env.BASE_URL` 而不是写死 `/static/`：dev 与 build 都由 vite 的
 * `base` 决定资源前缀（见 vite.config.ts），拼 BASE_URL 才能在两种模式下都命中同一路径。
 * 贴图放 `public/`，构建时随产物落到 `src/daemon/web_ui/static/`，由守护进程的
 * `/static/*path` 路由以 `image/webp` 提供。
 */
const EARTH_TEXTURE_URL = `${import.meta.env.BASE_URL}earth-night.webp`

/** 球体半径（世界单位） */
const GLOBE_RADIUS = 1

/**
 * 打点所在的球面半径：略高于球面。
 *
 * 为什么不是正好等于球半径：与球面共面会产生深度争用（z-fighting），点位边缘会被球体
 * 随机吃掉一块。抬高一点点（0.6%）在视觉上看不出，但深度测试稳定。
 */
const POINT_RADIUS = GLOBE_RADIUS * 1.006

/** 大气辉光球半径（略大于球体，BackSide + 加法混合 → 只剩轮廓外的一圈光晕） */
const HALO_RADIUS = GLOBE_RADIUS * 1.06
const HALO_OPACITY = 0.09

/**
 * 贴图亮度增益。
 *
 * 为什么需要：earth-night 是「夜间灯光」风格，实测 97.5% 的像素灰度 < 20/255（均值 10.6，
 * p90 = 18），直接渲染在大屏上就是一颗几乎全黑的球，大陆轮廓看不见。乘以一个大于 1 的
 * 系数把海岸线抬到可见区间（p90 → 约 40），同时让城市灯光自然过曝成光点——这正是本页
 * 想要的观感：深色球体 + 发光点位。
 */
const EARTH_BRIGHTNESS = 2.2

/** 单条弧线的采样段数（越大越圆滑，代价是顶点数线性增长） */
const ARC_SEGMENTS = 28
/** 弧顶抬升上限：最远的弧（对跖）弧顶抬到球半径的该比例，近距弧按夹角等比降低 */
const ARC_APEX_LIFT = 0.45
/** 弧线透明度：靠攻击源一端亮、靠本机一端几乎消失（alpha 沿弧线按幂次衰减） */
const ARC_HEAD_ALPHA = 0.55
const ARC_TAIL_ALPHA = 0.05

/** 打点屏幕尺寸（CSS px）：按封禁次数在区间内做 sqrt 插值（面积感知，避免长尾全被压成小点） */
const POINT_MIN_PX = 5
const POINT_MAX_PX = 22
/** 本机标记的屏幕尺寸：比打点大一点，作为弧线的视觉落点 */
const SELF_MARKER_PX = 13
/** 悬停命中半径下限（CSS px）：真机上小于这个值几乎点不中 */
const HIT_MIN_PX = 14

/** 相机初始距离与缩放范围（球半径为 1 时的观感比例） */
const CAMERA_DISTANCE = 2.6
const CAMERA_MIN_DISTANCE = 1.3
const CAMERA_MAX_DISTANCE = 5
/** 自转角速度（OrbitControls 的 autoRotateSpeed 单位）；慢到能在点位停住读提示 */
const AUTO_ROTATE_SPEED = 0.35
/** 单帧最大时间步长（秒）：从后台切回时丢掉大跳变，避免地球瞬移 */
const MAX_FRAME_DELTA = 0.1

/** 悬停提示框：与点位的间隙、最大宽度（宽度用于边界夹取）、以及「改到下方显示」的纵向阈值 */
const TOOLTIP_GAP_PX = 12
const TOOLTIP_MAX_W = 172
const TOOLTIP_FLIP_PX = 76
/** 悬停定位圈直径（CSS px） */
const MARKER_SIZE_PX = 26

// ---------------------------------------------------------------------------
// 本机位置（弧线终点）
// ---------------------------------------------------------------------------

/**
 * 本机（服务器）坐标。
 *
 * 来源：`GET /api/v1/stats/attack-geo` 的 `server_latitude` / `server_longitude`
 * 两个字段（由守护进程的配置项提供，或未配置时由出口 IP 探测确定）。三者必须一致
 * 才构造出本对象：`server_location_source` 为 `none`、或任一侧不是有限数值，都视为
 * 未配置——此时既不画本机标记、也不画弧线，而不是退回某个占位坐标。
 */
interface SelfPosition {
  latitude: number
  longitude: number
  /** 来源；`none` 不会构造出本对象（未配置即「没有本机位置」） */
  source: 'config' | 'detected'
}

/** 本机坐标来源的中文标注（与后端 ServerLocationSource 对应，`none` 不在此列） */
const SELF_SOURCE_LABEL: Record<SelfPosition['source'], string> = {
  config: '配置项',
  detected: '出口 IP 探测，非权威值仅供展示',
}

// ---------------------------------------------------------------------------
// 色调与令牌
// ---------------------------------------------------------------------------

/**
 * 语义色调 → CSS 令牌名。
 *
 * 与 components/console.tsx 的 `toneColor()` 一一对应：网页侧的颜色走 CSS 变量，
 * WebGL 侧拿不到 `var()`，必须解析成字面量后才能交给 three，因此这里保留同一套映射。
 */
const TONE_CSS_VAR: Record<Tone, string> = {
  default: '--fw-text',
  primary: '--fw-primary-strong',
  success: '--fw-success',
  warning: '--fw-warning',
  danger: '--fw-danger',
}

/** 3D 场景用到的颜色集（全部来自令牌的计算值） */
type SceneTokens = Record<Tone, THREE.Color>

/**
 * 读取设计令牌的计算值。
 *
 * 做什么：把 `color: var(--fw-x)` 挂到一个隐藏探针元素上，让浏览器解析成 `rgb(...)` 再
 *   交给 three——这是唯一能同时做到「只用令牌、不写死十六进制」又自动跟随深浅主题的做法。
 * 影响什么：令牌不存在时该声明整体无效，计算值回落到继承色（配色退化但不会抛错）。
 */
function readTokenColor(host: HTMLElement, cssVar: string): THREE.Color {
  const probe = document.createElement('span')
  probe.style.cssText = `color: var(${cssVar}); display: none;`
  host.appendChild(probe)
  const resolved = window.getComputedStyle(probe).color
  probe.remove()
  return new THREE.Color(resolved)
}

function readSceneTokens(host: HTMLElement): SceneTokens {
  return {
    default: readTokenColor(host, TONE_CSS_VAR.default),
    primary: readTokenColor(host, TONE_CSS_VAR.primary),
    success: readTokenColor(host, TONE_CSS_VAR.success),
    warning: readTokenColor(host, TONE_CSS_VAR.warning),
    danger: readTokenColor(host, TONE_CSS_VAR.danger),
  }
}

/**
 * 封禁次数占比（0~1）→ 语义色调。
 *
 * 单一真相源：球面打点的颜色与下方 TOP 列表的 Badge 共用同一个函数，同一份数据不会出现
 * 「图上标红、列表标黄」这种自相矛盾的配色。
 */
function bansTone(ratio: number): Tone {
  if (ratio >= 0.6) return 'danger'
  if (ratio >= 0.2) return 'warning'
  return 'primary'
}

// ---------------------------------------------------------------------------
// 球面几何
// ---------------------------------------------------------------------------

/**
 * 经纬度 → 球面坐标（与 three 的 SphereGeometry + 等距圆柱贴图一致）。
 *
 * 做什么：把 (lat, lon) 投到 radius 半径的球面上，uv.x = 0 对应经度 -180°。
 * 影响什么：打点、本机标记与弧线端点全部走这一个函数，因此它必须与贴图的经纬基准成对
 *   使用——公式取自 three 官方地球示例的约定，改动会让所有点位整体偏移。
 */
function latLonToVector3(latitude: number, longitude: number, radius: number): THREE.Vector3 {
  const phi = ((90 - latitude) * Math.PI) / 180
  const theta = ((longitude + 180) * Math.PI) / 180
  const sinPhi = Math.sin(phi)
  return new THREE.Vector3(
    -radius * sinPhi * Math.cos(theta),
    radius * Math.cos(phi),
    radius * sinPhi * Math.sin(theta),
  )
}

/**
 * 采样一条「贴球面拱起」的弧线（大圆等角插值 + 半波抬升）。
 *
 * 为什么不用二次贝塞尔：贝塞尔的极值只在 t=0.5 处，大夹角时为了把弧顶托到球面之上，
 * 控制点必须拉得很远，导致曲线离开端点的**切向指向球内**——靠近两端的那一小段会沉到
 * 球面以下被深度测试吃掉（实测对跖情形最低降到 0.945 个球半径）。
 * 这里改成两段各自可控的构造：
 *   · 方向：按大圆等角插值（对分量四元数做 slerp），端点方向精确；
 *   · 半径：POINT_RADIUS + (apex − POINT_RADIUS)·sin(πt) —— 两端正好落在球面上、
 *     弧顶正好等于目标半径、全程**不低于**球面（sin 在 [0,π] 上非负）。
 * 对跖（方向相反）时大圆有无数条，由 three 的 setFromUnitVectors 在退化分支里给出
 * 一个合法的垂直轴，不会产生 NaN。
 *
 * @param samples 预分配的采样点数组（长度须为 ARC_SEGMENTS + 1），就地写入避免每帧分配
 */
function sampleArc(from: THREE.Vector3, to: THREE.Vector3, samples: THREE.Vector3[]): void {
  _fromDir.copy(from).normalize()
  _toDir.copy(to).normalize()
  const angle = _fromDir.angleTo(_toDir)
  const lift = POINT_RADIUS + GLOBE_RADIUS * ARC_APEX_LIFT * (angle / Math.PI) - POINT_RADIUS
  _fullRotation.setFromUnitVectors(_fromDir, _toDir)

  for (let i = 0; i < samples.length; i += 1) {
    const t = i / ARC_SEGMENTS
    _partialRotation.slerpQuaternions(_identityRotation, _fullRotation, t)
    samples[i]
      .copy(_fromDir)
      .applyQuaternion(_partialRotation)
      .multiplyScalar(POINT_RADIUS + lift * Math.sin(Math.PI * t))
  }
}

// 弧线采样与命中检测复用的临时对象：这两处都是按点循环的热路径，不能在里面 new
const _fromDir = new THREE.Vector3()
const _toDir = new THREE.Vector3()
const _identityRotation = new THREE.Quaternion()
const _fullRotation = new THREE.Quaternion()
const _partialRotation = new THREE.Quaternion()

// ---------------------------------------------------------------------------
// 3D 场景
// ---------------------------------------------------------------------------

/** 悬停点位在容器内的像素锚点（相对画布左上角） */
interface ScreenAnchor {
  x: number
  y: number
}

/** 悬停提示框的锚点：已做水平夹取与上下翻转，调用方只需把元素摆上去 */
interface TooltipAnchor {
  x: number
  y: number
  /** true = 提示框摆在点位下方（点位靠近上边缘时用） */
  below: boolean
}

interface GlobeCallbacks {
  /** 悬停（或点按）命中的攻击源；null 表示没有命中 */
  onHoverChange: (point: GeoPoint | null) => void
  /** 命中点的屏幕锚点；每帧调用，供调用方直接写 DOM 样式（不走 React 重渲染） */
  onHoverMove: (anchor: ScreenAnchor, tooltip: TooltipAnchor) => void
  /** 贴图已就绪（可撤掉加载占位） */
  onTextureReady: () => void
  /** 贴图加载失败（球体会被隐藏，点位与弧线仍然可用） */
  onTextureError: () => void
}

/**
 * 攻击分布地球：封装「渲染器 + 场景 + 相机 + 控制器 + 三类几何」的生命周期。
 *
 * 为什么用类而不是一堆 useEffect：渲染器与 RAF 循环必须在挂载时建一次、卸载时整份销毁，
 * 而数据每轮轮询都会变（只该重建几何缓冲）。把两者分成「构造/销毁」与「setData」两组
 * 操作，页面侧就只剩两个短 effect，也不会有人在 render 路径里重建整个场景。
 *
 * 数据变动只重建 BufferGeometry 的顶点缓冲，不重建 Points / LineSegments 对象本身——
 * 每帧新建对象的代价在移动端会直接体现为掉帧。
 */
class AttackGlobe {
  private readonly container: HTMLElement
  private readonly callbacks: GlobeCallbacks

  private readonly renderer: THREE.WebGLRenderer
  private readonly canvas: HTMLCanvasElement
  private readonly scene: THREE.Scene
  private readonly camera: THREE.PerspectiveCamera
  private readonly controls: OrbitControls
  private readonly clock = new THREE.Clock()

  private readonly globeGeometry: THREE.SphereGeometry
  private readonly globeMaterial: THREE.MeshBasicMaterial
  private readonly globeTexture: THREE.Texture
  private readonly globe: THREE.Mesh<THREE.SphereGeometry, THREE.MeshBasicMaterial>

  private readonly haloGeometry: THREE.SphereGeometry
  private readonly haloMaterial: THREE.MeshBasicMaterial
  private readonly halo: THREE.Mesh<THREE.SphereGeometry, THREE.MeshBasicMaterial>

  private readonly pointsMaterial: THREE.ShaderMaterial
  private readonly arcsMaterial: THREE.LineBasicMaterial
  private points: THREE.Points | null = null
  private selfMarker: THREE.Points | null = null
  private arcs: THREE.LineSegments | null = null

  /** 本机（服务器）坐标；`null` = 未配置（不画标记与弧线）。由 `setData` 注入 */
  private selfPos: SelfPosition | null = null

  /** 当前参与绘制的地点（已剔除坐标非法的项），与 positions/sizes 下标一一对应 */
  private pointsData: GeoPoint[] = []
  /** 打点位置缓冲：悬停命中检测直接读它，避免每帧从几何属性里解包 */
  private positions: Float32Array | null = null
  /** 打点屏幕尺寸（CSS px），同样是命中半径的依据 */
  private sizes: Float32Array | null = null

  private tokens: SceneTokens
  /** 指针在容器内的位置（CSS px）；null = 指针不在画布上 */
  private pointer: ScreenAnchor | null = null
  /** 最近一次指针事件的类型（'mouse' / 'touch' / 'pen'）：决定抬起后是否保留选中 */
  private lastPointerType = 'mouse'
  private hovered: GeoPoint | null = null

  /** 容器内容尺寸（CSS px），供投影与提示框夹取使用 */
  private width = 1
  private height = 1

  private rafId = 0
  private readonly resizeObserver: ResizeObserver
  private detachers: Array<() => void> = []
  private readonly autoRotate: boolean

  constructor(container: HTMLElement, callbacks: GlobeCallbacks) {
    this.container = container
    this.callbacks = callbacks
    this.tokens = readSceneTokens(container)

    // ---- 渲染器 ----
    // alpha + 透明清屏：让页面底色（--fw-bg）从球体外透出来，地球不会嵌在一块黑方块里。
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    this.renderer.setClearAlpha(0)
    // 像素比封顶 2：高 DPR 手机上再往上加只是白烧 GPU，肉眼几乎无差
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
    this.canvas = this.renderer.domElement
    this.canvas.style.display = 'block'
    this.canvas.style.width = '100%'
    this.canvas.style.height = '100%'
    // touch-action: none —— 不设它时浏览器会把单指拖拽解释成页面滚动，手指一滑就变成滚屏
    // 而不是转地球。代价是画布区域内的页面滚动被让给地球（画布高度有限，页面其余区域
    // 照常可滚动）；页面侧还会拦掉画布上的 touch 事件冒泡，避免与下拉刷新抢同一手势。
    this.canvas.style.touchAction = 'none'
    this.canvas.style.cursor = 'grab'
    container.appendChild(this.canvas)

    this.scene = new THREE.Scene()
    this.camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100)
    this.camera.position.set(0, 0, CAMERA_DISTANCE)

    // ---- 球体 ----
    this.globeTexture = new THREE.TextureLoader().load(
      EARTH_TEXTURE_URL,
      () => this.callbacks.onTextureReady(),
      undefined,
      () => {
        // 贴图拿不到时把球体藏起来：一颗没有贴图的亮白球比空态更难看，而点位与弧线
        // 本身不依赖贴图，仍然照常渲染（页面侧会给出「贴图加载失败」的行内错误）。
        if (this.globe) this.globe.visible = false
        this.callbacks.onTextureError()
      },
    )
    this.globeTexture.colorSpace = THREE.SRGBColorSpace
    // 侧看球体边缘时各向异性过滤能显著减少贴图糊成一团（移动端上限通常 4~16）
    this.globeTexture.anisotropy = this.renderer.capabilities.getMaxAnisotropy()

    this.globeGeometry = new THREE.SphereGeometry(GLOBE_RADIUS, 64, 48)
    // 不需要光照：未受光材质让贴图颜色完全可控（也省掉一盏灯与一套光照计算）
    this.globeMaterial = new THREE.MeshBasicMaterial({ map: this.globeTexture })
    this.globeMaterial.color.setScalar(EARTH_BRIGHTNESS)
    const globe = new THREE.Mesh(this.globeGeometry, this.globeMaterial)
    this.globe = globe
    this.scene.add(globe)

    // ---- 大气辉光（背面 + 加法混合：球体遮住了朝前的部分，只剩轮廓外一圈） ----
    this.haloGeometry = new THREE.SphereGeometry(HALO_RADIUS, 48, 32)
    this.haloMaterial = new THREE.MeshBasicMaterial({
      color: this.tokens.primary,
      transparent: true,
      opacity: HALO_OPACITY,
      side: THREE.BackSide,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
    this.halo = new THREE.Mesh(this.haloGeometry, this.haloMaterial)
    this.halo.renderOrder = 0
    this.scene.add(this.halo)

    // ---- 点位 / 弧线 / 本机标记 ----
    this.pointsMaterial = AttackGlobe.createPointsMaterial(this.renderer.getPixelRatio())
    this.arcsMaterial = new THREE.LineBasicMaterial({
      vertexColors: true, // 顶点色带 alpha（itemSize = 4）→ 弧线沿程淡出
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
    // 本机标记与弧线不在这里建：本机坐标来自接口数据，要等第一轮 setData 才知道

    // ---- 交互 ----
    this.controls = new OrbitControls(this.camera, this.canvas)
    this.controls.enableDamping = true
    this.controls.dampingFactor = 0.08
    this.controls.enablePan = false // 平移只会把地球推出视野，没有意义
    this.controls.minDistance = CAMERA_MIN_DISTANCE
    this.controls.maxDistance = CAMERA_MAX_DISTANCE
    this.controls.rotateSpeed = 0.55
    this.controls.zoomSpeed = 0.8
    // 尊重「减少动效」偏好：该设置打开时不自转，但拖拽旋转与缩放照常可用
    this.autoRotate = !window.matchMedia('(prefers-reduced-motion: reduce)').matches
    this.controls.autoRotate = this.autoRotate
    this.controls.autoRotateSpeed = AUTO_ROTATE_SPEED

    this.listenElement(this.canvas, 'pointerdown', this.onPointerDown)
    this.listenElement(this.canvas, 'pointermove', this.onPointerMove)
    this.listenElement(this.canvas, 'pointerleave', this.onPointerLeave)
    this.listenElement(this.canvas, 'pointercancel', this.onPointerLeave)
    // 拦掉画布上的触摸事件冒泡：否则在球体上拖拽会同时被外层 PullToRefresh 当成下拉手势
    this.listenElement(this.canvas, 'touchstart', this.stopTouch)
    this.listenElement(this.canvas, 'touchmove', this.stopTouch)
    this.listenElement(this.canvas, 'touchend', this.stopTouch)

    const onVisibility = (): void => {
      // 后台标签页停掉 RAF：移动端上省电，也避免回来后 delta 大跳变
      if (document.hidden) this.stopLoop()
      else this.startLoop()
    }
    document.addEventListener('visibilitychange', onVisibility)
    this.detachers.push(() => document.removeEventListener('visibilitychange', onVisibility))

    this.resizeObserver = new ResizeObserver(() => this.resize())
    this.resizeObserver.observe(container)
    this.resize()
    this.startLoop()
  }

  /**
   * 点精灵材质：方形点裁圆 + 中心实、边缘晕的发光片。
   *
   * GLSL 源码本身刻意写成纯 ASCII（注释放在这一段 TS 注释里）：GLSL ES 的源码字符集
   * 只保证 ASCII，部分移动端驱动对注释里的非 ASCII 字节处理不一致，把中文写进 shader
   * 有「在某些机型上编译失败」的风险。着色逻辑的说明如下：
   *   顶点阶段：vColor 把每个点的颜色传给片元；gl_PointSize 用屏幕空间像素（不随深度衰减）
   *     ——地球在景深里只有一层，透视缩放只会让前后半球的点大小不一致，反而干扰读数。
   *   片元阶段：把方形点精灵按半径裁成圆并做幂次衰减（中心实、边缘晕）；加法混合下 alpha
   *     决定叠加强度，亮度用「底色 + 光晕」保证小点也看得见。
   */
  private static createPointsMaterial(pixelRatio: number): THREE.ShaderMaterial {
    return new THREE.ShaderMaterial({
      uniforms: { uPixelRatio: { value: pixelRatio } },
      vertexShader: `
        attribute float aSize;
        attribute vec3 aColor;
        uniform float uPixelRatio;
        varying vec3 vColor;
        void main() {
          vColor = aColor;
          gl_PointSize = aSize * uPixelRatio;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        varying vec3 vColor;
        void main() {
          vec2 offset = gl_PointCoord - vec2(0.5);
          float radius = length(offset) * 2.0;
          if (radius > 1.0) discard;
          float glow = pow(1.0 - radius, 2.2);
          gl_FragColor = vec4(vColor * (0.55 + glow), glow);
        }
      `,
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    })
  }

  /** 更新攻击源点位与本机坐标（每轮数据变化调用一次；同样的数据不必重复调用，页面侧已按签名去重） */
  setData(points: GeoPoint[], selfPosition: SelfPosition | null): void {
    this.selfPos = selfPosition
    const accepted = this.buildPoints(points)
    this.pointsData = accepted
    this.buildSelfMarker()
    this.buildArcs(accepted)
    if (this.hovered !== null && !accepted.includes(this.hovered)) this.setHovered(null)
  }

  /**
   * 主题切换后重新解析令牌并重绘。
   *
   * 点位与弧线的颜色写在顶点缓冲里，改色只能重写缓冲——但主题切换是低频操作，
   * 整份重建一次远比在每帧里维护两套配色便宜。
   */
  refreshTokens(): void {
    this.tokens = readSceneTokens(this.container)
    this.haloMaterial.color.copy(this.tokens.primary)
    this.buildSelfMarker()
    if (this.pointsData.length > 0) {
      const accepted = this.buildPoints(this.pointsData)
      this.pointsData = accepted
      this.buildArcs(accepted)
    }
  }

  /** 彻底释放 GPU 资源与监听；调用后本实例不可再用 */
  dispose(): void {
    this.stopLoop()
    for (const detach of this.detachers) detach()
    this.detachers = []
    this.resizeObserver.disconnect()

    this.controls.dispose()

    this.points?.geometry.dispose()
    this.selfMarker?.geometry.dispose()
    this.arcs?.geometry.dispose()
    this.pointsMaterial.dispose()
    this.arcsMaterial.dispose()

    this.globeGeometry.dispose()
    this.globeMaterial.dispose()
    this.globeTexture.dispose()
    this.haloGeometry.dispose()
    this.haloMaterial.dispose()

    this.scene.clear()
    this.renderer.dispose()
    // 主动交还 WebGL 上下文：移动端浏览器对同时存在的上下文数量有硬限制，
    // 不及时释放会让「返回再进入本页」直接失败（一张黑画布）
    this.renderer.forceContextLoss()
    this.canvas.remove()
  }

  // -------------------------------------------------------------------------
  // 几何构建
  // -------------------------------------------------------------------------

  /**
   * 重建打点几何：位置 / 屏幕尺寸 / 颜色三个属性缓冲。
   *
   * 返回真正参与绘制的地点列表（坐标非法的项被剔除），下标与缓冲一一对应。
   */
  private buildPoints(points: GeoPoint[]): GeoPoint[] {
    const accepted: GeoPoint[] = []
    const positions: number[] = []
    const sizes: number[] = []
    const colors: number[] = []

    // 基准取本批最大值：点径表达的是「相对谁更凶」，绝对值由下方列表的精确数字承担
    let maxBans = 1
    for (const point of points) maxBans = Math.max(maxBans, point.total_bans)

    for (const point of points) {
      // 坐标非法的项不参与绘制：NaN 会污染整个几何体的包围球，让整组点被裁掉
      if (!Number.isFinite(point.latitude) || !Number.isFinite(point.longitude)) continue
      const vertex = latLonToVector3(point.latitude, point.longitude, POINT_RADIUS)
      const ratio = Math.min(1, Math.max(0, point.total_bans / maxBans))
      const color = this.tokens[bansTone(ratio)]

      positions.push(vertex.x, vertex.y, vertex.z)
      sizes.push(POINT_MIN_PX + (POINT_MAX_PX - POINT_MIN_PX) * Math.sqrt(ratio))
      colors.push(color.r, color.g, color.b)
      accepted.push(point)
    }

    const positionArray = Float32Array.from(positions)
    const sizeArray = Float32Array.from(sizes)
    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(positionArray, 3))
    geometry.setAttribute('aSize', new THREE.BufferAttribute(sizeArray, 1))
    geometry.setAttribute('aColor', new THREE.BufferAttribute(Float32Array.from(colors), 3))

    if (this.points === null) {
      this.points = new THREE.Points(geometry, this.pointsMaterial)
      // depthTest 保持开启：球体写深度、远侧的点被自然遮挡，不需要自己算法线朝向
      this.points.renderOrder = 2
      this.scene.add(this.points)
    } else {
      // 只换几何体，保留 Points 对象：每轮轮询新建对象会在移动端累积 GPU 侧分配
      this.points.geometry.dispose()
      this.points.geometry = geometry
    }

    this.positions = positionArray
    this.sizes = sizeArray
    return accepted
  }

  /** 重建本机标记（单点，复用点位材质 → 同一套发光样式）；本机坐标未配置时隐藏 */
  private buildSelfMarker(): void {
    const self = this.selfPos
    if (self === null) {
      // 未配置本机坐标：不画标记。保留对象、只置不可见，免得坐标来回切换时反复建删
      if (this.selfMarker !== null) this.selfMarker.visible = false
      return
    }

    const vertex = latLonToVector3(self.latitude, self.longitude, POINT_RADIUS)
    const color = this.tokens.success
    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute(
      'position',
      new THREE.BufferAttribute(new Float32Array([vertex.x, vertex.y, vertex.z]), 3),
    )
    geometry.setAttribute('aSize', new THREE.BufferAttribute(new Float32Array([SELF_MARKER_PX]), 1))
    geometry.setAttribute(
      'aColor',
      new THREE.BufferAttribute(new Float32Array([color.r, color.g, color.b]), 3),
    )

    if (this.selfMarker === null) {
      this.selfMarker = new THREE.Points(geometry, this.pointsMaterial)
      this.selfMarker.renderOrder = 2
      this.scene.add(this.selfMarker)
    } else {
      this.selfMarker.geometry.dispose()
      this.selfMarker.geometry = geometry
      this.selfMarker.visible = true
    }
  }

  /** 重建「攻击源 → 本机」的弧线（全部合成一个 LineSegments，一次绘制调用）；本机坐标未配置时无弧线 */
  private buildArcs(points: GeoPoint[]): void {
    const self = this.selfPos
    const positions: number[] = []
    const colors: number[] = []

    if (self !== null) {
      const origin = latLonToVector3(self.latitude, self.longitude, POINT_RADIUS)
      const color = this.tokens.danger

      // 采样点数组在循环外分配一次并复用：每个弧线都 new 一遍会在移动端制造大量短命对象
      const samples: THREE.Vector3[] = []
      for (let i = 0; i <= ARC_SEGMENTS; i += 1) samples.push(new THREE.Vector3())

      // 沿弧线淡出：t = 0 在攻击源一端、t = 1 在本机一端
      const alphaAt = (t: number): number => ARC_HEAD_ALPHA * Math.pow(1 - t, 1.6) + ARC_TAIL_ALPHA

      for (const point of points) {
        if (!Number.isFinite(point.latitude) || !Number.isFinite(point.longitude)) continue
        const from = latLonToVector3(point.latitude, point.longitude, POINT_RADIUS)
        // 与本机几乎重合的地点画不出有意义的弧（长度为 0），跳过以免留下退化几何
        if (from.distanceTo(origin) < 1e-4) continue

        sampleArc(from, origin, samples)
        for (let i = 0; i < samples.length - 1; i += 1) {
          const head = samples[i]
          const tail = samples[i + 1]
          positions.push(head.x, head.y, head.z, tail.x, tail.y, tail.z)
          const t0 = i / ARC_SEGMENTS
          const t1 = (i + 1) / ARC_SEGMENTS
          colors.push(color.r, color.g, color.b, alphaAt(t0))
          colors.push(color.r, color.g, color.b, alphaAt(t1))
        }
      }
    }

    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(Float32Array.from(positions), 3))
    // itemSize = 4 会让 three 启用 USE_COLOR_ALPHA：顶点色里的 alpha 参与混合
    geometry.setAttribute('color', new THREE.BufferAttribute(Float32Array.from(colors), 4))

    if (this.arcs === null) {
      this.arcs = new THREE.LineSegments(geometry, this.arcsMaterial)
      this.arcs.renderOrder = 1
      this.scene.add(this.arcs)
    } else {
      this.arcs.geometry.dispose()
      this.arcs.geometry = geometry
    }
    // 未配置本机坐标时没有弧线可画，显式隐藏
    this.arcs.visible = self !== null
  }

  // -------------------------------------------------------------------------
  // 循环 / 命中检测 / 尺寸
  // -------------------------------------------------------------------------

  private startLoop(): void {
    if (this.rafId !== 0) return
    // 丢掉停机期间累积的时间差，否则恢复的第一帧会带着一个巨大的 delta 让地球瞬移
    this.clock.getDelta()
    this.rafId = window.requestAnimationFrame(this.tick)
  }

  private stopLoop(): void {
    if (this.rafId === 0) return
    window.cancelAnimationFrame(this.rafId)
    this.rafId = 0
  }

  private readonly tick = (): void => {
    const delta = Math.min(this.clock.getDelta(), MAX_FRAME_DELTA)
    this.controls.update(delta)
    this.updateHover()
    this.renderer.render(this.scene, this.camera)
    // 放在渲染之后：渲染抛错时循环就地停住，不会变成无限报错
    this.rafId = window.requestAnimationFrame(this.tick)
  }

  /**
   * 悬停命中检测：把每个点在屏幕上的投影与指针位置比较，取最近的一个。
   *
   * 为什么不用 Raycaster：球面上的点很多且大小不一，射线命中阈值需要按点径逐个调，
   * 反而比一次投影 + 距离比较更难预测；这里还能顺手复用同一套可见性判据。
   */
  private updateHover(): void {
    const pointer = this.pointer
    if (pointer === null || this.positions === null || this.pointsData.length === 0) {
      this.setHovered(null)
      return
    }

    const positions = this.positions
    const sizes = this.sizes
    const cameraPosition = this.camera.position
    let best: GeoPoint | null = null
    let bestDistance = Number.POSITIVE_INFINITY
    let bestX = 0
    let bestY = 0

    for (let i = 0; i < this.pointsData.length; i += 1) {
      const index = i * 3
      _normal.fromArray(positions, index).normalize()
      // 可见性：球心在原点时，切线条件 c·n > r（c 为相机位置、n 为单位法线、r 为球面半径）
      // 恰好就是「这个点落在朝向相机的那半边」的判据。与渲染侧的深度测试同源——球体写深度
      // 会挡住远侧的点，因此「看得见」才「点得中」。
      if (_normal.dot(cameraPosition) <= POINT_RADIUS) continue

      _projected.fromArray(positions, index).project(this.camera)
      const x = (_projected.x * 0.5 + 0.5) * this.width
      const y = (-_projected.y * 0.5 + 0.5) * this.height
      const distance = Math.hypot(x - pointer.x, y - pointer.y)
      const hitRadius = Math.max(HIT_MIN_PX, (sizes === null ? POINT_MIN_PX : sizes[i]) * 0.9)
      if (distance <= hitRadius && distance < bestDistance) {
        bestDistance = distance
        best = this.pointsData[i]
        bestX = x
        bestY = y
      }
    }

    this.setHovered(best)
    if (best !== null) {
      // 水平夹取用提示框最大宽度的一半：窄屏下宁可多留一点边距，也不让提示框被裁掉
      const half = TOOLTIP_MAX_W / 2
      const tooltipX = Math.min(Math.max(bestX, half), Math.max(half, this.width - half))
      const below = bestY < TOOLTIP_FLIP_PX
      this.callbacks.onHoverMove(
        { x: bestX, y: bestY },
        { x: tooltipX, y: below ? bestY + TOOLTIP_GAP_PX : bestY - TOOLTIP_GAP_PX, below },
      )
    }
  }

  private setHovered(point: GeoPoint | null): void {
    if (point === this.hovered) return
    this.hovered = point
    // 悬停时暂停自转：点位随球体移动会让提示框追不上，读不下去
    this.controls.autoRotate = this.autoRotate && point === null
    this.callbacks.onHoverChange(point)
  }

  /** 容器尺寸变化（转屏、面板折叠）→ 同步渲染器与相机 */
  private resize(): void {
    const rect = this.container.getBoundingClientRect()
    const width = Math.max(1, Math.round(rect.width))
    const height = Math.max(1, Math.round(rect.height))
    this.width = width
    this.height = height
    // updateStyle = false：画布的 CSS 尺寸由样式（100%）决定，这里只改绘制缓冲
    this.renderer.setSize(width, height, false)
    this.camera.aspect = width / height
    this.camera.updateProjectionMatrix()
    this.pointsMaterial.uniforms.uPixelRatio.value = this.renderer.getPixelRatio()
  }

  // -------------------------------------------------------------------------
  // 输入
  // -------------------------------------------------------------------------

  private readonly onPointerDown = (event: PointerEvent): void => {
    this.lastPointerType = event.pointerType
    this.pointer = this.toLocalPoint(event)
  }

  private readonly onPointerMove = (event: PointerEvent): void => {
    this.pointer = this.toLocalPoint(event)
  }

  private readonly onPointerLeave = (): void => {
    // 触摸抬起后**保留**选中：手指离开屏幕就丢掉提示与明细，手机上等于什么都看不到；
    // 鼠标则靠 pointerleave 收掉悬停态（换到别处自然取消）。触摸端下一次点按会改写选中。
    if (this.lastPointerType === 'touch') return
    this.pointer = null
  }

  /** 阻止画布上的触摸事件冒泡到外层下拉刷新（拖拽地球与下拉刷新是同一手势，必须二选一） */
  private readonly stopTouch = (event: TouchEvent): void => {
    event.stopPropagation()
  }

  private toLocalPoint(event: PointerEvent): ScreenAnchor {
    const rect = this.container.getBoundingClientRect()
    return { x: event.clientX - rect.left, y: event.clientY - rect.top }
  }

  private listenElement<K extends keyof HTMLElementEventMap>(
    target: HTMLElement,
    type: K,
    handler: (event: HTMLElementEventMap[K]) => void,
  ): void {
    target.addEventListener(type, handler)
    this.detachers.push(() => target.removeEventListener(type, handler))
  }
}

// 命中检测的复用的临时向量：每帧要对上百个点做投影，不能在里面 new 对象
const _normal = new THREE.Vector3()
const _projected = new THREE.Vector3()

// ---------------------------------------------------------------------------
// 页面
// ---------------------------------------------------------------------------

/** TOP 列表默认渲染条数：接口最多返回 200 个地点，全铺开会把一屏占满 */
const TOP_VISIBLE = 10

/** 无数据占位（比空格更明确，避免被误读为 0） */
const DASH = '—'

/** 拼接「国家 · 行政区 · 城市」，缺字段时逐级回退；全空则给出明确文案 */
function placeLabel(point: GeoPoint): string {
  const parts = [point.country, point.subdivision, point.city].filter((part) => part.trim() !== '')
  return parts.length > 0 ? parts.join(' · ') : '未知地区'
}

/**
 * 列表行的短标识：国家代码 + 城市（无城市时退到行政区）。
 *
 * 只放最短的一份——行标签列宽固定 96px，超长会被省略号截掉，把长名字塞进去反而
 * 看不见真正能区分彼此的那部分。
 */
function shortPlaceLabel(point: GeoPoint): string {
  const area = point.city.trim() !== '' ? point.city : point.subdivision
  return `${point.country_code} · ${area.trim() !== '' ? area : '未知地区'}`
}

export default function Globe() {
  const pollMs = usePollInterval()
  const { theme } = useTheme()
  const pushSecs = Math.max(1, Math.round(pollMs / 1000))

  // 地理分布没有 SSE 推送，按与推送同源的间隔轮询；后台标签页由 useAsync 自动暂停
  const { data, error, reload } = useAsync<AttackGeoResponse>(
    () => getAttackGeo(),
    [],
    { pollMs },
  )

  const geoEnabled = data?.geoip_enabled === true
  const points = useMemo<GeoPoint[]>(() => data?.points ?? [], [data])

  /**
   * 本机坐标（弧线终点）。接口给的来源为 `config`/`detected` 且两个字段都是有限数值
   * 才算「已配置」；来源为 `none` 或任一字段缺失即为未配置——返回 `null`，调用方据此
   * 不画本机标记与弧线，而不是退回占位坐标。
   */
  const selfPosition = useMemo<SelfPosition | null>(() => {
    const latitude = data?.server_latitude
    const longitude = data?.server_longitude
    const source = data?.server_location_source
    if (source !== 'config' && source !== 'detected') return null
    if (
      typeof latitude !== 'number' ||
      typeof longitude !== 'number' ||
      !Number.isFinite(latitude) ||
      !Number.isFinite(longitude)
    ) {
      return null
    }
    return { latitude, longitude, source }
  }, [data])

  const hostRef = useRef<HTMLDivElement | null>(null)
  const markerRef = useRef<HTMLDivElement | null>(null)
  const tooltipRef = useRef<HTMLDivElement | null>(null)
  const sceneRef = useRef<AttackGlobe | null>(null)

  const [hoveredPoint, setHoveredPoint] = useState<GeoPoint | null>(null)
  const [textureState, setTextureState] = useState<'loading' | 'ready' | 'failed'>('loading')

  /**
   * 悬停位置只写 DOM、不进 React 状态。
   *
   * 命中点每帧都可能移动（球体自转），若走 setState 就是每帧一次重渲染，在移动端直接掉帧。
   * 内容（当前选中了哪个地点）变化极少，才用状态驱动重渲染。
   */
  const handleHoverMove = useCallback((anchor: ScreenAnchor, tooltip: TooltipAnchor): void => {
    const marker = markerRef.current
    if (marker !== null) {
      // 定位圈靠 marginLeft/Top 把自身原点挪到中心，这里只需要摆到锚点
      marker.style.transform = `translate3d(${anchor.x}px, ${anchor.y}px, 0)`
    }
    const tip = tooltipRef.current
    if (tip !== null) {
      // 水平居中于锚点；纵向按 below 决定把提示框摆在点位下方还是上方
      const offset = tooltip.below ? '0' : '-100%'
      tip.style.transform = `translate3d(${tooltip.x}px, ${tooltip.y}px, 0) translate(-50%, ${offset})`
    }
  }, [])

  const handleHoverChange = useCallback((point: GeoPoint | null): void => {
    setHoveredPoint(point)
  }, [])

  const handleTextureReady = useCallback((): void => setTextureState('ready'), [])
  const handleTextureError = useCallback((): void => setTextureState('failed'), [])

  // 场景只在「地理解析可用」时创建：数据库未配置就完全不碰 WebGL 上下文
  useEffect(() => {
    const host = hostRef.current
    if (!geoEnabled || host === null) return

    // 上一次的画布由 dispose() 移除；这里再兜一次底，确保容器里始终只有一张画布
    host.replaceChildren()
    setTextureState('loading')

    const globe = new AttackGlobe(host, {
      onHoverChange: handleHoverChange,
      onHoverMove: handleHoverMove,
      onTextureReady: handleTextureReady,
      onTextureError: handleTextureError,
    })
    sceneRef.current = globe
    return () => {
      sceneRef.current = null
      globe.dispose()
    }
  }, [geoEnabled, handleHoverChange, handleHoverMove, handleTextureReady, handleTextureError])

  /**
   * 只有「影响绘制」的字段变了才重建几何缓冲。
   *
   * 轮询每 pushSecs 秒回来一次，数据通常一个字都没变；不按签名去重就会每个周期丢弃并重建
   * 一次顶点缓冲（移动端上这是可感知的卡顿来源）。本机坐标同样属于绘制输入（决定标记与
   * 弧线画不画、画在哪），故一并进签名。
   */
  const signature = useMemo(() => {
    const self =
      selfPosition === null
        ? 'none'
        : `self:${selfPosition.source}:${selfPosition.latitude}:${selfPosition.longitude}`
    const places = points
      .map((point) => `${point.latitude.toFixed(3)}:${point.longitude.toFixed(3)}:${point.total_bans}`)
      .join('|')
    return `${places}#${self}`
  }, [points, selfPosition])

  useEffect(() => {
    sceneRef.current?.setData(points, selfPosition)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- points/selfPosition 的内容由 signature 表达，签名不变即无需重建
  }, [signature])

  // 主题切换后重读令牌（3D 用色来自 CSS 变量，不会随 DOM 自动更新）
  useEffect(() => {
    sceneRef.current?.refreshTokens()
  }, [theme])

  const doRefresh = useCallback(async (): Promise<void> => {
    await reload()
  }, [reload])

  const maxBans = useMemo(
    () => points.reduce((max, point) => Math.max(max, point.total_bans), 0),
    [points],
  )
  const totalBans = useMemo(
    () => points.reduce((sum, point) => sum + point.total_bans, 0),
    [points],
  )
  const visiblePoints = points.slice(0, TOP_VISIBLE)

  /**
   * 概览判决：一句话回答「地理分布现在有没有内容」。
   *
   * 只在 `geoip_enabled` 的分支里渲染——数据库未装配时整块由 EmptyState 接管
   * （见下方渲染分支），故这里**不处理** `!geoip_enabled`：那样的分支永远不可达，
   * 文案还会与 EmptyState 的启用说明重复。
   */
  const verdict = useMemo((): { text: string; tone: Tone; sub: string; right: string } => {
    if (data === null) return { text: DASH, tone: 'default', sub: '', right: DASH }
    if (points.length === 0) {
      return {
        text: 'NO DATA',
        tone: 'default',
        sub: `近 7 天封禁记录中 ${formatNumber(data.total_ips, false)} 个 IP 参与统计，但没有可定位的城市级坐标`,
        right: DASH,
      }
    }
    return {
      text: 'LOCATED',
      tone: 'primary',
      sub: `近 7 天封禁记录中 ${formatNumber(data.located_ips, false)} / ${formatNumber(
        data.total_ips,
        false,
      )} 个 IP 可定位，聚合为 ${formatNumber(points.length, false)} 个地点（城市级）`,
      right: formatNumber(points.length, false),
    }
  }, [data, points.length])

  return (
    <PullToRefresh onRefresh={doRefresh}>
      <div className="fw-page">
        {/* 标题与顶栏同名，故只保留语义（srOnly），避免屏幕上出现两行同题标题 */}
        <PageHeader title="攻击地图" srOnly subtitle="近 7 天封禁记录的城市级地理分布；只读展示" />

        {/* ------------------------------ 概览 ------------------------------ */}
        <Panel
          title="地理分布概览"
          meta={data === null ? '数据读取中' : `近 7 天 · 轮询 ${pushSecs}s`}
        >
          {error !== null && data === null ? (
            <InlineError message={`地理分布加载失败：${error}`} onRetry={reload} />
          ) : data === null ? (
            <PanelLoading lines={3} />
          ) : !data.geoip_enabled ? (
            // 降级：数据库未配置时不渲染 3D，改为说明如何启用（本页唯一的信息来源）
            <EmptyState
              title="GeoIP 数据库未配置，地理分布不可用"
              description={
                <>
                  攻击源地理分布依赖城市级 GeoIP 数据库（DB-IP City Lite，含经纬度）。
                  <br />
                  启用方式：先运行 <span className="fw-mono">scripts/fetch-geoip.sh</span> 下载数据库，
                  再在 <span className="fw-mono">config/default.yaml</span> 中设置{' '}
                  <span className="fw-mono">geoip_db_path</span> 指向该文件，然后重启守护进程。
                  <br />
                  未启用不影响封禁、速率与其余统计。
                </>
              }
            />
          ) : (
            <>
              <Verdict
                text={verdict.text}
                tone={verdict.tone}
                sub={verdict.sub}
                right={
                  <span className="fw-mono fw-num" style={{ fontSize: 15, fontWeight: 600 }}>
                    {verdict.right}
                  </span>
                }
              />
              <Tiles columns={2}>
                <Tile
                  label="地点数"
                  value={formatNumber(points.length, false)}
                  unit="个"
                  tone="primary"
                />
                <Tile label="已定位 IP" value={formatNumber(data.located_ips, false)} unit="个" />
                <Tile label="参与统计 IP" value={formatNumber(data.total_ips, false)} unit="个" />
                <Tile
                  label="封禁合计"
                  value={formatNumber(totalBans, true)}
                  unit="次"
                  tone={totalBans > 0 ? 'warning' : 'default'}
                />
              </Tiles>
            </>
          )}
        </Panel>

        {/* 地理解析可用时才出现 3D 区块：避免创建 WebGL 上下文后又立刻拆掉 */}
        {geoEnabled && (
          <>
            <Panel
              title="攻击源分布"
              meta={`${formatNumber(points.length, false)} 地点 · 拖拽旋转 / 滚轮或双指缩放`}
              padded={false}
            >
              <div
                role="img"
                aria-label={`3D 地球：${formatNumber(points.length, false)} 个攻击源地点${
                  selfPosition === null ? '（本机位置未配置，未绘制弧线）' : '，弧线连到本机'
                }`}
                style={{
                  position: 'relative',
                  // 固定高度区间：手机上占 62vw，桌面端封顶 360px——地球是入口不是整屏落地页
                  height: 'clamp(240px, 62vw, 360px)',
                  touchAction: 'none',
                  overflow: 'hidden',
                  background: 'var(--fw-bg-alt)',
                }}
              >
                {/*
                  画布专用容器：**必须与下面的 marker/tooltip 分成两个节点**。
                  渲染器把自己的 canvas 挂进来，而 React 不认识它；若把它与 React 渲染的
                  兄弟节点放同一个 div，任何一次 reconcile（或这里的 replaceChildren）都会把
                  React 的那些节点摘掉，提示框就永远不再出现。
                */}
                <div ref={hostRef} style={{ position: 'absolute', inset: 0 }} />
                {/* 悬停定位圈：位置由 handleHoverMove 直写 transform（不走重渲染） */}
                <div
                  ref={markerRef}
                  aria-hidden="true"
                  style={{
                    position: 'absolute',
                    left: 0,
                    top: 0,
                    width: MARKER_SIZE_PX,
                    height: MARKER_SIZE_PX,
                    marginLeft: -MARKER_SIZE_PX / 2,
                    marginTop: -MARKER_SIZE_PX / 2,
                    border: '1px solid var(--fw-primary-strong)',
                    borderRadius: '50%',
                    pointerEvents: 'none',
                    opacity: hoveredPoint === null ? 0 : 1,
                    transition: 'opacity 120ms linear',
                  }}
                />
                {/* 悬停 / 点按提示：内容随选中地点变化，位置每帧直写 */}
                <div
                  ref={tooltipRef}
                  style={{
                    position: 'absolute',
                    left: 0,
                    top: 0,
                    maxWidth: TOOLTIP_MAX_W,
                    padding: '4px 6px',
                    border: '1px solid var(--fw-border-strong)',
                    background: 'var(--fw-surface)',
                    fontSize: 10,
                    lineHeight: 1.5,
                    pointerEvents: 'none',
                    opacity: hoveredPoint === null ? 0 : 1,
                    transition: 'opacity 120ms linear',
                  }}
                >
                  {hoveredPoint === null ? null : (
                    <>
                      <div className="fw-mono" style={{ fontSize: 11, color: 'var(--fw-text)' }}>
                        {hoveredPoint.top_ip}
                      </div>
                      <div style={{ color: 'var(--fw-text-2)' }}>{placeLabel(hoveredPoint)}</div>
                      <div className="fw-mono fw-num" style={{ color: 'var(--fw-text-3)' }}>
                        封禁 {formatNumber(hoveredPoint.total_bans, false)} 次 · 唯一 IP{' '}
                        {formatNumber(hoveredPoint.unique_ips, false)}
                      </div>
                    </>
                  )}
                </div>
                {/* 贴图解码期间占位：2048×1024 的 webp 在移动端要读一小会儿，别留一块空黑。
                    pointerEvents: none —— 占位期间地球照样可拖拽，不必等贴图到齐 */}
                {textureState === 'loading' ? (
                  <div style={{ position: 'absolute', inset: 0, padding: 8, pointerEvents: 'none' }}>
                    <PanelLoading lines={4} />
                  </div>
                ) : null}
              </div>

              {textureState === 'failed' ? (
                <InlineError
                  message={`地球贴图加载失败（${EARTH_TEXTURE_URL}）：球体已隐藏，攻击源点位${
                    selfPosition === null ? '' : '与弧线'
                  }仍然可用`}
                />
              ) : null}

              <Note>
                点径与颜色随封禁次数（相对本批最多者）变化：<Badge tone="danger">最多</Badge>{' '}
                <Badge tone="warning">较多</Badge> <Badge tone="primary">少量</Badge>
                {selfPosition === null ? '。' : '；弧线由攻击源连向本机位置。'}
              </Note>
              {/* 本机坐标已配置时才展示其值（并标出来源）；未配置时既不画标记与弧线，
                  图例项也随之隐藏——探测值不是权威值，界面必须能区分出来 */}
              {selfPosition === null ? null : (
                <Note tone={selfPosition.source === 'detected' ? 'warning' : 'default'}>
                  本机位置（{SELF_SOURCE_LABEL[selfPosition.source]}）：{selfPosition.latitude.toFixed(2)},{' '}
                  {selfPosition.longitude.toFixed(2)}
                </Note>
              )}
              {points.length === 0 ? (
                <Note>近 7 天没有可定位的封禁记录，因此暂无可绘制的攻击源。</Note>
              ) : null}
            </Panel>

            {/* 选中明细：触摸端没有 hover，这里是点按后唯一完整可读的明细入口 */}
            <Panel title="攻击源明细" meta={hoveredPoint === null ? '未选中' : hoveredPoint.country_code}>
              {hoveredPoint === null ? (
                <EmptyState
                  compact
                  title="未选中攻击源"
                  description="点按（或悬停）地球上的发光点即可查看该地点的完整明细；也可以从下方的来源列表快速定位"
                />
              ) : (
                <Rows>
                  <Row wide label="地点" value={placeLabel(hoveredPoint)} />
                  <Row
                    wide
                    label="坐标"
                    value={`${hoveredPoint.latitude.toFixed(2)}, ${hoveredPoint.longitude.toFixed(2)}`}
                  />
                  <Row
                    wide
                    label="封禁次数"
                    value={formatNumber(hoveredPoint.total_bans, false)}
                    tone={bansTone(maxBans > 0 ? hoveredPoint.total_bans / maxBans : 0)}
                  />
                  <Row
                    wide
                    label="唯一 IP"
                    value={formatNumber(hoveredPoint.unique_ips, false)}
                    unit="个"
                  />
                  <Row wide label="代表 IP" value={hoveredPoint.top_ip} />
                  <Row
                    wide
                    label="最近封禁"
                    value={formatDatetime(hoveredPoint.last_banned_at)}
                  />
                </Rows>
              )}
            </Panel>

            {/* TOP 来源列表：3D 之外的精确读数（可复制文本），也是触摸端的快速定位入口 */}
            <Panel
              title="TOP 攻击源地点"
              meta={`按封禁次数降序 · 显示 ${formatNumber(visiblePoints.length, false)} / ${formatNumber(
                points.length,
                false,
              )}`}
              padded={false}
            >
              {points.length === 0 ? (
                <EmptyState
                  compact
                  title="暂无可定位的封禁记录"
                  description="GeoIP 已就绪；近 7 天没有解析出带坐标的封禁来源"
                />
              ) : (
                <Rows>
                  {visiblePoints.map((point) => {
                    const ratio = maxBans > 0 ? point.total_bans / maxBans : 0
                    const tone = bansTone(ratio)
                    return (
                      <Row
                        key={`${point.latitude.toFixed(3)}:${point.longitude.toFixed(3)}:${point.top_ip}`}
                        label={shortPlaceLabel(point)}
                        value={formatNumber(point.total_bans, false)}
                        unit="次"
                        tone={tone}
                        tail={
                          <Badge tone={tone} dim>{`${formatNumber(point.unique_ips, false)} IP`}</Badge>
                        }
                      />
                    )
                  })}
                </Rows>
              )}
              {points.length > TOP_VISIBLE ? (
                <Note>
                  列表只展示封禁次数最高的 {formatNumber(TOP_VISIBLE, false)} 个地点，共{' '}
                  {formatNumber(points.length, false)} 个；完整数据见{' '}
                  <span className="fw-mono">GET /api/v1/stats/attack-geo</span>。
                </Note>
              ) : null}
            </Panel>
          </>
        )}
      </div>
    </PullToRefresh>
  )
}
