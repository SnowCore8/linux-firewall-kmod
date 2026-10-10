// 反向指令通道：内核 → 入站执行体。
//
// # 为什么需要这条通道
//
// 配置的独占所有权在入站执行体（见 InboundExecutor.cfg 与 Config 的注释）：只有它改配置
// （自动重载 / 回滚 / Web UI 启用状态桥接），组合根只留一份引用而不留副本。内核推送的
// CONFIG_CHANGE 由事件泵那个 goroutine 读到，若泵直接改 cfg，就会与执行体的重载路径互相
// 覆盖——同一条 ban_time 可能一边写新值一边按旧值重建规则集。故泵只把事实转成 Directive
// 投递，落地动作仍由执行体在自己的循环里做。
//
// # 投递语义
//
// 非阻塞：队列满时生产方记一条日志后丢弃，绝不为了等执行体而把事件流钉住（事件流一堵，
// 封禁/白名单状态变更就再也进不来了，比少一条指令严重得多）。丢一条 CONFIG_CHANGE 的后果
// 是配置继续按文件里的值生效；丢一条 BanIP 拒绝的后果是该 IP 少一轮下发抑制。两者都会被
// 下一次对账或下一条同类事件纠正。
//
// 消费节拍：执行体在每轮迭代开头排空队列（executor.step），因此指令最长延迟 = 本轮 poll
// 的超时上限（cfg.Interval 秒，默认量级 1 秒）——与既有的 jail 启用状态桥接同一节拍，
// 没有引入新的延迟类别。
//
// # 目前只有两类
//
// 契约里内核→daemon 的六类推播中，BanStateChange / WhitelistStateChange / DdosEvent 是
// 镜像事实，泵自己就能落地；ConfigAck 是回显 seq 的回复类型，正常由路由器配对认领，执行体
// 既不发起 SET_CONFIG 也就无从认领（等下发路径接上再补这一类）。真正需要「执行体做但只有
// 它能做」的只剩下面两类。
package runtime

import (
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// DirectiveKind 是反向指令的类型。
type DirectiveKind uint8

const (
	// DirectiveKernelConfigChanged：内核侧配置被 procfs 写入改变，载荷是整份配置快照。
	DirectiveKernelConfigChanged DirectiveKind = iota + 1
	// DirectiveCommandRejected：内核拒绝了本进程刚下发的一条封禁指令。
	DirectiveCommandRejected
)

// Directive 是一条待执行体落地的反向指令。字段按 Kind 取用，未用到的保持零值。
type Directive struct {
	Kind DirectiveKind

	// --- DirectiveKernelConfigChanged ---

	// ConfigFlags 是 contract.ConfigFlags 位图，标明内核侧哪些配置位变了。
	ConfigFlags uint32
	// BanTimeSecs 是内核当前的全局封禁时长（秒）；0 表示内核未给出，不采纳。
	BanTimeSecs uint32
	// DdosBanDurationSecs 是内核的 DDoS 自动封禁时长（秒）。
	DdosBanDurationSecs uint32

	// --- DirectiveCommandRejected ---

	// IP 是被拒指令的目标地址（内核给出的是 addr16，无法解析时为空串）。
	IP string
	// Cmd 是被拒指令的诊断名（contract.MsgType.String()）。
	Cmd string
	// Errno 是内核给出的失败码。
	Errno int32
}

// dispatchRejectionCooldown 是一条被拒封禁的下发抑制窗口。
//
// 为什么必须有：条目从镜像里消失后，该 IP 的下一条失败日志就能重新占位、重新下发，于是
// 「每行日志一个 netlink 往返」——内核因为封禁表满而拒绝时，两侧都会被同一个攻击者淹掉。
// 抑制只作用于下发，判定与计数照旧（面板仍看得见失败尝试在涨）。
const dispatchRejectionCooldown = 60 * time.Second

// drainDirectives 排空本轮已到达的反向指令。无指令时是一次 default，不产生等待。
func (e *InboundExecutor) drainDirectives() {
	for {
		select {
		case d, ok := <-e.cmd:
			if !ok {
				// 生产方已关闭：摘掉通道，否则每轮迭代都会在这里空转一遍（关闭的通道恒可读）。
				e.cmd = nil
				return
			}
			e.applyDirective(d)
		default:
			return
		}
	}
}

// applyDirective 把一条指令落到执行体的状态上。
func (e *InboundExecutor) applyDirective(d Directive) {
	switch d.Kind {
	case DirectiveKernelConfigChanged:
		e.adoptKernelConfig(d)
	case DirectiveCommandRejected:
		e.noteRejectedDispatch(d)
	default:
		e.warn("收到未知类型的反向指令，已忽略", "kind", uint8(d.Kind))
	}
}

// adoptKernelConfig 把内核侧的配置变更吸收进执行体持有的那份配置。
//
// 只有与配置字段一一对应的位才吸收：ban_time 对应 DefaultBanTime（并连带更新未显式配置
// ban_time 的 jail——它们继承默认值，默认变了它们必须跟着变，否则面板显示新值而实际下发
// 用旧值），ddos_ban_duration 对应 Ddos.AutoBanDuration。其余位（速率上限、动态阈值、
// 基线）内核只由 procfs 的 ban_time 一处广播（fw_procfs.c:550），今天不会有别的 flags
// 到达；真到了也只需记录，因为守护进程侧没有对应的可写字段——为没有生产者的分支预先映射，
// 等于把契约里「daemon 是配置权威」这句话偷偷改成「内核是权威」。
func (e *InboundExecutor) adoptKernelConfig(d Directive) {
	flags := contract.ConfigFlags(d.ConfigFlags)
	known := contract.ConfigFlagBanTime | contract.ConfigFlagDdosBanDuration
	if other := flags &^ known; other != 0 {
		e.info("内核侧配置变更含守护进程无对应字段的位，仅记录", "flags", uint32(other))
	}
	changed := false

	if flags&contract.ConfigFlagBanTime != 0 {
		// 0 在内核侧不是合法 bantime：采纳它会把每个继承默认值的 jail 变成永久封禁。
		if d.BanTimeSecs == 0 {
			e.warn("内核广播的 ban_time 为 0，不采纳", "flags", uint32(flags))
		} else if secs := clampKernelBanTime(d.BanTimeSecs); secs != e.cfg.DefaultBanTime {
			e.warn("采纳内核侧 ban_time", "old", e.cfg.DefaultBanTime, "new", secs)
			e.cfg.DefaultBanTime = secs
			for i := range e.cfg.Jails {
				if !e.cfg.Jails[i].BanTimeSet && e.cfg.Jails[i].BanTime != secs {
					e.cfg.Jails[i].BanTime = secs
				}
			}
			changed = true
		}
	}

	if flags&contract.ConfigFlagDdosBanDuration != 0 && d.DdosBanDurationSecs != 0 {
		if d.DdosBanDurationSecs != e.cfg.Ddos.AutoBanDuration {
			e.warn("采纳内核侧 DDoS 封禁时长",
				"old", e.cfg.Ddos.AutoBanDuration, "new", d.DdosBanDurationSecs)
			e.cfg.Ddos.AutoBanDuration = d.DdosBanDurationSecs
			changed = true
		}
	}

	if changed {
		// 规则集里带着每个 jail 的 ban_time（JailPolicy.BanTime），改了 cfg 必须重建，
		// 否则新值要等到下一次 SIGHUP 才生效。
		e.refreshJails()
	}
}

// clampKernelBanTime 把内核的 u32 秒数收进 cfg 的 int32 表示（上界钳到 int32 最大值，
// 远不到即保持原值）。
func clampKernelBanTime(secs uint32) int32 {
	const maxInt32 = uint32(1<<31 - 1)
	if secs > maxInt32 {
		return int32(maxInt32)
	}
	return int32(secs)
}

// noteRejectedDispatch 记下「内核拒绝了这个 IP 的封禁」，在抑制窗口内不再对它重复下发。
func (e *InboundExecutor) noteRejectedDispatch(d Directive) {
	if d.IP == "" {
		e.warn("内核拒绝的下发指令没有可用目标地址，无法抑制", "cmd", d.Cmd, "errno", d.Errno)
		return
	}
	if e.rejected == nil {
		e.rejected = make(map[string]time.Time)
	}
	until := time.Now().Add(e.rejectionTTL)
	if prev, ok := e.rejected[d.IP]; !ok || until.After(prev) {
		// 取较晚的到期点：连续被拒要把抑制窗口往后推，而不是用一个新窗口把旧的更晚值改短。
		e.rejected[d.IP] = until
	}
	e.warn("封禁下发被内核拒绝，抑制该 IP 的重复下发",
		"ip", d.IP, "cmd", d.Cmd, "errno", d.Errno, "until", until.Unix())
}

// dispatchSuppressed 报告该 IP 是否还在下发抑制窗口内。
func (e *InboundExecutor) dispatchSuppressed(ip string, now time.Time) bool {
	until, ok := e.rejected[ip]
	if !ok {
		return false
	}
	if now.Before(until) {
		return true
	}
	delete(e.rejected, ip)
	return false
}

// purgeRejectedDispatches 清掉已过期的抑制条目（跟着 60 秒的失败窗口清理同一节拍跑）。
func (e *InboundExecutor) purgeRejectedDispatches(now time.Time) {
	for ip, until := range e.rejected {
		if !now.Before(until) {
			delete(e.rejected, ip)
		}
	}
}
