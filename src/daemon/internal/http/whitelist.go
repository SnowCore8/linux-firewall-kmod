// 白名单面：GET/POST/DELETE /api/v1/whitelist。
//
// 契约给这条资源编的两个码各自覆盖一段操作：40003 = 添加失败，40004 = 移除失败。
// 两者都是 400，区分只能靠 code，所以这里不出现「顺手写个 409/404」——那两个数字在
// codes 段里没有对应条目，前端查不到语义。
//
// 两条契约都没给这两条路由编 50003（那是 GET /config、POST /bans/batch 一类才有的
// 「依赖未就绪」码），所以**内核缺席不是错误**：与封禁面同一口径——镜像照改、下发跳过、
// 记一条调试日志，操作按成功回。把「没有内核」报成 400 会让无模块的测试与开发环境里
// 这一面完全不可用，而契约并没有要求那样区分。
package http

import (
	"net/http"
	"net/netip"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// KernelWhitelist 是白名单的内核下发出口（由组合根注入内核客户端的实现）。
//
// 形状与 KernelBan 对齐：地址 + 前缀长度 + 一个错误，`Delivered` 那层包装在组合根里剥掉
// （它带的信息只有「发出去了没有」）。device 恒为空串——本实现的白名单是纯地址规则，
// 内核侧 fw_addr_normalize 也只看前缀，但线格式里有这一列，接口就把它留在签名上，
// 免得将来接按网卡放行时又要改一遍所有调用点。
type KernelWhitelist interface {
	Add(addr netip.Addr, prefixLen uint8, device string) error
	Remove(addr netip.Addr, prefixLen uint8, device string) error
}

// ListWhitelist 返回白名单镜像（GET /api/v1/whitelist）。
//
// 载荷是 WhitelistEntryResponse 数组而不是裸 CIDR 列表：前端 types.ts 的 WhitelistEntry
// 有两个字段，把 []string 直接写出去会让 `device` 在读侧根本不存在（面板上那一列恒为空，
// 而它空的原因和「这个网段没绑设备」是两回事）。
//
// device 恒为空串：本守护进程的白名单是**纯地址**规则（内核 fw_addr_normalize 只看
// 前缀），没有任何按网卡放行的概念，而契约把这一列的形状定成 String 而不是 Option——
// 空串正是「未绑定」的读法，前端也按这个显示。
func (h *APIHandlers) ListWhitelist(w http.ResponseWriter, r *http.Request) {
	WriteSuccess(w, whitelistEntries(bans.GlobalWhitelist().List()))
}

// whitelistEntries 把镜像里的键折成载荷条目。
//
// REST 与 SSE 的 whitelist 域共用它：两条路都给前端同一个数组形状，差别只在触发时机。
func whitelistEntries(cidrs []string) []WhitelistEntryResponse {
	entries := make([]WhitelistEntryResponse, 0, len(cidrs))
	for _, cidr := range cidrs {
		entries = append(entries, WhitelistEntryResponse{CIDR: cidr})
	}
	return entries
}

// AddWhitelist 收一个 CIDR 或裸 IP（裸 IP 按 /32 或 /128 落），成功回 201。
//
// 顺序是「先占镜像、再下发内核、下发失败把镜像撤回来」，与 CreateBan 完全同一形状：
// 面板上不得出现一条内核里没有的白名单——那意味着运维以为这个网段已经被放行，而它继续
// 被拦。反过来（先下发再占位）也行得通，但那样就得在成功路径上做两次归一化判定，
// 而 Add 的「已在表中」这个返回值本身就是判据。
func (h *APIHandlers) AddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req CreateWhitelistRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	prefix, err := parseWhitelistTarget(req.CIDR)
	if err != nil {
		WriteCode(w, httpcontract.Code40003, "添加白名单失败：CIDR 或 IP 非法 "+req.CIDR)
		return
	}
	// 掩到前缀边界之后再往下走：镜像的键、下发的三元组与响应里回显的 cidr 必须是同一个
	// 形状。内核按 af+addr+prefix_len 定位规则并在回显时给出归一化后的地址
	// （kernel/consumer.go 的 prefixFromAddr 直接用它），带主机位发出去的那一条与回显
	// 算出来的那一条不是同一个键——正是缺陷 HTTP_WHITELIST_KEY_DIVERGENCE 那一类病。
	prefix = prefix.Masked()

	if !bans.GlobalWhitelist().Add(prefix) {
		WriteCode(w, httpcontract.Code40003, "添加白名单失败：该网段已在表中 "+prefix.String())
		return
	}

	if h.kernelWhitelist != nil {
		if err := h.kernelWhitelist.Add(prefix.Addr(), uint8(prefix.Bits()), ""); err != nil {
			h.server.logger.Error("内核白名单下发失败", "cidr", prefix.String(), "error", err)
			bans.GlobalWhitelist().Remove(prefix)
			WriteCode(w, httpcontract.Code40003, "添加白名单失败：内核未确认（"+err.Error()+"）")
			return
		}
	}

	h.publishWhitelist()

	// cidr 回**归一后**的键（与 GET 列表同源）：把用户输入的 "10.0.0.1/8" 原样吐回去，
	// 调用方按它再删一次就会打不中表里那条 "10.0.0.0/8"。
	WriteCreated(w, WhitelistOperationResponse{CIDR: prefix.String(), Action: "added"})
}

// RemoveWhitelist 从白名单移除一个前缀（DELETE /api/v1/whitelist/{cidr}），失败回 40004。
func (h *APIHandlers) RemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	cidr := r.PathValue("cidr")

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		WriteCode(w, httpcontract.Code40004, "移除白名单失败：CIDR 非法 "+cidr)
		return
	}
	prefix = bans.NormalizeWhitelistPrefix(prefix).Masked()

	if !bans.GlobalWhitelist().Remove(prefix) {
		WriteCode(w, httpcontract.Code40004, "移除白名单失败：该网段不在表中 "+cidr)
		return
	}

	// 与添加路径相反，这里下发失败**不回滚**镜像：内核里那条规则最多活到下一条事件把
	// 镜像对齐，而把「镜像已撤、面板显示不再放行」报成一次失败，会让运维重复点删除按钮
	// 去追一个已经消失的条目。与 DeleteBan 同一口径。
	if h.kernelWhitelist != nil {
		if err := h.kernelWhitelist.Remove(prefix.Addr(), uint8(prefix.Bits()), ""); err != nil {
			h.server.logger.Error("内核白名单移除下发失败", "cidr", prefix.String(), "error", err)
		}
	}

	h.publishWhitelist()

	WriteSuccess(w, WhitelistOperationResponse{CIDR: prefix.String(), Action: "removed"})
}

// parseWhitelistTarget 把「CIDR 或裸 IP」两种写法折成一个前缀。
//
// 归一化本身不在这里重复实现：写入侧的三条路径（这条 HTTP 路径、组合根启动时下发配置里
// 的可信地址、事件泵按内核回显重建镜像）必须共用同一套键规则，见 bans.WhitelistPrefixFromText。
func parseWhitelistTarget(text string) (netip.Prefix, error) {
	return bans.WhitelistPrefixFromText(text)
}
