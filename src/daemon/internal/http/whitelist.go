// 白名单面：GET/POST/DELETE /api/v1/whitelist。
//
// 契约给这条资源编的两个码各自覆盖一段操作：40003 = 添加失败，40004 = 移除失败。
// 两者都是 400，区分只能靠 code，所以这里不出现「顺手写个 409/404」——那两个数字在
// codes 段里没有对应条目，前端查不到语义。
package http

import (
	"net/http"
	"net/netip"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

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
	entries := make([]WhitelistEntryResponse, 0)
	for _, cidr := range bans.GlobalWhitelist().List() {
		entries = append(entries, WhitelistEntryResponse{CIDR: cidr})
	}
	WriteSuccess(w, entries)
}

// AddWhitelist 收一个 CIDR 或裸 IP（裸 IP 按 /32 或 /128 落），成功回 201。
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

	if !bans.GlobalWhitelist().Add(prefix) {
		WriteCode(w, httpcontract.Code40003, "添加白名单失败：该网段已在表中 "+prefix.String())
		return
	}

	h.publishWhitelist()

	// cidr 回**归一后**的键（与 GET 列表同源）：把用户输入的 "10.0.0.1/8" 原样吐回去，
	// 调用方按它再删一次就会打不中表里那条 "10.0.0.0/8"。
	WriteCreated(w, WhitelistOperationResponse{CIDR: prefix.Masked().String(), Action: "added"})
}

// RemoveWhitelist 从白名单移除一个前缀（DELETE /api/v1/whitelist/{cidr}），失败回 40004。
func (h *APIHandlers) RemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	cidr := r.PathValue("cidr")

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		WriteCode(w, httpcontract.Code40004, "移除白名单失败：CIDR 非法 "+cidr)
		return
	}

	if !bans.GlobalWhitelist().Remove(prefix) {
		WriteCode(w, httpcontract.Code40004, "移除白名单失败：该网段不在表中 "+cidr)
		return
	}

	h.publishWhitelist()

	WriteSuccess(w, WhitelistOperationResponse{CIDR: prefix.Masked().String(), Action: "removed"})
}

// parseWhitelistTarget 把「CIDR 或裸 IP」两种写法折成一个前缀。
//
// 裸 IP 的主机位长度必须由地址自己决定：写死 32 会让 IPv6 的 /128 变成非法前缀，
// 而 Add 的调用方不该关心这次输入是 v4 还是 v6。
func parseWhitelistTarget(text string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}
