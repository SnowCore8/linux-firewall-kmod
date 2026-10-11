// 白名单写入面的核对：镜像、内核下发与契约码三者怎么互相让步。
//
// 两条路由各只编了一个失败码（POST 40003、DELETE 40004），也没有 50003——所以这里除了
// 「下发成功」，更要钉住两件事：① 内核回绝添加时镜像必须撤回那条（面板不得显示一条
// 内核里没有的放行规则），② 内核回绝移除时镜像**不**撤回、响应仍是成功（与 DeleteBan
// 同口径），以及 ③ 没有内核客户端时这一面照常工作而不是报 400。
package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// envelopeMessage 取信封的 message 原文（40003 一个码覆盖三种失败，只有这句话能分辨）。
func envelopeMessage(t *testing.T, env map[string]json.RawMessage) string {
	t.Helper()

	var message string
	if err := json.Unmarshal(env["message"], &message); err != nil {
		t.Fatalf("message 不是字符串: %v（raw=%s）", err, env["message"])
	}
	return message
}

// recordingWhitelist 是 KernelWhitelist 的假实现：把每次下发记成一条 cidr|device，
// err 非空时全部失败（内核回绝与 netlink 发送失败在 handler 眼里是同一件事）。
//
// 先记账再报错——「有没有试着下发」本身就是被测的性质，尤其在移除路径上：那里失败不改变
// 结果状态，只能从下发记录里看出 handler 到底有没有把这条规则交给内核。
type recordingWhitelist struct {
	added   []string
	removed []string
	err     error
}

func (f *recordingWhitelist) Add(addr netip.Addr, prefixLen uint8, device string) error {
	f.added = append(f.added, wireKey(addr, prefixLen, device))
	if f.err != nil {
		return f.err
	}
	return nil
}

func (f *recordingWhitelist) Remove(addr netip.Addr, prefixLen uint8, device string) error {
	f.removed = append(f.removed, wireKey(addr, prefixLen, device))
	if f.err != nil {
		return f.err
	}
	return nil
}

// wireKey 把下发的三元组折成可断言的文本：af+addr+prefix_len 正是内核定位一条白名单
// 规则用的键，device 也带上——它恒为空串，出现非空值就说明有人在 HTTP 侧臆造了网卡。
func wireKey(addr netip.Addr, prefixLen uint8, device string) string {
	return addr.String() + "/" + strconv.Itoa(int(prefixLen)) + "|" + device
}

// useWhitelistKey 让本用例从一批干净的键开始，并在结束后把它们摘掉。
//
// 白名单镜像是**进程级单例**：包里别的用例（sse_payload_test.go 的夹具）会在里面留自己的
// 条目，同一网段因此可能在本用例开始前就存在——那会让「添加」直接撞上「已在表中」，
// 断言看到的就是空的下发记录。所以这里在开始前先删一次，而不是只在结束后清。
func useWhitelistKey(t *testing.T, cidrs ...string) {
	t.Helper()

	remove := func() {
		for _, text := range cidrs {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				t.Fatalf("用例里的 CIDR 非法: %v", err)
			}
			bans.GlobalWhitelist().Remove(prefix)
		}
	}
	remove()
	t.Cleanup(remove)
}

// postWhitelist 打 POST /api/v1/whitelist 并回信封。
func postWhitelist(t *testing.T, s *Server, body string) (map[string]json.RawMessage, int) {
	t.Helper()

	rec := authedSend(t, s, http.MethodPost, "/api/v1/whitelist", "application/json", body)
	env := decodeEnvelope(t, rec.Body.Bytes())
	return env, rec.Code
}

func TestWhitelistAddDeliversToKernel(t *testing.T) {
	useWhitelistKey(t, "203.0.113.0/24")
	fake := &recordingWhitelist{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelWhitelist = fake })

	env, status := postWhitelist(t, s, `{"cidr":"203.0.113.0/24"}`)
	if want := httpcontract.CodeHTTPStatus[httpcontract.CodeOK]; status != http.StatusCreated && status != want {
		t.Fatalf("HTTP 状态 = %d，契约给 POST /api/v1/whitelist 定的是 201（alt 200）", status)
	}
	if code := envelopeCode(t, env); code != httpcontract.CodeOK {
		t.Fatalf("code = %d，期望 %d（body=%s）", code, httpcontract.CodeOK, env["data"])
	}
	if len(fake.added) != 1 || fake.added[0] != "203.0.113.0/24|" {
		t.Fatalf("下发记录 = %v，期望恰好一条 203.0.113.0/24（device 空串）", fake.added)
	}
	if !slices.Contains(bans.GlobalWhitelist().List(), "203.0.113.0/24") {
		t.Errorf("镜像里没有那条规则：%v", bans.GlobalWhitelist().List())
	}

	list := get[[]WhitelistEntryResponse](t, s, "/api/v1/whitelist")
	found := false
	for _, row := range list {
		if row.CIDR == "203.0.113.0/24" {
			found = true
		}
	}
	if !found {
		t.Errorf("GET 列表里没有刚加的网段：%+v", list)
	}
}

// TestWhitelistAddKernelFailureRollsBackMirror 是这条面最要紧的一条：下发被内核回绝之后，
// 镜像里不能留着那条规则。留着它意味着面板显示「这个网段已放行」，而内核继续拦截。
func TestWhitelistAddKernelFailureRollsBackMirror(t *testing.T) {
	useWhitelistKey(t, "192.0.2.0/24")
	fake := &recordingWhitelist{err: errors.New("内核拒绝：白名单已满")}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelWhitelist = fake })

	env, status := postWhitelist(t, s, `{"cidr":"192.0.2.0/24"}`)
	if want := httpcontract.CodeHTTPStatus[httpcontract.Code40003]; status != want {
		t.Errorf("HTTP 状态 = %d，契约 40003 对应 %d", status, want)
	}
	if code := envelopeCode(t, env); code != httpcontract.Code40003 {
		t.Errorf("code = %d，期望 40003", code)
	}
	if slices.Contains(bans.GlobalWhitelist().List(), "192.0.2.0/24") {
		t.Errorf("下发失败后镜像里仍留着那条规则：%v", bans.GlobalWhitelist().List())
	}
	// message 要带上内核的原因：40003 同时覆盖「非法 CIDR」「已在表中」「内核未确认」，
	// 运维只能靠这句话分辨是哪一种。
	if msg := envelopeMessage(t, env); !strings.Contains(msg, "内核未确认") {
		t.Errorf("message = %q，期望说明失败来自内核未确认", msg)
	}
}

func TestWhitelistAddDuplicateDoesNotTouchKernel(t *testing.T) {
	useWhitelistKey(t, "198.51.100.0/24")
	fake := &recordingWhitelist{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelWhitelist = fake })

	if _, _ = postWhitelist(t, s, `{"cidr":"198.51.100.0/24"}`); len(fake.added) != 1 {
		t.Fatalf("第一次添加的下发记录 = %v，期望一条", fake.added)
	}
	env, _ := postWhitelist(t, s, `{"cidr":"198.51.100.0/24"}`)
	if code := envelopeCode(t, env); code != httpcontract.Code40003 {
		t.Errorf("重复添加的 code = %d，期望 40003", code)
	}
	if len(fake.added) != 1 {
		t.Errorf("重复添加仍然下发了内核：%v", fake.added)
	}
}

// TestWhitelistAddNormalizesIPv4Mapped 钉住写入侧的键归一化。
//
// ::ffff:198.51.100.7/128 是同一条规则的另一种写法：不折成 198.51.100.7/32 的话，镜像里
// 存映射形态、事件泵按内核回显（AF_INET + /32）算出非映射形态，一条规则两份键，删除只能
// 打中其中一条——缺陷 HTTP_WHITELIST_KEY_DIVERGENCE 那一类，只是发生在写入侧。
func TestWhitelistAddNormalizesIPv4Mapped(t *testing.T) {
	useWhitelistKey(t, "198.51.100.7/32", "2001:db8::1/128")
	fake := &recordingWhitelist{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelWhitelist = fake })

	env, _ := postWhitelist(t, s, `{"cidr":"::ffff:198.51.100.7/128"}`)
	raw, err := json.Marshal(env["data"])
	if err != nil {
		t.Fatalf("data 再编码失败: %v", err)
	}
	var resp WhitelistOperationResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("data 解码失败: %v（raw=%s）", err, raw)
	}
	if resp.CIDR != "198.51.100.7/32" {
		t.Errorf("回显的 cidr = %q，期望折成 IPv4 本体 198.51.100.7/32", resp.CIDR)
	}
	if len(fake.added) != 1 || fake.added[0] != "198.51.100.7/32|" {
		t.Errorf("下发记录 = %v，期望按 /32 下发（AF_INET 的线格式装不下 /128 的映射写法）", fake.added)
	}

	// 真 IPv6 的裸地址仍是 /128，不能被这条归一化顺手改短。
	if _, _ = postWhitelist(t, s, `{"cidr":"2001:db8::1"}`); len(fake.added) != 2 ||
		fake.added[1] != "2001:db8::1/128|" {
		t.Errorf("IPv6 裸地址的下发记录 = %v，期望第二条是 2001:db8::1/128", fake.added)
	}
}

// TestWhitelistRemoveKeepsMirrorOnKernelFailure 与解封同口径：镜像已经撤了就别再塞回去。
func TestWhitelistRemoveKeepsMirrorOnKernelFailure(t *testing.T) {
	useWhitelistKey(t, "203.0.113.64/28")
	fake := &recordingWhitelist{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelWhitelist = fake })

	if _, _ = postWhitelist(t, s, `{"cidr":"203.0.113.64/28"}`); len(fake.added) != 1 {
		t.Fatalf("前置添加失败: %v", fake.added)
	}
	fake.err = errors.New("内核拒绝：规则不存在")

	// CIDR 里的 / 必须编码：未编码时那是两段路径，ServeMux 根本匹配不上这条路由
	// （前端 endpoints.ts 的 fill() 就是为此做 encodeURIComponent）。
	rec := authedSend(t, s, http.MethodDelete, "/api/v1/whitelist/203.0.113.64%2F28", "", "")
	env := decodeEnvelope(t, rec.Body.Bytes())
	if code := envelopeCode(t, env); code != httpcontract.CodeOK {
		t.Errorf("移除时内核回绝导致 code = %d，期望仍按成功（0）处理", code)
	}
	if slices.Contains(bans.GlobalWhitelist().List(), "203.0.113.64/28") {
		t.Errorf("镜像里那条规则被塞回去了：%v", bans.GlobalWhitelist().List())
	}
	if len(fake.removed) != 1 {
		t.Errorf("移除下发记录 = %v，期望一条", fake.removed)
	}
}

func TestWhitelistRemoveSuccessDeliversNormalizedKey(t *testing.T) {
	useWhitelistKey(t, "192.0.2.128/25")
	fake := &recordingWhitelist{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelWhitelist = fake })

	if _, _ = postWhitelist(t, s, `{"cidr":"192.0.2.128/25"}`); len(fake.added) != 1 {
		t.Fatalf("前置添加失败: %v", fake.added)
	}
	// 删除时带主机位（192.0.2.200/25）：按掩码后的键定位，与镜像里的键同源。
	rec := authedSend(t, s, http.MethodDelete, "/api/v1/whitelist/192.0.2.200%2F25", "", "")
	if code := envelopeCode(t, decodeEnvelope(t, rec.Body.Bytes())); code != httpcontract.CodeOK {
		t.Fatalf("带主机位的删除 code = %d，期望 0（归一化后应命中）", code)
	}
	if len(fake.removed) != 1 || fake.removed[0] != "192.0.2.128/25|" {
		t.Errorf("移除下发记录 = %v，期望按掩码后的 192.0.2.128/25 下发", fake.removed)
	}
}

// TestWhitelistWithoutKernelClient 钉住「内核缺席不是失败」：契约给这两条路由编的码里
// 没有 50003，模块未加载时白名单面仍按镜像成功回。
func TestWhitelistWithoutKernelClient(t *testing.T) {
	useWhitelistKey(t, "198.51.100.128/25")
	s, _ := newTestServer(t, nil)

	env, _ := postWhitelist(t, s, `{"cidr":"198.51.100.128/25"}`)
	if code := envelopeCode(t, env); code != httpcontract.CodeOK {
		t.Fatalf("code = %d，无内核客户端时期望 0 而不是新造一个码", code)
	}
	if !slices.Contains(bans.GlobalWhitelist().List(), "198.51.100.128/25") {
		t.Errorf("镜像里没有那条规则：%v", bans.GlobalWhitelist().List())
	}
}

func TestWhitelistAddRejectsUnparsableCIDR(t *testing.T) {
	fake := &recordingWhitelist{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelWhitelist = fake })

	env, _ := postWhitelist(t, s, `{"cidr":"not-a-cidr"}`)
	if code := envelopeCode(t, env); code != httpcontract.Code40003 {
		t.Errorf("code = %d，期望 40003", code)
	}
	if len(fake.added) != 0 {
		t.Errorf("非法输入仍下发了内核：%v", fake.added)
	}
}
