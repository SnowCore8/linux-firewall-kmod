// DELETE /api/v2/bans/{ip} 的下发顺序核对：内核解封没确认时镜像必须留着，确认之后才撤。
//
// 用例只需要一个可观测的 KernelBan 假实现：真实下发出口（banSink）在组合根里，HTTP 面
// 拿到的就是这个两方法接口（见 bans.go 的 KernelBan）。
package http

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// fakeKernelBan 记录收到的解封地址，并按 removeErr 决定这一次下发是否成功。
type fakeKernelBan struct {
	removeErr error
	removed   []netip.Addr
}

func (f *fakeKernelBan) Send(netip.Addr, uint8, uint32, string) error { return nil }

func (f *fakeKernelBan) Remove(addr netip.Addr, _ uint8) error {
	f.removed = append(f.removed, addr)
	return f.removeErr
}

// seedBan 往进程级封禁镜像里放一条永久封禁，并在用例结束时摘掉。
func seedBan(t *testing.T, ip string) {
	t.Helper()

	if !bans.GlobalCache().TryInsert(bans.BanInfo{
		IP:          ip,
		Reason:      "manual",
		BannedAt:    1700000000,
		IsPermanent: true,
	}) {
		t.Fatalf("%s 已在封禁镜像中，用例之间的状态不干净", ip)
	}
	t.Cleanup(func() { removeBanForTest(ip) })
}

// TestDeleteBanKeepsMirrorWhenKernelFails 核对内核失败口径：回 40002，镜像条目原样留着。
//
// 永久封禁（duration_secs=0）在内核侧没有到期定时器，条目不会自行消失；此时把镜像撤掉
// 会让面板说「已解封」而 netfilter 继续丢包。
func TestDeleteBanKeepsMirrorWhenKernelFails(t *testing.T) {
	const ip = "203.0.113.77"

	kernel := &fakeKernelBan{removeErr: errors.New("netlink 发送失败")}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelBan = kernel })
	seedBan(t, ip)

	w := authedSend(t, s, http.MethodDelete, "/api/v2/bans/"+ip, "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 %d，期望 %d（body=%s）", w.Code, http.StatusBadRequest, truncate(w.Body.Bytes()))
	}
	env := assertEnvelopeKeys(t, w.Body.Bytes())
	if got := envelopeCode(t, env); got != httpcontract.Code40002 {
		t.Errorf("code = %d，契约给这条路由编的失败码是 %d", got, httpcontract.Code40002)
	}
	if _, ok := bans.GlobalCache().Get(ip); !ok {
		t.Error("内核解封失败后镜像条目被撤掉了：面板会显示已解封，而内核那条永久封禁不消失")
	}
	if len(kernel.removed) != 1 {
		t.Errorf("下发内核解封 %d 次，期望 1 次", len(kernel.removed))
	}
}

// TestDeleteBanRemovesMirrorAfterKernelAck 核对成功路径：内核确认之后才撤镜像并回 200。
func TestDeleteBanRemovesMirrorAfterKernelAck(t *testing.T) {
	const ip = "203.0.113.78"

	kernel := &fakeKernelBan{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelBan = kernel })
	seedBan(t, ip)

	w := authedSend(t, s, http.MethodDelete, "/api/v2/bans/"+ip, "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d，期望 200（body=%s）", w.Code, truncate(w.Body.Bytes()))
	}
	if _, ok := bans.GlobalCache().Get(ip); ok {
		t.Error("内核已确认解封，镜像里那条还在")
	}
	if len(kernel.removed) != 1 {
		t.Errorf("下发内核解封 %d 次，期望 1 次", len(kernel.removed))
	}
}

// TestDeleteBanSkipsKernelWhenAbsent 核对缺席分支不下发内核解封：镜像查询是只读的，
// 查不到就没有可解封的组合。
func TestDeleteBanSkipsKernelWhenAbsent(t *testing.T) {
	const ip = "198.51.100.9"

	kernel := &fakeKernelBan{}
	s, _ := newTestServer(t, func(cfg *APIConfig) { cfg.KernelBan = kernel })

	w := authedSend(t, s, http.MethodDelete, "/api/v2/bans/"+ip, "", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("状态码 %d，期望 %d（body=%s）", w.Code, http.StatusBadRequest, truncate(w.Body.Bytes()))
	}
	env := assertEnvelopeKeys(t, w.Body.Bytes())
	if got := envelopeCode(t, env); got != httpcontract.Code40002 {
		t.Errorf("code = %d，期望 %d", got, httpcontract.Code40002)
	}
	if len(kernel.removed) != 0 {
		t.Errorf("不在封禁表中的 IP 也下发了 %d 次内核解封", len(kernel.removed))
	}
}
