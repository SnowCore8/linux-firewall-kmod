package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// Delivered 表示一条请求已投递到内核，但内核是否执行未获确认。
//
// ban / unban / 白名单增删在成功时没有任何回复，只有失败才有 CmdResult（进事件流）。
// 用独立类型把「已投递」与「已执行」区分开，避免调用方把发送成功当成执行成功。
type Delivered struct{}

// ErrTimeout 表示超时内未收到回复。既可能是内核没回，也可能是回复被丢弃。
var ErrTimeout = errors.New("等待内核回复超时")

// ErrLinkDown 表示与内核的链路已断：接收侧已退出，回复不可能到达。
var ErrLinkDown = errors.New("与内核的 netlink 链路已断开")

// ErrBusy 表示在途请求表已满，请求未发出。
var ErrBusy = errors.New("在途请求表已满，请求未发出")

// ErrSeqReused 表示请求序号与某条在途请求重复，请求未发出。
var ErrSeqReused = errors.New("请求序号与在途请求重复，请求未发出")

// UnexpectedReplyError 是「收到了回复，但类型不是本次请求该有的」的协议违例。
type UnexpectedReplyError struct {
	Expected contract.MsgType
	Got      contract.MsgType
}

// Error 实现 error。
func (e *UnexpectedReplyError) Error() string {
	return fmt.Sprintf("期望 %s 回复，实得 %s", e.Expected, e.Got)
}

// Client 是类型化请求客户端。可并发共享（内部只有原子计数与共享 socket/router）。
type Client struct {
	transport *Transport
	router    *Router
	nextSeq   atomic.Uint32
}

// NewClient 在既有 socket 与路由器上建立客户端。
func NewClient(t *Transport, r *Router) *Client {
	c := &Client{transport: t, router: r}
	// 从 1 起：契约里 seq == 0 表示「不参与配对」。
	c.nextSeq.Store(1)
	return c
}

// Transport 返回 socket 的所有者，供租约注册直接发送报文。
func (c *Client) Transport() *Transport { return c.transport }

// Router 返回路由器，供租约注册登记配对。
func (c *Client) Router() *Router { return c.router }

// allocSeq 分配一个非零请求序号。
//
// 取「自增前的值」，与 Rust 版一致：序号必须连续可预测，两侧计数才对得齐。
// 跳过 0：u32 回绕时自增会产出 0，而 0 在契约里意味着「本条不参与配对」。
func (c *Client) allocSeq() uint32 {
	for {
		if seq := c.nextSeq.Add(1) - 1; seq != 0 {
			return seq
		}
	}
}

// registered 登记在途请求，把登记失败映射为可辨识的错误。
func (c *Client) registered(replyType contract.MsgType, seq uint32) (*replyHandle, error) {
	h, err := c.router.Register(replyType, seq)
	if err == nil {
		return h, nil
	}
	switch err {
	case RegisterLinkDown:
		return nil, ErrLinkDown
	case RegisterFull:
		return nil, ErrBusy
	case RegisterDuplicate:
		return nil, ErrSeqReused
	default:
		return nil, err
	}
}

// exchangeWith 发出一条请求并等待配对回复。
//
// 先登记再发送：回复可能在本函数返回前的任何时刻到达，顺序不能颠倒。
func (c *Client) exchangeWith(
	replyType contract.MsgType,
	seq uint32,
	payload []byte,
	timeout time.Duration,
) (Incoming, error) {
	h, err := c.registered(replyType, seq)
	if err != nil {
		return Incoming{}, err
	}
	if err := c.transport.Send(payload); err != nil {
		h.Abandon()
		return Incoming{}, err
	}
	msg, err := h.RecvTimeout(ClampTimeout(timeout))
	if err != nil {
		h.Abandon()
		return Incoming{}, err
	}
	return msg, nil
}

// request 发出一条请求；seq 由本客户端分配，编码由 encode 完成。
func (c *Client) request(
	replyType contract.MsgType,
	timeout time.Duration,
	encode func(seq uint32) ([]byte, error),
) (Incoming, error) {
	seq := c.allocSeq()
	payload, err := encode(seq)
	if err != nil {
		return Incoming{}, err
	}
	return c.exchangeWith(replyType, seq, payload, timeout)
}

// QueryStats 查询内核统计。
func (c *Client) QueryStats(timeout time.Duration) (contract.StatsResponse, error) {
	msg, err := c.request(contract.MsgStatsResponse, timeout, func(seq uint32) ([]byte, error) {
		return contract.StatsQuery(seq), nil
	})
	if err != nil {
		return contract.StatsResponse{}, err
	}
	if msg.Stats == nil {
		return contract.StatsResponse{}, &UnexpectedReplyError{contract.MsgStatsResponse, msg.MsgType}
	}
	return *msg.Stats, nil
}

// QueryAnalysis 查询分析数据（包大小/TTL 分布、端口与扫描者 Top-N）。
func (c *Client) QueryAnalysis(timeout time.Duration) (contract.AnalysisResponse, error) {
	msg, err := c.request(contract.MsgAnalysisResponse, timeout, func(seq uint32) ([]byte, error) {
		return contract.AnalysisQuery(seq), nil
	})
	if err != nil {
		return contract.AnalysisResponse{}, err
	}
	if msg.Analysis == nil {
		return contract.AnalysisResponse{}, &UnexpectedReplyError{contract.MsgAnalysisResponse, msg.MsgType}
	}
	return *msg.Analysis, nil
}

// SetConfig 下发配置并返回内核的采纳/拒绝位图。
//
// 这是唯一的配置下发路径：基线更新也必须走这里，不得另开捷径。
func (c *Client) SetConfig(change *contract.SetConfig, timeout time.Duration) (contract.ConfigAck, error) {
	msg, err := c.request(contract.MsgConfigAck, timeout, func(seq uint32) ([]byte, error) {
		return change.Encode(seq)
	})
	if err != nil {
		return contract.ConfigAck{}, err
	}
	if msg.CfgAck == nil {
		return contract.ConfigAck{}, &UnexpectedReplyError{contract.MsgConfigAck, msg.MsgType}
	}
	return *msg.CfgAck, nil
}

// Register 注册为唯一守护进程，返回内核的接受/拒绝结论。
func (c *Client) Register(timeout time.Duration) (contract.DaemonRegisterAck, error) {
	msg, err := c.request(contract.MsgDaemonRegisterAck, timeout, func(seq uint32) ([]byte, error) {
		return contract.DaemonRegister(seq), nil
	})
	if err != nil {
		return contract.DaemonRegisterAck{}, err
	}
	if msg.RegAck == nil {
		return contract.DaemonRegisterAck{}, &UnexpectedReplyError{contract.MsgDaemonRegisterAck, msg.MsgType}
	}
	return *msg.RegAck, nil
}

// Ban 下发封禁。返回值表示已投递，不表示已生效。
//
// 失败时内核会单播 CmdResult，它进入事件流，不在本方法的返回路径上。
func (c *Client) Ban(addr netip.Addr, prefixLen uint8, durationSecs uint32, reason string) (Delivered, error) {
	af, a, err := addrToWire(addr)
	if err != nil {
		return Delivered{}, err
	}
	cmd := &contract.BanIp{
		AF:           af,
		PrefixLen:    prefixLen,
		DurationSecs: durationSecs,
		Addr:         a,
		Reason:       reason,
	}
	payload, err := cmd.Encode(c.allocSeq())
	if err != nil {
		return Delivered{}, err
	}
	if err := c.transport.Send(payload); err != nil {
		return Delivered{}, err
	}
	return Delivered{}, nil
}

// Unban 下发解封。返回值表示已投递。
//
// prefixLen 必须与封禁时一致（内核按 af+addr+prefix_len 三元组定位条目）。
func (c *Client) Unban(addr netip.Addr, prefixLen uint8) (Delivered, error) {
	af, a, err := addrToWire(addr)
	if err != nil {
		return Delivered{}, err
	}
	cmd := &contract.UnbanIp{AF: af, PrefixLen: prefixLen, Addr: a}
	payload, err := cmd.Encode(c.allocSeq())
	if err != nil {
		return Delivered{}, err
	}
	if err := c.transport.Send(payload); err != nil {
		return Delivered{}, err
	}
	return Delivered{}, nil
}

// SetProtectedPorts 下发受保护端口位图。返回值表示已投递，不表示已生效。
//
// 语义是「纳入防护」：置位端口的入站流量参与 DDoS 速率判定。count 由发送方按位图
// 实际统计，内核会自行重算，这里算只是为了让消息里的 count 与位图一致。
func (c *Client) SetProtectedPorts(bitmap [contract.ProtectedPortsLen]byte) (Delivered, error) {
	count := uint32(0)
	for _, b := range bitmap {
		count += uint32(popcount8(b))
	}
	cmd := &contract.SetProtectedPorts{Count: count, Bitmap: bitmap}
	payload, err := cmd.Encode(c.allocSeq())
	if err != nil {
		return Delivered{}, err
	}
	if err := c.transport.Send(payload); err != nil {
		return Delivered{}, err
	}
	return Delivered{}, nil
}

// AddWhitelist 添加白名单。返回值表示已投递。
func (c *Client) AddWhitelist(addr netip.Addr, prefixLen uint8, device string) (Delivered, error) {
	af, a, err := addrToWire(addr)
	if err != nil {
		return Delivered{}, err
	}
	cmd := &contract.AddWhitelist{AF: af, PrefixLen: prefixLen, Addr: a, Device: device}
	payload, err := cmd.Encode(c.allocSeq())
	if err != nil {
		return Delivered{}, err
	}
	if err := c.transport.Send(payload); err != nil {
		return Delivered{}, err
	}
	return Delivered{}, nil
}

// RemoveWhitelist 移除白名单。返回值表示已投递。
func (c *Client) RemoveWhitelist(addr netip.Addr, prefixLen uint8, device string) (Delivered, error) {
	af, a, err := addrToWire(addr)
	if err != nil {
		return Delivered{}, err
	}
	cmd := &contract.RemoveWhitelist{AF: af, PrefixLen: prefixLen, Addr: a, Device: device}
	payload, err := cmd.Encode(c.allocSeq())
	if err != nil {
		return Delivered{}, err
	}
	if err := c.transport.Send(payload); err != nil {
		return Delivered{}, err
	}
	return Delivered{}, nil
}

// ListBansPage 取封禁表一页。
func (c *Client) ListBansPage(offset, limit uint32, timeout time.Duration) (contract.ListBansResponse, error) {
	q := &contract.ListBansQuery{Offset: offset, Limit: limit}
	msg, err := c.request(contract.MsgListBansResponse, timeout, q.Encode)
	if err != nil {
		return contract.ListBansResponse{}, err
	}
	if msg.Bans == nil {
		return contract.ListBansResponse{}, &UnexpectedReplyError{contract.MsgListBansResponse, msg.MsgType}
	}
	return *msg.Bans, nil
}

// ListWhitelistPage 取白名单表一页。
func (c *Client) ListWhitelistPage(offset, limit uint32, timeout time.Duration) (contract.ListWhitelistResponse, error) {
	q := &contract.ListWhitelistQuery{Offset: offset, Limit: limit}
	msg, err := c.request(contract.MsgListWhitelistResponse, timeout, q.Encode)
	if err != nil {
		return contract.ListWhitelistResponse{}, err
	}
	if msg.Wls == nil {
		return contract.ListWhitelistResponse{}, &UnexpectedReplyError{contract.MsgListWhitelistResponse, msg.MsgType}
	}
	return *msg.Wls, nil
}

// ListRatesPage 取速率表一页。
func (c *Client) ListRatesPage(offset, limit uint32, timeout time.Duration) (contract.ListRatesResponse, error) {
	q := &contract.ListRatesQuery{Offset: offset, Limit: limit}
	msg, err := c.request(contract.MsgListRatesResponse, timeout, q.Encode)
	if err != nil {
		return contract.ListRatesResponse{}, err
	}
	if msg.Rates == nil {
		return contract.ListRatesResponse{}, &UnexpectedReplyError{contract.MsgListRatesResponse, msg.MsgType}
	}
	return *msg.Rates, nil
}

// RateSnapshot 是速率表的全量结果，附带最后一页的全局速率。
type RateSnapshot struct {
	GlobalPPS uint64
	GlobalBPS uint64
	Entries   []contract.RateEntry
}

// ListBansAll 取回封禁表全部条目（自动续页）。
func (c *Client) ListBansAll(timeout time.Duration) ([]contract.BanEntry, error) {
	var probe contract.ListBansResponse
	return drain(pageCap(probe.MaxTailEntries()),
		func(offset, limit uint32) (uint32, uint32, []contract.BanEntry, error) {
			page, err := c.ListBansPage(offset, limit, timeout)
			if err != nil {
				return 0, 0, nil, err
			}
			return page.Total, page.Offset, page.Entries, nil
		})
}

// ListWhitelistAll 取回白名单表全部条目（自动续页）。
func (c *Client) ListWhitelistAll(timeout time.Duration) ([]contract.WhitelistEntry, error) {
	var probe contract.ListWhitelistResponse
	return drain(pageCap(probe.MaxTailEntries()),
		func(offset, limit uint32) (uint32, uint32, []contract.WhitelistEntry, error) {
			page, err := c.ListWhitelistPage(offset, limit, timeout)
			if err != nil {
				return 0, 0, nil, err
			}
			return page.Total, page.Offset, page.Entries, nil
		})
}

// ListRatesAll 取回速率表全部条目（自动续页），附带最后一页的全局速率。
//
// 全局 pps/bps 是「自上次查询以来的平均速率」，只取最后一次响应即可。
func (c *Client) ListRatesAll(timeout time.Duration) (RateSnapshot, error) {
	var probe contract.ListRatesResponse
	var globals RateSnapshot
	entries, err := drain(pageCap(probe.MaxTailEntries()),
		func(offset, limit uint32) (uint32, uint32, []contract.RateEntry, error) {
			page, err := c.ListRatesPage(offset, limit, timeout)
			if err != nil {
				return 0, 0, nil, err
			}
			globals.GlobalPPS = page.GlobalPPS
			globals.GlobalBPS = page.GlobalBPS
			return page.Total, page.Offset, page.Entries, nil
		})
	if err != nil {
		return RateSnapshot{}, err
	}
	globals.Entries = entries
	return globals, nil
}

// drain 逐页收集一张表的全部条目。
//
// 结束条件有三个，缺一不可：
//  1. 收到的条目数为 0。内核在 `offset >= total` 时直接回空页，这是唯一可靠的收尾
//     信号（total 是内核读表时另行取的值，与已收集条数不保证一致，故不能拿它当
//     「已收齐」的唯一判据）；
//  2. 本页起点没有推进（防御性：任何情况下都不允许死循环）；
//  3. 已收条数达到已声明的总数（total 为 0 时的正常收尾）。
func drain[T any](
	pageCap uint32,
	page func(offset, limit uint32) (total, pageOffset uint32, entries []T, err error),
) ([]T, error) {
	all := make([]T, 0)
	var offset uint32
	for {
		total, pageOffset, entries, err := page(offset, pageCap)
		if err != nil {
			return nil, err
		}
		got := uint32(len(entries))
		all = append(all, entries...)
		if got == 0 {
			break
		}
		next := pageOffset + got
		if next <= offset {
			break
		}
		offset = next
		if uint64(len(all)) >= uint64(total) {
			break
		}
	}
	return all, nil
}

// pageCap 把契约给出的单页上限转成请求里的 u32 页大小。
//
// 显式请求上限（而不是传 limit=0 让内核取默认页）可以让每页多装条目、少跑几个来回。
func pageCap(maxEntries int) uint32 {
	if maxEntries < 0 {
		return 0
	}
	return uint32(maxEntries)
}

// addrToWire 把 netip.Addr 转成契约的 (af, addr16)。
func addrToWire(addr netip.Addr) (contract.AddrFamily, contract.Addr16, error) {
	var a contract.Addr16
	addr = addr.Unmap()
	if addr.Is4() {
		v4 := addr.As4()
		copy(a[:4], v4[:])
		return contract.AFInet, a, nil
	}
	if addr.Is6() {
		v16 := addr.As16()
		copy(a[:], v16[:])
		return contract.AFInet6, a, nil
	}
	return 0, a, fmt.Errorf("不是有效的单播地址：%s", addr)
}

// popcount8 统计一个字节中置位的个数。
func popcount8(b byte) int {
	n := 0
	for b != 0 {
		n += int(b & 1)
		b >>= 1
	}
	return n
}
