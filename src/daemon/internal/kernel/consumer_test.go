package kernel

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/runtime"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/telemetry"
)

// fakeSampler 是 Sampler 的可控替身：记录调用次数、按需返回预设值或抛错。
type fakeSampler struct {
	mu sync.Mutex

	ack    contract.DaemonRegisterAck
	regErr error

	stats    contract.StatsResponse
	statsErr error
	analysis contract.AnalysisResponse
	rates    RateSnapshot
	ratesErr error
	bans     []contract.BanEntry
	bansErr  error

	calls map[string]int
}

func newFakeSampler() *fakeSampler {
	return &fakeSampler{calls: map[string]int{}}
}

func (f *fakeSampler) count(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
}

func (f *fakeSampler) Calls(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeSampler) Register(time.Duration) (contract.DaemonRegisterAck, error) {
	f.count("register")
	return f.ack, f.regErr
}

func (f *fakeSampler) QueryStats(time.Duration) (contract.StatsResponse, error) {
	f.count("stats")
	return f.stats, f.statsErr
}

func (f *fakeSampler) QueryAnalysis(time.Duration) (contract.AnalysisResponse, error) {
	f.count("analysis")
	return f.analysis, nil
}

func (f *fakeSampler) ListRatesAll(time.Duration) (RateSnapshot, error) {
	f.count("rates")
	return f.rates, f.ratesErr
}

func (f *fakeSampler) ListBansAll(time.Duration) ([]contract.BanEntry, error) {
	f.count("bans")
	return f.bans, f.bansErr
}

// fakePublisher 记录推送过的域名与载荷序列。
type fakePublisher struct {
	mu     sync.Mutex
	domain []string
	data   []any
}

func (p *fakePublisher) Publish(event string, data any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.domain = append(p.domain, event)
	p.data = append(p.data, data)
}

func (p *fakePublisher) domains() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.domain...)
}

// payload 返回第 n 帧（0 起）的载荷，越界时报 nil。
func (p *fakePublisher) payload(i int) any {
	p.mu.Lock()
	defer p.mu.Unlock()
	if i < 0 || i >= len(p.data) {
		return nil
	}
	return p.data[i]
}

// fakeMirror 是 DomainMirror 的替身：给每个域一个可辨认的哨兵值，
// 并记下 Bans/Whitelist 收到的表内容（载荷形状归表现层，本包只测「内容取自哪张表」）。
type fakeMirror struct {
	bansEntries  [][]bans.BanInfo
	wlCIDRs      [][]string
	bansCalls    int
	whitelistCnt int
	statsCalls   int
	ratesCalls   int
}

func (m *fakeMirror) Bans(entries []bans.BanInfo) any {
	m.bansCalls++
	m.bansEntries = append(m.bansEntries, entries)
	return "mirror:bans"
}

func (m *fakeMirror) Whitelist(cidrs []string) any {
	m.whitelistCnt++
	m.wlCIDRs = append(m.wlCIDRs, cidrs)
	return "mirror:whitelist"
}

func (m *fakeMirror) Stats() any {
	m.statsCalls++
	return "mirror:stats"
}

func (m *fakeMirror) Rates() any {
	m.ratesCalls++
	return "mirror:rates"
}

// fakeMetrics 是 kernel.Metrics 的替身。
type fakeMetrics struct {
	mu sync.Mutex
	g  map[string]*fakeCounter
}

type fakeCounter struct {
	mu sync.Mutex
	v  int64
}

func (c *fakeCounter) Add(delta int64) {
	c.mu.Lock()
	c.v += delta
	c.mu.Unlock()
}

func (c *fakeCounter) Value() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.v
}

func newFakeMetrics() *fakeMetrics { return &fakeMetrics{g: map[string]*fakeCounter{}} }

func (m *fakeMetrics) Counter(name string) CounterHandle {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.g[name]
	if !ok {
		c = &fakeCounter{}
		m.g[name] = c
	}
	return c
}

func (m *fakeMetrics) value(name string) int64 {
	m.mu.Lock()
	c, ok := m.g[name]
	m.mu.Unlock()
	if !ok {
		return 0
	}
	return c.Value()
}

// pumpFixture 是一套已装配的泵与其替身。
type pumpFixture struct {
	pump    *EventPump
	sampler *fakeSampler
	pub     *fakePublisher
	mirror  *fakeMirror
	metrics *fakeMetrics
	store   *telemetry.Store
	cache   *bans.ActiveBanCache
	wl      *bans.Whitelist
	events  chan Incoming
	// directives 是反向指令队列：多数测试不读它，容量够大所以投递不会失败。
	directives chan runtime.Directive
}

func newPumpFixture(t *testing.T) *pumpFixture {
	t.Helper()
	f := &pumpFixture{
		sampler: newFakeSampler(),
		pub:     &fakePublisher{},
		mirror:  &fakeMirror{},
		metrics: newFakeMetrics(),
		store:   telemetry.NewStore(),
		cache:   bans.NewActiveBanCache(),
		wl:      bans.NewWhitelist(),
		events:  make(chan Incoming, 16),

		directives: make(chan runtime.Directive, 16),
	}
	f.sampler.ack = contract.DaemonRegisterAck{Accepted: true}
	p, err := NewEventPump(PumpDeps{
		Sampler:           f.sampler,
		Events:            f.events,
		Store:             f.store,
		Ring:              telemetry.NewRing(16),
		Cache:             f.cache,
		Whitelist:         f.wl,
		Publish:           f.pub,
		Mirror:            f.mirror,
		Metrics:           f.metrics,
		Directives:        f.directives,
		SampleEvery:       time.Hour,
		ReconcileEvery:    time.Hour,
		RegisterEvery:     time.Hour,
		ShutdownPollEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("装配事件泵失败: %v", err)
	}
	f.pump = p
	return f
}

// wireAddr 把文本地址换成契约的 (af, addr16)。
func wireAddr(t *testing.T, s string) (contract.AddrFamily, contract.Addr16) {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("解析测试地址 %q: %v", s, err)
	}
	af := contract.AFInet
	if addr.Is6() {
		af = contract.AFInet6
	}
	a, err := contract.Addr16FromIP(af, addr.AsSlice())
	if err != nil {
		t.Fatalf("装入 addr16 %q: %v", s, err)
	}
	return af, a
}

// TestNewEventPumpRequiresCoreDeps 验证必填依赖的校验：缺任一项都必须在装配期失败，
// 而不是等运行时 panic。
func TestNewEventPumpRequiresCoreDeps(t *testing.T) {
	base := PumpDeps{
		Sampler: newFakeSampler(),
		Events:  make(chan Incoming),
		Store:   telemetry.NewStore(),
	}
	if _, err := NewEventPump(base); err != nil {
		t.Fatalf("完整依赖应装配成功: %v", err)
	}
	for name, deps := range map[string]PumpDeps{
		"缺 Sampler": {Events: base.Events, Store: base.Store},
		"缺事件流":      {Sampler: base.Sampler, Store: base.Store},
		"缺快照存储":     {Sampler: base.Sampler, Events: base.Events},
	} {
		if _, err := NewEventPump(deps); err == nil {
			t.Fatalf("%s 时装配应失败", name)
		}
	}
}

// TestRegisterReflectsKernelVerdict 验证「发送成功」与「注册被认可」被区分对待。
//
// 内核在已有活跃守护进程时仍回 ack 但 Accepted=0；此时本进程一切指令都会被丢弃，
// 这个状态必须出现在快照里，否则面板上的数字看起来一切正常。
func TestRegisterReflectsKernelVerdict(t *testing.T) {
	f := newPumpFixture(t)

	f.pump.register("启动")
	if snap := f.store.Snapshot(); !snap.Link.Registered {
		t.Fatal("Accepted 的注册应置起 Registered")
	} else if snap.Link.LastError != "" {
		t.Fatalf("成功注册不该留下失败原文: %q", snap.Link.LastError)
	}

	f.sampler.ack = contract.DaemonRegisterAck{Accepted: false}
	f.pump.register("续约")
	snap := f.store.Snapshot()
	if snap.Link.Registered && snap.Link.LastError == "" {
		t.Fatalf("注册被拒必须可见: %+v", snap.Link)
	}
	if !strings.Contains(snap.Link.LastError, "拒绝") {
		t.Fatalf("失败原文应说明被拒: %q", snap.Link.LastError)
	}

	f.sampler.regErr = errors.New("超时")
	f.pump.register("续约")
	if got := f.store.Snapshot().Link.LastError; !strings.Contains(got, "超时") {
		t.Fatalf("注册报错未记入链路: %q", got)
	}
}

// TestHandleBanUpdatesMirrorAndPublishesOnce 验证封禁事件改写镜像、进事件环，
// 且「内核重发同一事实」不会变成推送风暴。
func TestHandleBanUpdatesMirrorAndPublishesOnce(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.7")
	ev := &contract.BanStateChange{
		Action:       contract.BanActionBan,
		AF:           af,
		PrefixLen:    32,
		DurationSecs: 3600,
		Addr:         addr,
		Reason:       "sshd: 5 次失败",
		JailName:     "sshd",
	}

	f.pump.handle(Incoming{MsgType: contract.MsgBanStateChange, Ban: ev})
	info, ok := f.cache.Get("203.0.113.7")
	if !ok {
		t.Fatal("封禁事件未写入镜像")
	}
	if info.JailName != "sshd" || !strings.Contains(info.Reason, "sshd") {
		t.Fatalf("镜像内容不符: %+v", info)
	}
	if info.IsPermanent {
		t.Fatal("带时长的封禁不该是永久封禁")
	}
	if info.ExpiresAt != info.BannedAt+3600 {
		t.Fatalf("过期时刻 = %d，期望 banned_at+3600(%d)", info.ExpiresAt, info.BannedAt+3600)
	}
	if got := f.pub.domains(); len(got) != 1 || got[0] != DomainBans {
		t.Fatalf("封禁域推送 = %v", got)
	}
	latest := f.pump.Ring().Latest(1)
	if len(latest) != 1 || latest[0].Kind != telemetry.EventBan || latest[0].IP != "203.0.113.7" {
		t.Fatalf("事件环记录不符: %+v", latest)
	}

	// 同一条事实再来一次（内核重发）：镜像没变，就不该再推一次。
	f.pump.handle(Incoming{MsgType: contract.MsgBanStateChange, Ban: ev})
	if got := len(f.pub.domains()); got != 1 {
		t.Fatalf("重复事件推送了 %d 次，期望仍为 1", got)
	}
	if n := f.pump.Ring().Len(); n != 2 {
		t.Fatalf("事件环应有 2 条原始事实，实际 %d", n)
	}

	// 永久封禁（duration 0）不带过期时刻。
	perm := *ev
	perm.DurationSecs = 0
	f.pump.handle(Incoming{MsgType: contract.MsgBanStateChange, Ban: &perm})
	if info, ok := f.cache.Get("203.0.113.7"); !ok || !info.IsPermanent || info.ExpiresAt != 0 {
		t.Fatalf("永久封禁形状不符: %+v ok=%v", info, ok)
	}
}

// TestHandleUnbanRemovesMirror 验证解封事件把条目从镜像摘掉并推送封禁域。
func TestHandleUnbanRemovesMirror(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.8")
	f.pump.handle(Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanActionBan, AF: af, PrefixLen: 32, DurationSecs: 60, Addr: addr, JailName: "sshd",
	}})
	f.pub.mu.Lock()
	f.pub.domain = nil
	f.pub.mu.Unlock()

	f.pump.handle(Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanActionUnban, AF: af, PrefixLen: 32, Addr: addr, JailName: "sshd",
	}})
	if _, ok := f.cache.Get("203.0.113.8"); ok {
		t.Fatal("解封事件后条目仍在镜像里")
	}
	if got := f.pub.domains(); len(got) != 1 || got[0] != DomainBans {
		t.Fatalf("解封未推送封禁域: %v", got)
	}
	if k := f.pump.Ring().Latest(1)[0].Kind; k != telemetry.EventUnban {
		t.Fatalf("事件类别 = %s，期望 unban", k)
	}

	// 内核重复解封：镜像已无变化，不再推送。
	before := len(f.pub.domains())
	f.pump.handle(Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanActionUnban, AF: af, PrefixLen: 32, Addr: addr,
	}})
	if len(f.pub.domains()) != before {
		t.Fatal("重复解封产生了多余推送")
	}
}

// TestHandleWhitelistNormalizesKey 验证白名单事件落到归一键上。
func TestHandleWhitelistNormalizesKey(t *testing.T) {
	f := newPumpFixture(t)
	// 内核已归一化，但事件里的地址仍可能带主机位（procfs 手工写入）。
	af, addr := wireAddr(t, "198.51.100.30")
	f.pump.handle(Incoming{WL: &contract.WhitelistStateChange{
		Action: contract.WhitelistActionAdd, AF: af, PrefixLen: 24, Addr: addr, Device: "eth0",
	}})
	keys := f.wl.List()
	if len(keys) != 1 || keys[0] != "198.51.100.0/24" {
		t.Fatalf("白名单键 = %v，期望归一化为 198.51.100.0/24", keys)
	}
	if got := f.pub.domains(); len(got) != 1 || got[0] != DomainWhitelist {
		t.Fatalf("白名单域推送 = %v", got)
	}

	// 同一子网再来一次（不同主机位写法）：不新增、不推送。
	f.pump.handle(Incoming{WL: &contract.WhitelistStateChange{
		Action: contract.WhitelistActionAdd, AF: af, PrefixLen: 24, Addr: addr, Device: "eth0",
	}})
	if len(f.wl.List()) != 1 || len(f.pub.domains()) != 1 {
		t.Fatalf("重复白名单事件造成新增或多余推送: %v", f.wl.List())
	}

	f.pump.handle(Incoming{WL: &contract.WhitelistStateChange{
		Action: contract.WhitelistActionRemove, AF: af, PrefixLen: 24, Addr: addr,
	}})
	if len(f.wl.List()) != 0 {
		t.Fatalf("移除后仍有 %v", f.wl.List())
	}
}

// TestHandleDdosCountsAndRings 验证 DDoS 事件同时进事件环与 Prometheus 计数。
func TestHandleDdosCountsAndRings(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.9")
	f.pump.handle(Incoming{Ddos: &contract.DdosEvent{
		AF: af, Addr: addr, Reason: "pps 超阈值", RatePPS: 50000,
	}})
	if got := f.metrics.value(CounterDdosEvents); got != 1 {
		t.Fatalf("DDoS 计数 = %d，期望 1", got)
	}
	e := f.pump.Ring().Latest(1)[0]
	if e.Kind != telemetry.EventDdos || e.Value != 50000 || e.IP != "203.0.113.9" {
		t.Fatalf("事件环记录不符: %+v", e)
	}
}

// TestHandleCmdResultRollsBackRejectedBan 验证失败回执是下发路径唯一的真实确认。
//
// Ban/Unban 都是「投递即返回」，内核只在失败时单播 CmdResult。此前失败完全不可见：
// 镜像里留着一条内核拒绝的封禁，面板显示成功，实际一个包都没被丢。
func TestHandleCmdResultRollsBackRejectedBan(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.10")
	// 时刻必须相对真实时钟：待确认标记的时限判断读的是 Unix 秒，用固定历史时刻会让
	// 「仍在等待确认」在测试里恰好已经过期，断言失去意义。
	now := time.Now()
	f.cache.TryInsert(bans.BanInfo{IP: "203.0.113.10", JailName: "sshd", BannedAt: now.Unix()})
	f.cache.MarkPending("203.0.113.10", now)

	f.pump.handle(Incoming{Cmd: &contract.CmdResult{
		OriginalCmd: contract.MsgBanIP, ErrorCode: -22, AF: af, Addr: addr,
	}})

	if f.cache.Len() != 0 {
		t.Fatalf("被拒封禁仍在镜像: %+v", f.cache.All())
	}
	if f.cache.IsPending("203.0.113.10", now.Unix()) {
		t.Fatal("被拒封禁仍挂着待确认标记")
	}
	if got := f.metrics.value(CounterCommandRejected); got != 1 {
		t.Fatalf("指令被拒计数 = %d，期望 1", got)
	}
	if got := f.store.Snapshot().Link.LastError; !strings.Contains(got, "BanIp") {
		t.Fatalf("链路失败原文未含被拒指令: %q", got)
	}
	if got := f.pub.domains(); len(got) != 1 || got[0] != DomainBans {
		t.Fatalf("回滚未推送封禁域: %v", got)
	}
}

// TestHandleUnknownAndBadAddressAreInert 验证非法地址与无载荷事件都不改写镜像。
func TestHandleUnknownAndBadAddressAreInert(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.11")

	f.pump.handle(Incoming{MsgType: contract.MsgBanStateChange})
	f.pump.handle(Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanActionBan, AF: contract.AddrFamily(99), Addr: addr,
	}})
	f.pump.handle(Incoming{WL: &contract.WhitelistStateChange{
		Action: contract.WhitelistAction(77), AF: af, PrefixLen: 32, Addr: addr,
	}})
	f.pump.handle(Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanAction(66), AF: af, PrefixLen: 32, Addr: addr,
	}})
	if f.cache.Len() != 0 || len(f.wl.List()) != 0 || len(f.pub.domains()) != 0 {
		t.Fatalf("非法事件改写了状态: cache=%d wl=%v pub=%v", f.cache.Len(), f.wl.List(), f.pub.domains())
	}
}

// TestSamplePublishesOnlyChangedDomains 验证「只序列化变化域」：安静时段不重复推送。
func TestSamplePublishesOnlyChangedDomains(t *testing.T) {
	f := newPumpFixture(t)
	f.sampler.stats = contract.StatsResponse{CurrentBans: 3, TotalBans: 12}
	f.sampler.rates = RateSnapshot{GlobalPPS: 100, GlobalBPS: 2000}

	f.pump.sample()
	if got := f.pub.domains(); len(got) != 2 {
		t.Fatalf("首轮采样应推送 stats 与 rates 两域，实际 %v", got)
	}
	snap := f.store.Snapshot()
	if snap.Stats.CurrentBans != 3 || snap.Rates.GlobalPPS != 100 || snap.Windows.Samples != 1 {
		t.Fatalf("快照未收录采样值: %+v", snap)
	}

	f.pump.sample()
	if got := len(f.pub.domains()); got != 2 {
		t.Fatalf("未变化的第二轮采样又推送了: %v", f.pub.domains())
	}
	if n := f.store.Snapshot().Windows.Samples; n != 2 {
		t.Fatalf("窗口样本数 = %d，期望每轮采样各喂一个", n)
	}

	f.sampler.stats = contract.StatsResponse{CurrentBans: 4, TotalBans: 12}
	f.pump.sample()
	if got := len(f.pub.domains()); got != 3 {
		t.Fatalf("统计变化后应再推一次: %v", f.pub.domains())
	}
}

// TestPublishDomainTakesPayloadFromMirror 验证帧载荷出自 DomainMirror，
// 而 bans/whitelist 交给镜像的是**本泵自己那张表**的内容（fixture 用的是私有实例，
// 生产装配传的是进程级单例——两条路都只可能读到泵持有的那份）。
//
// 载荷形状归表现层：本包不能出现 StatsResponse 那一类结构体，否则 kernel 反过来依赖
// internal/http 就成环。这里用哨兵字符串把「泵发的就是镜像返回值」这件事钉死。
func TestPublishDomainTakesPayloadFromMirror(t *testing.T) {
	f := newPumpFixture(t)

	af, addr := wireAddr(t, "203.0.113.11")
	f.pump.handle(Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanActionBan, AF: af, PrefixLen: 32, DurationSecs: 600,
		Addr: addr, JailName: "sshd",
	}})
	if got := f.pub.payload(0); got != "mirror:bans" {
		t.Fatalf("bans 帧载荷 = %#v，期望镜像给的那份", got)
	}
	entries := f.mirror.bansEntries[0]
	if len(entries) != 1 || entries[0].IP != "203.0.113.11" {
		t.Fatalf("交给镜像的封禁表内容不符: %+v", entries)
	}

	faf, faddr := wireAddr(t, "198.51.100.30")
	f.pump.handle(Incoming{WL: &contract.WhitelistStateChange{
		Action: contract.WhitelistActionAdd, AF: faf, PrefixLen: 24, Addr: faddr,
	}})
	if got := f.pub.payload(1); got != "mirror:whitelist" {
		t.Fatalf("whitelist 帧载荷 = %#v，期望镜像给的那份", got)
	}
	if keys := f.mirror.wlCIDRs[0]; len(keys) != 1 || keys[0] != "198.51.100.0/24" {
		t.Fatalf("交给镜像的白名单键 = %v", keys)
	}

	f.sampler.stats = contract.StatsResponse{CurrentBans: 3, TotalBans: 12}
	f.sampler.rates = RateSnapshot{GlobalPPS: 100, GlobalBPS: 2000}
	f.pump.sample()
	if got := f.pub.domains(); len(got) != 4 {
		t.Fatalf("采样后推送序列 = %v，期望再加 stats 与 rates", got)
	}
	if f.pub.payload(2) != "mirror:stats" || f.pub.payload(3) != "mirror:rates" {
		t.Fatalf("stats/rates 帧载荷不是镜像给的那份: %#v %#v", f.pub.payload(2), f.pub.payload(3))
	}
}

// TestPublishSkippedWithoutMirror 验证「没有可信载荷就不发帧」：
// 只接了 Publisher 而没接 Mirror 的泵一条都不推，而不是退回内部形状。
//
// 这条判据的意义在于分叉：一帧 stats 带的是内核统计结构时，前端按 StatsResponse 解析
// 得到的是另一套字段，页面上的读数取决于它是从 SSE 还是从 REST 拿的。
func TestPublishSkippedWithoutMirror(t *testing.T) {
	pub := &fakePublisher{}
	cache := bans.NewActiveBanCache()
	p, err := NewEventPump(PumpDeps{
		Sampler:   newFakeSampler(),
		Events:    make(chan Incoming, 1),
		Store:     telemetry.NewStore(),
		Cache:     cache,
		Whitelist: bans.NewWhitelist(),
		Publish:   pub,
	})
	if err != nil {
		t.Fatalf("装配泵失败: %v", err)
	}

	af, addr := wireAddr(t, "203.0.113.12")
	p.handle(Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanActionBan, AF: af, PrefixLen: 32, DurationSecs: 600,
		Addr: addr, JailName: "sshd",
	}})
	if got := pub.domains(); len(got) != 0 {
		t.Fatalf("没有域载荷镜像却推送了 %v", got)
	}
	// 镜像本身仍要落表：不推帧不等于不消费内核事件。
	if _, ok := cache.Get("203.0.113.12"); !ok {
		t.Fatal("封禁事件未写入镜像")
	}
}

// TestSampleToleratesPartialFailure 验证三个查询各自独立成败：速率表超时不拖垮统计快照。
func TestSampleToleratesPartialFailure(t *testing.T) {
	f := newPumpFixture(t)
	f.sampler.stats = contract.StatsResponse{CurrentBans: 1}
	f.sampler.ratesErr = errors.New("速率表查询超时")

	f.pump.sample()
	snap := f.store.Snapshot()
	if snap.Stats.CurrentBans != 1 {
		t.Fatal("速率失败连带统计未发布")
	}
	if snap.Link.SampleFailures != 1 {
		t.Fatalf("采样失败计数 = %d，期望 1", snap.Link.SampleFailures)
	}
	if snap.Link.LastSampleAt.IsZero() {
		t.Fatal("部分成功的轮次也应刷新采样时刻")
	}
}

// TestReconcileMakesKernelAuthoritative 验证对账双向纠正镜像。
func TestReconcileMakesKernelAuthoritative(t *testing.T) {
	f := newPumpFixture(t)
	now := time.Now()

	// 镜像里有三种条目：内核也有（内容需被纠正）、内核没有的幽灵、等待确认的新下发。
	ghost := bans.BanInfo{IP: "203.0.113.20", JailName: "sshd", BannedAt: now.Unix(), ExpiresAt: now.Unix() + 600}
	pending := bans.BanInfo{IP: "203.0.113.21", JailName: "sshd", BannedAt: now.Unix(), ExpiresAt: now.Unix() + 600}
	stale := bans.BanInfo{IP: "203.0.113.22", JailName: "sshd", BannedAt: now.Unix()}
	f.cache.TryInsert(ghost)
	f.cache.TryInsert(pending)
	f.cache.TryInsert(stale)
	f.cache.MarkPending(pending.IP, now)

	af, addr := wireAddr(t, "203.0.113.22")
	f.sampler.bans = []contract.BanEntry{{
		AF: af, IsPermanent: false, PrefixLen: 32, DurationSecs: 7200,
		BannedAt: uint64(now.Unix() - 100), Addr: addr, JailName: "recidive", Reason: "累犯升级",
	}}

	f.pump.reconcile()

	if f.cache.Len() != 2 {
		t.Fatalf("对账后镜像 %d 条: %+v", f.cache.Len(), f.cache.All())
	}
	if _, ok := f.cache.Get(ghost.IP); ok {
		t.Fatal("内核没有的幽灵条目未被摘除")
	}
	if _, ok := f.cache.Get(pending.IP); !ok {
		t.Fatal("等待确认的条目被对账抹掉了")
	}
	fixed, ok := f.cache.Get(stale.IP)
	if !ok || fixed.JailName != "recidive" || fixed.BannedAt != now.Unix()-100 ||
		fixed.ExpiresAt != now.Unix()-100+7200 {
		t.Fatalf("内核事实未覆盖镜像: %+v ok=%v", fixed, ok)
	}
	if got := f.pub.domains(); len(got) != 1 || got[0] != DomainBans {
		t.Fatalf("对账修正未推送封禁域: %v", got)
	}
	if f.store.Snapshot().Link.LastReconcileAt.IsZero() {
		t.Fatal("对账成功未刷新时刻")
	}
}

// TestReconcileSweepsExpiredAndSurvivesFailure 验证过期兜底与对账失败的可见性。
func TestReconcileSweepsExpiredAndSurvivesFailure(t *testing.T) {
	f := newPumpFixture(t)
	now := time.Now()
	expired := bans.BanInfo{IP: "203.0.113.23", JailName: "sshd", BannedAt: now.Unix() - 7200, ExpiresAt: now.Unix() - 60}
	f.cache.TryInsert(expired)

	f.pump.reconcile()
	if _, ok := f.cache.Get(expired.IP); ok {
		t.Fatal("已过期条目未被清扫")
	}

	f.sampler.bansErr = errors.New("链路超时")
	before := f.store.Snapshot().Link.ReconcileFailures
	f.pump.reconcile()
	snap := f.store.Snapshot()
	if snap.Link.ReconcileFailures != before+1 {
		t.Fatalf("对账失败计数未推进: %d -> %d", before, snap.Link.ReconcileFailures)
	}
	if snap.Link.LastReconcileAt.Equal(snap.Link.LastSampleAt) && !snap.Link.LastReconcileAt.IsZero() {
		t.Fatal("失败的对账不该刷新成功时刻")
	}
}

// TestReconcileAddsKernelOnlyEntry 验证 procfs 手工封禁经对账进入镜像。
func TestReconcileAddsKernelOnlyEntry(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.24")
	f.sampler.bans = []contract.BanEntry{{
		AF: af, IsPermanent: true, PrefixLen: 32, Addr: addr, JailName: "", Reason: "手工封禁",
	}}

	f.pump.reconcile()
	info, ok := f.cache.Get("203.0.113.24")
	if !ok {
		t.Fatal("内核独有的条目没有补进镜像")
	}
	if !info.IsPermanent || info.ExpiresAt != 0 {
		t.Fatalf("永久封禁形状不符: %+v", info)
	}
}

// TestRunConsumesEventsAndStopsOnShutdown 验证泵真的在消费事件流，并在关停请求后退出。
//
// 关停只有标志位而没有可 select 的通道，因此泵必须周期性醒来确认；这一条同时钉住
// 「不会等到下一个采样周期才被发现关停」。
func TestRunConsumesEventsAndStopsOnShutdown(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.25")
	f.pump.shutdownPoll = 5 * time.Millisecond
	f.pump.sampleEvery = 20 * time.Millisecond
	f.pump.reconcileEvery = 20 * time.Millisecond
	f.pump.registerEvery = 20 * time.Millisecond

	f.events <- Incoming{Ban: &contract.BanStateChange{
		Action: contract.BanActionBan, AF: af, PrefixLen: 32, DurationSecs: 60, Addr: addr, JailName: "sshd",
	}}

	stop := runtime.NewShutdown()
	done := make(chan struct{})
	go func() {
		f.pump.Run(stop)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		if _, ok := f.cache.Get("203.0.113.25"); ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("泵未在超时内消费事件")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if n := f.sampler.Calls("register"); n < 1 {
		t.Fatalf("泵未注册守护进程（调用 %d 次）", n)
	}

	stop.Request()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("关停请求后泵未退出")
	}
}

// TestRunExitsWithNoEvents 验证空事件流下泵也能按节拍退出（不依赖事件到达）。
func TestRunExitsWithNoEvents(t *testing.T) {
	f := newPumpFixture(t)
	f.pump.shutdownPoll = 2 * time.Millisecond
	f.pump.sampleEvery = time.Hour
	f.pump.reconcileEvery = time.Hour
	f.pump.registerEvery = time.Hour

	stop := runtime.NewShutdown()
	done := make(chan struct{})
	go func() {
		f.pump.Run(stop)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	stop.Request()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("空闲状态下泵未在关停请求后退出")
	}
}

// TestPrefixFromAddrRejectsOverlongLength 验证越界前缀长度退回完整前缀而不是当成有效掩码。
func TestPrefixFromAddrRejectsOverlongLength(t *testing.T) {
	v4 := netip.MustParseAddr("203.0.113.30")
	if got := prefixFromAddr(v4, 33); got.Bits() != 32 {
		t.Fatalf("IPv4 长度 33 未被夹回: %v", got)
	}
	if got := prefixFromAddr(v4, 24); got.Bits() != 24 {
		t.Fatalf("合法长度被改写: %v", got)
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	if got := prefixFromAddr(v6, 200); got.Bits() != 128 {
		t.Fatalf("IPv6 越界长度未被夹回: %v", got)
	}
}

// TestAddrFromWireRoundTrip 验证 (af, addr16) 还原与 client 侧装入互逆。
func TestAddrFromWireRoundTrip(t *testing.T) {
	for _, s := range []string{"203.0.113.31", "2001:db8::ff"} {
		af, a := wireAddr(t, s)
		got, err := addrFromWire(af, a)
		if err != nil {
			t.Fatalf("%s 还原失败: %v", s, err)
		}
		if got.String() != s {
			t.Fatalf("还原结果 = %s，期望 %s", got, s)
		}
	}
	if _, err := addrFromWire(contract.AddrFamily(99), contract.Addr16{}); err == nil {
		t.Fatal("未定义地址族应报错")
	}
}

// TestRatesConversionCarriesAllFields 验证 kernel → telemetry 的同构转换不丢字段。
func TestRatesConversionCarriesAllFields(t *testing.T) {
	_, addr := wireAddr(t, "203.0.113.32")
	s := RateSnapshot{
		GlobalPPS: 10,
		GlobalBPS: 20,
		Entries:   []contract.RateEntry{{Addr: addr, Packets: 5}},
	}
	out := Rates(s)
	if out.GlobalPPS != 10 || out.GlobalBPS != 20 || len(out.Entries) != 1 || out.Entries[0].Packets != 5 {
		t.Fatalf("转换丢字段: %+v", out)
	}
}

// TestRouterCountersReachSnapshot 验证接收侧计数经泵并入快照，且链路断开被如实上报。
func TestRouterCountersReachSnapshot(t *testing.T) {
	events := make(chan Incoming, 4)
	router := NewRouter(events)
	f := newPumpFixture(t)
	f.pump.router = router

	router.HandleDatagram(Datagram{PortID: 7, Payload: []byte("ignored")})
	f.pump.syncRouterCounters()
	if got := f.store.Snapshot().Link.ForeignPortIDs; got != 1 {
		t.Fatalf("外部 portid 计数未并入: %d", got)
	}

	router.Close()
	f.pump.syncRouterCounters()
	if !f.store.Snapshot().Link.LinkDown {
		t.Fatal("Router.Close 后快照仍显示链路正常")
	}
}

// CONFIG_CHANGE 必须转成反向指令：配置的执行体副本由入站执行体独占，泵既改不到也不该改，
// 否则同一条 ban_time 会一边被采纳一边被重载路径覆盖。
func TestConfigChangeBecomesDirective(t *testing.T) {
	f := newPumpFixture(t)
	f.pump.handle(Incoming{CfgChg: &contract.ConfigChange{ConfigPayload: contract.ConfigPayload{
		Flags: contract.ConfigFlagBanTime, BanTime: 123,
	}}})

	select {
	case d := <-f.directives:
		if d.Kind != runtime.DirectiveKernelConfigChanged {
			t.Fatalf("指令类型 = %d，期望 KernelConfigChanged", d.Kind)
		}
		if d.ConfigFlags != uint32(contract.ConfigFlagBanTime) || d.BanTimeSecs != 123 {
			t.Fatalf("指令载荷不符: %+v", d)
		}
	default:
		t.Fatal("CONFIG_CHANGE 没有转成反向指令")
	}
}

// 封禁被内核拒绝时，除了回滚镜像还要给执行体一条抑制指令：条目一消失，该 IP 的下一条
// 失败日志就能重新占位并再发一次指令，内核表满时会变成每行日志一个 netlink 往返。
func TestRejectedBanAlsoEmitsDirective(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.60")

	f.pump.handle(Incoming{Cmd: &contract.CmdResult{
		OriginalCmd: contract.MsgBanIP, ErrorCode: -28, AF: af, Addr: addr,
	}})

	select {
	case d := <-f.directives:
		if d.Kind != runtime.DirectiveCommandRejected || d.IP != "203.0.113.60" {
			t.Fatalf("抑制指令不符: %+v", d)
		}
		if d.Cmd != "BanIp" || d.Errno != -28 {
			t.Fatalf("指令未带上被拒的指令名与错误码: %+v", d)
		}
	default:
		t.Fatal("封禁被拒未产生反向指令")
	}
}

// 解封与白名单的失败回执不产生指令：这两类下发都不是入站主链路发起的，投递给执行体只会
// 把无处落地的东西塞进抑制表。
func TestNonBanRejectionEmitsNoDirective(t *testing.T) {
	f := newPumpFixture(t)
	af, addr := wireAddr(t, "203.0.113.61")

	for _, cmd := range []contract.MsgType{contract.MsgUnbanIP, contract.MsgAddWhitelist} {
		f.pump.handle(Incoming{Cmd: &contract.CmdResult{OriginalCmd: cmd, ErrorCode: -22, AF: af, Addr: addr}})
	}
	if n := len(f.directives); n != 0 {
		t.Fatalf("非封禁回执产生了 %d 条指令", n)
	}
}

// 队列满时必须丢弃而不是阻塞：事件流一堵，封禁与白名单的状态变更就再也进不来了。
func TestEmitDropsWhenDirectiveQueueFull(t *testing.T) {
	f := newPumpFixture(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 3*cap(f.directives); i++ {
			f.pump.handle(Incoming{CfgChg: &contract.ConfigChange{ConfigPayload: contract.ConfigPayload{
				Flags: contract.ConfigFlagBanTime, BanTime: uint32(i + 1),
			}}})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("指令队列已满时泵被钉住（应丢弃而非等待）")
	}
	if n := len(f.directives); n != cap(f.directives) {
		t.Fatalf("队列长度 = %d，期望恰好装满 %d", n, cap(f.directives))
	}
}

// 未接指令队列（单元测试或内核链路缺失的降级装配）时，两类事件仍要照常处理，不能 panic。
func TestHandleWithoutDirectiveChannelIsSafe(t *testing.T) {
	af, addr := wireAddr(t, "203.0.113.62")
	p, err := NewEventPump(PumpDeps{
		Sampler:   newFakeSampler(),
		Events:    make(chan Incoming, 1),
		Store:     telemetry.NewStore(),
		Cache:     bans.NewActiveBanCache(),
		Whitelist: bans.NewWhitelist(),
	})
	if err != nil {
		t.Fatalf("装配事件泵失败: %v", err)
	}
	p.handle(Incoming{CfgChg: &contract.ConfigChange{ConfigPayload: contract.ConfigPayload{
		Flags: contract.ConfigFlagBanTime, BanTime: 60,
	}}})
	p.handle(Incoming{Cmd: &contract.CmdResult{
		OriginalCmd: contract.MsgBanIP, ErrorCode: -28, AF: af, Addr: addr,
	}})
}
