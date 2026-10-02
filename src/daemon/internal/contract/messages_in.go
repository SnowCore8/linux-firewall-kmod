package contract

import "fmt"

// 本文件：内核 → daemon 方向的消息与其尾部元素结构。
// 偏移表既供编解码使用，也供 contract_test.go 与 netlink_layout.json 比对。

var offDdosEvent = map[string]int{
	"af": 12, "reason": 13, "rate_pps": 45, "addr": 49,
}

// DdosEvent DDoS 违规事件（内核 → daemon，命中速率或协议阈值时推送）。
type DdosEvent struct {
	AF      AddrFamily
	Reason  string
	RatePPS uint32
	Addr    Addr16
}

// Decode 解析 DdosEvent 报文。
func (m *DdosEvent) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgDdosEvent {
		return fmt.Errorf("期望 DdosEvent(%d)，实际 %d", MsgDdosEvent, h.MsgType)
	}
	if len(b) != wireLayouts["DdosEvent"].size {
		return fmt.Errorf("DdosEvent 长度 %d 应为 %d", len(b), wireLayouts["DdosEvent"].size)
	}
	o := offDdosEvent
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.Reason = getStr(b, o["reason"], 32)
	m.RatePPS = getU32(b, o["rate_pps"])
	m.Addr = getAddr16(b, o["addr"])
	return nil
}

// Encode 编码 DdosEvent 报文。
func (m *DdosEvent) Encode(seq uint32) ([]byte, error) {
	o := offDdosEvent
	b := make([]byte, wireLayouts["DdosEvent"].size)
	if err := putStr(b, o["reason"], 32, m.Reason); err != nil {
		return nil, err
	}
	putU8(b, o["af"], uint8(m.AF))
	putU32(b, o["rate_pps"], m.RatePPS)
	putAddr16(b, o["addr"], m.Addr)
	encodeHeader(b, MsgDdosEvent, seq)
	return b, nil
}

var offBanStateChange = map[string]int{
	"action": 12, "af": 13, "prefix_len": 14, "duration_secs": 15, "addr": 19,
	"reason": 35, "jail_name": 67, "packets_dropped": 99, "packets_accepted": 107,
	"current_bans": 115, "whitelist_count": 119,
}

// BanStateChange 封禁状态变更（procfs 手动操作或内核自动封禁时推送）。
type BanStateChange struct {
	Action          BanAction
	AF              AddrFamily
	PrefixLen       uint8
	DurationSecs    uint32
	Addr            Addr16
	Reason          string
	JailName        string
	PacketsDropped  uint64
	PacketsAccepted uint64
	CurrentBans     uint32
	WhitelistCount  uint32
}

// IsPermanent 报告该事件是否表示永久封禁（duration_secs == 0 为永久）。
func (m *BanStateChange) IsPermanent() bool { return m.DurationSecs == 0 }

// Decode 解析 BanStateChange 报文。
func (m *BanStateChange) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgBanStateChange {
		return fmt.Errorf("期望 BanStateChange(%d)，实际 %d", MsgBanStateChange, h.MsgType)
	}
	size := wireLayouts["BanStateChange"].size
	if len(b) != size {
		return fmt.Errorf("BanStateChange 长度 %d 应为 %d", len(b), size)
	}
	o := offBanStateChange
	m.Action = BanAction(getU8(b, o["action"]))
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.PrefixLen = getU8(b, o["prefix_len"])
	m.DurationSecs = getU32(b, o["duration_secs"])
	m.Addr = getAddr16(b, o["addr"])
	m.Reason = getStr(b, o["reason"], 32)
	m.JailName = getStr(b, o["jail_name"], 32)
	m.PacketsDropped = getU64(b, o["packets_dropped"])
	m.PacketsAccepted = getU64(b, o["packets_accepted"])
	m.CurrentBans = getU32(b, o["current_bans"])
	m.WhitelistCount = getU32(b, o["whitelist_count"])
	return nil
}

// Encode 编码 BanStateChange 报文。
func (m *BanStateChange) Encode(seq uint32) ([]byte, error) {
	o := offBanStateChange
	b := make([]byte, wireLayouts["BanStateChange"].size)
	if err := putStr(b, o["reason"], 32, m.Reason); err != nil {
		return nil, err
	}
	if err := putStr(b, o["jail_name"], 32, m.JailName); err != nil {
		return nil, err
	}
	putU8(b, o["action"], uint8(m.Action))
	putU8(b, o["af"], uint8(m.AF))
	putU8(b, o["prefix_len"], m.PrefixLen)
	putU32(b, o["duration_secs"], m.DurationSecs)
	putAddr16(b, o["addr"], m.Addr)
	putU64(b, o["packets_dropped"], m.PacketsDropped)
	putU64(b, o["packets_accepted"], m.PacketsAccepted)
	putU32(b, o["current_bans"], m.CurrentBans)
	putU32(b, o["whitelist_count"], m.WhitelistCount)
	encodeHeader(b, MsgBanStateChange, seq)
	return b, nil
}

var offWhitelistStateChange = map[string]int{
	"action": 12, "af": 13, "prefix_len": 14, "addr": 15,
	"device": 31, "whitelist_count": 47,
}

// WhitelistStateChange 白名单状态变更。
type WhitelistStateChange struct {
	Action         WhitelistAction
	AF             AddrFamily
	PrefixLen      uint8
	Addr           Addr16
	Device         string
	WhitelistCount uint32
}

// Decode 解析 WhitelistStateChange 报文。
func (m *WhitelistStateChange) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgWhitelistStateChange {
		return fmt.Errorf("期望 WhitelistStateChange(%d)，实际 %d", MsgWhitelistStateChange, h.MsgType)
	}
	size := wireLayouts["WhitelistStateChange"].size
	if len(b) != size {
		return fmt.Errorf("WhitelistStateChange 长度 %d 应为 %d", len(b), size)
	}
	o := offWhitelistStateChange
	m.Action = WhitelistAction(getU8(b, o["action"]))
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.PrefixLen = getU8(b, o["prefix_len"])
	m.Addr = getAddr16(b, o["addr"])
	m.Device = getStr(b, o["device"], 16)
	m.WhitelistCount = getU32(b, o["whitelist_count"])
	return nil
}

// Encode 编码 WhitelistStateChange 报文。
func (m *WhitelistStateChange) Encode(seq uint32) ([]byte, error) {
	o := offWhitelistStateChange
	b := make([]byte, wireLayouts["WhitelistStateChange"].size)
	if err := putStr(b, o["device"], 16, m.Device); err != nil {
		return nil, err
	}
	putU8(b, o["action"], uint8(m.Action))
	putU8(b, o["af"], uint8(m.AF))
	putU8(b, o["prefix_len"], m.PrefixLen)
	putAddr16(b, o["addr"], m.Addr)
	putU32(b, o["whitelist_count"], m.WhitelistCount)
	encodeHeader(b, MsgWhitelistStateChange, seq)
	return b, nil
}

var offCmdResult = map[string]int{
	"original_cmd": 12, "pad": 14, "error_code": 16, "af": 20, "addr": 21,
}

// CmdResult 命令执行失败通知（仅失败时推送）。
type CmdResult struct {
	OriginalCmd MsgType
	ErrorCode   int32
	AF          AddrFamily
	Addr        Addr16
}

// Decode 解析 CmdResult 报文。
func (m *CmdResult) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgCmdResult {
		return fmt.Errorf("期望 CmdResult(%d)，实际 %d", MsgCmdResult, h.MsgType)
	}
	size := wireLayouts["CmdResult"].size
	if len(b) != size {
		return fmt.Errorf("CmdResult 长度 %d 应为 %d", len(b), size)
	}
	o := offCmdResult
	m.OriginalCmd = MsgType(getU16(b, o["original_cmd"]))
	m.ErrorCode = getI32(b, o["error_code"])
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.Addr = getAddr16(b, o["addr"])
	return nil
}

// Encode 编码 CmdResult 报文。
func (m *CmdResult) Encode(seq uint32) ([]byte, error) {
	o := offCmdResult
	b := make([]byte, wireLayouts["CmdResult"].size)
	putU16(b, o["original_cmd"], uint16(m.OriginalCmd))
	putU16(b, o["pad"], 0)
	putI32(b, o["error_code"], m.ErrorCode)
	putU8(b, o["af"], uint8(m.AF))
	putAddr16(b, o["addr"], m.Addr)
	encodeHeader(b, MsgCmdResult, seq)
	return b, nil
}

var offConfigAck = map[string]int{"applied_flags": 12, "rejected_flags": 16}

// ConfigAck 配置更新确认：applied_flags 为已生效位、rejected_flags 为被拒位。
type ConfigAck struct {
	AppliedFlags  ConfigFlags
	RejectedFlags ConfigFlags
}

// Decode 解析 ConfigAck 报文。
func (m *ConfigAck) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgConfigAck {
		return fmt.Errorf("期望 ConfigAck(%d)，实际 %d", MsgConfigAck, h.MsgType)
	}
	size := wireLayouts["ConfigAck"].size
	if len(b) != size {
		return fmt.Errorf("ConfigAck 长度 %d 应为 %d", len(b), size)
	}
	o := offConfigAck
	m.AppliedFlags = ConfigFlags(getU32(b, o["applied_flags"]))
	m.RejectedFlags = ConfigFlags(getU32(b, o["rejected_flags"]))
	return nil
}

// Encode 编码 ConfigAck 报文。
func (m *ConfigAck) Encode(seq uint32) ([]byte, error) {
	o := offConfigAck
	b := make([]byte, wireLayouts["ConfigAck"].size)
	putU32(b, o["applied_flags"], uint32(m.AppliedFlags))
	putU32(b, o["rejected_flags"], uint32(m.RejectedFlags))
	encodeHeader(b, MsgConfigAck, seq)
	return b, nil
}

// offConfigChange 同时用于 ConfigChange 与 SetConfig：契约声明二者载荷布局一致。
var offConfigChange = map[string]int{
	"flags": 12, "ban_time": 16, "rate_window_seconds": 20,
	"max_packets_per_second": 24, "max_bytes_per_second": 32,
	"max_syn_per_second": 40, "max_udp_per_second": 48, "max_icmp_per_second": 56,
	"max_ack_per_second": 64, "max_rst_per_second": 72, "max_fin_per_second": 80,
	"dynamic_threshold_flags": 88, "dynamic_threshold_ratio_x100": 92,
	"baseline_pps": 96, "baseline_bps": 104, "ddos_ban_duration": 112,
}

// ConfigPayload 是 SetConfig 与 ConfigChange 共用的载荷（契约：布局一致）。
type ConfigPayload struct {
	Flags                     ConfigFlags
	BanTime                   uint32
	RateWindowSeconds         uint32
	MaxPacketsPerSecond       uint64
	MaxBytesPerSecond         uint64
	MaxSynPerSecond           uint64
	MaxUDPPerSecond           uint64
	MaxICMPPerSecond          uint64
	MaxACKPerSecond           uint64
	MaxRSTPerSecond           uint64
	MaxFINPerSecond           uint64
	DynamicThresholdFlags     uint32
	DynamicThresholdRatioX100 uint32
	BaselinePPS               uint64
	BaselineBPS               uint64
	DdosBanDuration           uint32
}

// encodeConfigPayload 把 ConfigPayload 写入 b（b 已含头，长度须为 116）。
func encodeConfigPayload(b []byte, p *ConfigPayload) {
	o := offConfigChange
	putU32(b, o["flags"], uint32(p.Flags))
	putU32(b, o["ban_time"], p.BanTime)
	putU32(b, o["rate_window_seconds"], p.RateWindowSeconds)
	putU64(b, o["max_packets_per_second"], p.MaxPacketsPerSecond)
	putU64(b, o["max_bytes_per_second"], p.MaxBytesPerSecond)
	putU64(b, o["max_syn_per_second"], p.MaxSynPerSecond)
	putU64(b, o["max_udp_per_second"], p.MaxUDPPerSecond)
	putU64(b, o["max_icmp_per_second"], p.MaxICMPPerSecond)
	putU64(b, o["max_ack_per_second"], p.MaxACKPerSecond)
	putU64(b, o["max_rst_per_second"], p.MaxRSTPerSecond)
	putU64(b, o["max_fin_per_second"], p.MaxFINPerSecond)
	putU32(b, o["dynamic_threshold_flags"], p.DynamicThresholdFlags)
	putU32(b, o["dynamic_threshold_ratio_x100"], p.DynamicThresholdRatioX100)
	putU64(b, o["baseline_pps"], p.BaselinePPS)
	putU64(b, o["baseline_bps"], p.BaselineBPS)
	putU32(b, o["ddos_ban_duration"], p.DdosBanDuration)
}

// decodeConfigPayload 从 b 读出 ConfigPayload。
func decodeConfigPayload(b []byte) ConfigPayload {
	o := offConfigChange
	return ConfigPayload{
		Flags:                     ConfigFlags(getU32(b, o["flags"])),
		BanTime:                   getU32(b, o["ban_time"]),
		RateWindowSeconds:         getU32(b, o["rate_window_seconds"]),
		MaxPacketsPerSecond:       getU64(b, o["max_packets_per_second"]),
		MaxBytesPerSecond:         getU64(b, o["max_bytes_per_second"]),
		MaxSynPerSecond:           getU64(b, o["max_syn_per_second"]),
		MaxUDPPerSecond:           getU64(b, o["max_udp_per_second"]),
		MaxICMPPerSecond:          getU64(b, o["max_icmp_per_second"]),
		MaxACKPerSecond:           getU64(b, o["max_ack_per_second"]),
		MaxRSTPerSecond:           getU64(b, o["max_rst_per_second"]),
		MaxFINPerSecond:           getU64(b, o["max_fin_per_second"]),
		DynamicThresholdFlags:     getU32(b, o["dynamic_threshold_flags"]),
		DynamicThresholdRatioX100: getU32(b, o["dynamic_threshold_ratio_x100"]),
		BaselinePPS:               getU64(b, o["baseline_pps"]),
		BaselineBPS:               getU64(b, o["baseline_bps"]),
		DdosBanDuration:           getU32(b, o["ddos_ban_duration"]),
	}
}

var offBanEntry = map[string]int{
	"af": 0, "is_permanent": 1, "prefix_len": 2, "duration_secs": 3,
	"banned_at": 7, "addr": 15, "jail_name": 31, "reason": 63,
}

// BanEntry 封禁条目（ListBansResponse 的尾部元素，偏移相对条目起点）。
type BanEntry struct {
	AF           AddrFamily
	IsPermanent  bool
	PrefixLen    uint8
	DurationSecs uint32
	BannedAt     uint64
	Addr         Addr16
	JailName     string
	Reason       string
}

func (e *BanEntry) decodeAt(b []byte, base int) {
	o := offBanEntry
	e.AF = AddrFamily(getU8(b, base+o["af"]))
	e.IsPermanent = getU8(b, base+o["is_permanent"]) != 0
	e.PrefixLen = getU8(b, base+o["prefix_len"])
	e.DurationSecs = getU32(b, base+o["duration_secs"])
	e.BannedAt = getU64(b, base+o["banned_at"])
	e.Addr = getAddr16(b, base+o["addr"])
	e.JailName = getStr(b, base+o["jail_name"], 32)
	e.Reason = getStr(b, base+o["reason"], 32)
}

func (e *BanEntry) encodeAt(b []byte, base int) error {
	o := offBanEntry
	if err := putStr(b, base+o["jail_name"], 32, e.JailName); err != nil {
		return err
	}
	if err := putStr(b, base+o["reason"], 32, e.Reason); err != nil {
		return err
	}
	putU8(b, base+o["af"], uint8(e.AF))
	if e.IsPermanent {
		putU8(b, base+o["is_permanent"], 1)
	}
	putU8(b, base+o["prefix_len"], e.PrefixLen)
	putU32(b, base+o["duration_secs"], e.DurationSecs)
	putU64(b, base+o["banned_at"], e.BannedAt)
	putAddr16(b, base+o["addr"], e.Addr)
	return nil
}

var offListBansResponse = map[string]int{"count": 12, "total": 16, "offset": 20}

// ListBansResponse 封禁列表响应（分页）。
type ListBansResponse struct {
	Count   uint32
	Total   uint32
	Offset  uint32
	Entries []BanEntry
}

// MaxTailEntries 返回 u16 长度上限内可承载的最大尾部条目数。
func (m *ListBansResponse) MaxTailEntries() int {
	t := tailElems["ListBansResponse"]
	return (MsgLenMax - wireLayouts["ListBansResponse"].size) / t.elemSize
}

// Decode 解析 ListBansResponse 报文。
func (m *ListBansResponse) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgListBansResponse {
		return fmt.Errorf("期望 ListBansResponse(%d)，实际 %d", MsgListBansResponse, h.MsgType)
	}
	fixed := wireLayouts["ListBansResponse"].size
	elem := wireLayouts["BanEntry"].size
	if len(b) < fixed {
		return fmt.Errorf("ListBansResponse 长度 %d 短于定长部分 %d", len(b), fixed)
	}
	o := offListBansResponse
	m.Count = getU32(b, o["count"])
	m.Total = getU32(b, o["total"])
	m.Offset = getU32(b, o["offset"])
	rest := len(b) - fixed
	if rest%elem != 0 {
		return fmt.Errorf("ListBansResponse 尾部 %d 字节不是 %d 的整数倍", rest, elem)
	}
	n := rest / elem
	if uint32(n) != m.Count {
		return fmt.Errorf("ListBansResponse count=%d 与尾部实际条目数 %d 不符", m.Count, n)
	}
	m.Entries = make([]BanEntry, n)
	for i := 0; i < n; i++ {
		m.Entries[i].decodeAt(b, fixed+i*elem)
	}
	return nil
}

// Encode 编码 ListBansResponse 报文。
func (m *ListBansResponse) Encode(seq uint32) ([]byte, error) {
	fixed := wireLayouts["ListBansResponse"].size
	elem := wireLayouts["BanEntry"].size
	if len(m.Entries) > m.MaxTailEntries() {
		return nil, fmt.Errorf("封禁条目 %d 条超出单页上限 %d", len(m.Entries), m.MaxTailEntries())
	}
	b := make([]byte, fixed+len(m.Entries)*elem)
	o := offListBansResponse
	m.Count = uint32(len(m.Entries))
	putU32(b, o["count"], m.Count)
	putU32(b, o["total"], m.Total)
	putU32(b, o["offset"], m.Offset)
	for i := range m.Entries {
		if err := m.Entries[i].encodeAt(b, fixed+i*elem); err != nil {
			return nil, err
		}
	}
	encodeHeader(b, MsgListBansResponse, seq)
	return b, nil
}

var offStatsResponse = map[string]int{
	"current_bans": 12, "total_bans": 20, "total_unbans": 28,
	"whitelist_count": 36, "packets_dropped": 44, "packets_accepted": 52,
}

// StatsResponse 统计响应（定长）。
type StatsResponse struct {
	CurrentBans     uint64
	TotalBans       uint64
	TotalUnbans     uint64
	WhitelistCount  uint64
	PacketsDropped  uint64
	PacketsAccepted uint64
}

// Decode 解析 StatsResponse 报文。
func (m *StatsResponse) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgStatsResponse {
		return fmt.Errorf("期望 StatsResponse(%d)，实际 %d", MsgStatsResponse, h.MsgType)
	}
	size := wireLayouts["StatsResponse"].size
	if len(b) != size {
		return fmt.Errorf("StatsResponse 长度 %d 应为 %d", len(b), size)
	}
	o := offStatsResponse
	m.CurrentBans = getU64(b, o["current_bans"])
	m.TotalBans = getU64(b, o["total_bans"])
	m.TotalUnbans = getU64(b, o["total_unbans"])
	m.WhitelistCount = getU64(b, o["whitelist_count"])
	m.PacketsDropped = getU64(b, o["packets_dropped"])
	m.PacketsAccepted = getU64(b, o["packets_accepted"])
	return nil
}

// Encode 编码 StatsResponse 报文。
func (m *StatsResponse) Encode(seq uint32) ([]byte, error) {
	o := offStatsResponse
	b := make([]byte, wireLayouts["StatsResponse"].size)
	putU64(b, o["current_bans"], m.CurrentBans)
	putU64(b, o["total_bans"], m.TotalBans)
	putU64(b, o["total_unbans"], m.TotalUnbans)
	putU64(b, o["whitelist_count"], m.WhitelistCount)
	putU64(b, o["packets_dropped"], m.PacketsDropped)
	putU64(b, o["packets_accepted"], m.PacketsAccepted)
	encodeHeader(b, MsgStatsResponse, seq)
	return b, nil
}

var offWhitelistEntry = map[string]int{"af": 0, "prefix_len": 1, "addr": 2, "device": 18}

// WhitelistEntry 白名单条目（ListWhitelistResponse 的尾部元素，偏移相对条目起点）。
type WhitelistEntry struct {
	AF        AddrFamily
	PrefixLen uint8
	Addr      Addr16
	Device    string
}

func (e *WhitelistEntry) decodeAt(b []byte, base int) {
	o := offWhitelistEntry
	e.AF = AddrFamily(getU8(b, base+o["af"]))
	e.PrefixLen = getU8(b, base+o["prefix_len"])
	e.Addr = getAddr16(b, base+o["addr"])
	e.Device = getStr(b, base+o["device"], 16)
}

func (e *WhitelistEntry) encodeAt(b []byte, base int) error {
	o := offWhitelistEntry
	if err := putStr(b, base+o["device"], 16, e.Device); err != nil {
		return err
	}
	putU8(b, base+o["af"], uint8(e.AF))
	putU8(b, base+o["prefix_len"], e.PrefixLen)
	putAddr16(b, base+o["addr"], e.Addr)
	return nil
}

var offListWhitelistResponse = map[string]int{"count": 12, "total": 16, "offset": 20}

// ListWhitelistResponse 白名单列表响应（分页）。
type ListWhitelistResponse struct {
	Count   uint32
	Total   uint32
	Offset  uint32
	Entries []WhitelistEntry
}

// MaxTailEntries 返回 u16 长度上限内可承载的最大尾部条目数。
func (m *ListWhitelistResponse) MaxTailEntries() int {
	t := tailElems["ListWhitelistResponse"]
	return (MsgLenMax - wireLayouts["ListWhitelistResponse"].size) / t.elemSize
}

// Decode 解析 ListWhitelistResponse 报文。
func (m *ListWhitelistResponse) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgListWhitelistResponse {
		return fmt.Errorf("期望 ListWhitelistResponse(%d)，实际 %d", MsgListWhitelistResponse, h.MsgType)
	}
	fixed := wireLayouts["ListWhitelistResponse"].size
	elem := wireLayouts["WhitelistEntry"].size
	if len(b) < fixed {
		return fmt.Errorf("ListWhitelistResponse 长度 %d 短于定长部分 %d", len(b), fixed)
	}
	o := offListWhitelistResponse
	m.Count = getU32(b, o["count"])
	m.Total = getU32(b, o["total"])
	m.Offset = getU32(b, o["offset"])
	rest := len(b) - fixed
	if rest%elem != 0 {
		return fmt.Errorf("ListWhitelistResponse 尾部 %d 字节不是 %d 的整数倍", rest, elem)
	}
	n := rest / elem
	if uint32(n) != m.Count {
		return fmt.Errorf("ListWhitelistResponse count=%d 与尾部实际条目数 %d 不符", m.Count, n)
	}
	m.Entries = make([]WhitelistEntry, n)
	for i := 0; i < n; i++ {
		m.Entries[i].decodeAt(b, fixed+i*elem)
	}
	return nil
}

// Encode 编码 ListWhitelistResponse 报文。
func (m *ListWhitelistResponse) Encode(seq uint32) ([]byte, error) {
	fixed := wireLayouts["ListWhitelistResponse"].size
	elem := wireLayouts["WhitelistEntry"].size
	if len(m.Entries) > m.MaxTailEntries() {
		return nil, fmt.Errorf("白名单条目 %d 条超出单页上限 %d", len(m.Entries), m.MaxTailEntries())
	}
	b := make([]byte, fixed+len(m.Entries)*elem)
	o := offListWhitelistResponse
	m.Count = uint32(len(m.Entries))
	putU32(b, o["count"], m.Count)
	putU32(b, o["total"], m.Total)
	putU32(b, o["offset"], m.Offset)
	for i := range m.Entries {
		if err := m.Entries[i].encodeAt(b, fixed+i*elem); err != nil {
			return nil, err
		}
	}
	encodeHeader(b, MsgListWhitelistResponse, seq)
	return b, nil
}

var offRateEntry = map[string]int{
	"af": 0, "pad": 1, "packets": 4, "bytes": 12, "syn_packets": 20,
	"udp_packets": 28, "icmp_packets": 36, "ack_packets": 44, "rst_packets": 52,
	"fin_packets": 60, "unique_ports": 68, "addr": 72,
}

// RateEntry 速率统计条目（ListRatesResponse 的尾部元素，偏移相对条目起点）。
type RateEntry struct {
	AF          AddrFamily
	Packets     uint64
	Bytes       uint64
	SynPackets  uint64
	UDPPackets  uint64
	ICMPPackets uint64
	ACKPackets  uint64
	RSTPackets  uint64
	FINPackets  uint64
	UniquePorts uint32
	Addr        Addr16
}

func (e *RateEntry) decodeAt(b []byte, base int) {
	o := offRateEntry
	e.AF = AddrFamily(getU8(b, base+o["af"]))
	e.Packets = getU64(b, base+o["packets"])
	e.Bytes = getU64(b, base+o["bytes"])
	e.SynPackets = getU64(b, base+o["syn_packets"])
	e.UDPPackets = getU64(b, base+o["udp_packets"])
	e.ICMPPackets = getU64(b, base+o["icmp_packets"])
	e.ACKPackets = getU64(b, base+o["ack_packets"])
	e.RSTPackets = getU64(b, base+o["rst_packets"])
	e.FINPackets = getU64(b, base+o["fin_packets"])
	e.UniquePorts = getU32(b, base+o["unique_ports"])
	e.Addr = getAddr16(b, base+o["addr"])
}

func (e *RateEntry) encodeAt(b []byte, base int) {
	o := offRateEntry
	putU8(b, base+o["af"], uint8(e.AF))
	putU16(b, base+o["pad"], 0)
	putU8(b, base+o["pad"]+2, 0)
	putU64(b, base+o["packets"], e.Packets)
	putU64(b, base+o["bytes"], e.Bytes)
	putU64(b, base+o["syn_packets"], e.SynPackets)
	putU64(b, base+o["udp_packets"], e.UDPPackets)
	putU64(b, base+o["icmp_packets"], e.ICMPPackets)
	putU64(b, base+o["ack_packets"], e.ACKPackets)
	putU64(b, base+o["rst_packets"], e.RSTPackets)
	putU64(b, base+o["fin_packets"], e.FINPackets)
	putU32(b, base+o["unique_ports"], e.UniquePorts)
	putAddr16(b, base+o["addr"], e.Addr)
}

var offListRatesResponse = map[string]int{
	"count": 12, "total": 16, "offset": 20, "global_pps": 24, "global_bps": 32,
}

// ListRatesResponse 速率统计响应（分页）。
type ListRatesResponse struct {
	Count     uint32
	Total     uint32
	Offset    uint32
	GlobalPPS uint64
	GlobalBPS uint64
	Entries   []RateEntry
}

// MaxTailEntries 返回 u16 长度上限内可承载的最大尾部条目数。
func (m *ListRatesResponse) MaxTailEntries() int {
	t := tailElems["ListRatesResponse"]
	return (MsgLenMax - wireLayouts["ListRatesResponse"].size) / t.elemSize
}

// Decode 解析 ListRatesResponse 报文。
func (m *ListRatesResponse) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgListRatesResponse {
		return fmt.Errorf("期望 ListRatesResponse(%d)，实际 %d", MsgListRatesResponse, h.MsgType)
	}
	fixed := wireLayouts["ListRatesResponse"].size
	elem := wireLayouts["RateEntry"].size
	if len(b) < fixed {
		return fmt.Errorf("ListRatesResponse 长度 %d 短于定长部分 %d", len(b), fixed)
	}
	o := offListRatesResponse
	m.Count = getU32(b, o["count"])
	m.Total = getU32(b, o["total"])
	m.Offset = getU32(b, o["offset"])
	m.GlobalPPS = getU64(b, o["global_pps"])
	m.GlobalBPS = getU64(b, o["global_bps"])
	rest := len(b) - fixed
	if rest%elem != 0 {
		return fmt.Errorf("ListRatesResponse 尾部 %d 字节不是 %d 的整数倍", rest, elem)
	}
	n := rest / elem
	if uint32(n) != m.Count {
		return fmt.Errorf("ListRatesResponse count=%d 与尾部实际条目数 %d 不符", m.Count, n)
	}
	m.Entries = make([]RateEntry, n)
	for i := 0; i < n; i++ {
		m.Entries[i].decodeAt(b, fixed+i*elem)
	}
	return nil
}

// Encode 编码 ListRatesResponse 报文。
func (m *ListRatesResponse) Encode(seq uint32) ([]byte, error) {
	fixed := wireLayouts["ListRatesResponse"].size
	elem := wireLayouts["RateEntry"].size
	if len(m.Entries) > m.MaxTailEntries() {
		return nil, fmt.Errorf("速率条目 %d 条超出单页上限 %d", len(m.Entries), m.MaxTailEntries())
	}
	b := make([]byte, fixed+len(m.Entries)*elem)
	o := offListRatesResponse
	m.Count = uint32(len(m.Entries))
	putU32(b, o["count"], m.Count)
	putU32(b, o["total"], m.Total)
	putU32(b, o["offset"], m.Offset)
	putU64(b, o["global_pps"], m.GlobalPPS)
	putU64(b, o["global_bps"], m.GlobalBPS)
	for i := range m.Entries {
		m.Entries[i].encodeAt(b, fixed+i*elem)
	}
	encodeHeader(b, MsgListRatesResponse, seq)
	return b, nil
}

var offUdpPortItem = map[string]int{
	"port": 0, "packets": 2, "bytes": 10, "last_seen_secs": 18,
}

// UdpPortItem UDP 端口分布子条目（偏移相对条目起点）。
type UdpPortItem struct {
	Port         uint16
	Packets      uint64
	Bytes        uint64
	LastSeenSecs uint64
}

var offIcmpTypeItem = map[string]int{
	"type": 0, "code": 1, "packets": 2, "bytes": 10, "last_seen_secs": 18,
}

// IcmpTypeItem ICMP 类型分布子条目（偏移相对条目起点）。
type IcmpTypeItem struct {
	Type         uint8
	Code         uint8
	Packets      uint64
	Bytes        uint64
	LastSeenSecs uint64
}

var offScannerItem = map[string]int{
	"af": 0, "pad": 1, "addr": 4, "metric": 20, "packets": 24,
}

// ScannerItem 端口扫描者 / 服务探测者子条目（偏移相对条目起点）。
type ScannerItem struct {
	AF      AddrFamily
	Addr    Addr16
	Metric  uint32
	Packets uint64
}

func decodeScannerItem(b []byte, base int) ScannerItem {
	o := offScannerItem
	return ScannerItem{
		AF:      AddrFamily(getU8(b, base+o["af"])),
		Addr:    getAddr16(b, base+o["addr"]),
		Metric:  getU32(b, base+o["metric"]),
		Packets: getU64(b, base+o["packets"]),
	}
}

func encodeScannerItem(b []byte, base int, s ScannerItem) {
	o := offScannerItem
	putU8(b, base+o["af"], uint8(s.AF))
	putU16(b, base+o["pad"], 0)
	putU8(b, base+o["pad"]+2, 0)
	putAddr16(b, base+o["addr"], s.Addr)
	putU32(b, base+o["metric"], s.Metric)
	putU64(b, base+o["packets"], s.Packets)
}

var offAnalysisResponse = map[string]int{
	"pkt_sizes": 12, "ttl_dist": 52, "ip_frag_total": 100, "ip_frag_count": 108,
	"udp_port_count": 116, "udp_port_capacity": 120, "udp_ports": 124,
	"icmp_type_count": 1788, "icmp_type_capacity": 1792, "icmp_types": 1796,
	"port_scan_count": 3460, "port_scan_threshold": 3464, "port_scanners": 3468,
	"service_probe_count": 4108, "service_probe_threshold": 4112, "service_probes": 4116,
}

// 分析响应里的定长数组容量（契约里是定长数组，不是变长尾部）。
const (
	AnalysisPktSizeBins = 5
	AnalysisTTLBins     = 6
	AnalysisUDPPortCap  = 64
	AnalysisICMPTypeCap = 64
	AnalysisScannerCap  = 20
)

// AnalysisResponse 分析数据响应（全定长：包大小分布 / TTL 分布 / 分片 / UDP 端口 / ICMP 类型 / 端口扫描者 / 服务探测者）。
type AnalysisResponse struct {
	PktSizes              [AnalysisPktSizeBins]uint64
	TTLDist               [AnalysisTTLBins]uint64
	IPFragTotal           uint64
	IPFragCount           uint64
	UDPPortCount          uint32
	UDPPortCapacity       uint32
	UDPPorts              [AnalysisUDPPortCap]UdpPortItem
	ICMPTypeCount         uint32
	ICMPTypeCapacity      uint32
	ICMPTypes             [AnalysisICMPTypeCap]IcmpTypeItem
	PortScanCount         uint32
	PortScanThreshold     uint32
	PortScanners          [AnalysisScannerCap]ScannerItem
	ServiceProbeCount     uint32
	ServiceProbeThreshold uint32
	ServiceProbes         [AnalysisScannerCap]ScannerItem
}

// Decode 解析 AnalysisResponse 报文。
func (m *AnalysisResponse) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgAnalysisResponse {
		return fmt.Errorf("期望 AnalysisResponse(%d)，实际 %d", MsgAnalysisResponse, h.MsgType)
	}
	size := wireLayouts["AnalysisResponse"].size
	if len(b) != size {
		return fmt.Errorf("AnalysisResponse 长度 %d 应为 %d", len(b), size)
	}
	o := offAnalysisResponse
	udpSize := wireLayouts["UdpPortItem"].size
	icmpSize := wireLayouts["IcmpTypeItem"].size
	scanSize := wireLayouts["ScannerItem"].size
	for i := 0; i < AnalysisPktSizeBins; i++ {
		m.PktSizes[i] = getU64(b, o["pkt_sizes"]+i*8)
	}
	for i := 0; i < AnalysisTTLBins; i++ {
		m.TTLDist[i] = getU64(b, o["ttl_dist"]+i*8)
	}
	m.IPFragTotal = getU64(b, o["ip_frag_total"])
	m.IPFragCount = getU64(b, o["ip_frag_count"])
	m.UDPPortCount = getU32(b, o["udp_port_count"])
	m.UDPPortCapacity = getU32(b, o["udp_port_capacity"])
	for i := 0; i < AnalysisUDPPortCap; i++ {
		d := b[o["udp_ports"]+i*udpSize:]
		m.UDPPorts[i] = UdpPortItem{
			Port:         getU16(d, offUdpPortItem["port"]),
			Packets:      getU64(d, offUdpPortItem["packets"]),
			Bytes:        getU64(d, offUdpPortItem["bytes"]),
			LastSeenSecs: getU64(d, offUdpPortItem["last_seen_secs"]),
		}
	}
	m.ICMPTypeCount = getU32(b, o["icmp_type_count"])
	m.ICMPTypeCapacity = getU32(b, o["icmp_type_capacity"])
	for i := 0; i < AnalysisICMPTypeCap; i++ {
		d := b[o["icmp_types"]+i*icmpSize:]
		m.ICMPTypes[i] = IcmpTypeItem{
			Type:         getU8(d, offIcmpTypeItem["type"]),
			Code:         getU8(d, offIcmpTypeItem["code"]),
			Packets:      getU64(d, offIcmpTypeItem["packets"]),
			Bytes:        getU64(d, offIcmpTypeItem["bytes"]),
			LastSeenSecs: getU64(d, offIcmpTypeItem["last_seen_secs"]),
		}
	}
	m.PortScanCount = getU32(b, o["port_scan_count"])
	m.PortScanThreshold = getU32(b, o["port_scan_threshold"])
	for i := 0; i < AnalysisScannerCap; i++ {
		m.PortScanners[i] = decodeScannerItem(b, o["port_scanners"]+i*scanSize)
	}
	m.ServiceProbeCount = getU32(b, o["service_probe_count"])
	m.ServiceProbeThreshold = getU32(b, o["service_probe_threshold"])
	for i := 0; i < AnalysisScannerCap; i++ {
		m.ServiceProbes[i] = decodeScannerItem(b, o["service_probes"]+i*scanSize)
	}
	return nil
}

// Encode 编码 AnalysisResponse 报文。
func (m *AnalysisResponse) Encode(seq uint32) ([]byte, error) {
	o := offAnalysisResponse
	b := make([]byte, wireLayouts["AnalysisResponse"].size)
	udpSize := wireLayouts["UdpPortItem"].size
	icmpSize := wireLayouts["IcmpTypeItem"].size
	scanSize := wireLayouts["ScannerItem"].size
	for i := 0; i < AnalysisPktSizeBins; i++ {
		putU64(b, o["pkt_sizes"]+i*8, m.PktSizes[i])
	}
	for i := 0; i < AnalysisTTLBins; i++ {
		putU64(b, o["ttl_dist"]+i*8, m.TTLDist[i])
	}
	putU64(b, o["ip_frag_total"], m.IPFragTotal)
	putU64(b, o["ip_frag_count"], m.IPFragCount)
	putU32(b, o["udp_port_count"], m.UDPPortCount)
	putU32(b, o["udp_port_capacity"], m.UDPPortCapacity)
	for i := 0; i < AnalysisUDPPortCap; i++ {
		d := b[o["udp_ports"]+i*udpSize:]
		p := m.UDPPorts[i]
		putU16(d, offUdpPortItem["port"], p.Port)
		putU64(d, offUdpPortItem["packets"], p.Packets)
		putU64(d, offUdpPortItem["bytes"], p.Bytes)
		putU64(d, offUdpPortItem["last_seen_secs"], p.LastSeenSecs)
	}
	putU32(b, o["icmp_type_count"], m.ICMPTypeCount)
	putU32(b, o["icmp_type_capacity"], m.ICMPTypeCapacity)
	for i := 0; i < AnalysisICMPTypeCap; i++ {
		d := b[o["icmp_types"]+i*icmpSize:]
		t := m.ICMPTypes[i]
		putU8(d, offIcmpTypeItem["type"], t.Type)
		putU8(d, offIcmpTypeItem["code"], t.Code)
		putU64(d, offIcmpTypeItem["packets"], t.Packets)
		putU64(d, offIcmpTypeItem["bytes"], t.Bytes)
		putU64(d, offIcmpTypeItem["last_seen_secs"], t.LastSeenSecs)
	}
	putU32(b, o["port_scan_count"], m.PortScanCount)
	putU32(b, o["port_scan_threshold"], m.PortScanThreshold)
	for i := 0; i < AnalysisScannerCap; i++ {
		encodeScannerItem(b, o["port_scanners"]+i*scanSize, m.PortScanners[i])
	}
	putU32(b, o["service_probe_count"], m.ServiceProbeCount)
	putU32(b, o["service_probe_threshold"], m.ServiceProbeThreshold)
	for i := 0; i < AnalysisScannerCap; i++ {
		encodeScannerItem(b, o["service_probes"]+i*scanSize, m.ServiceProbes[i])
	}
	encodeHeader(b, MsgAnalysisResponse, seq)
	return b, nil
}

var offDaemonRegisterAck = map[string]int{"accepted": 12}

// DaemonRegisterAck 单守护进程注册确认。
//
// 注册必须可观测：内核拒绝注册（已有活跃守护进程）时仍回本消息并置 Accepted=0，
// 调用方必须解析它，不得把「发送成功」当作「注册成功」。
type DaemonRegisterAck struct {
	Accepted bool
}

// Decode 解析 DaemonRegisterAck 报文。
func (m *DaemonRegisterAck) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgDaemonRegisterAck {
		return fmt.Errorf("期望 DaemonRegisterAck(%d)，实际 %d", MsgDaemonRegisterAck, h.MsgType)
	}
	size := wireLayouts["DaemonRegisterAck"].size
	if len(b) != size {
		return fmt.Errorf("DaemonRegisterAck 长度 %d 应为 %d", len(b), size)
	}
	m.Accepted = getU8(b, offDaemonRegisterAck["accepted"]) != 0
	return nil
}

// Encode 编码 DaemonRegisterAck 报文。
func (m *DaemonRegisterAck) Encode(seq uint32) ([]byte, error) {
	b := make([]byte, wireLayouts["DaemonRegisterAck"].size)
	if m.Accepted {
		putU8(b, offDaemonRegisterAck["accepted"], 1)
	}
	encodeHeader(b, MsgDaemonRegisterAck, seq)
	return b, nil
}
