package contract

import "fmt"

// 本文件：daemon → 内核方向的消息，以及仅含公共头的指令。

var offBanIp = map[string]int{
	"af": 12, "prefix_len": 13, "duration_secs": 14, "addr": 18, "reason": 34,
}

// BanIp 封禁 IP；与 UnbanIp 共用同一载荷布局。
type BanIp struct {
	AF           AddrFamily
	PrefixLen    uint8
	DurationSecs uint32
	Addr         Addr16
	Reason       string
}

// Decode 解析 BanIp 报文。
func (m *BanIp) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgBanIP {
		return fmt.Errorf("期望 BanIp(%d)，实际 %d", MsgBanIP, h.MsgType)
	}
	size := wireLayouts["BanIp"].size
	if len(b) != size {
		return fmt.Errorf("BanIp 长度 %d 应为 %d", len(b), size)
	}
	o := offBanIp
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.PrefixLen = getU8(b, o["prefix_len"])
	m.DurationSecs = getU32(b, o["duration_secs"])
	m.Addr = getAddr16(b, o["addr"])
	m.Reason = getStr(b, o["reason"], 32)
	return nil
}

// Encode 编码 BanIp 报文。
func (m *BanIp) Encode(seq uint32) ([]byte, error) {
	o := offBanIp
	b := make([]byte, wireLayouts["BanIp"].size)
	if err := putStr(b, o["reason"], 32, m.Reason); err != nil {
		return nil, err
	}
	putU8(b, o["af"], uint8(m.AF))
	putU8(b, o["prefix_len"], m.PrefixLen)
	putU32(b, o["duration_secs"], m.DurationSecs)
	putAddr16(b, o["addr"], m.Addr)
	encodeHeader(b, MsgBanIP, seq)
	return b, nil
}

// UnbanIp 解封 IP；prefix_len 须与封禁时一致（内核按 af+addr+prefix_len 定位条目）。
type UnbanIp struct {
	AF        AddrFamily
	PrefixLen uint8
	Addr      Addr16
}

// Decode 解析 UnbanIp 报文。
func (m *UnbanIp) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgUnbanIP {
		return fmt.Errorf("期望 UnbanIp(%d)，实际 %d", MsgUnbanIP, h.MsgType)
	}
	size := wireLayouts["UnbanIp"].size
	if len(b) != size {
		return fmt.Errorf("UnbanIp 长度 %d 应为 %d", len(b), size)
	}
	o := offBanIp
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.PrefixLen = getU8(b, o["prefix_len"])
	m.Addr = getAddr16(b, o["addr"])
	return nil
}

// Encode 编码 UnbanIp 报文；duration_secs 与 reason 恒置 0。
func (m *UnbanIp) Encode(seq uint32) ([]byte, error) {
	o := offBanIp
	b := make([]byte, wireLayouts["UnbanIp"].size)
	putU8(b, o["af"], uint8(m.AF))
	putU8(b, o["prefix_len"], m.PrefixLen)
	putU32(b, o["duration_secs"], 0)
	putAddr16(b, o["addr"], m.Addr)
	encodeHeader(b, MsgUnbanIP, seq)
	return b, nil
}

// SetConfig 配置下发（载荷布局与 ConfigChange 一致）。
type SetConfig struct {
	ConfigPayload
}

// Decode 解析 SetConfig 报文。
func (m *SetConfig) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgSetConfig {
		return fmt.Errorf("期望 SetConfig(%d)，实际 %d", MsgSetConfig, h.MsgType)
	}
	size := wireLayouts["SetConfig"].size
	if len(b) != size {
		return fmt.Errorf("SetConfig 长度 %d 应为 %d", len(b), size)
	}
	m.ConfigPayload = decodeConfigPayload(b)
	return nil
}

// Encode 编码 SetConfig 报文。
func (m *SetConfig) Encode(seq uint32) ([]byte, error) {
	b := make([]byte, wireLayouts["SetConfig"].size)
	encodeConfigPayload(b, &m.ConfigPayload)
	encodeHeader(b, MsgSetConfig, seq)
	return b, nil
}

// ConfigChange procfs 写入配置后的变更广播（载荷布局与 SetConfig 一致）。
type ConfigChange struct {
	ConfigPayload
}

// Decode 解析 ConfigChange 报文。
func (m *ConfigChange) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgConfigChange {
		return fmt.Errorf("期望 ConfigChange(%d)，实际 %d", MsgConfigChange, h.MsgType)
	}
	size := wireLayouts["ConfigChange"].size
	if len(b) != size {
		return fmt.Errorf("ConfigChange 长度 %d 应为 %d", len(b), size)
	}
	m.ConfigPayload = decodeConfigPayload(b)
	return nil
}

// Encode 编码 ConfigChange 报文。
func (m *ConfigChange) Encode(seq uint32) ([]byte, error) {
	b := make([]byte, wireLayouts["ConfigChange"].size)
	encodeConfigPayload(b, &m.ConfigPayload)
	encodeHeader(b, MsgConfigChange, seq)
	return b, nil
}

// ProtectedPortsBits 是受保护端口位图的位数（一端口一位）。
const ProtectedPortsBits = 65536

// ProtectedPortsLen 是受保护端口位图的字节数。
const ProtectedPortsLen = ProtectedPortsBits / 8

var offSetProtectedPorts = map[string]int{"count": 12, "bitmap": 16}

// SetProtectedPorts 受保护端口位图：位 i 置位表示端口 i 的入站流量参与速率判定。
type SetProtectedPorts struct {
	Count  uint32
	Bitmap [ProtectedPortsLen]byte
}

// SetPort 置位端口 p。
func (m *SetProtectedPorts) SetPort(p uint16) { m.Bitmap[p/8] |= 1 << (p % 8) }

// IsPortSet 报告端口 p 是否置位。
func (m *SetProtectedPorts) IsPortSet(p uint16) bool {
	return m.Bitmap[p/8]&(1<<(p%8)) != 0
}

// Decode 解析 SetProtectedPorts 报文。
func (m *SetProtectedPorts) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgSetProtectedPorts {
		return fmt.Errorf("期望 SetProtectedPorts(%d)，实际 %d", MsgSetProtectedPorts, h.MsgType)
	}
	size := wireLayouts["SetProtectedPorts"].size
	if len(b) != size {
		return fmt.Errorf("SetProtectedPorts 长度 %d 应为 %d", len(b), size)
	}
	o := offSetProtectedPorts
	m.Count = getU32(b, o["count"])
	copy(m.Bitmap[:], b[o["bitmap"]:o["bitmap"]+ProtectedPortsLen])
	return nil
}

// Encode 编码 SetProtectedPorts 报文。
func (m *SetProtectedPorts) Encode(seq uint32) ([]byte, error) {
	o := offSetProtectedPorts
	b := make([]byte, wireLayouts["SetProtectedPorts"].size)
	putU32(b, o["count"], m.Count)
	copy(b[o["bitmap"]:o["bitmap"]+ProtectedPortsLen], m.Bitmap[:])
	encodeHeader(b, MsgSetProtectedPorts, seq)
	return b, nil
}

var offListBansQuery = map[string]int{"offset": 12, "limit": 16}

// ListBansQuery 封禁列表分页查询。
type ListBansQuery struct {
	Offset uint32
	Limit  uint32
}

// Decode 解析 ListBansQuery 报文。
func (m *ListBansQuery) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgListBansQuery {
		return fmt.Errorf("期望 ListBansQuery(%d)，实际 %d", MsgListBansQuery, h.MsgType)
	}
	if len(b) != wireLayouts["ListBansQuery"].size {
		return fmt.Errorf("ListBansQuery 长度 %d 应为 %d", len(b), wireLayouts["ListBansQuery"].size)
	}
	o := offListBansQuery
	m.Offset = getU32(b, o["offset"])
	m.Limit = getU32(b, o["limit"])
	return nil
}

// Encode 编码 ListBansQuery 报文。
func (m *ListBansQuery) Encode(seq uint32) ([]byte, error) {
	o := offListBansQuery
	b := make([]byte, wireLayouts["ListBansQuery"].size)
	putU32(b, o["offset"], m.Offset)
	putU32(b, o["limit"], m.Limit)
	encodeHeader(b, MsgListBansQuery, seq)
	return b, nil
}

// ListWhitelistQuery 白名单列表分页查询（分页参数语义与 ListBansQuery 一致）。
type ListWhitelistQuery struct {
	Offset uint32
	Limit  uint32
}

// Decode 解析 ListWhitelistQuery 报文。
func (m *ListWhitelistQuery) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgListWhitelistQuery {
		return fmt.Errorf("期望 ListWhitelistQuery(%d)，实际 %d", MsgListWhitelistQuery, h.MsgType)
	}
	if len(b) != wireLayouts["ListWhitelistQuery"].size {
		return fmt.Errorf("ListWhitelistQuery 长度 %d 应为 %d", len(b), wireLayouts["ListWhitelistQuery"].size)
	}
	o := offListBansQuery
	m.Offset = getU32(b, o["offset"])
	m.Limit = getU32(b, o["limit"])
	return nil
}

// Encode 编码 ListWhitelistQuery 报文。
func (m *ListWhitelistQuery) Encode(seq uint32) ([]byte, error) {
	o := offListBansQuery
	b := make([]byte, wireLayouts["ListWhitelistQuery"].size)
	putU32(b, o["offset"], m.Offset)
	putU32(b, o["limit"], m.Limit)
	encodeHeader(b, MsgListWhitelistQuery, seq)
	return b, nil
}

// ListRatesQuery 速率统计分页查询（分页参数语义与 ListBansQuery 一致）。
type ListRatesQuery struct {
	Offset uint32
	Limit  uint32
}

// Decode 解析 ListRatesQuery 报文。
func (m *ListRatesQuery) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgListRatesQuery {
		return fmt.Errorf("期望 ListRatesQuery(%d)，实际 %d", MsgListRatesQuery, h.MsgType)
	}
	if len(b) != wireLayouts["ListRatesQuery"].size {
		return fmt.Errorf("ListRatesQuery 长度 %d 应为 %d", len(b), wireLayouts["ListRatesQuery"].size)
	}
	o := offListBansQuery
	m.Offset = getU32(b, o["offset"])
	m.Limit = getU32(b, o["limit"])
	return nil
}

// Encode 编码 ListRatesQuery 报文。
func (m *ListRatesQuery) Encode(seq uint32) ([]byte, error) {
	o := offListBansQuery
	b := make([]byte, wireLayouts["ListRatesQuery"].size)
	putU32(b, o["offset"], m.Offset)
	putU32(b, o["limit"], m.Limit)
	encodeHeader(b, MsgListRatesQuery, seq)
	return b, nil
}

var offAddWhitelist = map[string]int{"af": 12, "prefix_len": 13, "addr": 14, "device": 30}

// AddWhitelist 添加白名单；device 为空串表示不限设备。
type AddWhitelist struct {
	AF        AddrFamily
	PrefixLen uint8
	Addr      Addr16
	Device    string
}

// Decode 解析 AddWhitelist 报文。
func (m *AddWhitelist) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgAddWhitelist {
		return fmt.Errorf("期望 AddWhitelist(%d)，实际 %d", MsgAddWhitelist, h.MsgType)
	}
	size := wireLayouts["AddWhitelist"].size
	if len(b) != size {
		return fmt.Errorf("AddWhitelist 长度 %d 应为 %d", len(b), size)
	}
	o := offAddWhitelist
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.PrefixLen = getU8(b, o["prefix_len"])
	m.Addr = getAddr16(b, o["addr"])
	m.Device = getStr(b, o["device"], 16)
	return nil
}

// Encode 编码 AddWhitelist 报文。
func (m *AddWhitelist) Encode(seq uint32) ([]byte, error) {
	o := offAddWhitelist
	b := make([]byte, wireLayouts["AddWhitelist"].size)
	if err := putStr(b, o["device"], 16, m.Device); err != nil {
		return nil, err
	}
	putU8(b, o["af"], uint8(m.AF))
	putU8(b, o["prefix_len"], m.PrefixLen)
	putAddr16(b, o["addr"], m.Addr)
	encodeHeader(b, MsgAddWhitelist, seq)
	return b, nil
}

// RemoveWhitelist 移除白名单（载荷布局与 AddWhitelist 一致）。
type RemoveWhitelist struct {
	AF        AddrFamily
	PrefixLen uint8
	Addr      Addr16
	Device    string
}

// Decode 解析 RemoveWhitelist 报文。
func (m *RemoveWhitelist) Decode(b []byte) error {
	h, err := ParseHeader(b)
	if err != nil {
		return err
	}
	if h.MsgType != MsgRemoveWhitelist {
		return fmt.Errorf("期望 RemoveWhitelist(%d)，实际 %d", MsgRemoveWhitelist, h.MsgType)
	}
	size := wireLayouts["RemoveWhitelist"].size
	if len(b) != size {
		return fmt.Errorf("RemoveWhitelist 长度 %d 应为 %d", len(b), size)
	}
	o := offAddWhitelist
	m.AF = AddrFamily(getU8(b, o["af"]))
	m.PrefixLen = getU8(b, o["prefix_len"])
	m.Addr = getAddr16(b, o["addr"])
	m.Device = getStr(b, o["device"], 16)
	return nil
}

// Encode 编码 RemoveWhitelist 报文。
func (m *RemoveWhitelist) Encode(seq uint32) ([]byte, error) {
	o := offAddWhitelist
	b := make([]byte, wireLayouts["RemoveWhitelist"].size)
	if err := putStr(b, o["device"], 16, m.Device); err != nil {
		return nil, err
	}
	putU8(b, o["af"], uint8(m.AF))
	putU8(b, o["prefix_len"], m.PrefixLen)
	putAddr16(b, o["addr"], m.Addr)
	encodeHeader(b, MsgRemoveWhitelist, seq)
	return b, nil
}

// headerOnly 编码仅含公共头的指令。
func headerOnly(t MsgType, seq uint32) []byte {
	b := make([]byte, HdrLen)
	encodeHeader(b, t, seq)
	return b
}

// StatsQuery 编码统计查询（仅头）。
func StatsQuery(seq uint32) []byte { return headerOnly(MsgStatsQuery, seq) }

// AnalysisQuery 编码分析数据查询（仅头）。
func AnalysisQuery(seq uint32) []byte { return headerOnly(MsgAnalysisQuery, seq) }

// DaemonRegister 编码单守护进程注册请求（仅头）。
func DaemonRegister(seq uint32) []byte { return headerOnly(MsgDaemonRegister, seq) }

// DecodeHeaderOnly 校验一个仅含公共头的报文并返回其头。
func DecodeHeaderOnly(b []byte, want MsgType) (Header, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Header{}, err
	}
	if h.MsgType != want {
		return Header{}, fmt.Errorf("期望消息类型 %d，实际 %d", want, h.MsgType)
	}
	if len(b) != HdrLen {
		return Header{}, fmt.Errorf("该消息应为 %d 字节（仅头），实际 %d", HdrLen, len(b))
	}
	return h, nil
}
