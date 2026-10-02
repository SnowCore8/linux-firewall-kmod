// Package contract 是 netlink 线格式契约（contract/netlink.fwidl）的 Go 绑定。
//
// 契约是单一真相源，由 contract/gen.py 生成 C/Rust/TS/JSON 四端产物。Go 侧手写
// 对齐，并由 contract_test.go 逐字段比对 contract/generated/netlink_layout.json：
// 任一处偏移或长度不符即失败。
//
// 线格式约定（gen.py 强制）：所有结构 packed（无隐式填充）、所有多字节整数大端。
// 因此本包一律按显式偏移读写，绝不把 Go 结构体映射到字节——Go 会插入填充，布局
// 与契约不符。
package contract

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// Magic 是每条报文首个 u32；不匹配的报文一律丢弃。
	Magic uint32 = 0x46574C4E
	// HdrLen 是公共头 MsgHdr 的字节数。
	HdrLen = 12
	// MsgLenMax 是 msg_len（u16）的上限。
	MsgLenMax = 0xFFFF
	// Endianness 是契约承诺的字节序。
	Endianness = "big"
	// Addr16Len 是 addr16 别名的字节数。
	Addr16Len = 16
)

// AddrFamily 地址族；取值与 Linux AF_INET / AF_INET6 同值。
type AddrFamily uint8

// 地址族取值。
const (
	AFInet  AddrFamily = 2
	AFInet6 AddrFamily = 10
)

// Valid 报告地址族是否为契约定义的取值。
func (f AddrFamily) Valid() bool { return f == AFInet || f == AFInet6 }

// BanAction 封禁状态变更动作。
type BanAction uint8

// 封禁动作取值。
const (
	BanActionBan   BanAction = 1
	BanActionUnban BanAction = 2
)

// WhitelistAction 白名单状态变更动作。
type WhitelistAction uint8

// 白名单动作取值。
const (
	WhitelistActionAdd    WhitelistAction = 1
	WhitelistActionRemove WhitelistAction = 2
)

// MsgType netlink 消息类型。
type MsgType uint16

// 消息类型取值，与契约声明顺序一致。
const (
	MsgDdosEvent             MsgType = 1
	MsgBanIP                 MsgType = 2
	MsgUnbanIP               MsgType = 3
	MsgSetConfig             MsgType = 4
	MsgBanStateChange        MsgType = 5
	MsgListBansQuery         MsgType = 6
	MsgListBansResponse      MsgType = 7
	MsgStatsQuery            MsgType = 8
	MsgStatsResponse         MsgType = 9
	MsgListWhitelistQuery    MsgType = 10
	MsgListWhitelistResponse MsgType = 11
	MsgAddWhitelist          MsgType = 12
	MsgRemoveWhitelist       MsgType = 13
	MsgConfigAck             MsgType = 14
	MsgListRatesQuery        MsgType = 15
	MsgListRatesResponse     MsgType = 16
	MsgWhitelistStateChange  MsgType = 17
	MsgCmdResult             MsgType = 18
	MsgConfigChange          MsgType = 19
	MsgAnalysisQuery         MsgType = 20
	MsgAnalysisResponse      MsgType = 21
	MsgDaemonRegister        MsgType = 22
	MsgDaemonRegisterAck     MsgType = 23
	MsgSetProtectedPorts     MsgType = 24
)

// ConfigFlags 是 SetConfig / ConfigChange 的 flags 字段位标志（位序号见契约）。
type ConfigFlags uint32

// 配置位标志取值。
const (
	ConfigFlagBanTime          ConfigFlags = 1 << 0
	ConfigFlagRateWindow       ConfigFlags = 1 << 1
	ConfigFlagMaxPPS           ConfigFlags = 1 << 2
	ConfigFlagMaxBPS           ConfigFlags = 1 << 3
	ConfigFlagMaxSYN           ConfigFlags = 1 << 4
	ConfigFlagMaxUDP           ConfigFlags = 1 << 5
	ConfigFlagMaxICMP          ConfigFlags = 1 << 6
	ConfigFlagMaxACK           ConfigFlags = 1 << 7
	ConfigFlagMaxRST           ConfigFlags = 1 << 8
	ConfigFlagMaxFIN           ConfigFlags = 1 << 9
	ConfigFlagDynamicThreshold ConfigFlags = 1 << 10
	ConfigFlagBaselineUpdate   ConfigFlags = 1 << 11
	ConfigFlagDdosBanDuration  ConfigFlags = 1 << 12
)

// DynThresholdFlagEnabled 是 dynamic_threshold_flags 字段的启用位。
const DynThresholdFlagEnabled uint32 = 1 << 0

// Addr16 是契约里的 addr16：IPv4 占前 4 字节、余下为 0；IPv6 用全部 16 字节。
type Addr16 [Addr16Len]byte

// Addr16FromIP 按地址族把 net.IP 放进 addr16。
func Addr16FromIP(af AddrFamily, ip net.IP) (Addr16, error) {
	var a Addr16
	switch af {
	case AFInet:
		v4 := ip.To4()
		if v4 == nil {
			return a, fmt.Errorf("地址 %s 不是 IPv4", ip)
		}
		copy(a[:4], v4)
	case AFInet6:
		if ip.To4() != nil {
			return a, fmt.Errorf("地址 %s 不是 IPv6", ip)
		}
		v16 := ip.To16()
		if v16 == nil {
			return a, fmt.Errorf("地址 %s 不是 IPv6", ip)
		}
		copy(a[:], v16)
	default:
		return a, fmt.Errorf("未定义的地址族 %d", af)
	}
	return a, nil
}

// IP 按地址族还原 net.IP。
func (a Addr16) IP(af AddrFamily) (net.IP, error) {
	switch af {
	case AFInet:
		return net.IP(a[:4]), nil
	case AFInet6:
		return net.IP(a[:]), nil
	default:
		return nil, fmt.Errorf("未定义的地址族 %d", af)
	}
}

// Header 是解码后的公共头。
type Header struct {
	MsgType MsgType
	MsgLen  uint16
	Seq     uint32
}

// ParseHeader 校验并解析公共头；msg_len 必须与实际字节数一致，长度不符即报错
// （契约要求 msg_len 恒为「含头的总长度」，静默接受截断会把错位字段读成合法值）。
//
// 导出供接收路径复用：公共头的校验规则属于契约，任何调用方都不得另写一份。
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HdrLen {
		return Header{}, fmt.Errorf("报文短于公共头：%d < %d", len(b), HdrLen)
	}
	if m := binary.BigEndian.Uint32(b[0:4]); m != Magic {
		return Header{}, fmt.Errorf("魔数不匹配：0x%08X", m)
	}
	h := Header{
		MsgType: MsgType(binary.BigEndian.Uint16(b[4:6])),
		MsgLen:  binary.BigEndian.Uint16(b[6:8]),
		Seq:     binary.BigEndian.Uint32(b[8:12]),
	}
	if int(h.MsgLen) != len(b) {
		return Header{}, fmt.Errorf("msg_len=%d 与实际长度 %d 不符", h.MsgLen, len(b))
	}
	return h, nil
}

// encodeHeader 写入公共头。
func encodeHeader(b []byte, t MsgType, seq uint32) {
	binary.BigEndian.PutUint32(b[0:4], Magic)
	binary.BigEndian.PutUint16(b[4:6], uint16(t))
	binary.BigEndian.PutUint16(b[6:8], uint16(len(b)))
	binary.BigEndian.PutUint32(b[8:12], seq)
}

// 定长读写原语：一律按显式偏移存取，避免任何对齐假设。

func putU8(b []byte, off int, v uint8)   { b[off] = v }
func putU16(b []byte, off int, v uint16) { binary.BigEndian.PutUint16(b[off:], v) }
func putU32(b []byte, off int, v uint32) { binary.BigEndian.PutUint32(b[off:], v) }
func putU64(b []byte, off int, v uint64) { binary.BigEndian.PutUint64(b[off:], v) }
func putI32(b []byte, off int, v int32)  { binary.BigEndian.PutUint32(b[off:], uint32(v)) }

func putAddr16(b []byte, off int, a Addr16) { copy(b[off:off+Addr16Len], a[:]) }

func getU8(b []byte, off int) uint8   { return b[off] }
func getU16(b []byte, off int) uint16 { return binary.BigEndian.Uint16(b[off:]) }
func getU32(b []byte, off int) uint32 { return binary.BigEndian.Uint32(b[off:]) }
func getU64(b []byte, off int) uint64 { return binary.BigEndian.Uint64(b[off:]) }
func getI32(b []byte, off int) int32  { return int32(binary.BigEndian.Uint32(b[off:])) }

func getAddr16(b []byte, off int) Addr16 {
	var a Addr16
	copy(a[:], b[off:off+Addr16Len])
	return a
}

// putStr 写入 NUL 结尾的定长字符串，尾部补零。契约要求字符串必须落在 n 字节内
// 并留出结尾 NUL，故 len(s) 必须小于 n；超长即报错而非静默截断。
func putStr(b []byte, off, n int, s string) error {
	if len(s) >= n {
		return fmt.Errorf("字符串 %q 长度 %d 超出定长字段上限 %d（需留结尾 NUL）", s, len(s), n)
	}
	for i := 0; i < n; i++ {
		b[off+i] = 0
	}
	copy(b[off:off+n], s)
	return nil
}

// getStr 读取 NUL 结尾的定长字符串，取首个 NUL 之前的部分。
func getStr(b []byte, off, n int) string {
	end := off
	limit := off + n
	for end < limit && b[end] != 0 {
		end++
	}
	return string(b[off:end])
}

// wireLayout 是一个类型在 Go 侧的布局声明：定长字节数与逐字段偏移。
type wireLayout struct {
	size    int
	offsets map[string]int
}

// wireLayouts 是全部结构与消息的布局声明，契约测试以 netlink_layout.json 为准逐一比对。
//
// 每个类型的偏移表只在此处声明一次，编解码与测试共用，避免「编解码用错偏移、
// 而测试只校验了另一份声明」的真空通过。
var wireLayouts = map[string]wireLayout{
	"MsgHdr": {HdrLen, map[string]int{
		"magic": 0, "msg_type": 4, "msg_len": 6, "seq": 8,
	}},
	"DdosEvent":             {65, offDdosEvent},
	"BanStateChange":        {123, offBanStateChange},
	"WhitelistStateChange":  {51, offWhitelistStateChange},
	"CmdResult":             {37, offCmdResult},
	"ConfigAck":             {20, offConfigAck},
	"ConfigChange":          {116, offConfigChange},
	"BanEntry":              {95, offBanEntry},
	"ListBansResponse":      {24, offListBansResponse},
	"StatsResponse":         {60, offStatsResponse},
	"WhitelistEntry":        {34, offWhitelistEntry},
	"ListWhitelistResponse": {24, offListWhitelistResponse},
	"RateEntry":             {88, offRateEntry},
	"ListRatesResponse":     {40, offListRatesResponse},
	"UdpPortItem":           {26, offUdpPortItem},
	"IcmpTypeItem":          {26, offIcmpTypeItem},
	"ScannerItem":           {32, offScannerItem},
	"AnalysisResponse":      {4756, offAnalysisResponse},
	"DaemonRegisterAck":     {13, offDaemonRegisterAck},
	"BanIp":                 {66, offBanIp},
	"UnbanIp":               {66, offBanIp},
	"SetConfig":             {116, offConfigChange},
	"SetProtectedPorts":     {8208, offSetProtectedPorts},
	"ListBansQuery":         {20, offListBansQuery},
	"ListWhitelistQuery":    {20, offListBansQuery},
	"ListRatesQuery":        {20, offListBansQuery},
	"AddWhitelist":          {46, offAddWhitelist},
	"RemoveWhitelist":       {46, offAddWhitelist},
	"StatsQuery":            {HdrLen, map[string]int{}},
	"AnalysisQuery":         {HdrLen, map[string]int{}},
	"DaemonRegister":        {HdrLen, map[string]int{}},
}

// tailElems 声明各分页响应的尾部元素：元素类型、元素字节数、单页上限。
// 契约测试用它核对 netlink_layout.json 的 tail 段；MaxTailEntries 用它计算上限。
var tailElems = map[string]struct {
	elem       string
	elemSize   int
	maxEntries int
}{
	"ListBansResponse":      {"BanEntry", 95, 689},
	"ListWhitelistResponse": {"WhitelistEntry", 34, 1926},
	"ListRatesResponse":     {"RateEntry", 88, 744},
}
