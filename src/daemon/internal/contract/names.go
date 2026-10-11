package contract

import (
	"fmt"
	"strings"
)

// msgTypeNames 是消息类型到诊断名的映射，用于错误信息与日志。
var msgTypeNames = map[MsgType]string{
	MsgDdosEvent:             "DdosEvent",
	MsgBanIP:                 "BanIp",
	MsgUnbanIP:               "UnbanIp",
	MsgSetConfig:             "SetConfig",
	MsgBanStateChange:        "BanStateChange",
	MsgListBansQuery:         "ListBansQuery",
	MsgListBansResponse:      "ListBansResponse",
	MsgStatsQuery:            "StatsQuery",
	MsgStatsResponse:         "StatsResponse",
	MsgListWhitelistQuery:    "ListWhitelistQuery",
	MsgListWhitelistResponse: "ListWhitelistResponse",
	MsgAddWhitelist:          "AddWhitelist",
	MsgRemoveWhitelist:       "RemoveWhitelist",
	MsgConfigAck:             "ConfigAck",
	MsgListRatesQuery:        "ListRatesQuery",
	MsgListRatesResponse:     "ListRatesResponse",
	MsgWhitelistStateChange:  "WhitelistStateChange",
	MsgCmdResult:             "CmdResult",
	MsgConfigChange:          "ConfigChange",
	MsgAnalysisQuery:         "AnalysisQuery",
	MsgAnalysisResponse:      "AnalysisResponse",
	MsgDaemonRegister:        "DaemonRegister",
	MsgDaemonRegisterAck:     "DaemonRegisterAck",
	MsgSetProtectedPorts:     "SetProtectedPorts",
}

// String 返回消息类型的诊断名；未定义的取值返回 `未知(<n>)`。
func (t MsgType) String() string {
	if name, ok := msgTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("未知(%d)", uint16(t))
}

// Known 报告该取值是否为契约定义的消息类型。
func (t MsgType) Known() bool {
	_, ok := msgTypeNames[t]
	return ok
}

// SeqEchoedReply 报告该类型是否以「回显请求 seq」的方式回复，因而可以与在途请求配对。
//
// `CmdResult` 虽然也是单播，但它用内核自增序号，故不在此列：它只能进事件流。
func (t MsgType) SeqEchoedReply() bool {
	switch t {
	case MsgDaemonRegisterAck, MsgConfigAck, MsgStatsResponse, MsgAnalysisResponse,
		MsgListBansResponse, MsgListWhitelistResponse, MsgListRatesResponse:
		return true
	}
	return false
}

// configFlagFields 是 ConfigFlags 位 → 载荷字段名（契约 netlink.fwidl 的 ConfigFlags
// 位表与 SetConfig/ConfigChange 字段表逐位对照而来）。
//
// 诊断文本用字段名而不是位名（MAX_PPS 之类）：运维能改的是配置文件里的字段和载荷里的
// 键，位名只在读 C 代码时认得出来。按位序列出，因此 Names() 的输出确定，可以进测试断言
// 与响应文本。
var configFlagFields = []struct {
	bit   ConfigFlags
	field string
}{
	{ConfigFlagBanTime, "ban_time"},
	{ConfigFlagRateWindow, "rate_window_seconds"},
	{ConfigFlagMaxPPS, "max_packets_per_second"},
	{ConfigFlagMaxBPS, "max_bytes_per_second"},
	{ConfigFlagMaxSYN, "max_syn_per_second"},
	{ConfigFlagMaxUDP, "max_udp_per_second"},
	{ConfigFlagMaxICMP, "max_icmp_per_second"},
	{ConfigFlagMaxACK, "max_ack_per_second"},
	{ConfigFlagMaxRST, "max_rst_per_second"},
	{ConfigFlagMaxFIN, "max_fin_per_second"},
	{ConfigFlagDynamicThreshold, "dynamic_threshold"},
	{ConfigFlagBaselineUpdate, "baseline"},
	{ConfigFlagDdosBanDuration, "ddos_ban_duration"},
}

// Names 按位序列出该位图涉及的载荷字段名；空位图返回 nil。
func (f ConfigFlags) Names() []string {
	var out []string
	for _, e := range configFlagFields {
		if f&e.bit != 0 {
			out = append(out, e.field)
		}
	}
	return out
}

// String 返回位图的诊断形式，如 "ban_time|max_syn_per_second"；零位图是 "none"。
func (f ConfigFlags) String() string {
	names := f.Names()
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "|")
}
