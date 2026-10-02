package contract

import "fmt"

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
