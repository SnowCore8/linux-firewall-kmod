package contract

import "testing"

// 每一种契约消息类型都必须有诊断名，且名称互不重复。
func TestMsgTypeNamesAreCompleteAndUnique(t *testing.T) {
	seen := make(map[string]MsgType, len(msgTypeNames))
	for _, name := range []MsgType{
		MsgDdosEvent, MsgBanIP, MsgUnbanIP, MsgSetConfig, MsgBanStateChange,
		MsgListBansQuery, MsgListBansResponse, MsgStatsQuery, MsgStatsResponse,
		MsgListWhitelistQuery, MsgListWhitelistResponse, MsgAddWhitelist,
		MsgRemoveWhitelist, MsgConfigAck, MsgListRatesQuery, MsgListRatesResponse,
		MsgWhitelistStateChange, MsgCmdResult, MsgConfigChange, MsgAnalysisQuery,
		MsgAnalysisResponse, MsgDaemonRegister, MsgDaemonRegisterAck, MsgSetProtectedPorts,
	} {
		if !name.Known() {
			t.Fatalf("消息类型 %d 缺少诊断名", uint16(name))
		}
		if s := name.String(); s == "" {
			t.Fatalf("消息类型 %d 的诊断名为空", uint16(name))
		} else if prev, dup := seen[s]; dup {
			t.Fatalf("诊断名 %q 重复：%d 与 %d", s, uint16(prev), uint16(name))
		} else {
			seen[s] = name
		}
	}
	if got := msgTypeNames[MsgDdosEvent]; got != "DdosEvent" {
		t.Fatalf("DdosEvent 名=%q", got)
	}
	if MsgType(0).Known() || MsgType(25).Known() {
		t.Fatalf("未定义的取值不应判为已知")
	}
	if got := MsgType(99).String(); got != "未知(99)" {
		t.Fatalf("未知类型名=%q", got)
	}
}

func TestSeqEchoedReplySet(t *testing.T) {
	echoed := []MsgType{
		MsgDaemonRegisterAck, MsgConfigAck, MsgStatsResponse, MsgAnalysisResponse,
		MsgListBansResponse, MsgListWhitelistResponse, MsgListRatesResponse,
	}
	for _, m := range echoed {
		if !m.SeqEchoedReply() {
			t.Errorf("%s 应参与 seq 配对", m)
		}
	}
	notEchoed := []MsgType{
		MsgDdosEvent, MsgBanStateChange, MsgCmdResult, MsgConfigChange,
		MsgWhitelistStateChange, MsgBanIP, MsgUnbanIP,
	}
	for _, m := range notEchoed {
		if m.SeqEchoedReply() {
			t.Errorf("%s 不应参与 seq 配对（内核自增序号或单向推送）", m)
		}
	}
}
