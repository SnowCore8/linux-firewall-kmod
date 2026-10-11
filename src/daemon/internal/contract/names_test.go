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

// TestConfigFlagNamesCoverEveryBit 保证「位图里出现的每一位都有名字」。
//
// 拒绝位图是要进响应文本与日志的东西：漏了名字的那一位在运维眼里就是 `none` 或者干脆消失，
// 而 ConfigAck 明明说了「这一位没采纳」。新增位（契约 netlink.fwidl 的 ConfigFlags 表）必须
// 同时进 configFlagFields，这条断言就是拦住那一步的。
func TestConfigFlagNamesCoverEveryBit(t *testing.T) {
	all := ConfigFlagBanTime | ConfigFlagRateWindow | ConfigFlagMaxPPS | ConfigFlagMaxBPS |
		ConfigFlagMaxSYN | ConfigFlagMaxUDP | ConfigFlagMaxICMP | ConfigFlagMaxACK |
		ConfigFlagMaxRST | ConfigFlagMaxFIN | ConfigFlagDynamicThreshold |
		ConfigFlagBaselineUpdate | ConfigFlagDdosBanDuration

	names := all.Names()
	if len(names) != 13 {
		t.Fatalf("全位图的名字 = %d 个，期望 13 个（%v）", len(names), names)
	}
	for _, bit := range []ConfigFlags{
		ConfigFlagBanTime, ConfigFlagRateWindow, ConfigFlagMaxPPS, ConfigFlagMaxBPS,
		ConfigFlagMaxSYN, ConfigFlagMaxUDP, ConfigFlagMaxICMP, ConfigFlagMaxACK,
		ConfigFlagMaxRST, ConfigFlagMaxFIN, ConfigFlagDynamicThreshold,
		ConfigFlagBaselineUpdate, ConfigFlagDdosBanDuration,
	} {
		if len(bit.Names()) != 1 {
			t.Errorf("位 %#x 的名字数 = %d，期望 1 个（%v）", uint32(bit), len(bit.Names()), bit.Names())
		}
	}
	// 按位序列出：响应文本与测试断言都要能依赖这个顺序。
	if got := (ConfigFlagMaxSYN | ConfigFlagBanTime).String(); got != "ban_time|max_syn_per_second" {
		t.Errorf("String() = %q，期望按位序的 \"ban_time|max_syn_per_second\"", got)
	}
	if got := ConfigFlags(0).String(); got != "none" {
		t.Errorf("零位图的 String() = %q，期望 \"none\"", got)
	}
	// 未定义的位（契约表之外）不进名字表：全 1 的位图也不该多出第 14 个名字。
	if got := ConfigFlags(0xFFFF).Names(); len(got) != 13 {
		t.Errorf("未定义位的名字数 = %d，期望仍是 13（%v）", len(got), got)
	}
}
