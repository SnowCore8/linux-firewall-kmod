package contract

import (
	"bytes"
	"net"
	"testing"
)

// 本文件做往返验证：编码后解码须还原字段，且长度必须等于契约声明。
// 取值刻意包含非零 seq、非 ASCII 字符串与边界地址族，避免「全零恰好通过」。

func mustAddr16(t *testing.T, af AddrFamily, s string) Addr16 {
	t.Helper()
	a, err := Addr16FromIP(af, net.ParseIP(s))
	if err != nil {
		t.Fatalf("构造 addr16 失败（%s，%s）: %v", s, s, err)
	}
	return a
}

func mustLen(t *testing.T, name string, b []byte) {
	t.Helper()
	if want := wireLayouts[name].size; len(b) != want {
		t.Fatalf("%s 编码长度 %d，契约声明 %d", name, len(b), want)
	}
}

func TestRoundTripDdosEvent(t *testing.T) {
	in := DdosEvent{
		AF:      AFInet6,
		Reason:  "速率超限",
		RatePPS: 0x0102_0304,
		Addr:    mustAddr16(t, AFInet6, "2001:db8::1"),
	}
	b, err := in.Encode(0xDEADBEEF)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "DdosEvent", b)
	var out DdosEvent
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	h, _ := ParseHeader(b)
	if h.Seq != 0xDEADBEEF || h.MsgType != MsgDdosEvent || h.MsgLen != 65 {
		t.Fatalf("头不符: %+v", h)
	}
	if out.AF != in.AF || out.Reason != in.Reason || out.RatePPS != in.RatePPS || out.Addr != in.Addr {
		t.Fatalf("往返不一致: 得到 %+v，期望 %+v", out, in)
	}
}

func TestRoundTripBanStateChange(t *testing.T) {
	in := BanStateChange{
		Action:          BanActionUnban,
		AF:              AFInet,
		PrefixLen:       24,
		DurationSecs:    3600,
		Addr:            mustAddr16(t, AFInet, "203.0.113.7"),
		Reason:          "ssh 爆破",
		JailName:        "sshd",
		PacketsDropped:  1 << 40,
		PacketsAccepted: 1<<40 + 7,
		CurrentBans:     9,
		WhitelistCount:  3,
	}
	b, err := in.Encode(7)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "BanStateChange", b)
	var out BanStateChange
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if out != in {
		t.Fatalf("往返不一致: 得到 %+v，期望 %+v", out, in)
	}
	if out.IsPermanent() {
		t.Fatal("duration_secs=3600 不应被判为永久")
	}
}

func TestRoundTripWhitelistStateChange(t *testing.T) {
	in := WhitelistStateChange{
		Action:         WhitelistActionAdd,
		AF:             AFInet,
		PrefixLen:      32,
		Addr:           mustAddr16(t, AFInet, "198.51.100.9"),
		Device:         "eth0",
		WhitelistCount: 12,
	}
	b, err := in.Encode(1)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "WhitelistStateChange", b)
	var out WhitelistStateChange
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if out != in {
		t.Fatalf("往返不一致: 得到 %+v，期望 %+v", out, in)
	}
}

func TestRoundTripCmdResult(t *testing.T) {
	in := CmdResult{
		OriginalCmd: MsgBanIP,
		ErrorCode:   -13,
		AF:          AFInet6,
		Addr:        mustAddr16(t, AFInet6, "2001:db8::dead"),
	}
	b, err := in.Encode(3)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "CmdResult", b)
	var out CmdResult
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if out != in {
		t.Fatalf("往返不一致: 得到 %+v，期望 %+v", out, in)
	}
	if out.ErrorCode != -13 {
		t.Fatalf("负错误码未保号: %d", out.ErrorCode)
	}
}

func TestRoundTripConfigAck(t *testing.T) {
	in := ConfigAck{
		AppliedFlags:  ConfigFlagBanTime | ConfigFlagMaxPPS,
		RejectedFlags: ConfigFlagDdosBanDuration,
	}
	b, err := in.Encode(5)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "ConfigAck", b)
	var out ConfigAck
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if out != in {
		t.Fatalf("往返不一致: 得到 %+v，期望 %+v", out, in)
	}
}

func TestRoundTripConfigPayload(t *testing.T) {
	in := ConfigPayload{
		Flags:                     ConfigFlagBanTime | ConfigFlagDynamicThreshold | ConfigFlagDdosBanDuration,
		BanTime:                   900,
		RateWindowSeconds:         10,
		MaxPacketsPerSecond:       100000,
		MaxBytesPerSecond:         1 << 30,
		MaxSynPerSecond:           500,
		MaxUDPPerSecond:           20000,
		MaxICMPPerSecond:          1000,
		MaxACKPerSecond:           30000,
		MaxRSTPerSecond:           700,
		MaxFINPerSecond:           800,
		DynamicThresholdFlags:     DynThresholdFlagEnabled,
		DynamicThresholdRatioX100: 250,
		BaselinePPS:               12345,
		BaselineBPS:               987654321,
		DdosBanDuration:           600,
	}
	var sc SetConfig
	sc.ConfigPayload = in
	b, err := sc.Encode(11)
	if err != nil {
		t.Fatalf("SetConfig 编码失败: %v", err)
	}
	mustLen(t, "SetConfig", b)
	var scOut SetConfig
	if err := scOut.Decode(b); err != nil {
		t.Fatalf("SetConfig 解码失败: %v", err)
	}
	if scOut.ConfigPayload != in {
		t.Fatalf("SetConfig 载荷往返不一致: 得到 %+v，期望 %+v", scOut.ConfigPayload, in)
	}

	var cc ConfigChange
	cc.ConfigPayload = in
	cb, err := cc.Encode(12)
	if err != nil {
		t.Fatalf("ConfigChange 编码失败: %v", err)
	}
	mustLen(t, "ConfigChange", cb)
	var ccOut ConfigChange
	if err := ccOut.Decode(cb); err != nil {
		t.Fatalf("ConfigChange 解码失败: %v", err)
	}
	if ccOut.ConfigPayload != in {
		t.Fatalf("ConfigChange 载荷往返不一致: 得到 %+v，期望 %+v", ccOut.ConfigPayload, in)
	}
}

func TestRoundTripBanIpAndUnbanIp(t *testing.T) {
	ban := BanIp{
		AF:           AFInet,
		PrefixLen:    24,
		DurationSecs: 3600,
		Addr:         mustAddr16(t, AFInet, "203.0.113.99"),
		Reason:       "手动封禁",
	}
	b, err := ban.Encode(21)
	if err != nil {
		t.Fatalf("BanIp 编码失败: %v", err)
	}
	mustLen(t, "BanIp", b)
	var gotBan BanIp
	if err := gotBan.Decode(b); err != nil {
		t.Fatalf("BanIp 解码失败: %v", err)
	}
	if gotBan != ban {
		t.Fatalf("BanIp 往返不一致: 得到 %+v，期望 %+v", gotBan, ban)
	}

	unban := UnbanIp{AF: AFInet6, PrefixLen: 64, Addr: mustAddr16(t, AFInet6, "2001:db8:1::")}
	ub, err := unban.Encode(22)
	if err != nil {
		t.Fatalf("UnbanIp 编码失败: %v", err)
	}
	mustLen(t, "UnbanIp", ub)
	var gotUnban UnbanIp
	if err := gotUnban.Decode(ub); err != nil {
		t.Fatalf("UnbanIp 解码失败: %v", err)
	}
	if gotUnban != unban {
		t.Fatalf("UnbanIp 往返不一致: 得到 %+v，期望 %+v", gotUnban, unban)
	}
}

func TestRoundTripProtectedPorts(t *testing.T) {
	var in SetProtectedPorts
	in.Count = 3
	in.SetPort(22)
	in.SetPort(443)
	in.SetPort(65535)
	b, err := in.Encode(31)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "SetProtectedPorts", b)
	var out SetProtectedPorts
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if out.Count != in.Count {
		t.Fatalf("count 往返不一致: %d", out.Count)
	}
	for _, p := range []uint16{22, 443, 65535} {
		if !out.IsPortSet(p) {
			t.Fatalf("端口 %d 应置位", p)
		}
	}
	for _, p := range []uint16{0, 21, 80, 65534} {
		if out.IsPortSet(p) {
			t.Fatalf("端口 %d 不应置位", p)
		}
	}
}

func TestRoundTripPagedResponses(t *testing.T) {
	bans := ListBansResponse{
		Total:  2,
		Offset: 0,
		Entries: []BanEntry{
			{AF: AFInet, PrefixLen: 32, DurationSecs: 3600, BannedAt: 1700000000, Addr: mustAddr16(t, AFInet, "203.0.113.1"), JailName: "sshd", Reason: "爆破"},
			{AF: AFInet6, IsPermanent: true, PrefixLen: 128, BannedAt: 1700000001, Addr: mustAddr16(t, AFInet6, "2001:db8::2"), JailName: "sshd", Reason: "永久"},
		},
	}
	bb, err := bans.Encode(41)
	if err != nil {
		t.Fatalf("ListBansResponse 编码失败: %v", err)
	}
	if want := 24 + 2*95; len(bb) != want {
		t.Fatalf("ListBansResponse 长度 %d，期望 %d", len(bb), want)
	}
	var bansOut ListBansResponse
	if err := bansOut.Decode(bb); err != nil {
		t.Fatalf("ListBansResponse 解码失败: %v", err)
	}
	if bansOut.Count != 2 || bansOut.Total != 2 || len(bansOut.Entries) != 2 {
		t.Fatalf("ListBansResponse 头部往返不一致: %+v", bansOut)
	}
	for i := range bans.Entries {
		if bansOut.Entries[i] != bans.Entries[i] {
			t.Fatalf("ListBansResponse 第 %d 条不一致: 得到 %+v，期望 %+v", i, bansOut.Entries[i], bans.Entries[i])
		}
	}

	wl := ListWhitelistResponse{
		Total:   1,
		Entries: []WhitelistEntry{{AF: AFInet, PrefixLen: 8, Addr: mustAddr16(t, AFInet, "10.0.0.0"), Device: "eth0"}},
	}
	wb, err := wl.Encode(42)
	if err != nil {
		t.Fatalf("ListWhitelistResponse 编码失败: %v", err)
	}
	if want := 24 + 34; len(wb) != want {
		t.Fatalf("ListWhitelistResponse 长度 %d，期望 %d", len(wb), want)
	}
	var wlOut ListWhitelistResponse
	if err := wlOut.Decode(wb); err != nil {
		t.Fatalf("ListWhitelistResponse 解码失败: %v", err)
	}
	if wlOut.Entries[0] != wl.Entries[0] {
		t.Fatalf("ListWhitelistResponse 条目不一致: %+v", wlOut.Entries[0])
	}

	rates := ListRatesResponse{
		Total:     1,
		GlobalPPS: 123456789,
		GlobalBPS: 1 << 33,
		Entries: []RateEntry{{
			AF: AFInet, Packets: 1000, Bytes: 1 << 20, SynPackets: 10, UDPPackets: 20,
			ICMPPackets: 30, ACKPackets: 40, RSTPackets: 50, FINPackets: 60,
			UniquePorts: 7, Addr: mustAddr16(t, AFInet, "192.0.2.5"),
		}},
	}
	rb, err := rates.Encode(43)
	if err != nil {
		t.Fatalf("ListRatesResponse 编码失败: %v", err)
	}
	if want := 40 + 88; len(rb) != want {
		t.Fatalf("ListRatesResponse 长度 %d，期望 %d", len(rb), want)
	}
	var ratesOut ListRatesResponse
	if err := ratesOut.Decode(rb); err != nil {
		t.Fatalf("ListRatesResponse 解码失败: %v", err)
	}
	if ratesOut.GlobalPPS != rates.GlobalPPS || ratesOut.GlobalBPS != rates.GlobalBPS {
		t.Fatalf("ListRatesResponse 全局速率不一致: %+v", ratesOut)
	}
	if ratesOut.Entries[0] != rates.Entries[0] {
		t.Fatalf("ListRatesResponse 条目不一致: 得到 %+v，期望 %+v", ratesOut.Entries[0], rates.Entries[0])
	}
}

func TestRoundTripStatsResponse(t *testing.T) {
	in := StatsResponse{
		CurrentBans: 5, TotalBans: 100, TotalUnbans: 95,
		WhitelistCount: 4, PacketsDropped: 1 << 45, PacketsAccepted: 1<<45 + 1,
	}
	b, err := in.Encode(51)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "StatsResponse", b)
	var out StatsResponse
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if out != in {
		t.Fatalf("往返不一致: 得到 %+v，期望 %+v", out, in)
	}
}

func TestRoundTripQueries(t *testing.T) {
	lb := ListBansQuery{Offset: 100, Limit: 50}
	b, err := lb.Encode(61)
	if err != nil {
		t.Fatalf("ListBansQuery 编码失败: %v", err)
	}
	mustLen(t, "ListBansQuery", b)
	var lbOut ListBansQuery
	if err := lbOut.Decode(b); err != nil {
		t.Fatalf("ListBansQuery 解码失败: %v", err)
	}
	if lbOut != lb {
		t.Fatalf("ListBansQuery 往返不一致: %+v", lbOut)
	}

	lw := ListWhitelistQuery{Offset: 7, Limit: 25}
	wb, err := lw.Encode(62)
	if err != nil {
		t.Fatalf("ListWhitelistQuery 编码失败: %v", err)
	}
	mustLen(t, "ListWhitelistQuery", wb)
	var lwOut ListWhitelistQuery
	if err := lwOut.Decode(wb); err != nil {
		t.Fatalf("ListWhitelistQuery 解码失败: %v", err)
	}
	if lwOut != lw {
		t.Fatalf("ListWhitelistQuery 往返不一致: %+v", lwOut)
	}

	lr := ListRatesQuery{Offset: 0, Limit: 1000}
	rb, err := lr.Encode(63)
	if err != nil {
		t.Fatalf("ListRatesQuery 编码失败: %v", err)
	}
	mustLen(t, "ListRatesQuery", rb)
	var lrOut ListRatesQuery
	if err := lrOut.Decode(rb); err != nil {
		t.Fatalf("ListRatesQuery 解码失败: %v", err)
	}
	if lrOut != lr {
		t.Fatalf("ListRatesQuery 往返不一致: %+v", lrOut)
	}
}

func TestRoundTripWhitelistMutations(t *testing.T) {
	add := AddWhitelist{AF: AFInet, PrefixLen: 32, Addr: mustAddr16(t, AFInet, "203.0.113.10"), Device: "eth1"}
	b, err := add.Encode(71)
	if err != nil {
		t.Fatalf("AddWhitelist 编码失败: %v", err)
	}
	mustLen(t, "AddWhitelist", b)
	var addOut AddWhitelist
	if err := addOut.Decode(b); err != nil {
		t.Fatalf("AddWhitelist 解码失败: %v", err)
	}
	if addOut != add {
		t.Fatalf("AddWhitelist 往返不一致: 得到 %+v，期望 %+v", addOut, add)
	}

	rem := RemoveWhitelist{AF: AFInet6, PrefixLen: 48, Addr: mustAddr16(t, AFInet6, "2001:db8:2::"), Device: ""}
	rb, err := rem.Encode(72)
	if err != nil {
		t.Fatalf("RemoveWhitelist 编码失败: %v", err)
	}
	mustLen(t, "RemoveWhitelist", rb)
	var remOut RemoveWhitelist
	if err := remOut.Decode(rb); err != nil {
		t.Fatalf("RemoveWhitelist 解码失败: %v", err)
	}
	if remOut != rem {
		t.Fatalf("RemoveWhitelist 往返不一致: 得到 %+v，期望 %+v", remOut, rem)
	}
}

func TestRoundTripDaemonRegisterAck(t *testing.T) {
	for _, accepted := range []bool{true, false} {
		in := DaemonRegisterAck{Accepted: accepted}
		b, err := in.Encode(81)
		if err != nil {
			t.Fatalf("编码失败: %v", err)
		}
		mustLen(t, "DaemonRegisterAck", b)
		var out DaemonRegisterAck
		if err := out.Decode(b); err != nil {
			t.Fatalf("解码失败: %v", err)
		}
		if out.Accepted != accepted {
			t.Fatalf("accepted 往返不一致: 得到 %v，期望 %v", out.Accepted, accepted)
		}
	}
}

func TestHeaderOnlyCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		want MsgType
	}{
		{"StatsQuery", StatsQuery(91), MsgStatsQuery},
		{"AnalysisQuery", AnalysisQuery(92), MsgAnalysisQuery},
		{"DaemonRegister", DaemonRegister(93), MsgDaemonRegister},
	} {
		if len(tc.b) != HdrLen {
			t.Fatalf("%s 长度 %d，期望 %d", tc.name, len(tc.b), HdrLen)
		}
		h, err := DecodeHeaderOnly(tc.b, tc.want)
		if err != nil {
			t.Fatalf("%s 解码失败: %v", tc.name, err)
		}
		if h.MsgLen != HdrLen {
			t.Fatalf("%s msg_len=%d，期望 %d", tc.name, h.MsgLen, HdrLen)
		}
	}
}

func TestRoundTripAnalysisResponse(t *testing.T) {
	var in AnalysisResponse
	for i := range in.PktSizes {
		in.PktSizes[i] = uint64(i + 1)
	}
	for i := range in.TTLDist {
		in.TTLDist[i] = uint64(i + 100)
	}
	in.IPFragTotal = 12345
	in.IPFragCount = 67
	in.UDPPortCount = 2
	in.UDPPortCapacity = AnalysisUDPPortCap
	in.UDPPorts[0] = UdpPortItem{Port: 53, Packets: 900, Bytes: 1 << 18, LastSeenSecs: 1700000000}
	in.UDPPorts[1] = UdpPortItem{Port: 123, Packets: 800, Bytes: 1 << 17, LastSeenSecs: 1700000001}
	in.ICMPTypeCount = 1
	in.ICMPTypeCapacity = AnalysisICMPTypeCap
	in.ICMPTypes[0] = IcmpTypeItem{Type: 8, Code: 0, Packets: 500, Bytes: 1 << 15, LastSeenSecs: 1700000002}
	in.PortScanCount = 1
	in.PortScanThreshold = 20
	in.PortScanners[0] = ScannerItem{AF: AFInet, Addr: mustAddr16(t, AFInet, "198.51.100.7"), Metric: 35, Packets: 700}
	in.ServiceProbeCount = 1
	in.ServiceProbeThreshold = 10
	in.ServiceProbes[0] = ScannerItem{AF: AFInet6, Addr: mustAddr16(t, AFInet6, "2001:db8::9"), Metric: 12, Packets: 400}

	b, err := in.Encode(101)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	mustLen(t, "AnalysisResponse", b)
	var out AnalysisResponse
	if err := out.Decode(b); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if out != in {
		t.Fatalf("往返不一致:\n得到 %+v\n期望 %+v", out, in)
	}
}

func TestDecodeRejectsBadMagicAndLength(t *testing.T) {
	b, err := (&DdosEvent{AF: AFInet, Reason: "x"}).Encode(1)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	badMagic := bytes.Clone(b)
	badMagic[0] ^= 0xFF
	var m DdosEvent
	if err := m.Decode(badMagic); err == nil {
		t.Fatal("魔数被篡改后应报错")
	}

	if err := m.Decode(b[:len(b)-1]); err == nil {
		t.Fatal("长度短于 msg_len 时应报错")
	}

	short := bytes.Clone(b)
	short = append(short, 0)
	putU16(short, 6, uint16(len(b)))
	if err := m.Decode(short); err == nil {
		t.Fatal("msg_len 小于实际长度时应报错")
	}
}

func TestDecodeRejectsWrongTypeAndLength(t *testing.T) {
	// 用 StatsResponse 的字节去解 BanStateChange，类型与长度都必须被拒。
	b, err := (&StatsResponse{}).Encode(1)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	var m BanStateChange
	if err := m.Decode(b); err == nil {
		t.Fatal("消息类型不符时应报错")
	}

	// 尾部字节数不是元素整数倍时必须报错。
	bans := ListBansResponse{Total: 1, Entries: []BanEntry{{AF: AFInet, PrefixLen: 32}}}
	bb, err := bans.Encode(2)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	var out ListBansResponse
	if err := out.Decode(bb[:len(bb)-1]); err == nil {
		t.Fatal("尾部非整数倍时应报错")
	}

	// count 与尾部实际条目数不符时必须报错。
	tampered := bytes.Clone(bb)
	putU32(tampered, 12, 5)
	if err := out.Decode(tampered); err == nil {
		t.Fatal("count 与尾部不符时应报错")
	}
}

func TestPutStrRejectsOverlong(t *testing.T) {
	b := make([]byte, wireLayouts["DdosEvent"].size)
	if err := putStr(b, offDdosEvent["reason"], 32, string(make([]byte, 32))); err == nil {
		t.Fatal("刚好占满字段（无结尾 NUL）应被拒绝")
	}
	if _, err := (&BanStateChange{Reason: string(make([]byte, 40))}).Encode(1); err == nil {
		t.Fatal("超长 reason 编码应报错而非静默截断")
	}
}

func TestAddr16FamilyValidation(t *testing.T) {
	v6 := mustAddr16(t, AFInet6, "2001:db8::1")
	ip6, err := v6.IP(AFInet6)
	if err != nil {
		t.Fatalf("IPv6 还原失败: %v", err)
	}
	if _, err := Addr16FromIP(AFInet, ip6); err == nil {
		t.Fatal("把 IPv6 放进 AF_INET 应报错")
	}
	if _, err := Addr16FromIP(AddrFamily(99), nil); err == nil {
		t.Fatal("未定义地址族应报错")
	}
	if _, err := v6.IP(AddrFamily(99)); err == nil {
		t.Fatal("未定义地址族还原应报错")
	}
	a := mustAddr16(t, AFInet, "203.0.113.4")
	got, err := a.IP(AFInet)
	if err != nil {
		t.Fatalf("IPv4 还原失败: %v", err)
	}
	if got.String() != "203.0.113.4" {
		t.Fatalf("IPv4 还原为 %s", got)
	}
}
