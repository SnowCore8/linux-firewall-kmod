package kernel

import (
	"fmt"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/contract"
)

// decodeIncoming 按类型把载荷解成事件结构体。
//
// 调用方约定：`payload` 已通过公共头校验，`msgType` 为公共头里的类型。未知类型返回
// 错误，调用方应计为「类型不在契约内」而非「字段解码失败」。
func decodeIncoming(msgType contract.MsgType, payload []byte) (Incoming, error) {
	msg := Incoming{MsgType: msgType}
	h, err := contract.ParseHeader(payload)
	if err == nil {
		msg.Seq = h.Seq
	}
	switch msgType {
	case contract.MsgDdosEvent:
		v := &contract.DdosEvent{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Ddos = v
	case contract.MsgBanStateChange:
		v := &contract.BanStateChange{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Ban = v
	case contract.MsgWhitelistStateChange:
		v := &contract.WhitelistStateChange{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.WL = v
	case contract.MsgCmdResult:
		v := &contract.CmdResult{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Cmd = v
	case contract.MsgConfigAck:
		v := &contract.ConfigAck{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.CfgAck = v
	case contract.MsgConfigChange:
		v := &contract.ConfigChange{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.CfgChg = v
	case contract.MsgStatsResponse:
		v := &contract.StatsResponse{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Stats = v
	case contract.MsgListBansResponse:
		v := &contract.ListBansResponse{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Bans = v
	case contract.MsgListWhitelistResponse:
		v := &contract.ListWhitelistResponse{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Wls = v
	case contract.MsgListRatesResponse:
		v := &contract.ListRatesResponse{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Rates = v
	case contract.MsgAnalysisResponse:
		v := &contract.AnalysisResponse{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.Analysis = v
	case contract.MsgDaemonRegisterAck:
		v := &contract.DaemonRegisterAck{}
		if err := v.Decode(payload); err != nil {
			return Incoming{}, err
		}
		msg.RegAck = v
	default:
		return Incoming{}, fmt.Errorf("消息类型 %d 不在受理解码范围内", uint16(msgType))
	}
	return msg, nil
}

// decodeHeader 解析公共头；魔数与长度不符即报错。
//
// 契约要求 msg_len 恒为「含头的总长度」，静默接受截断会把错位字段读成合法值。
func decodeHeader(payload []byte) (contract.Header, error) {
	if len(payload) < contract.HdrLen {
		return contract.Header{}, fmt.Errorf("载荷短于公共头：%d < %d", len(payload), contract.HdrLen)
	}
	// 公共头是大端（与自定义载荷一致）；host 字段在 nlmsghdr 里，不在此处。
	var h contract.Header
	h.MsgType = contract.MsgType(beU16(payload[4:6]))
	h.MsgLen = beU16(payload[6:8])
	h.Seq = beU32(payload[8:12])
	if beU32(payload[0:4]) != contract.Magic {
		return contract.Header{}, fmt.Errorf("魔数不匹配：0x%08X", beU32(payload[0:4]))
	}
	if int(h.MsgLen) != len(payload) {
		return contract.Header{}, fmt.Errorf("msg_len=%d 与实际长度 %d 不符", h.MsgLen, len(payload))
	}
	return h, nil
}

func beU16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func beU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// ClampTimeout 把超时收敛到不小于零，零表示立即可返回。
func ClampTimeout(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}
