// 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。
// 单一真相源: netlink.fwidl
// 注意：netlink 线格式只涉及内核与 daemon；本 TS 产物供调试工具使用。

export const FW_NL_MAGIC = 0x46574C4E;

export enum AddrFamily {
  Inet = 2,
  Inet6 = 10,
}

export enum BanAction {
  Ban = 1,
  Unban = 2,
}

export enum WhitelistAction {
  Add = 1,
  Remove = 2,
}

export enum MsgType {
  DdosEvent = 1,
  BanIp = 2,
  UnbanIp = 3,
  SetConfig = 4,
  BanStateChange = 5,
  ListBansQuery = 6,
  ListBansResponse = 7,
  StatsQuery = 8,
  StatsResponse = 9,
  ListWhitelistQuery = 10,
  ListWhitelistResponse = 11,
  AddWhitelist = 12,
  RemoveWhitelist = 13,
  ConfigAck = 14,
  ListRatesQuery = 15,
  ListRatesResponse = 16,
  WhitelistStateChange = 17,
  CmdResult = 18,
  ConfigChange = 19,
  AnalysisQuery = 20,
  AnalysisResponse = 21,
  DaemonRegister = 22,
  DaemonRegisterAck = 23,
}

export const ConfigFlags = {
  BAN_TIME: 1 << 0,
  RATE_WINDOW: 1 << 1,
  MAX_PPS: 1 << 2,
  MAX_BPS: 1 << 3,
  MAX_SYN: 1 << 4,
  MAX_UDP: 1 << 5,
  MAX_ICMP: 1 << 6,
  MAX_ACK: 1 << 7,
  MAX_RST: 1 << 8,
  MAX_FIN: 1 << 9,
  DYNAMIC_THRESHOLD: 1 << 10,
  BASELINE_UPDATE: 1 << 11,
  DDOS_BAN_DURATION: 1 << 12,
} as const;

export const DynThresholdFlags = {
  ENABLED: 1 << 0,
} as const;

export interface MsgHdr {
  magic: number;
  msg_type: number;
  msg_len: number;
  seq: number;
}

export interface DdosEvent {
  hdr: MsgHdr;
  af: number;
  reason: string;
  rate_pps: number;
  addr: Uint8Array;
}

export interface BanStateChange {
  hdr: MsgHdr;
  action: number;
  af: number;
  duration_secs: number;
  addr: Uint8Array;
  reason: string;
  jail_name: string;
  packets_dropped: number;
  packets_accepted: number;
  current_bans: number;
  whitelist_count: number;
}

export interface WhitelistStateChange {
  hdr: MsgHdr;
  action: number;
  af: number;
  prefix_len: number;
  addr: Uint8Array;
  device: string;
  whitelist_count: number;
}

export interface CmdResult {
  hdr: MsgHdr;
  original_cmd: number;
  pad: number;
  error_code: number;
  af: number;
  addr: Uint8Array;
}

export interface ConfigAck {
  hdr: MsgHdr;
  applied_flags: number;
  rejected_flags: number;
}

export interface ConfigChange {
  hdr: MsgHdr;
  flags: number;
  ban_time: number;
  rate_window_seconds: number;
  max_packets_per_second: number;
  max_bytes_per_second: number;
  max_syn_per_second: number;
  max_udp_per_second: number;
  max_icmp_per_second: number;
  max_ack_per_second: number;
  max_rst_per_second: number;
  max_fin_per_second: number;
  dynamic_threshold_flags: number;
  dynamic_threshold_ratio_x100: number;
  baseline_pps: number;
  baseline_bps: number;
  ddos_ban_duration: number;
}

export interface BanEntry {
  af: number;
  is_permanent: number;
  duration_secs: number;
  banned_at: number;
  addr: Uint8Array;
  jail_name: string;
  reason: string;
}

export interface ListBansResponse {
  hdr: MsgHdr;
  count: number;
  total: number;
  offset: number;
}

export interface StatsResponse {
  hdr: MsgHdr;
  current_bans: number;
  total_bans: number;
  total_unbans: number;
  whitelist_count: number;
  packets_dropped: number;
  packets_accepted: number;
}

export interface WhitelistEntry {
  af: number;
  prefix_len: number;
  addr: Uint8Array;
  device: string;
}

export interface ListWhitelistResponse {
  hdr: MsgHdr;
  count: number;
  total: number;
  offset: number;
}

export interface RateEntry {
  af: number;
  pad: Uint8Array;
  packets: number;
  bytes: number;
  syn_packets: number;
  udp_packets: number;
  icmp_packets: number;
  ack_packets: number;
  rst_packets: number;
  fin_packets: number;
  addr: Uint8Array;
}

export interface ListRatesResponse {
  hdr: MsgHdr;
  count: number;
  total: number;
  offset: number;
  global_pps: number;
  global_bps: number;
}

export interface UdpPortItem {
  port: number;
  packets: number;
  bytes: number;
  last_seen_secs: number;
}

export interface IcmpTypeItem {
  type: number;
  code: number;
  packets: number;
  bytes: number;
  last_seen_secs: number;
}

export interface ScannerItem {
  af: number;
  pad: Uint8Array;
  addr: Uint8Array;
  metric: number;
  packets: number;
}

export interface AnalysisResponse {
  hdr: MsgHdr;
  pkt_sizes: number;
  ttl_dist: number;
  ip_frag_total: number;
  ip_frag_count: number;
  udp_port_count: number;
  udp_port_capacity: number;
  udp_ports: UdpPortItem[];
  icmp_type_count: number;
  icmp_type_capacity: number;
  icmp_types: IcmpTypeItem[];
  port_scan_count: number;
  port_scan_threshold: number;
  port_scanners: ScannerItem[];
  service_probe_count: number;
  service_probe_threshold: number;
  service_probes: ScannerItem[];
}

export interface DaemonRegisterAck {
  hdr: MsgHdr;
  accepted: number;
}

export interface BanIp {
  hdr: MsgHdr;
  af: number;
  duration_secs: number;
  addr: Uint8Array;
  reason: string;
}

export interface UnbanIp {
  hdr: MsgHdr;
  af: number;
  duration_secs: number;
  addr: Uint8Array;
  reason: string;
}

export interface SetConfig {
  hdr: MsgHdr;
  flags: number;
  ban_time: number;
  rate_window_seconds: number;
  max_packets_per_second: number;
  max_bytes_per_second: number;
  max_syn_per_second: number;
  max_udp_per_second: number;
  max_icmp_per_second: number;
  max_ack_per_second: number;
  max_rst_per_second: number;
  max_fin_per_second: number;
  dynamic_threshold_flags: number;
  dynamic_threshold_ratio_x100: number;
  baseline_pps: number;
  baseline_bps: number;
  ddos_ban_duration: number;
}

export interface ListBansQuery {
  hdr: MsgHdr;
  offset: number;
  limit: number;
}

export interface ListWhitelistQuery {
  hdr: MsgHdr;
  offset: number;
  limit: number;
}

export interface ListRatesQuery {
  hdr: MsgHdr;
  offset: number;
  limit: number;
}

export interface AddWhitelist {
  hdr: MsgHdr;
  af: number;
  prefix_len: number;
  addr: Uint8Array;
  device: string;
}

export interface RemoveWhitelist {
  hdr: MsgHdr;
  af: number;
  prefix_len: number;
  addr: Uint8Array;
  device: string;
}

export interface StatsQuery {
  hdr: MsgHdr;
}

export interface AnalysisQuery {
  hdr: MsgHdr;
}

export interface DaemonRegister {
  hdr: MsgHdr;
}

/**
 * 每种结构体/消息的线格式字节数（packed，无填充）。
 * 变长尾部的条目不计入：条目按 count 字段个跟在定长部分之后。
 */
export const WIRE_SIZES: Record<string, number> = {
  MsgHdr: 12,
  DdosEvent: 65,
  BanStateChange: 122,
  WhitelistStateChange: 51,
  CmdResult: 37,
  ConfigAck: 20,
  ConfigChange: 116,
  BanEntry: 94,
  ListBansResponse: 24,
  StatsResponse: 60,
  WhitelistEntry: 34,
  ListWhitelistResponse: 24,
  RateEntry: 84,
  ListRatesResponse: 40,
  UdpPortItem: 26,
  IcmpTypeItem: 26,
  ScannerItem: 32,
  AnalysisResponse: 4756,
  DaemonRegisterAck: 13,
  BanIp: 65,
  UnbanIp: 65,
  SetConfig: 116,
  ListBansQuery: 20,
  ListWhitelistQuery: 20,
  ListRatesQuery: 20,
  AddWhitelist: 46,
  RemoveWhitelist: 46,
  StatsQuery: 12,
  AnalysisQuery: 12,
  DaemonRegister: 12,
};

/** 变长消息的分页上限：count 最大取值、定长部分字节数、单条字节数。 */
export const TAIL_LIMITS: Record<string, { maxEntries: number; fixedSize: number; elemSize: number }> = {
  ListBansResponse: { maxEntries: 696, fixedSize: 24, elemSize: 94 },
  ListWhitelistResponse: { maxEntries: 1926, fixedSize: 24, elemSize: 34 },
  ListRatesResponse: { maxEntries: 779, fixedSize: 40, elemSize: 84 },
};
