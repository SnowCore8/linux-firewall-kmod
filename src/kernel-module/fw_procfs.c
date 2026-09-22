// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_procfs.c - /proc/firewall 的全部条目
 *
 * 对外协议由 contract/procfs.fwidl 冻结，生成物 contract/generated/procfs_uapi.h。
 * 本模块是**表现层**：只做「取数 → 格式化」与「解析 → 调模块 API」，不含表结构。
 *
 * 与旧实现的差别（见 docs/zh/development/kernel-rewrite-design.md）：
 *
 *   1. **stats 读前先刷**。旧实现 stats_show 直接读全局 atomic，而热路径只写本
 *      CPU 槽，导致读数陈旧（缺陷 PROC_STATS_STALE_NO_FLUSH）。新实现经
 *      fw_stats_snapshot()，其内部先 fw_stats_flush_all()。
 *
 *   2. **stats 的三个字段来自真正的所有者**。fw_stats_snapshot() 不填
 *      current_bans / current_whitelist / recent_additions（统计模块不反向依赖
 *      封禁表与白名单），由本模块分别取 fw_ban_count() / fw_wl_count() /
 *      fw_ban_recent_additions_stat()。
 *
 *   3. **去掉 "<ip> -1" 解封形式**。旧实现里 validate_duration_string() 只接受
 *      纯数字串，`-1` 根本解析不出来（`kstrtol` 成功但随后的「非数字字符」检查
 *      拒绝），是契约里的死形式（PROC_DEAD_UNBAN_FORM）。解封统一用 "unban <ip>"。
 *
 *   4. **封禁不再重复推事件**。旧实现自己调 fw_netlink_send_ban_state_change；
 *      新实现交给 fw_ban_try_add(notify=true) —— 泛洪闸门与事件推送都在封禁模块
 *      内统一，procfs / netlink / DDoS 三条路径行为一致。
 *
 *   5. **白名单 remove 不再自查本机 IP**。旧实现在这里用子网比较判断「本机接口
 *      IP」，接口配 /24 时整个网段的显式条目都删不掉
 *      （PROC_WHITELIST_REMOVE_SUBNET_OVERREACH）。新实现把该判定交给
 *      fw_wl_remove()（精确主机地址哈希集），本模块只负责归一化地址。
 *
 *   6. **白名单增删由本模块推送事件**。fw_wl_add() / fw_wl_remove() 自身不推送
 *      （与 fw_ban_add / fw_ban_del 不同），调用方负责发
 *      WHITELIST_STATE_CHANGE，本模块是手动条目的唯一来源。
 *
 * 已知取舍（写入契约修订说明）：
 *   - 11 个 unstable 条目的表格布局尽量保持旧样；唯 rates 的窗口列打印的是
 *     **配置的窗口宽度**（fw_info.rate_window_seconds），因为读侧行结构
 *     (struct fw_rate_row) 不带每条的窗口起点，而设计上不允许为读侧给热路径
 *     条目加共享字段。
 *   - udp_ports / icmp_types 的展示行数受 FW_ANALYSIS_*_PACK_MAX（64）限制
 *     （与 netlink AnalysisResponse 共用同一快照）；"Total entries" 行打印的
 *     是分析表的真实条目数（fw_info.udp_port_count / icmp_type_count）。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/inet.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "fw_procfs.h"
#include "fw_ban.h"
#include "fw_ports.h"
#include "fw_wl.h"
#include "fw_rate.h"
#include "fw_stats.h"
#include "fw_netlink.h"

/* 分页取数时的单页行数：限制单次 kmalloc 大小，避免读侧大块分配 */
#define FW_PROCFS_BAN_PAGE 32
#define FW_PROCFS_WL_PAGE 64
#define FW_PROCFS_RATE_PAGE 64

/* 受控输入上限：bans 的命令最长 "<ip> <seconds>"，whitelist 最长 "remove <subnet>" */
#define FW_PROCFS_BANS_INPUT 256
#define FW_PROCFS_WHITELIST_INPUT (FW_INET6_STR_LEN + 16)
#define FW_PROCFS_CONFIG_INPUT 256

/* ============================================================================
 * 写侧公共：取用户输入、截断、去尾换行、拒绝控制字符
 * ==========================================================================*/

/*
 * 取一条命令到 out（已 NUL 结尾）。返回 0 成功，负 errno 失败。
 * 控制字符策略（契约）：除 '\t' 外一律拒绝 < 0x20，**不区分位置**，
 * 因此 '\r' 也会被拒——旧实现的检查顺序正是如此。
 */
static int fw_procfs_read_cmd(const char __user *buf, size_t count, char *out, size_t out_size) {
  size_t len, i;

  if (count > out_size - 1)
    return -EINVAL;
  len = count;

  if (copy_from_user(out, buf, len))
    return -EFAULT;
  out[len] = '\0';

  if (len > 0 && out[len - 1] == '\n')
    out[len - 1] = '\0';

  for (i = 0; i < len && out[i] != '\0'; i++) {
    if (out[i] < 0x20 && out[i] != '\t')
      return -EINVAL;
  }
  return 0;
}

/*
 * 解析地址串为 (af, addr)。返回 0 成功；-EINVAL 表示不是合法地址或被拒的
 * 特殊地址（0.0.0.0 / 广播 / 组播 / 回环 / 链路本地等，见 fw_addr_is_valid）。
 */
static int fw_procfs_parse_addr(const char *str, u8 *af, union fw_addr *addr) {
  if (in4_pton(str, -1, (u8 *)&addr->ipv4, -1, NULL)) {
    *af = FW_AF_INET;
  } else if (in6_pton(str, -1, (u8 *)&addr->ipv6, -1, NULL)) {
    *af = FW_AF_INET6;
  } else {
    return -EINVAL;
  }

  if (!fw_addr_is_valid(*af, addr))
    return -EINVAL;
  return 0;
}

/* ============================================================================
 * bans：<ip> | <ip> <seconds> | <ip> 0 | unban <ip>
 * ==========================================================================*/

/*
 * 解析 IP 之后的时长字段。
 *   *has == false      ：未给出时长，使用内核默认 fw_ban_time（契约 BAN_DEFAULT）
 *   *has == true, *v==0：永久（契约 BAN_PERMANENT）
 *   *has == true, *v>0 ：指定秒数（契约 BAN_TIMED），上限 FW_BAN_TIME_MAX
 * 负数与非纯数字串一律 -EINVAL（不保留旧的 "-1 即解封" 死形式）。
 */
static int fw_procfs_parse_duration(const char *rest, bool *has, u32 *v) {
  const char *p = rest;
  unsigned long val;
  int ret;

  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0') {
    *has = false;
    return 0;
  }

  /* 只接受十进制数字；遇到其他字符（含 '-'、'\r' 残留）即拒绝 */
  {
    const char *q = p;

    while (*q >= '0' && *q <= '9')
      q++;
    while (*q == ' ' || *q == '\t')
      q++;
    if (*q != '\0')
      return -EINVAL;
  }

  ret = kstrtoul(p, 10, &val);
  if (ret)
    return -EINVAL;
  if (val > FW_BAN_TIME_MAX)
    return -EINVAL;

  *has = true;
  *v = (u32)val;
  return 0;
}

static ssize_t bans_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos) {
  char input[FW_PROCFS_BANS_INPUT];
  union fw_addr addr;
  u8 af;
  const char *p;
  char ip_str[FW_INET6_STR_LEN];
  bool is_unban = false, has_duration = false;
  u32 duration = 0;
  int ret;

  if (count == 0)
    return 0;

  ret = fw_procfs_read_cmd(buf, count, input, sizeof(input));
  if (ret)
    return ret;

  p = input;
  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0')
    return -EINVAL;

  if (strncmp(p, "unban ", 6) == 0 || strncmp(p, "unban\t", 6) == 0) {
    is_unban = true;
    p += 5;
    while (*p == ' ' || *p == '\t')
      p++;
  }

  /* IP 串到空白为止 */
  {
    const char *end = p;
    size_t n;

    while (*end && *end != ' ' && *end != '\t')
      end++;
    n = (size_t)(end - p);
    if (n == 0 || n >= sizeof(ip_str))
      return -EINVAL;
    memcpy(ip_str, p, n);
    ip_str[n] = '\0';

    /* 解封命令之后不允许再跟东西：一次 write 一条命令 */
    if (is_unban) {
      const char *q = end;

      while (*q == ' ' || *q == '\t')
        q++;
      if (*q != '\0')
        return -EINVAL;
    } else {
      ret = fw_procfs_parse_duration(end, &has_duration, &duration);
      if (ret)
        return ret;
    }
  }

  ret = fw_procfs_parse_addr(ip_str, &af, &addr);
  if (ret)
    return ret;

  if (is_unban)
    ret = fw_ban_del(af, &addr, true);
  else
    ret = fw_ban_try_add(af, &addr, has_duration ? duration : (u32)READ_ONCE(fw_ban_time),
                         "procfs", NULL, true);
  if (ret)
    return ret;

  return count;
}

static int bans_show(struct seq_file *m, void *v) {
  struct fw_ban_row *rows;
  u64 now_unix = ktime_get_real_seconds();
  char ip_str[FW_INET6_STR_LEN];
  int count = 0, permanent = 0, temporary = 0;
  u32 offset = 0;

  rows = kmalloc_array(FW_PROCFS_BAN_PAGE, sizeof(*rows), GFP_KERNEL);
  if (!rows)
    return -ENOMEM;

  seq_printf(m, "Banned IP List:\n");
  seq_printf(m, "-------------------\n");

  for (;;) {
    u32 got = fw_ban_fill_entries(offset, FW_PROCFS_BAN_PAGE, rows);
    u32 i;

    for (i = 0; i < got; i++) {
      struct fw_ban_row *r = &rows[i];

      fw_addr_to_str(r->af, &r->addr, ip_str, sizeof(ip_str));
      if (r->is_permanent) {
        seq_printf(m, "%-40s (permanent)\n", ip_str);
        permanent++;
        count++;
      } else {
        u64 expiry = r->banned_at + r->duration_secs;

        /* 已过期待摘链的条目不再显示（与旧实现一致） */
        if (now_unix >= expiry)
          continue;
        seq_printf(m, "%-40s (expires in %lu seconds)\n", ip_str,
                   (unsigned long)(expiry - now_unix));
        temporary++;
        count++;
      }
    }

    offset += got;
    if (got < FW_PROCFS_BAN_PAGE)
      break;
  }

  kfree(rows);

  seq_printf(m, "-------------------\n");
  seq_printf(m, "Total: %d active bans (%d permanent, %d temporary)\n", count,
             permanent, temporary);
  return 0;
}

static int bans_open(struct inode *inode, struct file *file) {
  return single_open(file, bans_show, NULL);
}

static const struct proc_ops bans_fops = {
  .proc_open = bans_open,
  .proc_read = seq_read,
  .proc_write = bans_write,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* ============================================================================
 * whitelist：add <subnet> | <subnet> | remove <subnet>
 * ==========================================================================*/

/*
 * 解析 [add|remove] <addr>[/prefix]。
 * 默认动作是 add（契约 WHITELIST_OP_ADD_IMPLICIT）；默认前缀为地址族全长。
 */
static int fw_procfs_parse_whitelist_cmd(char *input, bool *is_remove, u8 *af,
                                         union fw_addr *addr, u8 *prefix_len) {
  char *p = input;
  int plen = -1;
  char *slash;

  while (*p == ' ' || *p == '\t')
    p++;
  if (*p == '\0')
    return -EINVAL;

  *is_remove = false;
  if (strncmp(p, "add", 3) == 0 && (p[3] == ' ' || p[3] == '\t')) {
    p += 3;
    while (*p == ' ' || *p == '\t')
      p++;
  } else if (strncmp(p, "remove", 6) == 0 && (p[6] == ' ' || p[6] == '\t')) {
    *is_remove = true;
    p += 6;
    while (*p == ' ' || *p == '\t')
      p++;
  } else if (strncmp(p, "remove", 6) == 0 && p[6] == '\0') {
    return -EINVAL; /* 只有动作、没有子网 */
  }
  if (*p == '\0')
    return -EINVAL;

  /* 子网串到空白为止 */
  {
    char *end = p;

    while (*end && *end != ' ' && *end != '\t')
      end++;
    if (*end) {
      char *q = end;

      while (*q == ' ' || *q == '\t')
        q++;
      if (*q != '\0')
        return -EINVAL;
    }
    *end = '\0';
  }

  slash = strchr(p, '/');
  if (slash) {
    *slash = '\0';
    if (kstrtoint(slash + 1, 10, &plen) < 0)
      return -EINVAL;
    if (plen < 0)
      return -EINVAL;
  }

  if (in4_pton(p, -1, (u8 *)&addr->ipv4, -1, NULL)) {
    *af = FW_AF_INET;
    if (plen < 0)
      plen = 32;
    if (plen > 32)
      return -EINVAL;
  } else if (in6_pton(p, -1, (u8 *)&addr->ipv6, -1, NULL)) {
    *af = FW_AF_INET6;
    if (plen < 0)
      plen = 128;
    if (plen > 128)
      return -EINVAL;
  } else {
    return -EINVAL;
  }

  /*
   * 与旧实现一致的准入：拒绝 0.0.0.0 / 广播 / 组播 / 回环 / 链路本地。
   * 本机接口地址由 fw_netdev.c 自动维护，无需手工添加（也因此不存在
   * 「手工删本机地址」的合法场景）。
   */
  if (!fw_addr_is_valid(*af, addr))
    return -EINVAL;

  *prefix_len = (u8)plen;
  return 0;
}

static ssize_t whitelist_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos) {
  char input[FW_PROCFS_WHITELIST_INPUT];
  union fw_addr addr;
  u8 af, prefix_len;
  bool is_remove;
  int ret;

  if (count == 0)
    return 0;

  ret = fw_procfs_read_cmd(buf, count, input, sizeof(input));
  if (ret)
    return ret;

  ret = fw_procfs_parse_whitelist_cmd(input, &is_remove, &af, &addr, &prefix_len);
  if (ret)
    return ret;

  /* 白名单表存 network 地址：归一化后再增删，否则同一子网会重复入表 */
  fw_addr_normalize(af, &addr, prefix_len);

  if (is_remove) {
    ret = fw_wl_remove(af, &addr, prefix_len);
    if (ret)
      return ret;
    fw_nl_send_whitelist_state_change(
      FW_WHITELIST_ACTION_REMOVE, af, &addr, prefix_len, "manual");
  } else {
    ret = fw_wl_add(af, &addr, prefix_len, "manual");
    if (ret)
      return ret;
    fw_nl_send_whitelist_state_change(FW_WHITELIST_ACTION_ADD, af, &addr, prefix_len, "manual");
  }

  return count;
}

static int whitelist_show(struct seq_file *m, void *v) {
  struct fw_wl_row *rows;
  char ip_str[FW_INET6_STR_LEN];
  u32 offset = 0;

  rows = kmalloc_array(FW_PROCFS_WL_PAGE, sizeof(*rows), GFP_KERNEL);
  if (!rows)
    return -ENOMEM;

  seq_printf(m, "Whitelisted IPs (protected from banning):\n");
  seq_printf(m, "--------------------------------------\n");

  for (;;) {
    u32 got = fw_wl_fill_entries(offset, FW_PROCFS_WL_PAGE, rows);
    u32 i;

    for (i = 0; i < got; i++) {
      fw_addr_to_str(rows[i].af, &rows[i].addr, ip_str, sizeof(ip_str));
      seq_printf(m, "%s/%d  on %s\n", ip_str, rows[i].prefix_len, rows[i].device_name);
    }

    offset += got;
    if (got < FW_PROCFS_WL_PAGE)
      break;
  }

  kfree(rows);

  seq_printf(m, "--------------------------------------\n");
  seq_printf(m, "Total: %d entries\n", (int)fw_wl_count());
  return 0;
}

static int whitelist_open(struct inode *inode, struct file *file) {
  return single_open(file, whitelist_show, NULL);
}

static const struct proc_ops whitelist_fops = {
  .proc_open = whitelist_open,
  .proc_read = seq_read,
  .proc_write = whitelist_write,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* ============================================================================
 * config：ban_time <seconds>
 * ==========================================================================*/

static int config_show(struct seq_file *m, void *v) {
  seq_printf(m, "Current Firewall Configuration:\n");
  seq_printf(m, "--------------------------------\n");
  seq_printf(m, "ban_time: %u seconds\n", READ_ONCE(fw_ban_time));
  seq_printf(m, "Ban entries: %d\n", (int)fw_ban_count());
  seq_printf(m, "Whitelist entries: %d\n", (int)fw_wl_count());
  return 0;
}

static int config_open(struct inode *inode, struct file *file) {
  return single_open(file, config_show, NULL);
}

static ssize_t config_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos) {
  char input[FW_PROCFS_CONFIG_INPUT];
  char *p, *value;
  unsigned long val;
  int ret;

  if (count == 0)
    return 0;

  ret = fw_procfs_read_cmd(buf, count, input, sizeof(input));
  if (ret)
    return ret;

  p = input;
  while (*p == ' ' || *p == '\t')
    p++;

  /* 参数名与取值以空白（空格或制表符）分隔 */
  value = p;
  while (*value && *value != ' ' && *value != '\t')
    value++;
  if (*value == '\0')
    return -EINVAL;
  *value++ = '\0';
  while (*value == ' ' || *value == '\t')
    value++;
  if (*value == '\0')
    return -EINVAL;

  /* 只认 ban_time；未知参数名直接拒绝，避免「静默成功」 */
  if (strcmp(p, "ban_time") != 0)
    return -EINVAL;

  if (kstrtoul(value, 10, &val) || val < FW_BAN_TIME_MIN || val > FW_BAN_TIME_MAX)
    return -EINVAL;

  /* fw_ban_time 是默认封禁时长的唯一真相源（fw_ban_try_add 直接读它） */
  WRITE_ONCE(fw_ban_time, (unsigned int)val);
  fw_nl_send_config_change(FW_CONFIG_FLAGS_BAN_TIME, (u32)val);

  return count;
}

static const struct proc_ops config_fops = {
  .proc_open = config_open,
  .proc_read = seq_read,
  .proc_write = config_write,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* ============================================================================
 * stats：13 个 key 的机器可读格式（契约 read_format = machine，无标题行）
 * ==========================================================================*/

static int stats_show(struct seq_file *m, void *v) {
  struct fw_stats_snapshot s;

  fw_stats_snapshot(&s);

  seq_printf(m, "total_bans %u\n", (unsigned int)s.total_bans);
  seq_printf(m, "total_unbans %u\n", (unsigned int)s.total_unbans);
  seq_printf(m, "whitelist_rejects %u\n", (unsigned int)s.whitelist_rejects);
  seq_printf(m, "ban_table_full_rejects %u\n", (unsigned int)s.ban_table_full_rejects);
  seq_printf(m, "alloc_failures %u\n", (unsigned int)s.alloc_failures);
  seq_printf(m, "packets_dropped %llu\n", (unsigned long long)s.packets_dropped);
  seq_printf(m, "packets_accepted %llu\n", (unsigned long long)s.packets_accepted);
  seq_printf(m, "tcp_anomaly_dropped %llu\n", (unsigned long long)s.tcp_anomaly_dropped);
  seq_printf(m, "cleanup_cycles %u\n", (unsigned int)s.cleanup_cycles);
  seq_printf(m, "cleanup_expired_total %u\n", (unsigned int)s.cleanup_expired_total);
  seq_printf(m, "current_bans %d\n", (int)fw_ban_count());
  seq_printf(m, "current_whitelist %d\n", (int)fw_wl_count());
  seq_printf(m, "recent_additions %u\n", fw_ban_recent_additions_stat());
  return 0;
}

static int stats_open(struct inode *inode, struct file *file) {
  return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_fops = {
  .proc_open = stats_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* ============================================================================
 * rates：速率表快照
 * ==========================================================================*/

static int rates_show(struct seq_file *m, void *v) {
  struct fw_rate_row *rows;
  char ip_str[FW_INET6_STR_LEN];
  u32 offset = 0, count = 0;

  rows = kmalloc_array(FW_PROCFS_RATE_PAGE, sizeof(*rows), GFP_KERNEL);
  if (!rows)
    return -ENOMEM;

  seq_printf(m, "IP Rate Statistics (DDoS Detection):\n");
  seq_printf(m, "------------------------------------\n");
  seq_printf(m, "Configuration:\n");
  seq_printf(m, "  rate_window_seconds: %u\n", fw_info.rate_window_seconds);
  seq_printf(m, "  max_packets_per_second: %lu\n", (unsigned long)fw_info.max_packets_per_second);
  seq_printf(m, "  max_bytes_per_second: %lu\n", (unsigned long)fw_info.max_bytes_per_second);
  seq_printf(m, "------------------------------------\n");
  seq_printf(m, "%-40s %12s %12s %8s\n", "IP Address", "Packets", "Bytes", "Window(s)");

  for (;;) {
    u32 got = fw_rate_fill_entries(offset, FW_PROCFS_RATE_PAGE, rows);
    u32 i;

    for (i = 0; i < got; i++) {
      fw_addr_to_str(rows[i].af, &rows[i].addr, ip_str, sizeof(ip_str));
      seq_printf(m, "%-40s %12llu %12llu %6us\n", ip_str,
                 (unsigned long long)rows[i].packets,
                 (unsigned long long)rows[i].bytes, fw_info.rate_window_seconds);
    }

    offset += got;
    count += got;
    if (got < FW_PROCFS_RATE_PAGE)
      break;
  }

  kfree(rows);

  seq_printf(m, "------------------------------------\n");
  seq_printf(m, "Total: %u active rate entries\n", count);
  return 0;
}

static int rates_open(struct inode *inode, struct file *file) {
  return single_open(file, rates_show, NULL);
}

static const struct proc_ops rates_fops = {
  .proc_open = rates_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* ============================================================================
 * 分析类只读条目：共用一次 fw_stats_read_analysis() 快照
 * ==========================================================================*/

static int udp_ports_show(struct seq_file *m, void *v) {
  struct fw_analysis_snapshot *a;
  u32 i;
  int ret = 0;

  a = kzalloc(sizeof(*a), GFP_KERNEL);
  if (!a)
    return -ENOMEM;
  fw_stats_read_analysis(a);

  seq_printf(m, "UDP Port Distribution:\n");
  seq_printf(m, "----------------------\n");
  seq_printf(m, "Total entries: %d / %d\n",
             atomic_read(&fw_info.udp_port_count), MAX_UDP_PORT_ENTRIES);
  seq_printf(m, "----------------------\n");
  seq_printf(m, "%-8s %12s %12s %10s\n", "Port", "Packets", "Bytes", "LastSeen");

  for (i = 0; i < a->udp_count; i++)
    seq_printf(m, "%-8u %12llu %12llu %8llus\n", a->udp[i].port,
               (unsigned long long)a->udp[i].packets,
               (unsigned long long)a->udp[i].bytes,
               (unsigned long long)a->udp[i].last_seen_secs);

  seq_printf(m, "----------------------\n");
  seq_printf(m, "Displayed: %u ports\n", a->udp_count);

  kfree(a);
  return ret;
}

static int udp_ports_open(struct inode *inode, struct file *file) {
  return single_open(file, udp_ports_show, NULL);
}

static const struct proc_ops udp_ports_fops = {
  .proc_open = udp_ports_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int icmp_types_show(struct seq_file *m, void *v) {
  struct fw_analysis_snapshot *a;
  u32 i;
  int ret = 0;

  a = kzalloc(sizeof(*a), GFP_KERNEL);
  if (!a)
    return -ENOMEM;
  fw_stats_read_analysis(a);

  seq_printf(m, "ICMP Type Distribution:\n");
  seq_printf(m, "-----------------------\n");
  seq_printf(m, "Total entries: %d / %d\n",
             atomic_read(&fw_info.icmp_type_count), MAX_ICMP_TYPE_ENTRIES);
  seq_printf(m, "-----------------------\n");
  seq_printf(m, "%-6s %-6s %12s %12s %10s\n", "Type", "Code", "Packets", "Bytes", "LastSeen");

  for (i = 0; i < a->icmp_count; i++)
    seq_printf(m, "%-6u %-6u %12llu %12llu %8llus\n", a->icmp[i].type,
               a->icmp[i].code, (unsigned long long)a->icmp[i].packets,
               (unsigned long long)a->icmp[i].bytes,
               (unsigned long long)a->icmp[i].last_seen_secs);

  seq_printf(m, "-----------------------\n");
  seq_printf(m, "Displayed: %u types\n", a->icmp_count);

  kfree(a);
  return ret;
}

static int icmp_types_open(struct inode *inode, struct file *file) {
  return single_open(file, icmp_types_show, NULL);
}

static const struct proc_ops icmp_types_fops = {
  .proc_open = icmp_types_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* 包大小 / TTL 两个直方图的公共打印：5 行或 6 行的百分比表 */
static const char *const fw_pkt_size_labels[FW_PKT_SIZE_BUCKETS] = {
  "<64B", "64-256B", "256B-1KB", "1-1.5KB", ">1.5KB"
};
static const char *const fw_ttl_labels[FW_TTL_BUCKETS] = { "=1",      "2-32",
                                                           "33-64",   "65-128",
                                                           "129-192", "193-255" };

static void fw_procfs_print_hist(struct seq_file *m, const char *const *labels,
                                 const u64 *buckets, int n) {
  u64 total = 0;
  int i;

  for (i = 0; i < n; i++)
    total += buckets[i];

  for (i = 0; i < n; i++) {
    if (total)
      seq_printf(m, "%-12s %12llu %7llu%%\n", labels[i], (unsigned long long)buckets[i],
                 (unsigned long long)((buckets[i] * 100) / total));
    else
      seq_printf(m, "%-12s %12llu %7d%%\n", labels[i], (unsigned long long)buckets[i], 0);
  }
}

static int pkt_sizes_show(struct seq_file *m, void *v) {
  struct fw_analysis_snapshot *a = kzalloc(sizeof(*a), GFP_KERNEL);
  u64 total = 0;
  int i;

  if (!a)
    return -ENOMEM;
  fw_stats_read_analysis(a);

  for (i = 0; i < FW_PKT_SIZE_BUCKETS; i++)
    total += a->pkt_sizes[i];

  seq_printf(m, "Packet Size Distribution:\n");
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-12s %12s %8s\n", "Size Range", "Packets", "Percent");
  seq_printf(m, "-------------------------\n");
  fw_procfs_print_hist(m, fw_pkt_size_labels, a->pkt_sizes, FW_PKT_SIZE_BUCKETS);
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "Total: %llu packets\n", (unsigned long long)total);

  kfree(a);
  return 0;
}

static int pkt_sizes_open(struct inode *inode, struct file *file) {
  return single_open(file, pkt_sizes_show, NULL);
}

static const struct proc_ops pkt_sizes_fops = {
  .proc_open = pkt_sizes_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int ttl_dist_show(struct seq_file *m, void *v) {
  struct fw_analysis_snapshot *a = kzalloc(sizeof(*a), GFP_KERNEL);
  u64 total = 0;
  int i;

  if (!a)
    return -ENOMEM;
  fw_stats_read_analysis(a);

  for (i = 0; i < FW_TTL_BUCKETS; i++)
    total += a->ttl_dist[i];

  seq_printf(m, "TTL Distribution:\n");
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-12s %12s %8s\n", "TTL Range", "Packets", "Percent");
  seq_printf(m, "-------------------------\n");
  fw_procfs_print_hist(m, fw_ttl_labels, a->ttl_dist, FW_TTL_BUCKETS);
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "Total: %llu packets\n", (unsigned long long)total);

  kfree(a);
  return 0;
}

static int ttl_dist_open(struct inode *inode, struct file *file) {
  return single_open(file, ttl_dist_show, NULL);
}

static const struct proc_ops ttl_dist_fops = {
  .proc_open = ttl_dist_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int ip_frags_show(struct seq_file *m, void *v) {
  struct fw_analysis_snapshot *a = kzalloc(sizeof(*a), GFP_KERNEL);
  u64 pct = 0;

  if (!a)
    return -ENOMEM;
  fw_stats_read_analysis(a);

  if (a->ip_frag_total)
    pct = (a->ip_frag_count * 100) / a->ip_frag_total;

  seq_printf(m, "IP Fragment Statistics:\n");
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "Total IP packets:  %llu\n", (unsigned long long)a->ip_frag_total);
  seq_printf(m, "Fragmented packets: %llu\n", (unsigned long long)a->ip_frag_count);
  seq_printf(m, "Fragment ratio:    %llu%%\n", (unsigned long long)pct);

  kfree(a);
  return 0;
}

static int ip_frags_open(struct inode *inode, struct file *file) {
  return single_open(file, ip_frags_show, NULL);
}

static const struct proc_ops ip_frags_fops = {
  .proc_open = ip_frags_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int port_scanners_show(struct seq_file *m, void *v) {
  struct fw_analysis_snapshot *a = kzalloc(sizeof(*a), GFP_KERNEL);
  char ip_str[FW_INET6_STR_LEN];
  u32 i;

  if (!a)
    return -ENOMEM;
  fw_stats_read_analysis(a);

  seq_printf(m, "Port Scan Detection:\n");
  seq_printf(m, "Threshold: %d unique ports\n", (int)a->port_scan_threshold);
  seq_printf(m, "Total scans detected: %u\n", a->port_scan_count);
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-20s %12s %12s\n", "IP", "Unique Ports", "Packets");
  seq_printf(m, "-------------------------\n");

  if (!a->port_scan_count) {
    seq_printf(m, "No port scanners detected\n");
  } else {
    for (i = 0; i < a->port_scan_count && i < PORT_SCAN_MAX_RESULTS; i++) {
      fw_addr_to_str(a->port_scanners[i].af, &a->port_scanners[i].addr, ip_str,
                     sizeof(ip_str));
      seq_printf(m, "%-20s %12d %12llu\n", ip_str, (int)a->port_scanners[i].metric,
                 (unsigned long long)a->port_scanners[i].packets);
    }
  }

  kfree(a);
  return 0;
}

static int port_scanners_open(struct inode *inode, struct file *file) {
  return single_open(file, port_scanners_show, NULL);
}

static const struct proc_ops port_scanners_fops = {
  .proc_open = port_scanners_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int service_probes_show(struct seq_file *m, void *v) {
  struct fw_analysis_snapshot *a = kzalloc(sizeof(*a), GFP_KERNEL);
  char ip_str[FW_INET6_STR_LEN];
  u32 i;

  if (!a)
    return -ENOMEM;
  fw_stats_read_analysis(a);

  seq_printf(m, "Service Probe Detection:\n");
  seq_printf(m, "Threshold: %d protocol types\n", (int)a->service_probe_threshold);
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-20s %10s %12s\n", "IP", "Protocols", "Packets");
  seq_printf(m, "-------------------------\n");

  if (!a->service_probe_count) {
    seq_printf(m, "No service probes detected\n");
  } else {
    for (i = 0; i < a->service_probe_count && i < SERVICE_PROBE_MAX_RESULTS; i++) {
      fw_addr_to_str(a->service_probes[i].af, &a->service_probes[i].addr,
                     ip_str, sizeof(ip_str));
      seq_printf(m, "%-20s %10d %12llu\n", ip_str, (int)a->service_probes[i].metric,
                 (unsigned long long)a->service_probes[i].packets);
    }
  }

  kfree(a);
  return 0;
}

static int service_probes_open(struct inode *inode, struct file *file) {
  return single_open(file, service_probes_show, NULL);
}

static const struct proc_ops service_probes_fops = {
  .proc_open = service_probes_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/*
 * 受保护端口清单。只读观测面：集合由 daemon 扫描本机对外监听端口后经
 * netlink 下发，本文件不提供写入口。
 *
 * 未下发位图时打印「全端口受保护」而非空白清单——空清单会被误读成
 * 「没有任何端口受保护」，与实际的失败开放语义正好相反（见 fw_ports.c）。
 */
static int protected_ports_show(struct seq_file *m, void *v) {
  u8 *bitmap;
  u32 count, i;
  bool published;
  unsigned int shown = 0;
  bool truncated = false;

  /* 位图快照需 8KB，走 kzalloc 而非栈：seq_show 在内核栈上跑 */
  bitmap = kzalloc(FW_PROTECTED_PORTS_BYTES, GFP_KERNEL);
  if (!bitmap)
    return -ENOMEM;

  published = fw_ports_snapshot(bitmap);
  count = fw_ports_count();

  seq_printf(m, "Protected Ports (rate detection scope):\n");
  if (!published) {
    seq_printf(m, "State: not published - ALL ports participate in rate detection\n");
    seq_printf(m, "Hint: daemon has not sent a port set yet\n");
    kfree(bitmap);
    return 0;
  }

  seq_printf(m, "State: published\n");
  seq_printf(m, "Protected port count: %u\n", count);
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-8s %-6s\n", "Port", "Proto");

  /*
   * 逐位列出。端口数与协议无关（位图只按目的端口编号），协议列给出该端口
   * 在扫描结果中的类型；这里不存储协议信息，故统一按「tcp/udp」并列展示，
   * 避免让读者以为某个端口只在单一协议上受保护。
   */
  for (i = 0; i < FW_PROTECTED_PORTS_MAX; i++) {
    if (!test_bit(i, (const unsigned long *)bitmap))
      continue;
    if (shown >= FW_PROCFS_PROTECTED_PORTS_MAX_LINES) {
      truncated = true;
      break;
    }
    seq_printf(m, "%-8u %-6s\n", i, "tcp/udp");
    shown++;
  }

  if (!shown)
    seq_printf(m, "No protected ports\n");
  if (truncated)
    seq_printf(m, "... (%u protected, output truncated)\n", count);

  kfree(bitmap);
  return 0;
}

static int protected_ports_open(struct inode *inode, struct file *file) {
  return single_open(file, protected_ports_show, NULL);
}

static const struct proc_ops protected_ports_fops = {
  .proc_open = protected_ports_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

int fw_procfs_init(void) {
  struct proc_dir_entry *dir;

  dir = proc_mkdir("firewall", NULL);
  if (!dir) {
    pr_err("创建 %s 失败\n", FW_PROCFS_ROOT);
    return -ENOMEM;
  }
  fw_info.proc_dir = dir;

  fw_info.proc_bans = proc_create("bans", FW_PROCFS_BANS_MODE, dir, &bans_fops);
  fw_info.proc_config = proc_create("config", FW_PROCFS_CONFIG_MODE, dir, &config_fops);
  fw_info.proc_whitelist = proc_create(
    "whitelist", FW_PROCFS_WHITELIST_MODE, dir, &whitelist_fops);
  fw_info.proc_stats = proc_create("stats", FW_PROCFS_STATS_MODE, dir, &stats_fops);
  fw_info.proc_rates = proc_create("rates", FW_PROCFS_RATES_MODE, dir, &rates_fops);
  fw_info.proc_udp_ports = proc_create(
    "udp_ports", FW_PROCFS_UDP_PORTS_MODE, dir, &udp_ports_fops);
  fw_info.proc_icmp_types = proc_create(
    "icmp_types", FW_PROCFS_ICMP_TYPES_MODE, dir, &icmp_types_fops);
  fw_info.proc_pkt_sizes = proc_create(
    "pkt_sizes", FW_PROCFS_PKT_SIZES_MODE, dir, &pkt_sizes_fops);
  fw_info.proc_ttl_dist = proc_create("ttl_dist", FW_PROCFS_TTL_DIST_MODE, dir, &ttl_dist_fops);
  fw_info.proc_ip_frags = proc_create("ip_frags", FW_PROCFS_IP_FRAGS_MODE, dir, &ip_frags_fops);
  fw_info.proc_port_scanners = proc_create(
    "port_scanners", FW_PROCFS_PORT_SCANNERS_MODE, dir, &port_scanners_fops);
  fw_info.proc_service_probes = proc_create(
    "service_probes", FW_PROCFS_SERVICE_PROBES_MODE, dir, &service_probes_fops);
  fw_info.proc_protected_ports = proc_create(
    "protected_ports", FW_PROCFS_PROTECTED_PORTS_MODE, dir, &protected_ports_fops);

  if (!fw_info.proc_bans || !fw_info.proc_config || !fw_info.proc_whitelist ||
      !fw_info.proc_stats || !fw_info.proc_rates || !fw_info.proc_udp_ports ||
      !fw_info.proc_icmp_types || !fw_info.proc_pkt_sizes ||
      !fw_info.proc_ttl_dist || !fw_info.proc_ip_frags ||
      !fw_info.proc_port_scanners || !fw_info.proc_service_probes ||
      !fw_info.proc_protected_ports) {
    pr_err("创建 procfs 条目失败\n");
    fw_procfs_exit();
    return -ENOMEM;
  }

  return 0;
}

void fw_procfs_exit(void) {
  /* 逆序移除：先条目后根目录，避免根目录被摘走时留下悬空 dentry 引用 */
  proc_remove(fw_info.proc_protected_ports);
  proc_remove(fw_info.proc_service_probes);
  proc_remove(fw_info.proc_port_scanners);
  proc_remove(fw_info.proc_ip_frags);
  proc_remove(fw_info.proc_ttl_dist);
  proc_remove(fw_info.proc_pkt_sizes);
  proc_remove(fw_info.proc_icmp_types);
  proc_remove(fw_info.proc_udp_ports);
  proc_remove(fw_info.proc_rates);
  proc_remove(fw_info.proc_stats);
  proc_remove(fw_info.proc_whitelist);
  proc_remove(fw_info.proc_config);
  proc_remove(fw_info.proc_bans);
  proc_remove(fw_info.proc_dir);

  fw_info.proc_protected_ports = NULL;
  fw_info.proc_service_probes = NULL;
  fw_info.proc_port_scanners = NULL;
  fw_info.proc_ip_frags = NULL;
  fw_info.proc_ttl_dist = NULL;
  fw_info.proc_pkt_sizes = NULL;
  fw_info.proc_icmp_types = NULL;
  fw_info.proc_udp_ports = NULL;
  fw_info.proc_rates = NULL;
  fw_info.proc_stats = NULL;
  fw_info.proc_whitelist = NULL;
  fw_info.proc_config = NULL;
  fw_info.proc_bans = NULL;
  fw_info.proc_dir = NULL;
}
