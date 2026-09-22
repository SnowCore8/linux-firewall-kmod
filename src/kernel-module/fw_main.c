// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_main.c - 模块生命周期、模块参数与 fw_info 单例
 *
 * init / exit 的顺序本身就是设计的一部分，见
 * docs/zh/development/kernel-rewrite-design.md「并发与生命周期」：
 *
 *   init: 参数校验 → 单例字段与运行态默认值 → 各子系统表/锁/原子初始化
 *         → netlink → 状态恢复 → 本机地址首次发现 → netdev notifier
 *         → procfs → netfilter 钩子(v4,v6)
 *   exit: shutting_down=1 → 取消 delayed work → 注销钩子(v4,v6) → synchronize_rcu
 *         → 注销 notifier → 销毁 procfs → synchronize_rcu → 保存状态
 *         → 全表清理（ban/wl/rate/stats/local）→ netlink
 *
 * 顺序上的硬约束（写反就是缺陷）：
 *
 *   1. **本机地址首次发现必须在注册钩子之前**（fw_netdev_rebuild_local()）。
 *      设计要消除旧实现「local_ip_cache 为空即判定非本机」的空表窗口；该调用
 *      返回负值时不注册钩子、直接放弃加载——宁可不工作，也不能让本机地址被
 *      当成外来地址参与封禁。
 *   2. **状态保存必须在全表清理之前**（fw_state_save() 要读封禁表与白名单表）。
 *   3. **netlink 最后销毁**：前面每一步都可能推送事件（ban 到期回调在
 *      rcu_read_unlock() 之后调 fw_nl_send_*；发送函数以 fw_nl_sock 是否为
 *      NULL 作为唯一保护）。
 *
 * 本文件不复用旧实现的 get_fw_info() / is_banned() / is_permanently_banned()
 * 三个导出：新代码不导出任何符号（模块内自足），故删除（设计文档「本次新查出
 * 的稳定性问题 3」）。
 *
 * 遗留风险（本轮未修，需在 1.2d/1.2e 定夺）：fw_ban 的到期回调在
 * rcu_read_unlock() 之后推送事件，而 fw_ban_exit() 的 synchronize_rcu() +
 * rcu_barrier() 只保证「临界区内」的部分结束。理论上存在一个极窄窗口：回调已
 * 离开临界区、尚未进入 netlink_broadcast()，此时 fw_netlink_exit() 释放 socket
 * ⇒ 回调访问已释放对象。旧实现（cleanup.c/netlink.c）有同样的窗口。彻底修法
 * 是给发送/销毁加一把共用的读写锁，属独立改动。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/module.h>
#include <linux/random.h>
#include <net/net_namespace.h>

#include "fw_ban.h"
#include "fw_local.h"
#include "fw_netdev.h"
#include "fw_netlink.h"
#include "fw_ports.h"
#include "fw_procfs.h"
#include "fw_rate.h"
#include "fw_state.h"
#include "fw_stats.h"
#include "fw_wl.h"

/* ============================================================================
 * 模块参数（名称与默认值是对外承诺，见设计文档「module_param」）
 *
 * 已冻结的 7 个：fw_ban_time / state_file / fw_max_bans_per_second /
 * fw_max_rate_entries / fw_static_threshold / fw_dynamic_threshold /
 * fw_ddos_detection（名称与默认值不可改，只能追加）。
 * 新增 3 个容量参数：fw_max_ban_entries / fw_max_whitelist_entries /
 * fw_max_local_ips（补齐旧实现「无上限插入」的三个缺口）。
 * ==========================================================================*/

unsigned int fw_ban_time = DEFAULT_BAN_TIME;
/*
 * sysfs 名保持契约冻结的 state_file；内部变量名是 fw_state_file（fw_state.c
 * 直接读该全局），故用 module_param_named 把两者对上。
 */
char *fw_state_file = "/var/lib/firewall/state";
unsigned int fw_max_bans_per_second = 200;
unsigned int fw_max_rate_entries = 65536; /* 文档化范围 1024-262144 */
unsigned int fw_max_ban_entries = 65535;
unsigned int fw_max_whitelist_entries = 65535;
unsigned int fw_max_local_ips = 256;
unsigned int fw_static_threshold = 1;  /* 默认开启静态阈值检测 */
unsigned int fw_dynamic_threshold = 0; /* 默认关闭动态阈值 */
unsigned int fw_ddos_detection = 1;    /* DDoS 检测总开关 */

module_param(fw_ban_time, uint, 0400);
MODULE_PARM_DESC(fw_ban_time, "封禁持续时间（秒）（默认 600）");
module_param_named(state_file, fw_state_file, charp, 0444);
MODULE_PARM_DESC(state_file, "用于保存/恢复封禁和白名单条目的状态文件路径（默认 "
                             "/var/lib/firewall/state）");
module_param(fw_max_bans_per_second, uint, 0400);
MODULE_PARM_DESC(fw_max_bans_per_second, "泛洪保护下每秒最大封禁添加次数（默认 200）");
module_param(fw_max_rate_entries, uint, 0644);
MODULE_PARM_DESC(fw_max_rate_entries, "速率表最大条目数（默认 65536，范围 1024-262144）。"
                                      "较小值节省内存，较大值支持更多并发源 IP");
module_param(fw_max_ban_entries, uint, 0644);
MODULE_PARM_DESC(fw_max_ban_entries, "封禁表最大条目数（默认 65535）。到限即拒绝新增并计入 "
                                     "ban_table_full_rejects");
module_param(fw_max_whitelist_entries, uint, 0644);
MODULE_PARM_DESC(fw_max_whitelist_entries, "白名单最大条目数（默认 65535）。到限即拒绝新增");
module_param(fw_max_local_ips, uint, 0644);
MODULE_PARM_DESC(fw_max_local_ips, "本机地址集合容量下界（默认 256）。实际地址数超过该值时按需"
                                   "扩容，绝不因容量不足而漏掉本机地址");
module_param(fw_static_threshold, uint, 0644);
MODULE_PARM_DESC(fw_static_threshold, "启用静态阈值检测（默认 1 开启，设为 0 关闭）。"
                                      "关闭后仅依赖动态阈值检测（如果启用）");
module_param(fw_dynamic_threshold, uint, 0644);
MODULE_PARM_DESC(fw_dynamic_threshold, "启用动态阈值检测（默认 0 关闭，设为 1 启用）。"
                                       "启用后实际阈值 = max(静态阈值, 基线 × 倍数)，"
                                       "基线由守护进程通过 netlink 定期下发");
module_param(fw_ddos_detection, uint, 0644);
MODULE_PARM_DESC(fw_ddos_detection, "DDoS 检测总开关（默认 1 开启，设为 0 关闭）。"
                                    "关闭后跳过所有速率检测和 DDoS 封禁，"
                                    "仅保留白名单和封禁表功能");

/* ============================================================================
 * 全局单例
 * ==========================================================================*/

struct fw_info fw_info;

/* 哈希种子：每引导随机，防哈希碰撞攻击（IPv6 地址哈希尤其需要） */
u32 fw_hash_seed;

/* ============================================================================
 * 初始化
 * ==========================================================================*/

/* 参数校验：拒绝的值一律返回 -EINVAL，由内核报「Unknown symbol in module /
 * invalid parameters」并中止加载，而不是带着坏配置运行。 */
static int fw_params_validate(void) {
  if (READ_ONCE(fw_ban_time) < FW_BAN_TIME_MIN || READ_ONCE(fw_ban_time) > FW_BAN_TIME_MAX) {
    pr_err("fw_ban_time=%u 超出允许范围 [%d, %d]\n", fw_ban_time,
           FW_BAN_TIME_MIN, FW_BAN_TIME_MAX);
    return -EINVAL;
  }

  /*
   * 容量参数为 0 会让对应表完全不可用（封禁/白名单全拒，或速率表恒建失败、
   * 退化成不做速率检测），因此视为配置错误直接拒绝加载，而不是静默退化。
   */
  if (!fw_max_ban_entries || !fw_max_whitelist_entries || !fw_max_local_ips ||
      !fw_max_rate_entries) {
    pr_err("容量参数不得为 0: max_ban_entries=%u max_whitelist_entries=%u "
           "max_local_ips=%u max_rate_entries=%u\n",
           fw_max_ban_entries, fw_max_whitelist_entries, fw_max_local_ips,
           fw_max_rate_entries);
    return -EINVAL;
  }

  return 0;
}

/* 单例字段与运行态默认值。必须在各子系统 init 之前设置：速率判定读的就是
 * fw_info 里的这些值，而不是模块参数。 */
static void fw_info_defaults_init(void) {
  atomic_set(&fw_info.shutting_down, 0);

  /* 容量参数快照（运行期只读；改参数需重新加载模块） */
  fw_info.max_ban_entries = fw_max_ban_entries;
  fw_info.max_wl_entries = fw_max_whitelist_entries;
  fw_info.max_local_ips = fw_max_local_ips;
  fw_info.max_bans_per_second = fw_max_bans_per_second;

  /* 速率检测默认配置 */
  fw_info.rate_window_seconds = DEFAULT_RATE_WINDOW_SECONDS;
  fw_info.rate_window_jiffies = msecs_to_jiffies(DEFAULT_RATE_WINDOW_SECONDS * 1000);
  fw_info.max_packets_per_second = DEFAULT_MAX_PACKETS_PER_SECOND;
  fw_info.max_bytes_per_second = DEFAULT_MAX_BYTES_PER_SECOND;
  fw_info.max_syn_per_second = DEFAULT_MAX_SYN_PER_SECOND;
  fw_info.max_udp_per_second = DEFAULT_MAX_UDP_PER_SECOND;
  fw_info.max_icmp_per_second = DEFAULT_MAX_ICMP_PER_SECOND;
  fw_info.max_ack_per_second = DEFAULT_MAX_ACK_PER_SECOND;
  fw_info.max_rst_per_second = DEFAULT_MAX_RST_PER_SECOND;
  fw_info.max_fin_per_second = DEFAULT_MAX_FIN_PER_SECOND;

  /* 阈值开关与动态比例 */
  fw_info.static_threshold_enabled = fw_static_threshold != 0;
  fw_info.dynamic_threshold_enabled = fw_dynamic_threshold != 0;
  fw_info.dynamic_threshold_ratio_x100 = DEFAULT_DYNAMIC_THRESHOLD_RATIO_X100;
  fw_info.baseline_pps = 0;
  fw_info.baseline_bps = 0;

  /* DDoS 自决封禁时长：0 表示走 fw_ban_time（见 fw_types.h 注释） */
  fw_info.ddos_ban_duration = DEFAULT_DDOS_BAN_DURATION;

  fw_info.netdev_notifier_registered = false;
}

static int __init fw_init(void) {
  int ret;

  pr_info("模块初始化开始\n");

  ret = fw_params_validate();
  if (ret)
    return ret;

  /* 每引导随机种子（与 fw_hash_addr 配对） */
  get_random_bytes(&fw_hash_seed, sizeof(fw_hash_seed));

  fw_info_defaults_init();

  /* ---- 子系统表/锁/原子初始化：统计 → 本机 → 白名单 → 封禁 → 速率 ---- */
  ret = fw_stats_init();
  if (ret) {
    pr_err("统计子系统初始化失败: %d\n", ret);
    return ret;
  }

  fw_local_init();
  fw_ports_init();
  ret = fw_wl_init();
  if (ret) {
    pr_err("白名单初始化失败: %d\n", ret);
    goto err_wl;
  }
  ret = fw_ban_init();
  if (ret) {
    pr_err("封禁表初始化失败: %d\n", ret);
    goto err_ban;
  }
  ret = fw_rate_init();
  if (ret) {
    pr_err("速率表初始化失败: %d\n", ret);
    goto err_rate;
  }

  /* ---- netlink：状态恢复与后续事件推送都依赖它 ---- */
  ret = fw_netlink_init();
  if (ret) {
    pr_err("netlink 通信层初始化失败: %d\n", ret);
    goto err_rate;
  }

  /* 状态恢复：文件不存在/损坏只在日志里体现，属正常启动路径 */
  (void)fw_state_restore();

  /* ---- 本机地址首次发现：必须在注册钩子之前 ---- */
  ret = fw_netdev_rebuild_local();
  if (ret) {
    pr_err("本机地址首次发现失败: %d，放弃注册钩子\n", ret);
    goto err_rebuild;
  }

  ret = fw_netdev_init();
  if (ret)
    goto err_rebuild;

  ret = fw_procfs_init();
  if (ret)
    goto err_netdev;

  /* ---- 钩子最后注册：此前所有判定依赖的表都已就绪且已发布 ---- */
  ret = nf_register_net_hook(&init_net, &nf_ops_ipv4);
  if (ret) {
    pr_err("注册 IPv4 netfilter 钩子失败: %d\n", ret);
    goto err_procfs;
  }

  ret = nf_register_net_hook(&init_net, &nf_ops_ipv6);
  if (ret) {
    pr_err("注册 IPv6 netfilter 钩子失败: %d\n", ret);
    goto err_hook_v4;
  }

  pr_info("模块初始化完成 (ban_time=%u, ddos_ban_duration=%u, "
          "max_bans/s=%u, max_ban_entries=%u)\n",
          fw_ban_time, fw_info.ddos_ban_duration, fw_max_bans_per_second, fw_max_ban_entries);
  return 0;

/* 失败回退：按初始化的逆序逐层拆，每层只拆自己已建成的部分 */
err_hook_v4:
  nf_unregister_net_hook(&init_net, &nf_ops_ipv4);
err_procfs:
  fw_procfs_exit();
err_netdev:
  fw_netdev_exit();
err_rebuild:
  fw_netdev_cancel_sync();
err_rate:
  fw_rate_exit();
err_ban:
  fw_ban_exit();
err_wl:
  fw_wl_exit();
  fw_ports_exit();
  fw_local_exit();
  fw_stats_exit();
  return ret;
}

/* ============================================================================
 * 退出
 * ==========================================================================*/

static void __exit fw_exit(void) {
  pr_info("模块清理开始\n");

  /* 1) 热路径第一道判断置位：此后不再有新报文进入判定与封禁 */
  atomic_set(&fw_info.shutting_down, 1);

  /* 2) 取消防抖中的 delayed work：此后不再重建本机地址表 */
  fw_netdev_cancel_sync();

  /* 3) 注销钩子，并等所有在途读者离开 RCU 临界区 */
  nf_unregister_net_hook(&init_net, &nf_ops_ipv4);
  nf_unregister_net_hook(&init_net, &nf_ops_ipv6);
  synchronize_rcu();

  fw_netdev_exit();

  /* 4) procfs 条目可能还有在途读者（写侧会改表），再等一次宽限期 */
  fw_procfs_exit();
  synchronize_rcu();

  /* 5) 保存状态必须在清表之前（保存要读封禁表与白名单表） */
  if (fw_state_file && fw_state_file[0])
    (void)fw_state_save();

  /* 6) 全表清理：每个子系统自带 synchronize_rcu() + rcu_barrier() */
  fw_ban_exit();
  fw_wl_exit();
  fw_rate_exit();
  fw_stats_exit();
  fw_local_exit();
  fw_ports_exit();

  /* 7) netlink 最后销毁：以上各步都可能推送事件 */
  fw_netlink_exit();

  pr_info("模块清理完成\n");
}

module_init(fw_init);
module_exit(fw_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Firewall Authors");
MODULE_DESCRIPTION("Kernel-level IP banning module (fail2ban alternative, "
                   "IPv4/IPv6)");
MODULE_VERSION("2.2");
