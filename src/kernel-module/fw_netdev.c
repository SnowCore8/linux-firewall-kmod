// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_netdev.c - netdev notifier、本机地址集合重建、自动白名单对账
 *
 * 与旧实现（netdev.c）的差别（见 docs/zh/development/kernel-rewrite-design.md）：
 *
 *   - **空表窗口消除**：旧实现在 `local_ip_cache` 为 NULL / count == 0 时直接
 *     返回「非本机」，那是个失败开放窗口。新实现由 fw_main.c 在注册钩子**之前**
 *     同步调用 fw_netdev_rebuild_local()，运行期必然有一张已发布的表。
 *   - **只存精确主机地址**：不把接口掩码对应的整段子网当作本机豁免。
 *   - **白名单对账用 (af, 地址, 前缀) 三元组精确比较**，而不是旧实现的
 *     「IP + 掩码」比较后按 device_name 猜归属；manual / restored 条目永不被
 *     自动删除（用户手工添加与状态恢复的条目必须活得比接口本身久）。
 *   - **不做无谓的事件推送**：旧实现在 count == 0 时无条件清空自动白名单并逐条
 *     推送；新实现只在「对账真的删掉了某条」时推送。
 *
 * 并发模型：新表整体构建后 rcu_assign_pointer 发布，旧表 kfree_rcu 释放；
 * 发布后表内容不再修改，热路径只需 RCU 只读。重建在 delayed work（进程上下文）
 * 中完成，可能与热路径并发，因此构建期间绝不改动已发布的表。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/slab.h>
#include <net/addrconf.h>
#include <net/if_inet6.h>
#include <net/net_namespace.h>

#include "fw_netdev.h"
#include "fw_local.h"
#include "fw_wl.h"
#include "fw_netlink.h"

/* notifier 事件后的防抖时延（ms）：USB 插拔/改 IP 常伴随多次事件 */
#define FW_NETDEV_SYNC_DELAY_MS 500

/* 本机地址集合容量的下界与硬上界（上界受 fw_hash_addr 低 16 位限制） */
#define FW_NETDEV_LOCAL_MIN 16
#define FW_NETDEV_LOCAL_MAX (1u << 16)

/* 白名单对账的分页大小与最大遍数（每遍至少删掉一条，故有限终止） */
#define FW_NETDEV_WL_PAGE 128
#define FW_NETDEV_MAX_PASSES 64

/* 自动条目的标记：既非 manual（用户手工）也非 restored（状态恢复） */
#define FW_NETDEV_DEV_MANUAL "manual"
#define FW_NETDEV_DEV_RESTORED "restored"

static bool fw_netdev_work_ready;

static void fw_netdev_sync_work(struct work_struct *work);

/* ============================================================================
 * 地址发现
 * ==========================================================================*/

/*
 * 遍历 init_net 中所有 IFF_UP 接口的精确主机地址。
 * rows 为 NULL 时只计数（第一遍），否则写入至多 max 行并按行记录接口名。
 * 返回发现的地址总数（rows != NULL 时不超过 max）。
 */
static u32 fw_netdev_collect(struct fw_wl_row *rows, u32 max) {
  struct net_device *dev;
  u32 n = 0;

  rcu_read_lock();
  for_each_netdev_rcu(&init_net, dev) {
    struct in_device *in_dev;
    struct inet6_dev *in6_dev;

    if (!(dev->flags & IFF_UP))
      continue;

    /* IPv4：只取接口主机地址本身（/32），不取掩码对应的网段 */
    in_dev = __in_dev_get_rcu(dev);
    if (in_dev) {
      struct in_ifaddr *ifa;

      for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
           ifa = rcu_dereference(ifa->ifa_next)) {
        if (!ifa->ifa_local)
          continue;
        if (rows) {
          if (n >= max)
            break;
          rows[n].af = FW_AF_INET;
          rows[n].prefix_len = 32;
          rows[n].addr.ipv4 = ifa->ifa_local;
          strscpy(rows[n].device_name, dev->name, sizeof(rows[n].device_name));
        }
        n++;
      }
    }

    /* IPv6：inet6_dev->addr_list 受 inet6_dev->lock（rwlock）保护 */
    in6_dev = __in6_dev_get(dev);
    if (in6_dev) {
      struct inet6_ifaddr *ifp;

      read_lock_bh(&in6_dev->lock);
      list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
        if (rows) {
          if (n >= max)
            break;
          rows[n].af = FW_AF_INET6;
          rows[n].prefix_len = 128;
          rows[n].addr.ipv6 = ifp->addr;
          strscpy(rows[n].device_name, dev->name, sizeof(rows[n].device_name));
        }
        n++;
      }
      read_unlock_bh(&in6_dev->lock);
    }
  }
  rcu_read_unlock();

  return n;
}

/*
 * 集合容量：以 fw_max_local_ips 为下界（向上取 2 的幂），但**以实际地址数为准**
 * ——地址数超过参数时按需要扩容，绝不因为容量不足而漏掉本机地址（漏掉即等于
 * 允许封禁本机地址，属失败开放）。硬上界 FW_NETDEV_LOCAL_MAX。
 */
static u32 fw_netdev_local_capacity(u32 n) {
  u32 want = READ_ONCE(fw_info.max_local_ips);
  u32 cap = FW_NETDEV_LOCAL_MIN;

  while (cap < want && cap < FW_NETDEV_LOCAL_MAX)
    cap <<= 1;

  if (cap < n) {
    pr_warn_once("本机地址数 %u 超过 fw_max_local_ips=%u，本机集合按实际需要扩容\n", n, want);
    while (cap < n && cap < FW_NETDEV_LOCAL_MAX)
      cap <<= 1;
  }
  if (n > FW_NETDEV_LOCAL_MAX)
    pr_warn("本机地址数 %u 超过容量上界 %u，仅保留前 %u 个\n", n,
            FW_NETDEV_LOCAL_MAX, FW_NETDEV_LOCAL_MAX);

  return cap;
}

/* 一次完整快照：本机地址集合 + 地址清单（供白名单对账） */
struct fw_netdev_snapshot {
  struct fw_local_set *set;
  struct fw_wl_row *rows;
  u32 n;
};

static int fw_netdev_snapshot_build(struct fw_netdev_snapshot *s) {
  u32 n, i;

  memset(s, 0, sizeof(*s));

  n = fw_netdev_collect(NULL, 0);

  s->set = fw_local_set_alloc(fw_netdev_local_capacity(n));
  if (!s->set)
    return -ENOMEM;

  if (!n)
    return 0; /* 无活动地址：发布空表 */

  s->rows = kcalloc(n, sizeof(*s->rows), GFP_KERNEL);
  if (!s->rows) {
    fw_local_free_rcu(s->set);
    s->set = NULL;
    return -ENOMEM;
  }

  s->n = fw_netdev_collect(s->rows, n);
  for (i = 0; i < s->n; i++)
    fw_local_set_insert(s->set, s->rows[i].af, &s->rows[i].addr);

  return 0;
}

/* ============================================================================
 * 自动白名单对账
 * ==========================================================================*/

static bool fw_netdev_dev_is_auto(const char *name) {
  return strcmp(name, FW_NETDEV_DEV_MANUAL) != 0 &&
         strcmp(name, FW_NETDEV_DEV_RESTORED) != 0;
}

/* 本机地址清单中是否存在与白名单条目完全一致的 (af, 地址, 前缀) */
static bool fw_netdev_local_has(const struct fw_wl_row *locals, u32 n,
                                const struct fw_wl_row *wl) {
  u32 i;

  for (i = 0; i < n; i++) {
    if (locals[i].af != wl->af)
      continue;
    if (locals[i].prefix_len != wl->prefix_len)
      continue;
    if (fw_addr_equal(wl->af, &locals[i].addr, &wl->addr))
      return true;
  }
  return false;
}

/*
 * 移除「接口地址已消失」的自动白名单条目。
 *
 * 分页读取整张白名单表；一旦删掉某条就从头重扫——因为 hlist 删除会改变后续
 * 遍历位置，重扫比在原页上做 offset 补偿更不容易出错。每遍至少删除一条，
 * 故以 FW_NETDEV_MAX_PASSES 为上界必然终止。
 *
 * 用 fw_wl_remove_quiet()：不触发「白名单变更 → 解封」联动（接口消失不是用户
 * 撤销信任的行为，不应连带解封）。
 */
static void fw_netdev_reconcile_whitelist(const struct fw_wl_row *locals, u32 n) {
  struct fw_wl_row *page;
  u32 passes = 0;
  bool removed;

  page = kmalloc_array(FW_NETDEV_WL_PAGE, sizeof(*page), GFP_KERNEL);
  if (!page)
    return; /* 对账失败不影响本机集合已发布 */

  do {
    u32 offset = 0, got, i;

    removed = false;
    for (;;) {
      got = fw_wl_fill_entries(offset, FW_NETDEV_WL_PAGE, page);
      if (!got)
        break;

      for (i = 0; i < got; i++) {
        if (!fw_netdev_dev_is_auto(page[i].device_name))
          continue;
        if (fw_netdev_local_has(locals, n, &page[i]))
          continue;

        if (!fw_wl_remove_quiet(page[i].af, &page[i].addr, page[i].prefix_len)) {
          fw_nl_send_whitelist_state_change(FW_WHITELIST_ACTION_REMOVE, page[i].af,
                                            &page[i].addr, page[i].prefix_len,
                                            page[i].device_name);
          removed = true;
          break;
        }
      }
      if (removed)
        break;
      if (got < FW_NETDEV_WL_PAGE)
        break;
      offset += got;
    }
  } while (removed && ++passes < FW_NETDEV_MAX_PASSES);

  kfree(page);
}

/* ============================================================================
 * 重建与 notifier
 * ==========================================================================*/

int fw_netdev_rebuild_local(void) {
  struct fw_netdev_snapshot s;

  /* 只初始化一次；fw_netdev_cancel_sync() 依赖此标记判断 work 是否可用 */
  if (!fw_netdev_work_ready) {
    INIT_DELAYED_WORK(&fw_info.sync_work, fw_netdev_sync_work);
    fw_netdev_work_ready = true;
  }

  if (fw_netdev_snapshot_build(&s))
    return -ENOMEM;

  fw_local_publish(s.set);
  kfree(s.rows);
  return 0;
}

static void fw_netdev_sync_work(struct work_struct *work) {
  struct fw_netdev_snapshot s;

  (void)work;

  /* 退出中：不再重建，也不启动新的对账 */
  if (fw_is_shutting_down())
    return;

  if (fw_netdev_snapshot_build(&s)) {
    pr_warn("本机地址重建失败，保留原有集合\n");
    return;
  }

  fw_local_publish(s.set);
  fw_netdev_reconcile_whitelist(s.rows, s.n);
  kfree(s.rows);
}

static void fw_netdev_schedule(void) {
  if (fw_is_shutting_down())
    return;
  if (!fw_netdev_work_ready)
    return;
  mod_delayed_work(system_wq, &fw_info.sync_work, msecs_to_jiffies(FW_NETDEV_SYNC_DELAY_MS));
}

static int fw_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr) {
  struct net_device *dev;

  (void)nb;

  if (fw_is_shutting_down())
    return NOTIFY_DONE;

  dev = netdev_notifier_info_to_dev(ptr);
  if (!dev)
    return NOTIFY_DONE;

  switch (event) {
  case NETDEV_UP:
  case NETDEV_DOWN:
  case NETDEV_CHANGE:
  case NETDEV_CHANGEADDR:
  case NETDEV_REGISTER:
  case NETDEV_UNREGISTER:
    fw_netdev_schedule();
    break;
  default:
    break;
  }

  return NOTIFY_DONE;
}

int fw_netdev_init(void) {
  int ret;

  fw_info.netdev_notifier.notifier_call = fw_netdev_event;

  ret = register_netdevice_notifier(&fw_info.netdev_notifier);
  if (ret) {
    fw_info.netdev_notifier_registered = false;
    pr_err("netdev notifier 注册失败: %d\n", ret);
    return ret;
  }

  fw_info.netdev_notifier_registered = true;
  return 0;
}

void fw_netdev_cancel_sync(void) {
  if (fw_netdev_work_ready)
    cancel_delayed_work_sync(&fw_info.sync_work);
}

void fw_netdev_exit(void) {
  if (fw_info.netdev_notifier_registered) {
    unregister_netdevice_notifier(&fw_info.netdev_notifier);
    fw_info.netdev_notifier_registered = false;
  }
}
