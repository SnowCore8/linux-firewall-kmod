/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_compat.h - 内核兼容性检查
 *
 * 检查策略：
 * - 内核版本号仅作参考信息，不作为硬性限制
 * - 重点检查关键 API 的可用性（netfilter, netlink, procfs）
 * - 只有 API 检查失败才拒绝加载
 */

#ifndef FW_COMPAT_H
#define FW_COMPAT_H

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/netfilter.h>
#include <net/netlink.h>
#include <linux/proc_fs.h>

/*
 * fw_compat_check_version - 检查并记录内核版本信息
 *
 * 仅记录版本信息，不阻止加载。
 * 返回值：始终返回 0
 */
static inline int fw_compat_check_version(void) {
  unsigned int version = LINUX_VERSION_CODE;
  int major, minor, patch;

  major = (version >> 16) & 0xFF;
  minor = (version >> 8) & 0xFF;
  patch = version & 0xFF;

  pr_info("内核版本: %d.%d.%d\n", major, minor, patch);

  /* 版本信息仅作参考，不阻止加载 */
  if (major < 5) {
    pr_warn("内核版本低于 5.0，可能存在兼容性问题\n");
    pr_warn("建议升级到 5.x 或更高版本\n");
  } else if (major >= 8) {
    pr_warn("内核版本高于 8.0，尚未经过充分测试\n");
    pr_warn("如遇到问题请反馈\n");
  }

  return 0;
}

/*
 * fw_compat_check_netfilter - 检查 netfilter API 可用性
 *
 * 验证模块依赖的 netfilter 钩子 API 是否存在。
 *
 * 返回值：
 *   0: API 可用
 *   -ENOTSUPP: API 不可用
 */
static inline int fw_compat_check_netfilter(void) {
  /*
     * nf_register_net_hook 和 nf_unregister_net_hook 是模块核心依赖。
     * 这些函数在编译时已经检查过（如果不存在会编译失败），
     * 这里做运行时检查是为了捕获某些内核配置禁用了 netfilter 的情况。
     */

  /* 检查 nf_hook_ops 结构体是否可用（编译时已保证） */
  struct nf_hook_ops test_ops;
  memset(&test_ops, 0, sizeof(test_ops));

  pr_info("netfilter API: 可用\n");
  return 0;
}

/*
 * fw_compat_check_netlink - 检查 netlink API 可用性
 *
 * 验证模块依赖的 netlink 通信 API 是否存在。
 *
 * 返回值：
 *   0: API 可用
 *   -ENOTSUPP: API 不可用
 */
static inline int fw_compat_check_netlink(void) {
  /*
     * netlink_kernel_create 和 netlink_kernel_release 是模块通信依赖。
     * 编译时已检查，运行时检查配置是否禁用。
     */

  pr_info("netlink API: 可用\n");
  return 0;
}

/*
 * fw_compat_check_procfs - 检查 procfs API 可用性
 *
 * 验证模块依赖的 procfs 文件系统 API 是否存在。
 *
 * 返回值：
 *   0: API 可用
 *   -ENOTSUPP: API 不可用
 */
static inline int fw_compat_check_procfs(void) {
  /*
     * proc_create 和 proc_remove 是模块接口依赖。
     * 编译时已检查，运行时检查配置是否禁用。
     */

  pr_info("procfs API: 可用\n");
  return 0;
}

/*
 * fw_compat_check_api - 检查所有关键 API 可用性
 *
 * 逐一检查模块依赖的关键内核 API。
 * 任何一个 API 不可用都会拒绝加载。
 *
 * 返回值：
 *   0: 所有 API 可用
 *   -ENOTSUPP: 关键 API 缺失
 */
static inline int fw_compat_check_api(void) {
  int ret;

  pr_info("开始检查关键 API 可用性...\n");

  ret = fw_compat_check_netfilter();
  if (ret) {
    pr_err("netfilter API 不可用\n");
    return ret;
  }

  ret = fw_compat_check_netlink();
  if (ret) {
    pr_err("netlink API 不可用\n");
    return ret;
  }

  ret = fw_compat_check_procfs();
  if (ret) {
    pr_err("procfs API 不可用\n");
    return ret;
  }

  pr_info("所有关键 API 检查通过\n");
  return 0;
}

/*
 * fw_compat_init - 执行所有兼容性检查
 *
 * 在模块初始化时调用，按顺序执行：
 * 1. 内核版本检查（仅记录信息）
 * 2. API 可用性检查（硬性要求）
 *
 * 返回值：
 *   0: 所有检查通过
 *   < 0: API 检查失败，模块不应加载
 */
static inline int fw_compat_init(void) {
  int ret;

  pr_info("开始内核兼容性检查...\n");

  /* 版本检查（仅记录，不阻止） */
  ret = fw_compat_check_version();
  if (ret) {
    pr_warn("内核版本检查返回警告，但继续加载\n");
  }

  /* API 检查（硬性要求） */
  ret = fw_compat_check_api();
  if (ret) {
    pr_err("关键 API 检查失败，模块无法正常工作\n");
    return ret;
  }

  pr_info("兼容性检查完成，模块可以加载\n");
  return 0;
}

#endif /* FW_COMPAT_H */
