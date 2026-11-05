/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_compat.h - 内核兼容性检查
 *
 * 检查策略：
 * - 内核版本号仅作参考信息，不作为硬性限制
 * - API 可用性由编译时保证（如果 API 不存在，编译会失败）
 * - 运行时不再做冗余的 API 检查
 */

#ifndef FW_COMPAT_H
#define FW_COMPAT_H

#include <linux/version.h>
#include <linux/kernel.h>

/*
 * fw_compat_init - 记录内核版本信息
 *
 * 仅记录版本信息，不阻止加载。
 * API 可用性由编译时保证，无需运行时检查。
 *
 * 返回值：始终返回 0
 */
static inline int fw_compat_init(void) {
  unsigned int version = LINUX_VERSION_CODE;
  int major, minor, patch;

  major = (version >> 16) & 0xFF;
  minor = (version >> 8) & 0xFF;
  patch = version & 0xFF;

  pr_info("内核版本: %d.%d.%d\n", major, minor, patch);
  pr_info("API 可用性由编译时保证\n");

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

#endif /* FW_COMPAT_H */
