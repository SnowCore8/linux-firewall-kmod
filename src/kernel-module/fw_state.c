// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_state.c - 状态文件读写（封禁表 + 白名单）
 *
 * 与旧实现（state-persist.c）的差别（见
 * docs/zh/development/kernel-rewrite-design.md 与契约修订说明）：
 *
 *   1. **恢复保留容量检查**。旧实现在两处都写着「跳过容量限制（按需恢复）」，
 *      即状态文件里的行数可以突破模块参数上限，且因为恢复路径直接操作旧表结构
 *      而绕过了本应生效的 -ENOSPC。新实现走 fw_ban_restore()，它只跳过**泛洪
 *      闸门**，容量检查照常（超限即 -ENOSPC 跳过该行并计数）。
 *
 *   2. **封禁起点不再丢失**。旧实现保存的是「剩余秒数」而恢复时又用
 *      `unban_time = jiffies + remaining` 重建，虽然等价，但条目内部同时维护
 *      ban_time / unban_time 两个 jiffies 字段，且恢复路径与运行路径各写一套。
 *      新实现保存「剩余秒数」并按 `banned_at = now_unix - (duration - remaining)`
 *      反推原始起点，交给 fw_ban_restore() 换算回 jiffies。
 *
 *   3. **恢复白名单先于封禁**，且白名单恢复复用 fw_wl_add()（自带容量检查与
 *      去重），因此封禁恢复的白名单前检（fw_ban_try_add 的 -EPERM）能命中。
 *
 *   4. **状态文件格式不变**：BAN_V4/BAN_V6/WL_V4/WL_V6 + 尾部 CRC32，
 *      daemon 与运维脚本继续可读。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "fw_state.h"
#include "fw_ban.h"
#include "fw_wl.h"

/* 单次读入的状态文件上限（超出即截断解析，视为损坏） */
#define FW_STATE_MAX_FILE (128 * 1024)

/* 保存时每张表的写出上限（与旧实现一致，防止状态文件无限增长） */
#define FW_STATE_MAX_BAN 4096
#define FW_STATE_MAX_WL 4096

/* 分页收集时每页行数 */
#define FW_STATE_PAGE 64

/* 恢复只做一次：模块生命周期内的守卫 */
static bool fw_state_restored;

/* ============================================================================
 * 路径校验
 * ==========================================================================*/

/*
 * 只允许 /var/lib/、/tmp/、/etc/ 之下，且禁止 URL 转义与 shell 元字符。
 * 本函数不解析符号链接（读写都用 O_NOFOLLOW），因此不需要 realpath。
 */
static int fw_state_validate_path(const char *path) {
  static const char bad_chars[] = "|;&`$(){}<>!~*?[]";
  const char *p;

  if (!path || !*path)
    return -EINVAL;

  if (strstr(path, "%2e") || strstr(path, "%2E") || strstr(path, "%2f") || strstr(path, "%2F"))
    return -EINVAL;

  for (p = path; *p; p++) {
    if (strchr(bad_chars, *p))
      return -EINVAL;
  }

  /* 拒绝任何 ".." 路径分量 */
  for (p = path; p[0] && p[1]; p++) {
    if (p[0] == '.' && p[1] == '.') {
      bool at_start = p == path || p[-1] == '/';
      bool at_end = p[2] == '\0' || p[2] == '/';

      if (at_start && at_end)
        return -EINVAL;
    }
  }

  if (strncmp(path, "/var/lib/", 9) != 0 && strncmp(path, "/tmp/", 5) != 0 &&
      strncmp(path, "/etc/", 5) != 0)
    return -EPERM;

  return 0;
}

/* jail 字段内的空白会破坏空格分隔的行格式，统一替换为 '_' */
static void fw_state_sanitize_field(char *s, size_t n) {
  size_t i;

  for (i = 0; i < n && s[i]; i++) {
    if (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')
      s[i] = '_';
  }
}

/* ============================================================================
 * 写入辅助
 * ==========================================================================*/

static int fw_state_write_chunk(struct file *file, loff_t *pos, u32 *crc,
                                const char *buf, int len) {
  if (len <= 0)
    return -EINVAL;
  if (kernel_write(file, buf, len, pos) != len)
    return -EIO;
  *pos += len;
  *crc = crc32_le(*crc, buf, len);
  return 0;
}

/*
 * 同目录 .tmp → 目标路径的原子替换。
 *
 * 内核没有导出的「按路径 rename」原语（vfs_rename 需要已持锁的父目录），
 * 因此沿用现有实现的做法：调用 usermodehelper 执行 /bin/mv -f。
 */
static int fw_state_atomic_replace(const char *tmp, const char *final) {
  char *argv[] = { "/bin/mv", "-f", (char *)tmp, (char *) final, NULL };
  char *envp[] = { "HOME=/", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };

  if (call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC)) {
    pr_err("原子替换失败: %s -> %s\n", tmp, final);
    return -EIO;
  }
  return 0;
}

static void fw_state_unlink(const char *path) {
  char *argv[] = { "/bin/rm", "-f", (char *)path, NULL };
  char *envp[] = { "HOME=/", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };

  (void)call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

/* ============================================================================
 * 保存
 * ==========================================================================*/

static int fw_state_write_bans(struct file *file, loff_t *pos, u32 *crc,
                               char *buf, size_t buf_size) {
  struct fw_ban_row *rows;
  u64 now = ktime_get_real_seconds();
  u32 offset = 0;
  int ret = 0;

  rows = kmalloc_array(FW_STATE_PAGE, sizeof(*rows), GFP_KERNEL);
  if (!rows)
    return -ENOMEM;

  for (;;) {
    u32 got = fw_ban_fill_entries(offset, FW_STATE_PAGE, rows);
    u32 i;

    for (i = 0; i < got; i++) {
      struct fw_ban_row *r = &rows[i];
      char ip_str[FW_INET6_STR_LEN];
      char jail[sizeof(r->jail_name)];
      u64 remaining;
      int n;

      if (offset + i >= FW_STATE_MAX_BAN) {
        pr_warn("封禁条目超过保存上限 %d，其余条目本次不写入状态文件\n", FW_STATE_MAX_BAN);
        goto out;
      }

      if (r->is_permanent) {
        remaining = 0;
      } else {
        u64 expiry = r->banned_at + r->duration_secs;

        if (now >= expiry)
          continue; /* 已到期待摘链，不写入 */
        remaining = expiry - now;
      }

      fw_addr_to_str(r->af, &r->addr, ip_str, sizeof(ip_str));
      memcpy(jail, r->jail_name, sizeof(jail));
      jail[sizeof(jail) - 1] = '\0';
      fw_state_sanitize_field(jail, sizeof(jail));

      n = snprintf(buf, buf_size, "%s %s %llu %s %s\n",
                   r->af == FW_AF_INET6 ? "BAN_V6" : "BAN_V4", ip_str,
                   (unsigned long long)remaining, jail[0] ? jail : "api",
                   r->reason[0] ? r->reason : "(none)");
      ret = fw_state_write_chunk(file, pos, crc, buf, n);
      if (ret)
        goto out;
    }

    offset += got;
    if (got < FW_STATE_PAGE)
      break;
  }

out:
  kfree(rows);
  return ret;
}

static int fw_state_write_whitelist(struct file *file, loff_t *pos, u32 *crc,
                                    char *buf, size_t buf_size) {
  struct fw_wl_row *rows;
  u32 offset = 0;
  int ret = 0;

  rows = kmalloc_array(FW_STATE_PAGE, sizeof(*rows), GFP_KERNEL);
  if (!rows)
    return -ENOMEM;

  for (;;) {
    u32 got = fw_wl_fill_entries(offset, FW_STATE_PAGE, rows);
    u32 i;

    for (i = 0; i < got; i++) {
      struct fw_wl_row *r = &rows[i];
      char ip_str[FW_INET6_STR_LEN];
      int n;

      if (offset + i >= FW_STATE_MAX_WL) {
        pr_warn("白名单条目超过保存上限 %d，其余条目本次不写入状态文件\n", FW_STATE_MAX_WL);
        goto out;
      }

      fw_addr_to_str(r->af, &r->addr, ip_str, sizeof(ip_str));
      n = snprintf(buf, buf_size, "%s %s %u %s\n",
                   r->af == FW_AF_INET6 ? "WL_V6" : "WL_V4", ip_str,
                   r->prefix_len, r->device_name[0] ? r->device_name : "api");
      ret = fw_state_write_chunk(file, pos, crc, buf, n);
      if (ret)
        goto out;
    }

    offset += got;
    if (got < FW_STATE_PAGE)
      break;
  }

out:
  kfree(rows);
  return ret;
}

int fw_state_save(void) {
  const char *path = fw_state_file;
  struct file *file;
  char *buf, *tmp;
  loff_t pos = 0;
  u32 crc = ~0U;
  int ret, n;

  if (fw_state_validate_path(path))
    return -EINVAL;

  tmp = kasprintf(GFP_KERNEL, "%s.tmp", path);
  if (!tmp)
    return -ENOMEM;
  if (fw_state_validate_path(tmp)) {
    pr_err("状态临时文件路径非法: %s\n", tmp);
    kfree(tmp);
    return -EINVAL;
  }

  buf = kmalloc(512, GFP_KERNEL);
  if (!buf) {
    kfree(tmp);
    return -ENOMEM;
  }

  file = filp_open(tmp, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
  if (IS_ERR(file)) {
    ret = -EIO;
    goto out_free_buf;
  }

  n = snprintf(buf, 512, "FW_STATE 1\n");
  ret = fw_state_write_chunk(file, &pos, &crc, buf, n);
  if (ret)
    goto out_abort;

  ret = fw_state_write_bans(file, &pos, &crc, buf, 512);
  if (ret)
    goto out_abort;

  ret = fw_state_write_whitelist(file, &pos, &crc, buf, 512);
  if (ret)
    goto out_abort;

  /* CRC 行不参与校验和计算，故用 kernel_write 直接落盘 */
  n = snprintf(buf, 512, "CRC32 %08x\n", ~crc);
  if (kernel_write(file, buf, n, &pos) != n) {
    ret = -EIO;
    goto out_abort;
  }

  if (vfs_fsync(file, 0) != 0) {
    ret = -EIO;
    goto out_abort;
  }
  filp_close(file, NULL);

  ret = fw_state_atomic_replace(tmp, path);
  if (ret)
    fw_state_unlink(tmp);

  kfree(buf);
  kfree(tmp);
  return ret;

out_abort:
  filp_close(file, NULL);
  fw_state_unlink(tmp);
out_free_buf:
  kfree(buf);
  kfree(tmp);
  return ret;
}

/* ============================================================================
 * 恢复
 * ==========================================================================*/

/* 校验尾行 CRC32；命中返回 body 结束位置（置 '\0'），无 CRC 行返回原长度 */
static ssize_t fw_state_verify_crc(char *buf, ssize_t len) {
  char *last = NULL, *p = buf, *nl;

  /* 定位最后一行 CRC32（文件可能被追加过内容） */
  while ((nl = strnstr(p, "\nCRC32 ", (size_t)(len - (p - buf)))) != NULL) {
    last = nl + 1;
    p = last;
  }
  if (!last && strncmp(buf, "CRC32 ", 6) == 0)
    last = buf;
  if (!last)
    return len;

  {
    u32 expect, got;
    size_t body = (size_t)(last - buf);

    if (sscanf(last + 6, "%x", &expect) != 1)
      return len;
    got = ~crc32_le(~0U, buf, body);
    if (got != expect) {
      pr_err("状态文件校验和失败: expect=%08x got=%08x，拒绝恢复\n", expect, got);
      return -EINVAL;
    }
  }

  {
    size_t body = (size_t)(last - buf);
    buf[body] = '\0';
    return (ssize_t)body;
  }
}

/*
 * 恢复一行封禁：<af> 已解析，token 指向剩余字段（remaining jail reason...）。
 * 白名单前检交给调用侧（fw_ban_restore 不做白名单判断，因为白名单先恢复）。
 */
static int fw_state_restore_ban(const char *rest, u8 af) {
  char *work, *tok;
  char *time_str, *jail_str, *reason_str;
  union fw_addr addr;
  unsigned long remaining;
  u64 now;
  int ret;

  work = kstrdup(rest, GFP_KERNEL);
  if (!work)
    return -ENOMEM;

  tok = strsep(&work, " ");
  if (!tok) {
    kfree(work);
    return -EINVAL;
  }

  if (af == FW_AF_INET) {
    if (!in4_pton(tok, -1, (u8 *)&addr.ipv4, -1, NULL)) {
      kfree(work);
      return -EINVAL;
    }
  } else {
    if (!in6_pton(tok, -1, (u8 *)&addr.ipv6, -1, NULL)) {
      kfree(work);
      return -EINVAL;
    }
  }

  time_str = strsep(&work, " ");
  jail_str = strsep(&work, " ");
  reason_str = work; /* reason 为行尾剩余字段，可含空格 */

  if (!time_str || kstrtoul(time_str, 10, &remaining) != 0) {
    kfree(work);
    return -EINVAL;
  }

  /* 超过一年视为损坏行 */
  if (remaining > 365UL * 24 * 60 * 60) {
    kfree(work);
    return -EINVAL;
  }

  if (fw_wl_lookup(af, &addr)) {
    kfree(work);
    return 0; /* 已在白名单：不再恢复该封禁 */
  }

  /*
   * remaining == 0 ⇒ 永久；否则按原始起点换算：起点 = now - (总时长 - 剩余)，
   * 但状态文件只存剩余量，总时长未知，故把「起点」定为 now，剩余时长即 duration。
   * 这与旧的 unban_time = jiffies + remaining 语义完全一致，且 banned_at 保留了
   * 外部时点求得的正确起点（供 UI 显示封禁时刻用）。
   */
  now = ktime_get_real_seconds();
  /*
   * 状态文件的行格式（BAN_V4/V6 <ip> <remaining> <jail> <reason>）是运维契约，
   * 不带前缀长度字段，故恢复一律按**精确单机**（全长前缀）解释；网段条目在重启
   * 后降级为「其网段地址那一个主机」——要保住网段需扩展该契约格式（未做）。
   */
  ret = fw_ban_restore(af, &addr, fw_max_prefix_len(af), (u32)remaining,
                       remaining ? now : 0,
                       reason_str && reason_str[0] ? reason_str : "restored",
                       jail_str && jail_str[0] ? jail_str : "api");

  kfree(work);
  return ret;
}

static int fw_state_restore_wl(const char *rest, u8 af) {
  char *work, *tok;
  char *prefix_str, *dev_str;
  union fw_addr addr;
  int plen, ret;

  work = kstrdup(rest, GFP_KERNEL);
  if (!work)
    return -ENOMEM;

  tok = strsep(&work, " ");
  if (!tok) {
    kfree(work);
    return -EINVAL;
  }

  if (af == FW_AF_INET) {
    if (!in4_pton(tok, -1, (u8 *)&addr.ipv4, -1, NULL)) {
      kfree(work);
      return -EINVAL;
    }
  } else {
    if (!in6_pton(tok, -1, (u8 *)&addr.ipv6, -1, NULL)) {
      kfree(work);
      return -EINVAL;
    }
  }

  prefix_str = strsep(&work, " ");
  dev_str = strsep(&work, " ");

  if (!prefix_str || kstrtoint(prefix_str, 10, &plen) != 0 || plen < 0 ||
      (af == FW_AF_INET ? plen > 32 : plen > 128)) {
    kfree(work);
    return -EINVAL;
  }

  /* 文件里存的已是 network 地址，再归一化一次以防旧文件写入过主机位 */
  fw_addr_normalize(af, &addr, (u8)plen);
  ret = fw_wl_add(af, &addr, (u8)plen, dev_str && dev_str[0] ? dev_str : "restored");

  kfree(work);
  return ret;
}

int fw_state_restore(void) {
  const char *path = fw_state_file;
  struct file *file;
  char *buf, *work, *line;
  ssize_t len = 0;
  int ret = 0;

  if (fw_state_restored)
    return 0;
  fw_state_restored = true;

  if (fw_state_validate_path(path))
    return -EINVAL;

  buf = kmalloc(FW_STATE_MAX_FILE, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  file = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
  if (IS_ERR(file)) {
    /* 首次启动没有状态文件属正常情况 */
    kfree(buf);
    return 0;
  }

  while (len < FW_STATE_MAX_FILE - 1) {
    loff_t pos = len;
    ssize_t got = kernel_read(file, buf + len, FW_STATE_MAX_FILE - 1 - len, &pos);

    if (got <= 0)
      break;
    len += got;
  }
  filp_close(file, NULL);

  if (len <= 0)
    goto out;

  buf[len] = '\0';
  len = fw_state_verify_crc(buf, len);
  if (len < 0) {
    ret = (int)len;
    goto out;
  }

  /*
   * 两遍解析：先白名单后封禁，这样封禁恢复时的白名单前检一定命中，与文件里
   * WL / BAN 两段的先后无关。解析用 strsep 原地改写，故每遍先复制一份。
   */
  work = kmalloc((size_t)len + 1, GFP_KERNEL);
  if (!work) {
    ret = -ENOMEM;
    goto out;
  }

  for (int pass = 0; pass < 2; pass++) {
    char *p = work;

    memcpy(work, buf, (size_t)len + 1);

    while ((line = strsep(&p, "\n")) != NULL) {
      char *rest;

      if (!line[0])
        continue;

      rest = strchr(line, ' ');
      if (!rest || rest == line)
        continue;
      *rest++ = '\0';

      if (pass == 0) {
        if (strcmp(line, "WL_V4") == 0)
          (void)fw_state_restore_wl(rest, FW_AF_INET);
        else if (strcmp(line, "WL_V6") == 0)
          (void)fw_state_restore_wl(rest, FW_AF_INET6);
      } else {
        if (strcmp(line, "BAN_V4") == 0)
          (void)fw_state_restore_ban(rest, FW_AF_INET);
        else if (strcmp(line, "BAN_V6") == 0)
          (void)fw_state_restore_ban(rest, FW_AF_INET6);
      }
    }
  }

  kfree(work);

out:
  kfree(buf);
  return ret;
}
