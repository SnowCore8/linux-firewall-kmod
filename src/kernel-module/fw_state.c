// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_state.c - 状态文件读写（封禁表 + 白名单）
 *
 * 与旧实现（state-persist.c）的差别（见
 * docs/zh/development/kernel-module-design.md 与契约修订说明）：
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
 *   4. **封禁行带前缀长度**（格式表见 fw_state.h）：旧格式把 CIDR 封禁写成裸
 *      地址，恢复时只能按 /32、/128 解释，重启一次就把网段封禁降级成单主机
 *      封禁。新格式在地址后加「/前缀」；不带斜杠的地址字段按全长解释，因此
 *      仍读得懂旧文件。
 *
 *   5. **CRC32 尾行由「可选」改为必需**：旧实现遇到没有 CRC 行的文件直接整份
 *      接受，于是写盘中途被打断（只剩半份 body）的快照会被当作可信状态恢复。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "fw_state.h"
#include "fw_ban.h"
#include "fw_wl.h"

/*
 * 状态文件大小上限：按容量参数反推（每条一行 × 单行最长），而不是拍一个定值。
 * 旧实现写死 128 KB，而保存上限是 4096 行——一份接近写满的快照读进来必然被截断，
 * CRC 必然不符，于是「保存成功、恢复必失败」。
 */
#define FW_STATE_MAX_LINE 160
#define FW_STATE_MAX_FILE_CAP (32 * 1024 * 1024)
/* CRC32 尾行 "CRC32 %08x\n" 的固定字节数（6 + 8 + 1） */
#define FW_STATE_CRC_LINE_LEN 15

/*
 * 保存时每张表的写出上限：取 fw_info 里的容量快照（fw_main.c 载入参数时写入），
 * 快照才可能覆盖表的全部内容。不能读 fw_max_ban_entries / fw_max_whitelist_entries
 * 这两个 0644 模块参数：运行期改写它们并不改变已分配表的实际容量，却会让保存
 * 路径与文件预算按新值静默丢弃条目。
 */
#define FW_STATE_MAX_BAN fw_info.max_ban_entries
#define FW_STATE_MAX_WL fw_info.max_wl_entries

/* 分页收集时每页行数 */
#define FW_STATE_PAGE 64

/* 成功恢复只做一次：模块生命周期内的守卫。失败路径会放位，故失败仍可重试；
 * 用 bit 操作保证并发下只有一个执行者进入恢复流程。 */
static unsigned long fw_state_restored_flag;
/* 状态保存截断累计计数：fw_state_save 在因条目上限或字节预算丢弃条目时递增一次，
 * 由 procfs stats 暴露给守护进程。用 atomic64 因为递增发生在保存路径（无锁上下文），
 * 而读取发生在 procfs show（不同 CPU）。 */
static atomic64_t fw_state_save_truncated_count;

/* 按容量快照推出状态文件的可读上限（超出即视为损坏，不尝试恢复） */
static size_t fw_state_max_file_size(void) {
  u64 lines = (u64)FW_STATE_MAX_BAN + FW_STATE_MAX_WL + 4;
  u64 bytes = lines * FW_STATE_MAX_LINE;

  if (bytes > FW_STATE_MAX_FILE_CAP)
    return FW_STATE_MAX_FILE_CAP;
  return (size_t)bytes;
}

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
    if ((unsigned char)*p < 0x20) {
      pr_warn("state path contains control character at pos %zu\n", (size_t)(p - path));
      return -EINVAL;
    }
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

/*
 * 字段内的空白（空格 / 制表 / 换行 / 回车）会破坏空格分隔、换行分行的文件格式，
 * 统一替换为 '_'。reason 与 device_name 都由外部输入（HTTP 请求 / 设备名）而来，
 * 不清洗就能把 "x\nWL_V4 6.6.6.6 32 api" 这样的内容写成合法的白名单行。
 */
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
  /* kernel_write 会按写入长度推进 *pos，此处不得再推一次：重复推进会在
   * 每个 chunk 后留下等长空洞，CRC 于是对不上实际文件字节，恢复侧直接
   * 在 CRC 校验处失败（且空洞开头的行会被当空行跳过）。 */
  if (kernel_write(file, buf, len, pos) != len)
    return -EIO;
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

/*
 * 状态持久化依赖 /bin/mv 与 /bin/rm（call_usermodehelper 路径）。最小化环境
 * （BusyBox 只装到 /usr/bin、嵌入式 initramfs 缺 bin 目录）可能缺失。模块加载
 * 时探测一次，缺失则告警——保存/恢复会在运行期失败，但不阻止加载：首次启动
 * 没有状态文件属正常路径，缺失工具只影响后续保存。
 */
int fw_state_init(void) {
  struct file *f;

  f = filp_open("/bin/mv", O_PATH | O_LARGEFILE, 0);
  if (IS_ERR(f)) {
    pr_warn("状态持久化: /bin/mv 不存在，状态保存将失败\n");
  } else {
    filp_close(f, NULL);
  }

  f = filp_open("/bin/rm", O_PATH | O_LARGEFILE, 0);
  if (IS_ERR(f)) {
    pr_warn("状态持久化: /bin/rm 不存在，状态保存/清理将失败\n");
  } else {
    filp_close(f, NULL);
  }

  return 0;
}

/* ============================================================================
 * 保存
 * ==========================================================================*/

/*
 * 保存侧的字节预算。上限取 fw_state_max_file_size()，与恢复端的拒绝阈值同一
 * 口径：写出的文件必然 ≤ 该值，否则下次启动会因 -EFBIG 整份拒绝恢复。
 * used 计入已写字节（含头行）；判断每条时另加 CRC 尾行长度，保证尾行也放得下。
 * dropped 是本轮因条目上限或字节预算未写入的条目数，告警在保存收尾时统一发一次。
 */
struct fw_state_write_ctx {
  size_t limit;
  size_t used;
  u64 dropped;
};

/* 一条 n 字节的条目行（外加必写的 CRC 尾行）是否仍在字节预算内 */
static bool fw_state_line_fits(const struct fw_state_write_ctx *ctx, int n) {
  return ctx->used + (size_t)n + FW_STATE_CRC_LINE_LEN <= ctx->limit;
}

static int fw_state_write_bans(struct file *file, loff_t *pos, u32 *crc, char *buf,
                               size_t buf_size, struct fw_state_write_ctx *ctx) {
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
      char reason[sizeof(r->reason)];
      u64 remaining;
      int n;

      if (offset + i >= FW_STATE_MAX_BAN) {
        ctx->dropped++;
        continue;
      }

      if (r->is_permanent) {
        remaining = 0;
      } else {
        u64 expiry = r->banned_at + r->duration_secs;

        if (now >= expiry)
          continue; /* 已到期待摘链，不写入 */
        remaining = expiry - now;
      }

      /*
       * 地址带前缀：网段封禁必须原样落盘，否则重启后按全长解释，/24 封禁缩水成
       * 其中一台主机（见 fw_state.h 的格式表）。
       */
      fw_addr_to_str(r->af, &r->addr, ip_str, sizeof(ip_str));
      /* jail 与 reason 都在本地拷贝上清洗，绝不改表节点本身 */
      memcpy(jail, r->jail_name, sizeof(jail));
      jail[sizeof(jail) - 1] = '\0';
      fw_state_sanitize_field(jail, sizeof(jail));
      memcpy(reason, r->reason, sizeof(reason));
      reason[sizeof(reason) - 1] = '\0';
      fw_state_sanitize_field(reason, sizeof(reason));

      n = snprintf(buf, buf_size, "%s %s/%u %llu %s %s\n",
                   r->af == FW_AF_INET6 ? "BAN_V6" : "BAN_V4", ip_str,
                   (unsigned int)r->prefix_len, (unsigned long long)remaining,
                   jail[0] ? jail : "api", reason[0] ? reason : "(none)");
      if (n >= (int)buf_size) {
        ret = -ENOSPC;
        goto out;
      }
      if (!fw_state_line_fits(ctx, n)) {
        ctx->dropped++;
        continue; /* 超出预算：不再写后续条目，文件保持在恢复端可接受的大小 */
      }
      ret = fw_state_write_chunk(file, pos, crc, buf, n);
      if (ret)
        goto out;
      ctx->used += (size_t)n;
    }

    offset += got;
    if (got < FW_STATE_PAGE)
      break;
  }

out:
  kfree(rows);
  return ret;
}

static int fw_state_write_whitelist(struct file *file, loff_t *pos, u32 *crc, char *buf,
                                    size_t buf_size, struct fw_state_write_ctx *ctx) {
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
      char dev[sizeof(r->device_name)];
      int n;

      if (offset + i >= FW_STATE_MAX_WL) {
        ctx->dropped++;
        continue;
      }

      fw_addr_to_str(r->af, &r->addr, ip_str, sizeof(ip_str));
      /* device_name 可能来自接口名或外部下发，同样在本地拷贝上清洗 */
      memcpy(dev, r->device_name, sizeof(dev));
      dev[sizeof(dev) - 1] = '\0';
      fw_state_sanitize_field(dev, sizeof(dev));
      n = snprintf(buf, buf_size, "%s %s %u %s\n", r->af == FW_AF_INET6 ? "WL_V6" : "WL_V4",
                   ip_str, r->prefix_len, dev[0] ? dev : "api");
      if (n >= (int)buf_size) {
        ret = -ENOSPC;
        goto out;
      }
      if (!fw_state_line_fits(ctx, n)) {
        ctx->dropped++;
        continue; /* 超出预算：不再写后续条目，文件保持在恢复端可接受的大小 */
      }
      ret = fw_state_write_chunk(file, pos, crc, buf, n);
      if (ret)
        goto out;
      ctx->used += (size_t)n;
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
  struct fw_state_write_ctx ctx = { .limit = 0, .used = 0, .dropped = 0 };
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

  n = snprintf(buf, 512, "FW_STATE 2\n");
  ret = fw_state_write_chunk(file, &pos, &crc, buf, n);
  if (ret)
    goto out_abort;

  /* 头行计入预算；上限与恢复端同一口径，保证写出的文件一定能被恢复接受 */
  ctx.limit = fw_state_max_file_size();
  ctx.used = (size_t)n;

  ret = fw_state_write_bans(file, &pos, &crc, buf, 512, &ctx);
  if (ret)
    goto out_abort;

  ret = fw_state_write_whitelist(file, &pos, &crc, buf, 512, &ctx);
  if (ret)
    goto out_abort;

  /* 截断只告警一次，带本轮丢弃条数与实际上限，便于定位容量参数配得过大 */
  if (ctx.dropped) {
    atomic64_inc(&fw_state_save_truncated_count);
    pr_warn("状态文件达到上限 %zu 字节，本次丢弃 %llu 个条目\n", ctx.limit,
            (unsigned long long)ctx.dropped);
  }

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

/*
 * 校验尾行 CRC32；命中返回 body 结束位置（置 '\0'）。
 *
 * CRC 行缺失或读不出十六进制都按「拒绝恢复」处理：写盘中途被打断的快照正是只有
 * body、没有 CRC 行的形状，旧实现返回原长度等于把半截状态当可信数据。
 */
static ssize_t fw_state_verify_crc(char *buf, ssize_t len) {
  char *last = NULL, *p = buf, *nl;

  /* 定位最后一行 CRC32（文件可能被追加过内容） */
  while ((nl = strnstr(p, "\nCRC32 ", (size_t)(len - (p - buf)))) != NULL) {
    last = nl + 1;
    p = last;
  }
  if (!last && strncmp(buf, "CRC32 ", 6) == 0)
    last = buf;
  if (!last) {
    pr_err("状态文件缺少 CRC32 尾行（半截快照？），拒绝恢复\n");
    return -EINVAL;
  }

  {
    u32 expect, got;
    size_t body = (size_t)(last - buf);

    if (sscanf(last + 6, "%x", &expect) != 1) {
      pr_err("状态文件 CRC32 行无法解析，拒绝恢复\n");
      return -EINVAL;
    }
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
 * 恢复一行封禁：<af> 已解析，token 指向剩余字段（[<ip>[/<plen>]] remaining jail reason...）。
 * 白名单前检交给调用侧（fw_ban_restore 不做白名单判断，因为白名单先恢复）。
 *
 * strsep 会把 work 推进到缓冲区内部，故 base 另存一份用于 kfree：直接
 * kfree(work) 是释放非块首地址，slab 会当场报错。
 */
static int fw_state_restore_ban(const char *rest, u8 af) {
  char *base, *work, *tok;
  char *time_str, *jail_str, *reason_str;
  union fw_addr addr;
  unsigned long remaining;
  u32 parsed_prefix;
  u8 prefix_len = fw_max_prefix_len(af);
  u64 now;
  int ret;

  base = kstrdup(rest, GFP_KERNEL);
  if (!base)
    return -ENOMEM;
  work = base;

  tok = strsep(&work, " ");
  if (!tok) {
    kfree(base);
    return -EINVAL;
  }

  /* 地址字段可带「/前缀长度」；不带斜杠时按全长解释，即版本 1 文件的形状 */
  {
    char *slash = strchr(tok, '/');

    if (slash) {
      *slash = '\0';
      if (kstrtouint(slash + 1, 10, &parsed_prefix) != 0 ||
          parsed_prefix > (u32)fw_max_prefix_len(af)) {
        kfree(base);
        return -EINVAL;
      }
      prefix_len = (u8)parsed_prefix;
    }
  }

  if (af == FW_AF_INET) {
    if (!in4_pton(tok, -1, (u8 *)&addr.ipv4, -1, NULL)) {
      kfree(base);
      return -EINVAL;
    }
  } else {
    if (!in6_pton(tok, -1, (u8 *)&addr.ipv6, -1, NULL)) {
      kfree(base);
      return -EINVAL;
    }
  }

  time_str = strsep(&work, " ");
  jail_str = strsep(&work, " ");
  reason_str = work; /* reason 为行尾剩余字段，可含空格 */

  if (!time_str || kstrtoul(time_str, 10, &remaining) != 0) {
    kfree(base);
    return -EINVAL;
  }

  /* 超过一年视为损坏行 */
  if (remaining > 365UL * 24 * 60 * 60) {
    kfree(base);
    return -EINVAL;
  }

  if (fw_wl_lookup(af, &addr)) {
    kfree(base);
    return 0; /* 已在白名单：不再恢复该封禁 */
  }

  /*
   * remaining == 0 ⇒ 永久；否则按原始起点换算：起点 = now - (总时长 - 剩余)，
   * 但状态文件只存剩余量，总时长未知，故把「起点」定为 now，剩余时长即 duration。
   * 这与旧的 unban_time = jiffies + remaining 语义完全一致，且 banned_at 保留了
   * 外部时点求得的正确起点（供 UI 显示封禁时刻用）。
   */
  now = ktime_get_real_seconds();
  /* 与 fw_wl 恢复一样先归一化：短前缀条目必须存网络地址，否则同一网段的不同主机位
   * 会在同一桶里各建一条（fw_ban_find_locked 按地址全等比较） */
  fw_addr_normalize(af, &addr, prefix_len);
  ret = fw_ban_restore(af, &addr, prefix_len, (u32)remaining, remaining ? now : 0,
                       reason_str && reason_str[0] ? reason_str : "restored",
                       jail_str && jail_str[0] ? jail_str : "api");

  kfree(base);
  return ret;
}

static int fw_state_restore_wl(const char *rest, u8 af) {
  char *base, *work, *tok;
  char *prefix_str, *dev_str;
  union fw_addr addr;
  int plen, ret;

  base = kstrdup(rest, GFP_KERNEL);
  if (!base)
    return -ENOMEM;
  work = base;

  tok = strsep(&work, " ");
  if (!tok) {
    kfree(base);
    return -EINVAL;
  }

  if (af == FW_AF_INET) {
    if (!in4_pton(tok, -1, (u8 *)&addr.ipv4, -1, NULL)) {
      kfree(base);
      return -EINVAL;
    }
  } else {
    if (!in6_pton(tok, -1, (u8 *)&addr.ipv6, -1, NULL)) {
      kfree(base);
      return -EINVAL;
    }
  }

  prefix_str = strsep(&work, " ");
  dev_str = strsep(&work, " ");

  if (!prefix_str || kstrtoint(prefix_str, 10, &plen) != 0 || plen < 0 ||
      (af == FW_AF_INET ? plen > 32 : plen > 128)) {
    kfree(base);
    return -EINVAL;
  }

  /* 文件里存的已是 network 地址，再归一化一次以防旧文件写入过主机位 */
  fw_addr_normalize(af, &addr, (u8)plen);
  ret = fw_wl_add(af, &addr, (u8)plen, dev_str && dev_str[0] ? dev_str : "restored");

  kfree(base);
  return ret;
}

/*
 * 返回值：0 表示恢复完成，或首次启动确实没有状态文件（ENOENT）；负 errno 表示
 * 快照存在却读不到/不可用。后者不能静默降级——白名单没恢复回来，内核照常收包，
 * 管理员自己的地址就可能被当成攻击源封掉。调用方据此放弃加载（fw_main.c）。
 *
 * 一次性标志只在「路径合法、打开成功、且本次恢复扫完整个文件」之后保留置位；
 * 任何失败路径都 clear_bit，使同一实例内的再次调用仍有机会恢复。
 */
int fw_state_restore(void) {
  const char *path = fw_state_file;
  struct file *file;
  char *buf = NULL, *work, *line;
  size_t cap;
  loff_t isize;
  ssize_t len = 0;
  int ret = 0;

  /*
   * test_and_set_bit 返回旧值：已（成功）恢复则直接返回。并发下只有抢到位的
   * 线程进入恢复流程，抢不到的在任何读写之前就返回；抢到者直到函数结束才放位，
   * 故不存在两条线程同时解析同一份快照。
   */
  if (test_and_set_bit(0, &fw_state_restored_flag))
    return 0;

  ret = fw_state_validate_path(path);
  if (ret) {
    /* 路径来自模块参数：报出具体 errno，管理员改对参数后重新加载即可 */
    pr_err("state_file 路径非法: %d，白名单与封禁未恢复\n", ret);
    goto out;
  }

  file = filp_open(path, O_RDONLY | O_NOFOLLOW, 0);
  if (IS_ERR(file)) {
    ret = (int)PTR_ERR(file);
    if (ret == -ENOENT) {
      ret = 0; /* 首次启动还没有快照：正常路径，不告警 */
    } else {
      /*
       * EACCES / EIO / ELOOP（O_NOFOLLOW 撞上符号链接）等都与「没有文件」不同：
       * 快照本该在却读不到，必须让失败可见，不能当成干净启动。
       */
      pr_err("打开状态文件 %s 失败: %d，白名单与封禁未恢复\n", path, ret);
    }
    goto out;
  }

  /*
   * 读多少配多少：上限按容量参数反推（见 fw_state_max_file_size）。保存路径
   * 必定写 FW_STATE 头行与 CRC32 尾行，故 0 字节文件只可能是损坏，不是空快照。
   */
  cap = fw_state_max_file_size();
  isize = i_size_read(file_inode(file));
  if (isize <= 0) {
    pr_err("状态文件 %s 为空（保存路径总要写头行与 CRC），按损坏处理，拒绝恢复\n", path);
    ret = -EINVAL;
    goto out_close;
  }
  if ((u64)isize > (u64)cap) {
    pr_err("状态文件 %lld 字节超过上限 %zu（按容量参数反推），拒绝恢复\n",
           (long long)isize, cap);
    ret = -EFBIG;
    goto out_close;
  }

  /* 快照可达数 MB：用 vmalloc，不依赖高阶连续页 */
  buf = vmalloc((size_t)isize + 1);
  if (!buf) {
    ret = -ENOMEM;
    goto out_close;
  }

  while (len < isize) {
    loff_t pos = len;
    ssize_t got = kernel_read(file, buf + len, (size_t)(isize - len), &pos);

    if (got <= 0)
      break;
    len += got;
  }
  if (len != isize) {
    /* 读不满说明文件被截断或底层报错：半份 body 的 CRC 本就对不上，直接拒绝 */
    pr_err("状态文件 %s 读取不完整: %zd/%lld 字节，拒绝恢复\n", path, len, (long long)isize);
    ret = -EIO;
    goto out_close;
  }

out_close:
  filp_close(file, NULL);

  if (ret)
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
  work = vmalloc((size_t)len + 1);
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

  kvfree(work);

out:
  kvfree(buf);
  if (ret) {
    /*
     * 只有「扫完整个文件」才算消费掉这次机会，失败一律放位。CRC 不符 / 超上限 /
     * 读失败属于「文件存在但内容不可用」，重读同一份坏文件不会变好，这里仍清位
     * 只为把规则收敛成「恢复到底才置位」；加载失败后重新 insmod 本就是新实例，
     * 不会因旧标志挡住重试。
     */
    clear_bit(0, &fw_state_restored_flag);
  }
  return ret;
}

u64 fw_state_truncated_count(void) {
  return (u64)atomic64_read(&fw_state_save_truncated_count);
}
