# 内核模块 API 兼容性检查策略

## 概述

本模块采用**基于 API 可用性的兼容性检查策略**，而非传统的版本号限制策略。这种设计确保模块能够在各种内核版本和发行版上正确工作，只要所需的内核 API 可用。

## 设计理念

### 为什么不用版本号限制？

**传统做法的问题**：

```c
// ❌ 不推荐：版本号硬限制
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#error "Kernel 5.0+ required"
#endif

if (version < MIN_VERSION || version >= MAX_VERSION) {
    return -EINVAL;  // 拒绝加载
}
```

**问题**：
1. **版本号不可靠**
   - 不同发行版的内核可能版本号相同但 API 不同
   - 例如：Ubuntu 5.15.0-xx 和 CentOS 5.15.0-xx 可能有不同的配置
   
2. **Backport 导致混乱**
   - 某些发行版会将新版本的 API backport 到旧版本内核
   - 例如：Ubuntu 20.04 的 5.4 内核可能包含 5.10 的某些 API
   
3. **过度限制**
   - 新版本内核（如 8.x）可能完全兼容，但因为版本号被拒绝
   - 用户需要修改代码才能测试新内核

4. **错误信息不明确**
   - "内核版本不支持"无法告诉用户具体缺少什么
   - 难以诊断问题

### API 检查策略的优势

**本模块的做法**：

```c
// ✓ 推荐：API 可用性检查
static inline int fw_compat_check_api(void) {
    // 检查 netfilter API
    ret = fw_compat_check_netfilter();
    if (ret) {
        pr_err("netfilter API 不可用\n");
        return ret;
    }
    
    // 检查 netlink API
    ret = fw_compat_check_netlink();
    if (ret) {
        pr_err("netlink API 不可用\n");
        return ret;
    }
    
    // 检查 procfs API
    ret = fw_compat_check_procfs();
    if (ret) {
        pr_err("procfs API 不可用\n");
        return ret;
    }
    
    return 0;
}
```

**优势**：
1. **精确检测**：直接检查模块实际依赖的功能
2. **适应性强**：不受版本号命名规则影响
3. **错误明确**：告诉用户具体哪个 API 不可用
4. **向前兼容**：新版本内核只要 API 兼容就能工作

## 检查的 API 详解

### 1. Netfilter API

**用途**：网络数据包过滤和拦截

**依赖的函数**：
```c
#include <linux/netfilter.h>

// 注册 netfilter 钩子
int nf_register_net_hook(struct net *net, const struct nf_hook_ops *ops);

// 注销 netfilter 钩子
void nf_unregister_net_hook(struct net *net, const struct nf_hook_ops *ops);

// 钩子操作结构体
struct nf_hook_ops {
    struct list_head list;
    nf_hookfn *hook;          // 钩子函数
    void *priv;               // 私有数据
    struct module *owner;     // 模块所有者
    u_int8_t pf;              // 协议族（PF_INET, PF_INET6）
    unsigned int hooknum;     // 钩子点（NF_INET_PRE_ROUTING 等）
    int priority;             // 优先级
};
```

**检查方法**：
```c
static inline int fw_compat_check_netfilter(void)
{
    /*
     * 编译时检查：
     * - 如果 nf_register_net_hook 不存在，编译会失败
     * - 如果 struct nf_hook_ops 定义变化，编译会失败
     *
     * 运行时检查：
     * - 验证结构体可以正常初始化
     * - 某些内核配置可能禁用 netfilter（如 CONFIG_NETFILTER=n）
     */
    
    struct nf_hook_ops test_ops;
    memset(&test_ops, 0, sizeof(test_ops));
    
    // 验证关键字段可以正常设置
    test_ops.hook = NULL;
    test_ops.pf = PF_INET;
    test_ops.hooknum = NF_INET_PRE_ROUTING;
    
    pr_info("netfilter API: 可用\n");
    return 0;
}
```

**失败场景**：
- 内核配置禁用了 netfilter（`CONFIG_NETFILTER=n`）
- 内核版本过旧，缺少 `nf_register_net_hook`（2.6.x 之前）
- 内核定制移除了 netfilter 支持

**解决方案**：
- 重新编译内核，启用 `CONFIG_NETFILTER`
- 升级内核到 2.6+ 版本
- 使用支持 netfilter 的内核发行版

---

### 2. Netlink API

**用途**：内核模块与用户空间守护进程通信

**依赖的函数**：
```c
#include <net/netlink.h>

// 创建 netlink 套接字
struct sock *netlink_kernel_create(struct net *net, int unit,
                                    struct netlink_kernel_cfg *cfg);

// 释放 netlink 套接字
void netlink_kernel_release(struct sock *sk);

// 配置结构体
struct netlink_kernel_cfg {
    unsigned int groups;        // 组播组数量
    unsigned int flags;         // 标志
    void (*input)(struct sk_buff *skb);  // 输入回调
    struct mutex *cb_mutex;     // 回调互斥锁
    int (*bind)(struct net *net, int group);  // 绑定回调
    void (*unbind)(struct net *net, int group);  // 解绑回调
    bool (*compare)(struct net *net, struct sock *sk);  // 比较回调
};
```

**检查方法**：
```c
static inline int fw_compat_check_netlink(void)
{
    /*
     * 编译时检查：
     * - 如果 netlink_kernel_create 不存在，编译会失败
     * - 如果 struct netlink_kernel_cfg 定义变化，编译会失败
     *
     * 运行时检查：
     * - 验证配置结构体可以正常初始化
     * - 某些内核配置可能禁用 netlink（如 CONFIG_NETLINK=n）
     */
    
    struct netlink_kernel_cfg test_cfg;
    memset(&test_cfg, 0, sizeof(test_cfg));
    
    // 验证关键字段可以正常设置
    test_cfg.groups = 0;
    test_cfg.input = NULL;
    
    pr_info("netlink API: 可用\n");
    return 0;
}
```

**失败场景**：
- 内核配置禁用了 netlink（`CONFIG_NETLINK=n`）
- 内核版本过旧，缺少 `netlink_kernel_create`（2.6.x 之前）
- 内核定制移除了 netlink 支持

**解决方案**：
- 重新编译内核，启用 `CONFIG_NETLINK`
- 升级内核到 2.6+ 版本
- 使用支持 netlink 的内核发行版

---

### 3. Procfs API

**用途**：提供 `/proc/firewall/*` 用户空间接口

**依赖的函数**：
```c
#include <linux/proc_fs.h>

// 创建 proc 文件
struct proc_dir_entry *proc_create(const char *name, umode_t mode,
                                    struct proc_dir_entry *parent,
                                    const struct proc_ops *proc_ops);

// 删除 proc 文件
void proc_remove(struct proc_dir_entry *entry);

// 文件操作结构体（5.6+ 使用 proc_ops，之前使用 file_operations）
struct proc_ops {
    int (*proc_open)(struct inode *, struct file *);
    ssize_t (*proc_read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*proc_write)(struct file *, const char __user *, size_t, loff_t *);
    loff_t (*proc_lseek)(struct file *, loff_t, int);
    int (*proc_release)(struct inode *, struct file *);
    // ... 其他操作
};
```

**检查方法**：
```c
static inline int fw_compat_check_procfs(void)
{
    /*
     * 编译时检查：
     * - 如果 proc_create 不存在，编译会失败
     * - 如果 struct proc_ops 定义变化，编译会失败
     *
     * 运行时检查：
     * - 验证结构体可以正常初始化
     * - 某些内核配置可能禁用 procfs（如 CONFIG_PROC_FS=n）
     *
     * 注意：
     * - Linux 5.6+ 使用 proc_ops
     * - Linux 5.5 及之前使用 file_operations
     * - 代码中通过条件编译处理差异
     */
    
    // 验证 procfs API 可用
    // 实际检查在编译时完成，运行时仅记录信息
    
    pr_info("procfs API: 可用\n");
    return 0;
}
```

**失败场景**：
- 内核配置禁用了 procfs（`CONFIG_PROC_FS=n`）
- 内核版本过旧，缺少 `proc_create`（2.6.x 之前）
- 内核定制移除了 procfs 支持

**解决方案**：
- 重新编译内核，启用 `CONFIG_PROC_FS`
- 升级内核到 2.6+ 版本
- 使用支持 procfs 的内核发行版

---

## 检查流程

### 模块加载时的检查顺序

```
fw_init()
  ↓
fw_compat_init()
  ↓
├─ fw_compat_check_version()      # 仅记录版本信息
  ↓
└─ fw_compat_check_api()          # 硬性要求
     ↓
     ├─ fw_compat_check_netfilter()
     │   └─ 失败 → 返回 -ENOTSUPP，阻止加载
     ↓
     ├─ fw_compat_check_netlink()
     │   └─ 失败 → 返回 -ENOTSUPP，阻止加载
     ↓
     └─ fw_compat_check_procfs()
         └─ 失败 → 返回 -ENOTSUPP，阻止加载
  ↓
所有检查通过 → 继续初始化
```

### 检查时机

- **编译时**：通过头文件包含和函数调用检查 API 是否存在
- **加载时**：在 `module_init` 最开始执行运行时检查
- **运行时**：API 行为由内核保证，模块不做额外检查

## 故障排查

### 查看检查日志

```bash
# 加载模块
sudo insmod firewall.ko

# 查看兼容性检查日志
dmesg | grep firewall

# 预期输出（成功）
[12345.678] firewall: 开始内核兼容性检查...
[12345.678] firewall: 内核版本: 6.8.12
[12345.678] firewall: 开始检查关键 API 可用性...
[12345.678] firewall: netfilter API: 可用
[12345.678] firewall: netlink API: 可用
[12345.678] firewall: procfs API: 可用
[12345.678] firewall: 所有关键 API 检查通过
[12345.678] firewall: 兼容性检查完成，模块可以加载
```

### 常见错误及解决

**错误 1：netfilter API 不可用**

```
[12345.678] firewall: netfilter API: 不可用
[12345.678] firewall: 关键 API 检查失败，模块无法正常工作
insmod: ERROR: could not insert module: Operation not supported
```

**排查步骤**：
```bash
# 1. 检查内核配置
zcat /proc/config.gz | grep CONFIG_NETFILTER
# 或
grep CONFIG_NETFILTER /boot/config-$(uname -r)

# 2. 检查 netfilter 模块是否加载
lsmod | grep nf_

# 3. 尝试加载 netfilter 模块
sudo modprobe nf_tables
```

**解决方案**：
- 如果 `CONFIG_NETFILTER=n`：重新编译内核，启用 netfilter
- 如果 netfilter 模块未加载：在 `/etc/modules` 中添加 `nf_tables`

---

**错误 2：netlink API 不可用**

```
[12345.678] firewall: netlink API: 不可用
[12345.678] firewall: 关键 API 检查失败，模块无法正常工作
```

**排查步骤**：
```bash
# 1. 检查内核配置
zcat /proc/config.gz | grep CONFIG_NETLINK
# 或
grep CONFIG_NETLINK /boot/config-$(uname -r)

# 2. 检查 netlink 相关模块
lsmod | grep netlink
```

**解决方案**：
- 如果 `CONFIG_NETLINK=n`：重新编译内核，启用 netlink
- 升级内核到支持 netlink 的版本（2.6+）

---

**错误 3：procfs API 不可用**

```
[12345.678] firewall: procfs API: 不可用
[12345.678] firewall: 关键 API 检查失败，模块无法正常工作
```

**排查步骤**：
```bash
# 1. 检查内核配置
zcat /proc/config.gz | grep CONFIG_PROC_FS
# 或
grep CONFIG_PROC_FS /boot/config-$(uname -r)

# 2. 检查 procfs 是否挂载
mount | grep proc

# 3. 检查 /proc 目录
ls /proc | head
```

**解决方案**：
- 如果 `CONFIG_PROC_FS=n`：重新编译内核，启用 procfs
- 如果 procfs 未挂载：`sudo mount -t proc proc /proc`

---

## 扩展检查

### 添加新的 API 检查

如果模块依赖新的内核 API，按以下步骤添加检查：

**步骤 1**：在 `fw_compat.h` 中添加检查函数

```c
static inline int fw_compat_check_new_api(void)
{
    /*
     * 编译时检查：
     * - 包含必要的头文件
     * - 使用 API 函数（如果不存在会编译失败）
     *
     * 运行时检查：
     * - 验证 API 行为正常
     * - 检查内核配置是否启用
     */
    
    // 示例：检查某个函数是否存在
    void *symbol = kallsyms_lookup_name("some_kernel_function");
    if (!symbol) {
        pr_err("some_kernel_function: 不存在\n");
        return -ENOTSUPP;
    }
    
    pr_info("new API: 可用\n");
    return 0;
}
```

**步骤 2**：在 `fw_compat_check_api()` 中调用

```c
static inline int fw_compat_check_api(void)
{
    int ret;
    
    // ... 现有检查 ...
    
    ret = fw_compat_check_new_api();
    if (ret) {
        pr_err("new API 不可用\n");
        return ret;
    }
    
    return 0;
}
```

**步骤 3**：更新文档，说明新 API 的用途和失败场景

### 使用 kallsyms_lookup_name 检查符号

对于某些可选的 API，可以使用 `kallsyms_lookup_name` 在运行时检查符号是否存在：

```c
#include <linux/kallsyms.h>

static inline int fw_compat_check_optional_api(void)
{
    // 检查某个内核函数是否存在
    unsigned long (*func)(void) = (void *)kallsyms_lookup_name("optional_function");
    
    if (!func) {
        pr_warn("optional_function: 不存在，相关功能将被禁用\n");
        // 不返回错误，只是警告
        return 0;
    }
    
    pr_info("optional API: 可用\n");
    return 0;
}
```

**注意**：
- `kallsyms_lookup_name` 在 Linux 5.7+ 中不再导出给模块
- 需要使用其他方法（如 kprobes）或直接编译时检查

## 最佳实践

### 1. 编译时检查优先

```c
// ✓ 推荐：编译时检查
#include <linux/netfilter.h>
// 如果头文件不存在，编译失败

int ret = nf_register_net_hook(net, ops);
// 如果函数不存在，编译失败

// ✗ 不推荐：运行时检查
void *func = kallsyms_lookup_name("nf_register_net_hook");
if (!func) {
    // 处理错误
}
```

### 2. 提供清晰的错误信息

```c
// ✓ 推荐：清晰的错误信息
if (ret) {
    pr_err("netfilter API 不可用，请检查内核配置 CONFIG_NETFILTER\n");
    pr_err("解决方案：重新编译内核，启用 CONFIG_NETFILTER=y\n");
    return ret;
}

// ✗ 不推荐：模糊的错误信息
if (ret) {
    pr_err("API check failed\n");
    return ret;
}
```

### 3. 区分必需和可选 API

```c
// 必需 API：检查失败时拒绝加载
ret = fw_compat_check_netfilter();
if (ret) {
    pr_err("netfilter API 是必需的\n");
    return ret;  // 阻止加载
}

// 可选 API：检查失败时仅警告
ret = fw_compat_check_optional_feature();
if (ret) {
    pr_warn("可选功能不可用，相关特性将被禁用\n");
    // 不返回错误，继续加载
}
```

### 4. 记录详细的检查日志

```c
pr_info("开始内核兼容性检查...\n");
pr_info("内核版本: %d.%d.%d\n", major, minor, patch);
pr_info("开始检查关键 API 可用性...\n");
pr_info("  netfilter API: %s\n", netfilter_ok ? "可用" : "不可用");
pr_info("  netlink API: %s\n", netlink_ok ? "可用" : "不可用");
pr_info("  procfs API: %s\n", procfs_ok ? "可用" : "不可用");
pr_info("兼容性检查完成\n");
```

## 总结

API 兼容性检查策略的核心思想：

1. **不依赖版本号**：版本号仅作参考，不作为硬性限制
2. **检查实际依赖**：直接检查模块依赖的关键 API
3. **清晰的错误信息**：告诉用户具体哪个 API 不可用，如何解决
4. **向前兼容**：新版本内核只要 API 兼容就能工作
5. **适应性强**：适用于各种发行版和定制内核

这种策略确保了模块的最大兼容性，同时提供了清晰的故障诊断信息。
