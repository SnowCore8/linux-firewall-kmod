# Rust Kmod 翻译设计方案

## 概述

将 `src/kernel-module/` 下的 C 语言内核模块（约 2800 行，9 个源文件）逐模块翻译为 Rust 内核模块。

## 架构映射

### C → Rust 模块对应关系

| C 源文件 | Rust 模块 | 行数 | 核心职责 |
|----------|-----------|------|----------|
| `firewall.h` | `types.rs` | ~340 | 数据结构、常量、内联辅助函数 |
| `firewall-main.c` | `lib.rs` | ~220 | 模块 init/exit、全局状态 |
| `ban-manager.c` | `ban.rs` | ~480 | IP 封禁/解封核心逻辑 |
| `whitelist.c` | `whitelist.rs` | ~230 | 白名单增删查 |
| `cleanup.c` | `cleanup.rs` | ~180 | 定时器、RCU 释放、过期清理 |
| `netdev.c` | `netdev.rs` | ~330 | 网络设备通知器、IP 自动发现 |
| `netfilter.c` | `netfilter.rs` | ~320 | Netfilter 钩子（热路径） |
| `procfs.c` | `procfs.rs` | ~1004 | procfs 接口（bans/whitelist/config/stats） |
| `state-persist.c` | `state.rs` | ~580 | 状态持久化 |

### 核心技术替换

| C 技术 | Rust 替换 | 说明 |
|--------|-----------|------|
| `spinlock_t` + `DEFINE_HASHTABLE` | `kernel::sync::SpinLock<HashTable<T>>` | 内核 SpinLock API |
| `rcu_read_lock()` / `call_rcu()` | `kernel::sync::Rcu` + `kernel::rcu::RcuHead` | 内核 RCU API |
| `atomic_t` / `atomic64_t` | `kernel::sync::Atomic` / `Atomic64` | 内核原子操作 API |
| `DEFINE_PER_CPU` | `kernel::percpu::PerCpu<T>` | 内核 Per-CPU API |
| `kmalloc` / `kfree` | `kernel::alloc::KernelAlloc` | 内核分配器 |
| `timer_list` + `mod_timer` | `kernel::timer::Timer` | 内核定时器 API |
| `work_struct` + `delayed_work` | `kernel::workqueue::DelayedWork` | 内核工作队列 |
| `notifier_block` | `kernel::net::NetDevNotifier` | 内核网络设备通知器 |
| `nf_hook_ops` + `nf_register_net_hook` | `kernel::net::NetFilterHook` | 内核 Netfilter API |
| `proc_create` + `seq_file` | `kernel::procfs::ProcEntry` | 内核 procfs API |
| `filp_open` / `kernel_write` / `kernel_read` | `kernel::file::File` | 内核文件操作 API |
| `pr_err` / `pr_warn` / `pr_info` | `pr_err!` / `pr_warn!` / `pr_info!` | 内核日志宏 |

## 数据结构设计

### 核心结构体

```rust
// types.rs

// 地址族常量
pub const FW_AF_INET: u8 = 2;   // AF_INET
pub const FW_AF_INET6: u8 = 10; // AF_INET6

// IP 地址联合体
#[repr(C)]
pub union IpAddress {
    pub ipv4: u32,        // 网络字节序
    pub ipv6: [u8; 16],   // in6_addr
}

// 封禁条目
pub struct BanEntry {
    pub af: u8,
    pub addr: IpAddress,
    pub ban_time: u64,        // jiffies
    pub unban_time: u64,      // jiffies (0 = 永久)
    pub retry_count: AtomicU32,
    pub is_permanent: bool,
    // RCU 管理由 kernel::sync::Rcu 处理
}

// 白名单条目
pub struct WhitelistEntry {
    pub af: u8,
    pub addr: IpAddress,
    pub mask: IpMask,  // IPv4: u32 mask; IPv6: u8 prefix_len
    pub device_name: [u8; 16],
    // RCU 管理
}

// 全局防火墙状态
pub struct FirewallInfo {
    // 封禁表
    pub ban_table_ipv4: HashTable<BanEntry>,
    pub ban_table_ipv6: HashTable<BanEntry>,
    pub ban_locks_ipv4: [SpinLock<()>; 4096],  // 每桶锁
    pub ban_locks_ipv6: [SpinLock<()>; 4096],
    pub ban_count: AtomicI32,
    
    // 白名单表
    pub whitelist_table_ipv4: HashTable<WhitelistEntry>,
    pub whitelist_table_ipv6: HashTable<WhitelistEntry>,
    pub whitelist_lock: SpinLock<()>,
    pub whitelist_count: AtomicI32,
    
    // 子网链表（RCU）
    pub ipv4_subnet_wl: RcuList<WhitelistEntry>,
    pub ipv6_subnet_wl: RcuList<WhitelistEntry>,
    
    // 统计计数器
    pub total_ban_count: AtomicU32,
    pub total_unban_count: AtomicU32,
    pub whitelist_reject_count: AtomicU32,
    pub ban_table_full_count: AtomicU32,
    pub alloc_failure_count: AtomicU32,
    pub packets_dropped: AtomicI64,
    pub packets_accepted: AtomicI64,
    pub cleanup_cycles: AtomicU32,
    pub cleanup_expired_total: AtomicU32,
    
    // 定时器与工作队列
    pub cleanup_timer: Timer,
    pub sync_work: DelayedWork,
    pub shutting_down: AtomicBool,
    
    // procfs
    pub proc_dir: Option<ProcDir>,
    
    // 网络设备通知器
    pub netdev_notifier: NetDevNotifier,
}
```

## 关键设计决策

### 1. RCU 并发模型

C 版使用 `rcu_read_lock()` + `call_rcu()` + `synchronize_rcu()` 三重机制。
Rust 内核提供 `kernel::sync::Rcu` 类型安全封装：

- 读侧：`rcu_read_lock()` → 使用 `Guard` 自动释放
- 写侧：`hlist_del_rcu()` → `entry.remove_from_list()`
- 释放：`call_rcu()` → `RcuHead::schedule_free()`

### 2. 每桶自旋锁

C 版 `ban_locks_ipv4[4096]` 在 Rust 中实现为：

```rust
// 方案 A：固定大小数组（编译时确定）
pub ban_locks_ipv4: [SpinLock<()>; 1 << BAN_HASH_BITS];

// 方案 B：动态分配（更灵活，但需要额外初始化）
pub ban_locks_ipv4: KernelVec<SpinLock<()>>;
```

**选择方案 A**：与 C 版行为完全一致，编译时确定大小，避免运行时分配失败。

### 3. Per-CPU 计数器

C 版 `DEFINE_PER_CPU(struct fw_per_cpu_stats, fw_cpu_stats)`：

```rust
// Rust 内核 Per-CPU API
pub static FW_CPU_STATS: PerCpu<FwPerCpuStats> = PerCpu::new();

pub struct FwPerCpuStats {
    pub packets_accepted: u64,
    pub packets_dropped: u64,
}
```

### 4. 哈希表

C 版 `DECLARE_HASHTABLE` + `hash_min` / `jhash`：

```rust
// 使用内核提供的哈希表类型
use kernel::sync::HashTable;

// 哈希函数保持一致
pub fn hash_ip(af: u8, ip: &IpAddress, bits: u32) -> u32 {
    match af {
        FW_AF_INET6 => {
            // jhash(ipv6, fw_hash_seed) & mask
            let seed = unsafe { FW_HASH_SEED };
            kernel::crypto::jhash(&ip.ipv6, seed) & ((1 << bits) - 1)
        }
        _ => {
            // hash_min(ipv4, bits)
            kernel::hash::hash_min(ip.ipv4, bits)
        }
    }
}
```

### 5. Netfilter 热路径

C 版热路径（`handle_ban_check`）是性能关键：

```rust
// Rust 实现保持零分配、零拷贝
#[netfilter_hook(NFPROTO_IPV4, NF_INET_PRE_ROUTING)]
fn nf_hook_ipv4(skb: &mut SkBuff) -> NetFilterVerdict {
    // 直接从 skb 读取 IP 头，不分配
    let iph = match skb.get_ip_header::<Ipv4Header>() {
        Some(hdr) => hdr,
        None => return NetFilterVerdict::Accept,
    };
    
    // RCU 读侧（无锁）
    let rcu_guard = rcu_read_lock();
    let is_banned = is_ip_banned_rcu(&iph.src_addr);
    rcu_guard.release();
    
    if is_banned {
        // Per-CPU 计数器更新（无 atomic）
        let stats = FW_CPU_STATS.get();
        stats.packets_dropped += 1;
        if stats.packets_dropped >= FW_PER_CPU_BATCH_SIZE {
            flush_cpu_stats();
        }
        return NetFilterVerdict::Drop;
    }
    
    NetFilterVerdict::Accept
}
```

### 6. Procfs 接口

C 版使用 `seq_file` + `proc_ops`：

```rust
// Rust 内核 procfs API
pub fn create_procfs_entries(fw: &FirewallInfo) -> Result<()> {
    let proc_dir = ProcDir::create("firewall")?;
    
    proc_dir.create("bans", bans_fops, 0o600)?;
    proc_dir.create("whitelist", whitelist_fops, 0o600)?;
    proc_dir.create("config", config_fops, 0o600)?;
    proc_dir.create("stats", stats_fops, 0o400)?;
    
    Ok(())
}
```

### 7. 状态持久化

C 版使用 `filp_open` + `kernel_write` / `kernel_read`：

```rust
// Rust 内核文件 API
pub fn save_state_to_file(filename: &CStr) -> Result<()> {
    let file = File::open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0o600)?;
    
    // 序列化并写入
    let mut writer = FileWriter::new(file);
    // ... 写入 ban/whitelist 条目
    
    Ok(())
}
```

## 构建集成

### Kbuild 集成

修改 `src/kernel-module/Makefile` 支持 Rust：

```makefile
# 原始 C 版（保留为回退）
obj-m := firewall.o
firewall-y := firewall-main.o ban-manager.o ...

# Rust 版（新增）
ifdef CONFIG_RUST
obj-m += firewall_rust.o
firewall_rust-y := firewall_rust.rs
endif
```

### DKMS 集成

`dkms.conf` 保持不变（DKMS 负责构建，不关心语言）。

### Makefile 集成

```makefile
# 默认使用 Rust kmod
KMOD_RUST ?= 1

ifeq ($(KMOD_RUST),1)
kernel-module: rust-kernel-module
else
kernel-module: c-kernel-module
endif

rust-kernel-module:
	$(MAKE) -C $(KDIR) M=$(PWD)/src/kernel-module RUST_KERNEL=1 modules
```

## 行为等价性验证

移植完成后，必须验证以下等价性：

1. **模块参数**：`fw_ban_time`, `state_file`, `fw_max_bans_per_second` 行为一致
2. **procfs 接口**：`/proc/firewall/{bans,whitelist,config,stats}` 输出格式一致
3. **封禁/解封语义**：`ban_ip`, `unban_ip`, `is_banned` 返回值一致
4. **统计不变量**：`total_bans == current_bans + total_unbans + cleanup_expired_total`
5. **RCU 安全性**：无 use-after-free，通过 `lockdep` + `KASAN` 验证
6. **Netfilter 热路径**：包处理行为一致（accept/drop 决策一致）

## 实施步骤

1. ✅ 环境搭建（rustc 1.82 + 内核源码）
2. ⏳ 创建 Cargo 项目骨架 + 绑定生成
3. ⏳ 逐模块翻译（按依赖顺序）
   - `types.rs` → 数据结构
   - `ban.rs` → 封禁逻辑
   - `whitelist.rs` → 白名单
   - `cleanup.rs` → 定时器
   - `netdev.rs` → 网络设备
   - `netfilter.rs` → Netfilter
   - `procfs.rs` → procfs
   - `state.rs` → 状态持久化
   - `lib.rs` → 模块 init/exit
4. ⏳ 构建集成（Kbuild + Makefile + DKMS）
5. ⏳ 行为等价性测试
6. ⏳ 审计 + 修复
