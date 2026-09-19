# Kernel Module Rewrite Design (Phase 1)

This document is the single design source for rewriting `src/kernel-module/` from scratch.
Measured hot-path numbers and quantitative targets live in the
[performance baseline](perf-baseline.md); this document references them without repeating them.

## Decisions

| Item | Decision | Rationale |
|------|----------|-----------|
| Language | **C**, rewritten to the new design | Adds no build dependency; the existing softirq-per-packet baseline stays directly comparable; per-CPU, RCU and static_key semantics are fully controllable in C |
| Legacy code reuse | **None** | The new code reuses neither the old file split, the old data structures, nor the old hot-path algorithms. The old implementation is used only as a source of **behavioural and defect evidence** |
| Contract status | The three `contract/*.fwidl` files are the interface source of truth | The rewrite must not diverge from the generated artifacts; interface changes go through the contract first |
| Upstream translation plan | **Retired** | The "translate C file-by-file into Rust" plan in `rust-kmod-design.md` will not be executed; see that file's replacement notice |

> Why not Rust: this host's kernel `6.17.0-35-generic` has `CONFIG_RUST=y` and
> `CONFIG_RUSTC_VERSION=108200` (the rustup `1.82.0` toolchain is installed), but `build/rust`
> points at the not-installed `linux-hwe-6.17-lib-rust-6.17.0-35-generic`, and `bindgen` is absent —
> building would require new system packages. C can proceed with zero dependencies and needs no
> re-calibration of the baseline already established.

## Scope and acceptance

**Scope**: all of `src/kernel-module/`, plus its two interface surfaces toward the daemon
(netlink and procfs).

**Acceptance criteria**:

1. The **full gate** passes (see the repo root `AGENTS.md` / `Makefile` gate targets).
2. **Contract verification**: `contract/verify_procfs.py`, `verify_layout.py` and `verify_http.py`
   are all green; every defect in the contract is either fixed with the contract updated in step,
   or explicitly re-classified as intentionally preserved.
3. **Performance targets**: every entry of
   [performance baseline § Phase 1 quantitative targets](perf-baseline.md#phase-1-quantitative-targets)
   is met, re-measured on the same host, with the same `scripts/bench/` harness and the same
   module parameters.
4. **Integration acceptance**: the whole `tests/` pytest suite passes.

Where each of the three goals lands:

- **Real-time behaviour** — per-packet softirq and hot-path structural metrics (see the target table).
- **Stability** — remove unbounded growth and un-capped insertion (ban table, whitelist table,
  DDoS self-decision ban rate), remove fail-open decision branches, and drop fields that have no
  reachable reader.
- **Conformance** — interfaces follow the contract and agree across all three tiers; the module split
  follows data ownership; documentation no longer contradicts the implementation (including a rewrite
  of `docs/en/architecture/kernel-module.md`).

## Frozen surface: external behaviour that must be preserved verbatim

The following is carried by the contract and by `tests/` and **must not change** in the rewrite.
It is not "legacy code"; it is an external promise.

### netlink (`contract/generated/netlink_uapi.h`)

- Protocol `NETLINK_USERSOCK`; magic `0x46574C4E`; **12-byte** header; every struct `packed`;
  every multi-byte integer **big-endian**; addresses are raw bytes (IPv4 in the first 4 bytes).
- **23 message types** (1–21 historical, plus 22 `DAEMON_REGISTER` / 23 `DAEMON_REGISTER_ACK`).
- Single-daemon exclusive registration: a successful `DAEMON_REGISTER` owns the channel; when an
  active daemon already exists the reply carries `accepted = 0`; the activity timeout is 30 s.
  **Commands from an unregistered instance must be rejected.**
- Fixed sizes: `DdosEvent` 65, `BanStateChange` 122, `WhitelistStateChange` 51, `CmdResult` 37,
  `ConfigAck` 20, `ConfigChange`/`SetConfig` 116, `StatsResponse` 60, `BanIp`/`UnbanIp` 65,
  `AddWhitelist`/`RemoveWhitelist` 46, header-only messages 12.
- **Variable-length responses must be paged**: `ListBansResponse` 24 + 94×N (N ≤ 696),
  `ListWhitelistResponse` 16 + 34×N (N ≤ 1927), `ListRatesResponse` 36 + 84×N (N ≤ 779).
- `AnalysisResponse` is fully fixed at **4756 bytes**, with no variable tail.
- `ConfigFlags` has 13 bits and `DynThresholdFlags` 1 bit; bit order must not change.

### procfs (`contract/procfs.fwidl`)

- Root directory `/proc/firewall`, **12 entries**.
- `stats` is the **only machine-readable** entry: 13 `key value` lines whose key names and numeric
  types must not change.
- The other 11 entries are `read_format = unstable`; the rewrite **may** change their layout.
- Modes: `bans`/`whitelist`/`config` are 0600; the remaining 9 are 0400.
- The three grammars must not be extended (a new form requires a contract change first):

  | File | Command | Semantics |
  |------|---------|-----------|
  | `bans` | `<ip>` / `<ip> <seconds>` / `<ip> 0` / `unban <ip>` | `BAN_DEFAULT` / `BAN_TIMED` / `BAN_PERMANENT` / `UNBAN` |
  | `whitelist` | `add <subnet>` / `<subnet>` / `remove <subnet>` | `ADD` / `ADD_IMPLICIT` / `REMOVE` |
  | `config` | `ban_time <seconds>` | `BAN_TIME` |

- Write-side conventions: one command per `write(2)`; separators are space or tab; every byte below
  0x20 other than `\t` is rejected; failure returns a negative errno with no textual error channel.

### module parameters

The 7 parameters keep their names and defaults (`fw_ban_time`=600, `state_file`=`/var/lib/firewall/state`,
`fw_max_bans_per_second`=200, `fw_max_rate_entries`=65536, `fw_static_threshold`=1,
`fw_dynamic_threshold`=0, `fw_ddos_detection`=1). New parameters may only be appended; existing
names must not change.

### Decision semantics

A whitelist hit is never banned; an exact local interface address passes straight through; a ban-table
hit is dropped; DDoS detection runs only when the source is not whitelisted and the master switch is on;
a timed ban is unlinked by its per-entry timer, with no global cleanup thread.

## New module split

Split by **data ownership**. Each file exposes one narrow interface; hot-path functions live in
headers as `static inline`.

| File | Owns | Interface |
|------|------|-----------|
| `fw_types.h` | Nothing (types and constants) | includes the contract-generated header; internal structs; `BAN_HASH_BITS` and friends |
| `fw_main.c` | Module lifecycle, the `fw_info` singleton | `module_param`, `fw_init`/`fw_exit`, the shutdown state machine |
| `fw_stats.c` | Per-CPU counters and histograms | `fw_stat_account()` (hot path), `fw_stats_flush_local/_all()` |
| `fw_local.c` | The local-address set | `fw_is_local()` (hot-path RCU read) |
| `fw_wl.c` | Whitelist exact buckets + subnet chain | `fw_wl_lookup()` (hot-path RCU read), `fw_wl_add/remove()` |
| `fw_ban.c` | The ban table | `fw_ban_lookup()` (hot-path RCU read), `fw_ban_add/remove()`, per-entry timers |
| `fw_rate.c` | Rate table, window, EWMA, violation checks | `fw_rate_observe()` (hot path: one lookup returns the verdict) |
| `fw_hook.c` | netfilter hook registration and packet parsing | none (hook registrations only) |
| `fw_netlink.c` | netlink socket, send and receive | `fw_nl_init/exit()`, `fw_nl_send_*()` |
| `fw_procfs.c` | The 12 procfs entries | `fw_procfs_init/exit()` |
| `fw_state.c` | State file I/O | `fw_state_save()`, `fw_state_restore()` |
| `fw_netdev.c` | netdev notifier, local-address rebuild | `fw_netdev_init/exit()` |

The old files are broken up and reassembled by responsibility; the new files do not reuse old code:
`netfilter.c` becomes `fw_hook.c` (parsing) plus `fw_local.c`/`fw_wl.c`/`fw_ban.c`/`fw_rate.c`
(decisions); `firewall.h` becomes `fw_types.h` (pure types) plus per-module private headers;
`cleanup.c` folds into `fw_ban.c`/`fw_state.c`. The rate algorithm in `rate-detector.c` is
**rewritten**, not moved, because its window accounting is precisely what this phase removes.

## Data structures

### Ban table

Keep "4096 hlist buckets + RCU + per-bucket spinlock" — not as reuse of an old algorithm, but because
the baseline does not falsify it (the banned path at 1.272 µs is the cheapest of the five). Changes:

- **Drop `retry_count`**: the whole tree only zeroes it; nothing reads it.
- **Add a real capacity limit**: a new `fw_max_ban_entries` module parameter (default 65535, matching
  the daemon-side setting) checked atomically under the bucket lock before insertion; at the limit,
  reject and increment `ban_table_full_rejects`.
- This gives `ban_table_full_rejects` its only increment site, fixing
  `PROC_BAN_TABLE_FULL_NEVER_INC`.

### Whitelist

Keep "64 exact buckets + subnet chain". The subnet chain is necessary (it avoids walking all 64
buckets doing prefix compares) and stays.

- **Add a capacity limit**: a new `fw_max_whitelist_entries` (default 65535), fixing
  `PROC_WHITELIST_CAPACITY_UNENFORCED`.
- **De-duplicate the IPv6 compare**: the old code, in both the in-bucket candidate loop and the subnet
  chain loop, assembles a `struct in6_addr` from `4 × READ_ONCE(u32)` plus `barrier()` before
  comparing. A whitelist entry is **not modified** after `hlist_add_head_rcu`, so an RCU reader sees
  either the whole old value or the whole new value; comparing the whole `struct in6_addr` directly is
  sufficient. Use `data_race()` to annotate it for KCSAN rather than falling back to the byte-by-byte
  assembly.
- **Make the `remove` "local interface IP" test exact**: fixes
  `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH` — the old subnet comparison makes every explicitly added
  entry inside a `/24` interface's subnet undeletable (`-EPERM`).

### Local-address set

The old design is "array + one O(N) linear scan per packet + masked compare", returning "not local"
whenever `count == 0`. Replace with an **open-addressed hash set**:

- Key is `(af, addr)`, fixed capacity (default 256, module parameter `fw_max_local_ips`), matched
  exactly on `af` plus the full address.
- Rebuild path: `fw_netdev.c` builds a **new table** on notifier events and at init, publishes it with
  `rcu_assign_pointer`, and hands the old one to `kfree_rcu`. Publication is atomic, so readers never
  see a half-built table.
- The degenerate `count == 0` state disappears: hook registration happens **after** the first address
  discovery, so there is no runtime window with an empty table.
- **Do not extend it to subnet exemption**: only exact host addresses are exempt. The old code's
  mistake here is the exact same pattern as `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH`.

### Rate table

Keep "65536 hlist buckets + RCU + per-bucket lock (cold path only)". Window accounting is **rewritten**:

- The old in-window counters (`packet_count`, `byte_count`, `syn/udp/icmp/ack/rst/fin_count`) are
  **shared `atomic64_t`**, contended across cores on one cache line per packet.
- Those raw counters are read in exactly one place: the window roll, to compute the new EWMA. The
  decision path reads `smoothed_*` (already smoothed) and never the raw counters.
- Therefore move the raw counters into **per-CPU slots**: one direct-mapped slot set per CPU holding
  `{af, addr, packets, bytes, syn, udp, icmp, ack, rst, fin, seen_ports[32], seen_port_n, last_activity}`.
  The hot path writes only local memory; the window roll (on whichever CPU holds the bucket lock)
  merges the per-CPU slots and zeroes them.
- When a slot is displaced by a different source address, **first flush the old occupant's counters
  into its entry** before reuse; silently dropping counters is not allowed (rate detection cannot
  tolerate lost counts; analysis counters can, see below).

### Analysis histograms

`pkt_size_*` (5 buckets), `ttl_*` (6 buckets) and `ip_total_count`/`ip_frag_count` are monotonic
histograms, and each packet lands in exactly one size bucket and one TTL bucket. Make them
**unconditional per-CPU accumulation**; the read side (the 5 procfs analysis entries, netlink
`ANALYSIS_QUERY`) flushes across CPUs and sums first, reusing the existing `on_each_cpu` flush
mechanism and the "flush before read" discipline.

### UDP port / ICMP type distributions

Capped at 512 / 128; today the hot path does "global table lookup, and on a hit two `atomic64`
operations plus one `WRITE_ONCE`". Replace with per-CPU direct-mapped slot accumulation merged into
the global table at the batch threshold or on a read-side flush. Read-side semantics are unchanged
(same table contents, same entry caps).

## Hot-path redesign

### Decision order (new)

```
nf_hook(ipv4/ipv6)
  |- packet sanity (length/version/checksum/first fragment/extension-header depth)  -- bad => ACCEPT
  |- source sanity (0/broadcast/loopback/multicast/link-local)                      -- bad => ACCEPT
  |- fw_stats_account_basic()      <- per-CPU, no shared write
  |- transport parse + protocol anomaly check (TCP flag anomaly)                    -- bad => NF_DROP
  \- fw_ban_check(af, src, ...)    <- a single RCU critical section
       |- one lookup: fw_wl_lookup()
       |- one lookup: fw_ban_lookup()
       |- local address: fw_is_local()        (hash, O(1))
       \- not whitelisted and DDoS on => fw_rate_observe()
            \- inside: one lookup, one pointer carrying window roll + all four violation checks
```

Key differences from the old structure:

1. **One RCU critical section.** The old code enters RCU once for the whitelist/ban decision, exits,
   calls `update_rate_stats`, then re-enters for the violation checks — three `rcu_read_lock` pairs.
2. **One rate-table lookup.** The old `update_rate_stats`, `check_rate_violation` and
   `check_protocol_violation` (or `check_tcp_flood_violation`) each call `find_rate_entry_rcu`,
   totalling 2.81 per packet. The new code passes the `ip_rate_entry *` from the single lookup down.
3. **No spinlock on the hot path.** On the old "window not expired" fast path, any packet with
   `dst_port > 0` takes the rate bucket lock to update `seen_ports` (a linear scan of up to 32 items).
   The port dedup set moves into the per-CPU slot and is merged at window roll.
4. **No shared cache-line writes on the hot path.** Histograms, UDP/ICMP distributions, rate window
   counters and `last_activity` all land in per-CPU memory.

### Per-packet shared cache-line writes: correcting the baseline figure

The baseline document records "≈11" as per-packet atomic operations; that figure needs restating as
the number of **sites**: `record_packet_size`'s 5 buckets are 5 *sites* but each packet hits one;
`record_ttl` likewise one; `record_ip_frag` is a fixed 1 (`ip_total_count`) plus possibly 1
(`ip_frag_count`). Counting per packet from the code:

| Path | Shared atomic writes per packet | Spinlocks per packet |
|------|--------------------------------|----------------------|
| Whitelist hit / DDoS off (UDP traffic) | 6 (size 1 + ttl 1 + ip_total 1 + UDP packet/byte/last_seen 3) | 0 |
| DDoS on (UDP traffic) | 10 (the 6 above + rate entry packet/byte/udp/last_activity 4) | 1 |
| Banned and dropped | 0 | 0 |

The new design's figure is **0**, better than the "≤ 2" target.

## Concurrency and lifecycle

**Locks** (counts and duties rearranged; the ordering protocol is documented in `fw_types.h`):

| Lock | Protects | Taken as |
|------|----------|----------|
| `ban_locks[4096]` | ban buckets, entry timers, unlink | `spin_lock_bh` |
| `wl_lock` | whitelist tables, subnet chains, counters | `spin_lock_bh` |
| `rate_locks[65536]` | rate buckets, window roll | `spin_lock_bh` |
| `flood_lock` | the ban-rate window | `spin_lock_bh` |
| `udp_port_lock` / `icmp_type_lock` | analysis tables (flush and lazy insert only) | `spin_lock_bh` |

The hot path (softirq context) holds none of them. The old ordering rules — "global lock and bucket
locks never nest" and "bucket lock to `active_bans_lock`, one direction only" — are preserved and
written into the header comments.

**RCU**: ban entries, whitelist entries, rate entries, the local-address table and analysis-table
entries are all RCU-published; deletion goes through `hlist_del_rcu` + `call_rcu`, and the exit path
does `synchronize_rcu` + `rcu_barrier`.

**Timers**: a timed ban uses a per-entry `timer_list`; on expiry the callback takes the bucket lock,
unlinks, `call_rcu`-frees, and pushes `BAN_STATE_CHANGE`. A permanent ban only does `timer_setup`
and never `mod_timer`. The renewal path must handle the "old callback already running" race, keeping
the old approach: inside the callback, re-compare `unban_time` and re-arm if not yet due.

**Workqueue**: exactly one delayed work, debounced 500 ms after netdev events, rebuilding the
local-address table. No periodic work.

**init/exit order**:

```
init:  parameter validation -> locks/tables/atomics -> rate defaults -> netlink -> state restore
       -> first local-address discovery -> netdev notifier -> procfs -> netfilter hooks (v4, v6)
exit:  shutting_down=1 -> cancel delayed work -> unregister hooks (v4, v6) -> synchronize_rcu
       -> unregister notifier -> destroy procfs -> synchronize_rcu -> save state -> purge tables -> netlink
```

`shutting_down` is the hot path's first check (double-checked); once set, the hot path passes traffic
straight through so teardown is not held up by new traffic.

## Contract revisions

The rewrite may change contracts, but the contract always changes **before** the code, and it goes
through the `contract/` verification. Phase 1 needs the following revisions:

| Contract site | Revision | Reason |
|---------------|----------|--------|
| `netlink.fwidl` `DaemonRegisterAck` | None needed (already states the correct intent) | The fix is in the kernel: the old code wrote `accepted` into the low byte of `seq`, and the daemon never parsed it |
| `netlink.fwidl` `ListRatesResponse` | None needed (already requires paging) | The fix is in the kernel: the old code had no paging and no cap, and `msg_len` wrapped above 780 entries |
| `procfs.fwidl` `limit bans` | `entries` from `none` to the new parameter's default | New `fw_max_ban_entries` |
| `procfs.fwidl` `limit whitelist` | `entries` from `none` to the new parameter's default | New `fw_max_whitelist_entries` |
| `procfs.fwidl` `limit rates` | `where` pointing at the new module-parameter declaration line | Line numbers move |
| `procfs.fwidl` defect section | Disposition each entry (see below) | The contract requires: a fixed defect must be rewritten in step |

## Defect disposition

Defects in the contract are **part of the contract**, and the contract must be updated with each
disposition. The kernel side has 10 (`procfs.fwidl`) plus 2 (`netlink.fwidl`), and 3 more stability
problems found during this design pass.

### Fix

| Defect | Fix |
|--------|-----|
| `PROC_DEAD_UNBAN_FORM` (high) | Delete the unreachable `<ip> -1` branch and its enum value, and fix the README plus `docs/*/configuration/procfs.md` that advertise it. If the form is kept instead, it must become genuinely reachable (teach `validate_duration_string` to accept a leading minus) — pick one, leave no dead code |
| `PROC_BAN_TABLE_FULL_NEVER_INC` (high) | Add the capacity limit, which gives the counter its only increment site (see "Ban table") |
| `PROC_WHITELIST_CAPACITY_UNENFORCED` (medium) | Add the capacity limit (see "Whitelist") |
| `PROC_DOC_FORMAT_FICTIONAL` (medium) | Rewrite `docs/{zh,en}/configuration/procfs.md` to describe the real format as generated and implemented |
| `PROC_CONFIG_DOC_SAYS_READONLY` (low) | Same rewrite: `config` is writable (0600, supports `ban_time`) |
| `PROC_CLEANUP_CYCLES_DEAD` (low) | Keep the field (external parsers depend on it) but comment that it is always 0; rewrite the contract entry as "intentionally preserved" with the reason |
| `PROC_WRITE_NO_TEXT_ERROR` (low) | Rewrite the contract entry as "intentionally preserved": no textual error channel is a deliberate kernel-side design; the reason goes to the kernel log only |
| `PROC_STATS_STALE_NO_FLUSH` (medium) | `stats_show` flushes across CPUs before reading, matching netlink `STATS_QUERY` |
| `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH` (low) | Make the `remove` "local interface IP" test exact (see "Whitelist") |
| `DaemonRegisterAck` payload misplacement | Write `accepted` to its own byte; `seq` is a sequence number only |
| `ListRatesResponse` unpaged | Page by `count`/`total`, at most 779 entries per page |

### Stability problems found in this pass (contract first, then fix)

1. **Flood protection only applies on the procfs path.** The only call site of
   `check_flood_protection()` in the whole tree is `procfs.c:264`; neither the netlink command path
   nor the DDoS self-decision ban path checks `fw_max_bans_per_second`. Consequence: both
   kernel-decided bans and daemon-issued bans have no rate ceiling, and each one costs a `kmalloc`,
   a timer, a list insert and a netlink event. Fix: route all three paths through one rate gate.
2. **Fail-open decision branches**: the local-address `count == 0` case and the rate table's
   `-ENOSPC` case both err toward passing traffic when information is short. The former's empty-table
   window disappears after the rewrite; the latter's behaviour must be stated in the contract
   (passing is recommended, since dropping on a full rate table would hit innocent traffic, but it
   must be written down rather than left implicit).
3. **`is_banned()` / `is_permanently_banned()` are `EXPORT_SYMBOL`'d but have no in-module caller.**
   If they have no external user, drop the export; otherwise document the user.

## Staged implementation and acceptance

Each stage is independently testable, independently committable and independently revertible. No
stage depends on a later one.

| Stage | Content | Acceptance |
|-------|---------|-----------|
| **1.A** | Module split, histogram per-CPU conversion, dead-code removal (`retry_count`, `proc_settings`, the unreachable unban branch) | Gate green; A/E-group per-packet softirq down; no shared atomic writes (A group 6 → ≤3) |
| **1.B** | Rate hot-path rewrite: one lookup + per-CPU window counters + per-CPU port dedup set | `find_rate_entry_rcu` ≤ 1.0 per packet; no `_raw_spin_lock_bh` on the hot path; B-group per-packet softirq on target |
| **1.C** | Local addresses as a hash; UDP/ICMP analysis tables per-CPU | Single-flow A group ≤ 1.8 µs; banned D group ≤ 1.0 µs |
| **1.D** | Contract revisions, disposition of all 10 defects, fixes for the 3 new stability problems | `contract/*` verification green; pytest green |
| **1.E** | Documentation rewrite: `docs/{zh,en}/architecture/kernel-module.md` rewritten from the new implementation | Docs align item by item with the code (hook priority, hash structures, whitelist capacity, `config` permissions, expiry mechanism) |

`docs/en/architecture/kernel-module.md` currently contradicts the implementation and must be handled
in 1.E: the priority is actually `NF_IP_PRI_FILTER - 1`, not `NF_IP_PRI_FIRST`; the
`HASH_TABLE_SIZE 4096` `struct banned_ip` does not exist; the `WHITELIST_SIZE 64` array is now hash
buckets plus a subnet chain; `config` is writable; and the "global cleanup thread" is really a
per-entry timer.

## Measurement discipline

- Every performance conclusion must be re-measured on the same host, with the same `scripts/bench/`
  harness and the same module parameters.
- Single-flow and multi-flow numbers **must not** be compared against each other (multi-flow has
  significant cross-core contention).
- Until the sender side reaches its ceiling, the pps ceiling is not a hard metric.
- Each stage must end with a reviewable increment: gate output, baseline comparison data, and
  contract verification results.
