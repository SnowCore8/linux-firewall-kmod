# Baseline Performance of the Kernel Hot Path

This document records the measured hot-path baseline **before** the rewrite. It serves
two purposes: to set checkable quantitative targets for the Phase 1 kernel rewrite, and
to document the reproducible method.

Absolute numbers depend on CPU, kernel version and NIC; **the method is portable, the
numbers are reference only**. Every post-rewrite comparison must re-run
`scripts/bench/` on the same machine.

## Measurement environment

| Item | Value |
|------|------|
| Kernel | `6.17.0-35-generic` |
| CPU | 8 logical cores, no `isolcpus` |
| Module | Loaded `firewall.ko` srcversion `229754D1C290E8A436A112B`, identical to `build/kernel-module/firewall.ko` |
| Hook | `nf_register_net_hook(&init_net, ...)`, `NF_INET_PRE_ROUTING`, `priority = NF_IP_PRI_FILTER - 1` |
| Module params | `fw_ddos_detection=1` (default), `fw_static_threshold=1`, `fw_dynamic_threshold=0` |

## Method

### Why traffic must cross a network namespace

The hook is registered only on **init_net**. Two common measurement setups never reach it:

- `lo` and `127.0.0.0/8`: `netfilter.c` returns early at the entry point, and
  `skb->dev->flags & IFF_LOOPBACK` is skipped as well;
- traffic entirely inside a single netns never leaves that netns, so it never traverses
  the `NF_INET_PRE_ROUTING` of init_net.

Therefore a veth pair is built between two network namespaces so packets **cross the
netns boundary into init_net**. On this host `ip netns add` fails with
`Invalid argument` (the `/var/run/netns` mount style is unsupported), so a long-lived
`unshare -n` process holds the namespace and `ip link set <dev> netns <pid>` moves the
interface in.

### Why the receive side must be a non-reading sink

With a reading receiver, unmatched UDP packets make the kernel emit **ICMP port
unreachable**, so every request spawns an extra reply that traverses the hook again. The
sink only `bind`s and never `recv`s: packets still follow the local-delivery path and
netfilter, while the receive side adds neither ICMP noise nor userspace CPU cost.

### Why softirq, not total CPU

At ~1 Mpps, `blast2` itself consumes several cores of userspace CPU (sendmmsg syscalls),
which swamps the total-CPU delta. Softirq (field 8 of `/proc/stat`) is where the,
per-packet cost lands. Every per-packet cost below is softirq delta divided by packets.

### Why a source address outside the whitelist

The kernel automatically adds local interface IPs to the whitelist (`netdev.c` address
discovery, `device_name` = interface name). Once the source is auto-listed, the hook takes
the whitelist short-circuit and all five comparison groups collapse into the same path.
Additionally, the procfs whitelist `remove` decides "local interface IP" by **interface
subnet** (see `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH` in `contract/procfs.fwidl`), hence
the receive side uses `/32` and the send side `/24`; otherwise a same-subnet control
address cannot be removed from the whitelist at all.

### Why a hook-free control flow is required

"Banned 9.7 µs/pkt, miss 18.1 µs/pkt" alone cannot separate the hook's share from the
protocol stack's. `fwctl.sh` runs veth-to-veth inside a single netns: identical
send/receive, routing, netfilter framework and local delivery, minus the hook. The
difference is the hook's net cost.

## Reproduction

```bash
# 1) Build the sender and sink
sudo make -C scripts/bench

# 2) Start one flow path, note the printed NS_PID (foreground, Ctrl-C cleans up)
sudo scripts/bench/fwflow.sh 10.99.0.11 10.99.0.1 9999

# 3) In another terminal, run the five-path comparison
sudo scripts/bench/fwsweep.sh <NS_PID> 8 3 3

# 4) Hook-free control
sudo scripts/bench/fwctl.sh 8 3
```

The scripts only add/remove their own veth and child processes and clean up on exit.
During a run they read/write `/proc/firewall/{bans,whitelist,stats}` and the module
parameter `fw_ddos_detection`, restoring it to `1` at the end.

## Results

### Per-packet softirq, five paths

Single flow, 3 threads, `secs=8`, median of 3 runs (`scripts/bench/fwsweep.sh`):

| Path | Packets (median) | softirq (median) | Per packet |
|------|------|------|------|
| E) `ddos` off + whitelist (shortest) | 6,258,765 | 13.470 s | **2.15 µs** |
| A) `ddos` off + not whitelisted (both tables miss) | 5,707,857 | 14.040 s | **2.46 µs** |
| B) `ddos` on + not whitelisted (+ rate engine) | 5,754,122 | 13.990 s | **2.44 µs** |
| C) `ddos` on + whitelist (control for E) | 6,226,313 | 13.500 s | **2.17 µs** |
| D) Banned (hit → `NF_DROP`) | 8,256,448 | 10.500 s | **1.27 µs** |

### Hook-free control and the hook's net cost

Veth-to-veth inside one netns, 3 runs: **0.67 / 0.68 / 0.69 µs/pkt**
(`scripts/bench/fwctl.sh`).

Hook net cost on a single flow (path softirq − control baseline):

| Path | Per packet | Net of hook |
|------|------|------|
| E whitelist short-circuit | 2.15 µs | ≈ **1.5 µs** |
| A both tables miss | 2.46 µs | ≈ **1.8 µs** |
| D banned drop | 1.27 µs | ≈ **0.6 µs** |

> With multiple concurrent flows (`mflow.sh`, 4 flows) the per-packet softirq rises to
> **4.6 µs**, showing significant cross-core contention (cache-line ping-pong on shared
> counters). Single-flow and multi-flow numbers must never be compared directly; always
> state the flow count when quoting them.
>
> **The "net of hook" column above uses a flawed baseline**: `fwctl.sh`'s control puts
> both veth ends inside a new netns, which is not the same network stack as the
> main measurement's init_net (init_net additionally carries conntrack and the `mihomo`
> nat). The correct convention is **same path, module ON minus OFF**; see the "Floor"
> section under "Post-rewrite re-measurement" below.

### pps ceiling (sender-limited on this host)

| Setup | Send side | Hook processed |
|------|------|------|
| Single flow, 1 thread | 250 Kpps | same as send side (no loss) |
| Single flow, 8 threads | 1.07 Mpps | 1.07 Mpps |
| 4 concurrent flows (2 threads each) | 0.97 Mpps | 0.97 Mpps |

**The sender tops out around 1.5 Mpps per flow**; a single flow cannot saturate 8 cores,
and the hook was never the drop point (send count == hook processed count, no
`packets_dropped`).

Historical peaks measured right after a module reload (`fw_ddos_detection=0`, no
whitelist, single flow, multiple threads):

- accept path: **2.21 Mpps** (saturates at 4 threads, single-core bound);
- drop path (banned): **2.74 Mpps**.

### Structure from `function_graph`

`function_graph` sampling (n=715) gives per-packet kernel operation counts:

| Item | Per packet |
|------|------|
| `__rcu_read_lock` / `__rcu_read_unlock` | 3.16 each |
| `find_rate_entry_rcu` | 2.81 |
| `_raw_spin_lock_bh` | 0.71 |
| `update_rate_stats` | 0.71 |
| `check_rate_violation` / `check_protocol_violation` / `check_tcp_flood_violation` | ~0.7 each |

Module-owned functions (p50 under `function_graph`):

| Function | p50 |
|------|------|
| `nf_hook_func_ipv4` | 26.1 µs |
| `handle_ban_check` | 23.3 µs |
| `update_rate_stats` | 8.3 µs |

> **`function_graph` absolute values are not usable as cost**: every traced call adds
> roughly 0.4 µs of fixed overhead, and there are about 65 traced calls per packet
> (≈25 µs), which precisely explains the gap between 26 µs and the measured 2.15 µs.
> Interrupt pollution must also be filtered: of the longest 151 µs block, about 134 µs
> is `__sysvec_apic_timer_interrupt` → `hrtimer_interrupt` landing inside the traced
> region, not this module's code. Hence **conclusions use the counter-based
> (softirq/packet) figures; `function_graph` only localizes structural problems**.

## Structural problems identified

1. **Repeated lookups per packet**: `update_rate_stats` calls `find_rate_entry_rcu`, then
   `check_rate_violation`, `check_protocol_violation` and `check_tcp_flood_violation` each
   look the entry up again (2.81 per packet in total) — the same source-IP entry is
   looked up over and over.
2. **~11 shared-cache-line histogram sites**: `record_packet_size` (5 buckets),
   `record_ttl` (6 buckets), `record_ip_frag` (1–2), plus `record_udp_port` /
   `record_icmp_type`, all global `atomic64_inc`.

   > Correction of the earlier wording: **11 counts sites, not per-packet operations.**
   > A packet lands in exactly one size bucket and one TTL bucket, so counting per
   > packet from the code gives — UDP traffic with DDoS off: 6
   > (size 1 + ttl 1 + ip_total 1 + UDP packet/byte/last_seen 3); with DDoS on: 10
   > (plus the rate entry's packet/byte/udp/last_activity 4); the banned-and-dropped
   > path: 0.
3. **One rate-bucket spinlock per packet on the hot path**: in `update_rate_stats`'s
   "window not expired" fast path, **any packet with `dst_port > 0`** takes a
   `rate_locks` bucket lock to update `seen_ports` (the
   `/* 端口扫描去重集合需桶锁 */` block in `rate-detector.c`, a linear scan of up to
   32 items) — that is the direct source of `_raw_spin_lock_bh` at 0.71 per packet.
   The window-expiry reset path (up to 18 atomic reads + 8 EWMA atomic writes under
   the same lock) does take the same lock, but only once per window, which cannot
   account for 0.71 per packet and is therefore not the main cause.
4. **`is_local_ip` is an O(N) linear scan per packet**: one entry per CPU, mask
   `0xFFFFFFFF` exact match; with `cache->count == 0` it **fails open** and returns false.
5. **`stats` never flushes per-CPU counters**: see `PROC_STATS_STALE_NO_FLUSH` in
   `contract/procfs.fwidl` (a module defect, now in the contract with a mechanical
   assertion).

## Phase 1 quantitative targets

The primary metric is **per-packet softirq under concurrent flows** (single-flow numbers
are masked by the sender); `function_graph` structural metrics are secondary.

| Metric | Baseline | Target | How to verify |
|------|------|------|------|
| Per-packet softirq (4 concurrent flows, both tables miss) | 4.6 µs | **≤ 3.0 µs** (−35%) | `mflow.sh 4` |
| Per-packet softirq (single flow, both tables miss) | 2.46 µs | **≤ 1.8 µs** | `fwsweep.sh` group A |
| Per-packet softirq (single flow, banned drop) | 1.27 µs | **≤ 1.0 µs** | `fwsweep.sh` group D |
| `find_rate_entry_rcu` per packet | 2.81 | **≤ 1.0** (merge into one lookup) | `function_graph` |
| Rate-bucket spinlocks per packet | 1.0 (`dst_port > 0`) | **0** | no `_raw_spin_lock_bh` in `function_graph` |
| Shared cache-line writes per packet | 6 (DDoS off) / 10 (DDoS on) | **0** (per-CPU aggregation) | source + `function_graph` |

Judging discipline:

- Every metric must be re-measured on the **same machine, same `scripts/bench/`, same
  module parameters**;
- Until the sender-side ceiling is raised, pps ceilings are not hard targets (this host's
  sender is the bottleneck, see table above);
- Single-flow and multi-flow figures **must not be mixed**.

## Post-rewrite re-measurement (Phase 1.3)

Conditions: same machine, same `scripts/bench/`, same module parameters. The old module
was rebuilt from git history:

```bash
git worktree add /tmp/fw-old 3a313ad --detach
make -C /lib/modules/$(uname -r)/build M=/tmp/fw-old/src/kernel-module modules
```

The rebuilt artifact's srcversion `229754D1C290E8A436A112B` matches the value recorded
above byte for byte, i.e. the numbers above were measured on this exact binary.

### Floor: same-path ON/OFF decomposition

The section above uses `fwctl.sh` as the "hook-free control", but that control puts
**both veth ends inside one new netns**, whereas the init_net side still carries
`nf_conntrack` and `table inet mihomo` (nat prerouting, `priority dstnat + 1`), both of
which still cost on that flow. So "main measurement − fwctl" mixed two **different**
floors and overstated the hook's net cost.

The clean convention is **same flow, module ON minus `rmmod` OFF**:

| Setup | Floor OFF (same path, rmmod) | Old module ON | Old hook net | New module ON | New hook net |
|------|------|------|------|------|------|
| Single flow, both tables miss | 1.932 / 1.955 µs | 2.109 µs | +0.18 | 2.080 µs | +0.13 |
| 4 concurrent flows, both tables miss | 4.140 / 4.162 µs | 4.468 µs | +0.33 | 4.340 µs | **+0.18** |

The two floor figures are one OFF measurement each (old module, new module); they agree
within 1.2%.

The drop path has a lower floor: an `nft` rule at `priority -2` (before the module hook
at `-1`) drops in place, so packets never reach the hook — equivalent to the drop floor
with no module.

| Setup | Floor (nft drop at `priority -2`) | New module group D | Diff |
|------|------|------|------|
| Single flow, banned drop | **1.172 µs** | 1.147 µs | ≈ 0 (no measurable module cost on the drop path) |

### Item-by-item verdict on the six targets

| # | Metric | Baseline | Target | Host floor | Measured (new module) | Verdict |
|---|------|------|------|------|------|------|
| 1 | Per-packet softirq, 4 flows | 4.6 µs | ≤ 3.0 µs | 4.14 µs | 4.340 µs | ✗ floor above target |
| 2 | Single flow, both tables miss | 2.46 µs | ≤ 1.8 µs | 1.93 µs | 2.080 µs | ✗ floor above target |
| 3 | Single flow, banned drop | 1.27 µs | ≤ 1.0 µs | 1.17 µs | 1.147 µs | ✗ floor above target |
| 4 | Lookups per packet | 2.81 | ≤ 1.0 | — | **1.0000** | ✓ |
| 5 | Hot-path spinlocks per packet | 1.0 | 0 | — | **≤ 0.0006** | ✓ |
| 6 | Shared cache-line writes per packet | 6 / 10 | 0 | — | **0** | ✓ |

Targets 1/2/3 are all **below the host floor**: conntrack plus the `mihomo` nat on the
init_net side make merely "delivering the packet to prerouting" cost 1.93 µs (single
flow) / 4.14 µs (4 flows). That cost is unrelated to the firewall module — it survives
`rmmod`, and it is present when `nft` at `priority -2` drops in place. Without changing
the host network stack, total softirq cannot be pushed below the floor, so these three
are unreachable on this host.

Item 4: ftrace `function_profile` summed across `trace_stat/function*` gives
`fw_rate_find_locked / fw_rate_observe = 651787 / 651784 = 1.0000` (one lookup).
Item 5: `_raw_spin_lock_bh` fired 2 437 times over 4 208 192 packets (`ddos=1`: 2 643 over
6 300 352), i.e. ≤ 0.0006/pkt, from entry creation and window rollover on the cold path,
not from the per-packet decision path.
Item 6: source inspection — every hot-path write lands in `this_cpu_ptr(stats_pcpu)` or a
per-CPU rate slot; the only shared write is one `atomic_cmpxchg(&n->rolling)` per window.

### Old vs new, path by path

| Path | Old module | New module | Change |
|------|------|------|------|
| E) `ddos` off + whitelist | 2.086 µs | 2.054 µs | −1.5% |
| A) `ddos` off + non-whitelist | 2.109 µs | 2.080 µs | −1.4% |
| B) `ddos` on + non-whitelist | 1.238 µs | 1.171 µs | −5.4% |
| C) `ddos` on + whitelist | 2.116 µs | 2.046 µs | −3.3% |
| D) banned drop | 1.233 µs | 1.147 µs | −7.0% |
| 4 flows, **hook net cost** | 0.328 µs | 0.178 µs | **−45.7%** |

On a single flow the hook's net cost is already near measurement noise (0.13–0.18 µs),
so old and new are hard to separate; under **4 concurrent flows the hook's net cost drops
by about 46%**, matching the rewrite goal (eliminating cross-core shared writes) — the
gain is concentrated in cross-core contention. Total softirq dilutes it: the hook is only
4% (4 flows) to 8% (single flow) of the floor.
