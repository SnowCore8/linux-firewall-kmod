# Daemon Rewrite Design (Phase 2)

This document is the single source of truth for rewriting `src/daemon/` under the new design.
For the three-tier rewrite goals and the per-tier criteria, see
[Kernel Rewrite Design § Scope and Acceptance](kernel-rewrite-design.md#scope-and-acceptance);
for measured hot-path numbers on the kernel side, see
[Performance Baseline](perf-baseline.md). This document references them without repeating them.

## Decision Record

| Item | Decision | Rationale |
|------|----------|-----------|
| Implementation language | **Rust**, rewritten under the new design | Toolchain unchanged; the netlink/procfs/HTTP ecosystem is mature; what this round changes is **structure**, not language |
| Old code reuse | **None** | The new code reuses neither the old file layout, the old data structures, nor the old loop shape. The old implementation serves only as a source of **behavioral evidence and defect evidence** |
| Concurrency model | **Dedicated OS threads for the main chain + tokio only at the network boundary** | The main chain is "blocking IO + CPU regex"; putting it in an async reactor lets parsing block the network, while putting HTTP in bare threads means hand-rolling SSE. Split by shape of work, each on the runtime it suits |
| State ownership | **Single owner + message passing** (remove the global service locator) | Today there are 46 global `OnceLock`-class statics plus a documented 6-step lock-ordering protocol, which the repo itself already labels an "observability/testability debt" (`runtime_status.rs`, `lib.rs`) |
| Contract status | The three `contract/*.fwidl` files are the source of truth | The rewrite must not drift from the generated artifacts; to change an interface, **change the contract first, then the code**. `netlink.fwidl` may be revised this round (see [Contract Revision List](#contract-revision-list)) |
| Functional scope this round | **Main chain only**; the rest migrates in later batches | User ruling: "rewrite the main chain first, migrate the rest in batches." The main chain = log parsing → ban decision → netlink event → SSE straight to the frontend |
| Threat model | **Inbound-only defense (external)** | User ruling. No egress hooks, no outbound detection, no outbound-behavior analysis |

**Why not full tokio async**: each batch of log lines requires
open/metadata/seek/read + regex matching + sliding-window counting — all blocking or CPU-bound.
Putting that in tokio means either `spawn_blocking` (i.e. back to a thread pool, plus scheduler and
cancellation semantics) or letting regex block the reactor. HTTP/SSE, by contrast, are naturally
async: carrying thousands of idle long-lived connections on threads is wasteful. Split by shape of
work, not by technological uniformity.

## Scope and Acceptance

**Change scope**: all of `src/daemon/`, plus its four external interfaces
(netlink, procfs, HTTP/SSE, YAML config).

**Functional boundary this round** (the main chain):

| Category | Content |
|----------|---------|
| **Implemented this round** | Log collection and rotation, line splitting and regex parsing, IP extraction and validation, failure counting and threshold decision, progressive banning, netlink send/receive with request-response correlation, active ban state, SSE push, HTTP envelope and auth, config parsing and hot reload, graceful start/stop |
| **Migrating in later batches** | IP reputation, attack prediction, collaborative attack detection, periodic-attacker detection, ban-duration / threshold recommendation, SQLite history DB and snapshots, the Prometheus exporter, and the analysis-class Web UI endpoints (heatmap, packet-size distribution, TTL distribution, UDP-port / ICMP-type distribution, network distribution, recidivism) |

Modules for later batches are **not rewritten and not deleted** this round; they keep compiling as-is.
The main-chain interfaces are designed so later batches can attach (see the `analysis/` placeholder in
[New Module Layout](#new-module-layout-by-data-ownership)). This keeps the batched migration from
requiring a second pass over the main chain.

**Acceptance criteria**:

1. **Full gates** pass (as defined by the repo-root `Makefile` / `.github/workflows/ci.yml`):
   `make format-check`, `cargo fmt --check`, `cargo clippy --release --lib -- -D warnings`,
   `cargo test --release --lib`, `make frontend-typecheck`.
2. **Contract verification**: `bash scripts/check_contract.sh` is fully green; every defect in the
   `http` / `netlink` / `procfs` contracts is either fixed with the contract updated to match, or
   explicitly reclassified as "intentionally kept."
3. **Integration acceptance**: the full `tests/` pytest suite passes, and the vacuous assertions in
   [Test Debt](#test-debt) are replaced with assertions that can actually fail (no more tautologies).
4. **Main-chain latency**: an end-to-end probe in `scripts/bench/` measures the
   "log line written → matching SSE event received" latency distribution, reported as p50/p95/p99,
   and demonstrates that this latency **does not degrade as event throughput rises** (periodic
   maintenance no longer competes with event traffic for the same loop).
5. **Stability**: unbounded growth and unbounded insertion are eliminated; no "silent drop" write
   path remains; the shutdown order is provably free of in-flight writes landing on closed resources.

Acceptance is judged primarily on **kernel and daemon stability + performance** (per the user).

Where each of the three goals lands:

- **Latency** — the main-chain end-to-end latency distribution, and the invariant
  "event throughput → maintenance on-time rate"; eliminating the three structural problems of
  "parsing blocks events," "periodic tasks starved by events," and "write work inside the read path."
- **Stability** — eliminating silent drops (history-DB writes, unregistered netlink commands,
  whole-response discards), eliminating unbounded growth (failure entries, post-rotation offset
  drift), and eliminating the implicit assumption that "send succeeded == execute succeeded."
- **Consistency** — interfaces governed by the contracts and aligned across all three tiers; module
  boundaries split by data ownership; the global service locator gone; documentation no longer
  contradicting the implementation (including the rewrite of `docs/zh/architecture/daemon.md`).

## Current-State Inventory

### The four main-chain segments (pre-rewrite)

```
inotify event
  └─ process_new_lines(idx)            read new bytes (256 KB batch)
      └─ process_lines_in_buffer       split on \n
          └─ process_single_line       length check → regex/IP extraction
              └─ extract_and_validate_ip
                  └─ handle_failed_attempt_for_jail   sliding window + threshold
                      └─ ban_ip → send_ban            netlink dispatch
                          └─ kernel bans
                              └─ BanStateChange event pushed back
                                  └─ ACTIVE_BAN_CACHE update + wake_sse_clients()
                                      └─ SSE tick re-serializes 5 full payloads
```

Every step of **all four segments runs synchronously on the same main thread** (netlink event
push-back is on the receiver thread, SSE on tokio):

| Segment | Current location | Shape |
|---------|------------------|-------|
| Log parsing | `file_monitor/{processor,monitor_loop}.rs` + `line_processor.rs` + `log_parser/` | Shares one `poll` loop with event dispatch and periodic maintenance |
| Ban decision | `failed_tracker/tracking.rs` | Called synchronously from the parse path, no queue |
| netlink | `netlink/{mod,handlers,commands,responses,protocol}.rs` | Dedicated receiver thread; sends go through `&NetlinkContext` directly |
| SSE | `web_ui/sse.rs` | tokio task; re-serializes a full snapshot each interval |

### Identified structural problems (with evidence)

**A. Event traffic starves periodic maintenance.** All periodic tasks live in `handle_timeout`,
which runs only when `poll()` returns 0 (timeout) — the three-way branch in
`monitor_loop.rs:110-171`. While inotify events keep arriving, `poll` always returns > 0 and the
60 s / 300 s / 2 s task classes are all deferred. Among them the 2 s rate query and baseline push
(`monitor_loop.rs:390-406`, `send_baseline_update`) carry dynamic-threshold convergence; starving it
directly degrades ban-decision quality.

**B. A full open sequence is repeated on every event.** Each `process_new_lines` call performs
open(`O_NOFOLLOW`) + `metadata()` + `seek()` + `vec![0u8; 256*1024]`
(`processor.rs:37`, `:73-120`, `:123`). No long-lived fd, no buffer reuse. A 256 KB allocation is
repeated at event frequency under attack traffic.

**C. File identity is a `Vec` index.** `FILE_STATES` is a `Vec<FileState>`, and the `idx` passed to
`process_new_lines(idx)` is that index (`state.rs` comment: `FILE_STATES` index = `FileState.wd`);
yet a jail enable/disable change triggers `setup_inotify(cfg)`, which rebuilds the **entire** `Vec`
(`monitor_loop.rs:80-107`). After a rebuild, the index-to-watch mapping depends on rebuild order —
an implicit contract.

**D. 46 global mutable statics form a service locator.** `OnceLock|LazyLock|lazy_static` hits are
spread across 15 files; `lib.rs` documents a 6-step lock-acquisition order specifically for this and
mandates "no IO while holding a lock"; `runtime_status.rs` describes its own existence as mitigation
for "the observability/testability debt of the global `OnceLock` service locator."
The lock-ordering protocol is held by convention with no compile-time enforcement.

**E. The read path performs writes and mutates stats.** `get_active_bans()` (`ban_ops.rs:126`)
performs a throttled `purge_expired` (`PURGE_INTERVAL_SECS = 5`) inside the **read** path, and that
purge increments `DAEMON_STATS.total_unbans` and feeds `record_ban_duration`. A read endpoint has
statistics-mutating side effects.

**F. SSE re-serializes 5 full payloads every round.** `web_ui/sse.rs` refetches
`stats` / `bans` / `jails` / `whitelist` / `rates` each tick and `serde_json::to_string`s each one,
regardless of whether the data changed. With many bans the `bans` payload dominates the cost, and
every connection repeats this.

**G. The persistence queue drops silently when full.** `enqueue_db_write` uses `try_send`; when the
queue is full it logs one warn and **drops that write** (`history_snapshot/mod.rs`:
"history DB write queue busy, dropping one persistence").

**H. Two idle periodic tasks.** `write_stats_snapshot(_cfg)` is a single `debug!`
(`periodic_tasks.rs:18-27`); `check_and_handle_ddos(_cfg)` is `// intentionally empty`
(`periodic_tasks.rs:155-159`). Both still occupy a 60 s / `check_interval` timeout slot.

**I. netlink lacks a request-response correlation layer.** The receive side dispatches on
`msg_type` only and discards `seq` after parsing (`netlink/mod.rs`); the send side always sets
`nlmsghdr.nlmsg_seq = 0`; the one pagination correlation relies on a global single slot
`PendingListBans`, which two concurrent LISTs (startup one-shot + 60 s reconciliation) reset on
each other.

**J. Pagination is one-third done, and its failure direction is silent.**

| Response | Current state | Consequence |
|----------|---------------|-------------|
| `ListBansResponse` | Paginated (`offset`/`total`/continuation) | Fine |
| `ListWhitelistResponse` | Contract has no `offset`/`total`; daemon parse limit hard-coded to 64 | Kernel default page is 256; above 64 entries the **whole response is discarded** and `WHITELIST_CACHE` is not updated |
| `ListRatesResponse` | Contract has `total` but daemon never reads it; request has no `offset`/`limit` | Rate table page max 779 (`FW_NL_RATES_PAGE_MAX`); above 779 entries **silently truncated with no awareness** |

> Erratum: `4096` / `64` are the **hash-bucket counts** of `BAN_HASH_BITS` / `WHITELIST_HASH_BITS`,
> not entry capacities and not page sizes — the first version wrote "capacity 4096" for the rate
> table, conflating bucket count with capacity. This table records the pre-2.A state; after 2.A the
> whitelist, ban, and rate page maxima are `FW_NL_WL_PAGE_MAX` (1926), `FW_NL_BANS_PAGE_MAX` (696),
> and `FW_NL_RATES_PAGE_MAX` (779).

**K. Registration state is invisible to the daemon.** `DAEMON_REGISTER` is sent once at startup;
`DAEMON_REGISTER_ACK` has **no struct and no parse branch** in the daemon (it lands in the
"unknown message type" branch). The kernel does not reply with an error when it rejects a command
(only `pr_warn`), while the daemon treats `sendto` success as success — so after a module reload or
a registration takeover, the daemon keeps "sending successfully with nobody executing," with no
detection path except BanIp's 3 s ack timeout.

**L. The baseline update bypasses the single config-dispatch entry point.** `netlink/config_sync.rs`
states it "converges 'config → kernel' into a single implementation," but `send_baseline_update`
(`monitor_loop.rs:456-462`) builds its own `ConfigUpdate` and calls `ctx.send_config_update`
directly.

**M. The whitelist CIDR key differs between the two write paths.** The LIST path always uses
`format!("{}/{}", ip, prefix_len)`; the event path omits the prefix for `/32`, `/128`, `/0`.
The same entry yields two keys, so event removal and LIST overwrite do not cancel each other.

### Global mutable state inventory (coupling to eliminate)

| Category | Representatives | Current problem |
|----------|-----------------|-----------------|
| Runtime switches | `GLOBAL_RUNNING` / `GLOBAL_RELOAD` / `GLOBAL_ROLLBACK` (`signals.rs`) | Atomic bools + an `EINTR`-driven loop exit; the deliberate absence of `SA_RESTART` is load-bearing |
| File monitoring | `FILE_STATES`, `INOTIFY_STATE` (`static`, not `OnceLock`) | Index is identity; `raw_fd` and `fd` duplicate state |
| Ban state | `ACTIVE_BAN_CACHE`, `BAN_HISTORY`, `PENDING_BAN_ACK`, `BAN_ACK_WAITERS` | ack keyed by IP string |
| Stats/caches | `DAEMON_STATS`, `JAIL_STATS`, `RATE_CACHE`, `WHITELIST_CACHE`, `RATE_HISTORY`, `ANALYSIS_CACHE` | Read side and write side share mutable globals |
| Config | `CONFIG_HISTORY`, `GLOBAL_TRUSTED_IPS`, `GLOBAL_CAPACITY`, `GLOBAL_JAILS_ENABLED`, `CONFIG_TARGET_PATH` | Global carriers for config snapshot/rollback |
| Service location | `GLOBAL_NETLINK_CTX`, `GLOBAL_JAILS`, the `get_global_*()` family | `Arc`s stored in a never-dropped `OnceLock`, making `Drop` effectively dead code |

### Thread and lifecycle inventory

There are **4** non-main spawn sites today:

| Thread | Location | Shape |
|--------|----------|-------|
| netlink receiver | `netlink/mod.rs:119` | `thread::spawn` + `poll(100ms)` |
| netlink stats poll | `main.rs:331` | 1 s `send_stats_query` + `send_analysis_query`; every 60 ticks a full `send_list_bans_query` reconciliation |
| History DB writer | `history_snapshot/mod.rs:265` | `history-db-writer` + `sync_channel` |
| HTTP | `http_exporter/lifecycle.rs:35` | tokio runtime |

The main loop is not spawned (`monitor_loop` runs on the main thread). The cleanup order carries one
hard invariant: **the history DB must be closed only after the netlink receiver has stopped and
joined**, otherwise events in the shutdown window write into an already-closed queue.

## Frozen Surface: External Behavior That Must Be Preserved Verbatim

The following is carried by the contracts and by `tests/`. It is an **external promise**, not "old code."

### netlink (`contract/netlink.fwidl`)

- Protocol number `NETLINK_USERSOCK`; magic `0x46574C4E`; message header **12 bytes**; all structs
  `packed`; all multi-byte integers **big-endian**; addresses are raw bytes.
- **23 message types**; the fixed-length constraints of each response/event and the per-page limits
  of variable-length responses (`ListBans` 696, `ListWhitelist` 1927, `ListRates` 779 entries/page)
  are unchangeable.
- Single-daemon mutual-exclusion registration; 30 s activity timeout; **commands sent by an
  unregistered instance must be rejected.**
- `ConfigFlags` 13 bits and `DynThresholdFlags` 1 bit keep their bit order.

What may be revised this round is listed in [Contract Revision List](#contract-revision-list)
(pagination parameters, `seq` correlation, `RegisterAck` parsing). Revisions follow
"change the contract → change the code → verify with `check_contract.sh`."

### procfs (`contract/procfs.fwidl`)

The daemon only reads and does not define the procfs format; it stays aligned with the kernel side's
12 entries. The daemon's startup existence checks on `/proc/firewall` and `/proc/firewall/bans` are
kept.

### HTTP / SSE (`contract/http.fwidl`)

- **Envelope**: `{code, data, message}`, success `code=0` / `message=""`, failure `data=null`;
  `skip_serializing_if` must not be used.
- **The two SSE streams have mutually independent limits**: `/api/v1/events` = 10,
  `/api/v1/logs/stream` = 5.
- `/api/v1/events` has the fixed event set `connected, stats, bans, jails, whitelist, rates`;
  keepalive 15 s.
- Auth: `/metrics` and `/api/v1/*` require Basic Auth; SPA static routes and `/health`, `/healthz`
  do not.

### YAML config

Config field names and semantics are user-visible interfaces. `WebuiConfig` / `WebuiConfigUpdate` in
`http.fwidl` already reflect the limit fields (`max_ban_entries`, `max_whitelist_entries`,
`max_rate_entries`, `max_local_ip_cache`), aligned with the new kernel module parameters.

### Decision semantics

Whitelist hit ⇒ never ban; effective threshold for `max_retries` =
`max_retries × peak_hours(1.5) × internal_ip(2.0) × reputation`; progressive durations
`0→base, 1→1800, 2→86400, ≥3→permanent`; `ban_time < 0` ⇒ permanent.

## New Architecture

### Runtime model

**Five kinds of execution entity, split by shape of data:**

| Entity | Carries | Blocking nature |
|--------|---------|-----------------|
| `ingest` thread | inotify fd ownership, `poll`, reading new bytes, rotation detection | Blocking IO |
| `pipeline` thread group | Line splitting, regex matching, IP validation, failure counting, threshold decision | CPU + small allocations |
| `kernel reactor` thread | Sole netlink socket owner: send commands, receive events, request-response correlation | Blocking IO |
| `scheduler` thread | Monotonic-clock timers (maintenance, reconciliation, rate query) | Timed waits |
| tokio runtime | HTTP routing, SSE long connections, auth, static assets | async |

**Wired by bounded channels**, each declaring its own backpressure policy:

```
inotify ──LogChunk{jail, source, bytes}──▶ parse ──Failure{jail, ip, ts}──▶ decide
                                                                              │
                                                                      BanIntent{ip, duration, reason}
                                                                              ▼
                                                     kernel reactor ──send_ban──▶ kernel
                                                              ▲                    │
                                                              └── BanStateChange ──┘
                                                                       │
                                                              state hub (versioned snapshot)
                                                                       │
                                                                  SSE / API
```

**Backpressure and drop policy** (each explicit; nothing silent):

| Queue | Behavior when full | Rationale |
|-------|--------------------|-----------|
| ingest → parse | Block ingest (never drop bytes) | Logs are the **evidence source**; dropping lines means missing bans — better to slow reads |
| parse → decide | Block parse | Same; and decide is pure in-memory O(1), so it will not be the bottleneck |
| BanIntent → kernel | Bounded queue + counter; when full, **record and refuse**, never silently | Bans must not be lost, but must not pile up unboundedly either. Refusals must be visible (counter + log) and drive retry |
| events → state hub | Overwrite-style publish (latest-snapshot semantics) | SSE only needs the latest state; intermediate states are disposable |
| state hub → persistence | Bounded queue; when full, **block the producer**, do not drop | Fixes F/G: history is audit data and must not be silently dropped |

**Periodic maintenance is no longer event-driven.** `scheduler` uses a monotonic clock (`Instant`)
rather than `SystemTime`, avoiding timer drift from clock steps; each task expires independently and
is fully decoupled from event traffic. This directly eliminates problem A.

`poll` does one thing only: wait on the inotify fd. Signals go through `signalfd` (folded into the
same `poll` fd set), no longer relying on the implicit `EINTR`-interrupts-`poll` protocol.

### New module layout (by data ownership)

Each module **exclusively owns** its state; cross-module traffic is only narrow-interface messages
or immutable snapshots.

| Module | Data ownership | Interface |
|--------|----------------|-----------|
| `main.rs` | None (composition root) | CLI parse → wire dependencies → start supervisor; holds no business logic |
| `runtime/supervisor.rs` | Execution-entity lifecycle, shutdown token | `spawn_all()` / `shutdown(timeout)`, stopping and joining in **dependency order** |
| `runtime/timers.rs` | Monotonic-clock timer table | `Timer::every(Duration, Job)`, `Timer::at(Instant, Job)` |
| `ingest/watcher.rs` | inotify fd | `events()` iterator (does not `Drop` the fd, does not lend out the handle) |
| `ingest/registry.rs` | `SourceId ↔ (path, inode, wd)` mapping | `resolve(wd) -> SourceId`; `SourceId` is the **stable identifier** (fixes problem C) |
| `ingest/reader.rs` | Per-source fd, offset, reusable buffer | `read_new(SourceId) -> Option<Chunk>`; long-lived fd + reusable buffer (fixes B) |
| `parse/splitter.rs` | Per-source partial-line buffer | `lines(&[u8]) -> impl Iterator<Item = &str>` |
| `parse/rules.rs` | Per-jail compiled regex (immutable, `Arc`) | `match_rule(&str) -> Option<IpAddr>`; compiled once, read-only on the hot path |
| `parse/extract.rs` | None | `extract_ip(&str) -> Option<IpAddr>` (pure function) |
| `decision/window.rs` | Per (jail, ip) failure-timestamp window | `observe(ip, ts) -> Verdict`; single owner, no cross-module locks |
| `decision/policy.rs` | None (pure functions) | `effective_threshold(...)`, `progressive_duration(...)` |
| `pipeline/mod.rs` | Per-jail rules/policy/failure window + per-source line splitter (sole owner) | `on_chunk(...)` → `Vec<BanIntent>`; `cleanup(now)` driven by the timer (fixes A) |
| `kernel/codec.rs` | None | Consumes `contract/generated/netlink_contract.rs` directly (fixes "hand-copied structs") |
| `kernel/transport.rs` | netlink socket (sole owner) | `send(Frame)`; single writer, no send lock needed |
| `kernel/reactor.rs` | In-flight request table (`seq → pending`) | `dispatch(msg)`; routes by **type + seq** (fixes I/K) |
| `kernel/client.rs` | None (typed API over `Arc<Transport>`) | `ban()` / `unban()` / `list_bans()` / `list_whitelist()` / `list_rates()` / `set_config()` |
| `kernel/lease.rs` | Registration lease state | `register()` → await Ack; periodic renewal; visible loss of contact (fixes K) |
| `state/bans.rs` | Active bans (sole owner) | `apply(Event)` / `snapshot() -> Arc<BanSnapshot>` |
| `state/whitelist.rs` | Whitelist (sole owner) | `apply(Event)` / `snapshot()`; a **single CIDR normalization function** (fixes M) |
| `state/rates.rs` | Rates and EWMA baseline | `apply(Response)` / `snapshot()` / `baseline()` |
| `state/stats.rs` | Counters (atomics, increment-only) | `inc(Counter)` / `snapshot()` |
| `state/hub.rs` | Versioned snapshot publication | `publish(Domain)` / `subscribe() -> watch::Receiver`; SSE only subscribes to changes (fixes F) |
| `api/routes/*.rs` | None (thin adapter layer) | Reads from `snapshot()` and applies the envelope; **zero side effects on the read path** (fixes E) |
| `api/sse.rs` | Per-connection subscription | Subscribes to the hub, serializes only when the version changes |
| `api/auth.rs` | Credentials (injected at startup) | `check(headers) -> Result<Principal>` |
| `persist/mod.rs` | SQLite connection (sole owner) | Bounded queue + backpressure; stop netlink before flushing on shutdown (fixes G). **Not created this round**: after 2.F was narrowed, G is fixed in place inside the existing `history_snapshot/mod.rs`; `persist/` is left to a later batch |
| `config/mod.rs` | Config + validation | `load()` / `validate()`; hot reload produces a new immutable snapshot |
| `config/reload.rs` | Reload and rollback transaction | `apply(new_snapshot)`; keep the old snapshot on failure |
| `signal/mod.rs` | `signalfd` | `Signal::next()`; no more atomic bools + `EINTR` |
| `log/mod.rs` | Log sink (async, bounded) | `Logger::log(Record)` |
| `analysis/` | **Placeholder** | Attachment point for later batches (reputation/prediction/collaborative detection); not implemented this round, but the interface is reserved here |

**Files not kept**: `file_monitor/` (split into `ingest/` + `parse/`), `failed_tracker/`
(split into `decision/`), `netlink/` (split into `kernel/`), `web_ui/` (split into `api/` + `state/`),
and the procfs side effects in `ban/mod.rs` (moved out of the read path). Old files are broken up and
recombined by responsibility; new files reuse none of their contents.

### State ownership

**Remove every service locator.** `OnceLock` is permitted in exactly two places: the `log` global
logger (logging is a cross-cutting concern for every module, and it writes but never reads business
state), and test fixtures. All other state is **injected at construction**: `main.rs` creates each
module in dependency order and passes `Arc` handles to whoever needs them.

**The lock-ordering protocol is no longer needed.** Each module exclusively owns its state, and
cross-module traffic is **messages** or `Arc<immutable snapshot>`. This removes from the root the
"6-step lock order" class of convention-held implicit contract.

**Snapshot semantics**: the write side (`state/*`) is a single owner; the read side (`api/*`, SSE)
gets an `Arc<Snapshot>`. A reader never sees a half-applied update, because publication is
"construct a complete new snapshot → atomically swap the `Arc`."

**Lifecycle**: `supervisor` explicitly owns each entity's join handle and shutdown token.
The shutdown order is the **reverse of the dependency order**, and each step awaits completion:

```
stop HTTP ingress (no new requests)
  → stop scheduler
  → stop kernel reactor (flush in-flight requests first)
  → stop pipeline (drain queues)
  → stop ingest
  → flush persist (no new events can arrive now)
  → PID file cleanup
```

The invariant "in-flight events may write to the DB only after the netlink receiver stops" is
guaranteed by **ordering**, not by a comment.

### Main-chain data flow (new)

```mermaid
sequenceDiagram
    participant Log as Log file
    participant Ingest as ingest thread
    participant Parse as pipeline thread
    participant Decide as decision
    participant K as kernel reactor
    participant Hub as state hub
    participant SSE as SSE connection

    Log->>Ingest: inotify MODIFY
    Ingest->>Ingest: long-lived fd read + rotation detect
    Ingest->>Parse: LogChunk (bounded, blocking backpressure)
    Parse->>Parse: split → regex → IP validate
    Parse->>Decide: Failure{jail, ip, ts}
    Decide->>Decide: window count + threshold (O(1))
    Decide->>K: BanIntent
    K->>K: send_ban (seq registered in-flight)
    K-->>Hub: state change
    Hub->>Hub: bump version, publish new snapshot
    Hub-->>SSE: watch notification
    SSE->>SSE: serialize only the changed domain
    Note over K,Hub: kernel BanStateChange updates the Hub on the same path
```

### SSE redesign

- **Subscription, not polling**: `state/hub.rs` is the versioned publication point; an SSE connection
  holds a `watch::Receiver` and builds events only when the version changes.
- **Per-domain serialization**: `stats` / `bans` / `jails` / `whitelist` / `rates` each carry a
  version; only changed domains are re-`serde_json::to_string`ed (fixes F).
- **Limits and counters**: separate counters for the two streams, matching the contract;
  `sse-status` reports **both** streams (fixes `HTTP_SSE_STATUS_INCOMPLETE`).
- **Backpressure**: one slow consumer neither blocks other connections nor the write side
  (independent task per connection + bounded send buffer; slow consumers are disconnected rather
  than allowed to slow down the whole).

### netlink redesign

- **Model**: `Transport` (sole socket owner, single writer) + `Reactor` (receive + route) + `Client`
  (typed API) + `Lease` (registration/renewal).
- **Request-response correlation**: `seq` is allocated monotonically by `Transport` and registered in
  the in-flight table; responses route by **type + seq**. Pagination state for list requests hangs off
  **that request**, not a global single slot (fixes I).
- **All pagination**: `list_whitelist` / `list_rates` gain `offset`/`limit` parameters and a
  continuation loop, matching `list_bans`; per-page limits come from the contract (fixes J).
- **Registration visibility**: `Lease` parses `DAEMON_REGISTER_ACK` and renews periodically;
  loss of contact (timeout / takeover) produces an **explicit state** visible in the API and logs
  (fixes K).
- **Send-result semantics**: a successful `sendto` means only "delivered to the kernel." Commands
  needing execution confirmation (ban) await an ack; `Client`'s return type distinguishes
  "delivered" from "confirmed," forbidding the former to be read as the latter (fixes K).
- **Single config-dispatch entry point**: `client.set_config()` is the only path, including the
  baseline update (fixes L).
- **codec**: include `contract/generated/netlink_contract.rs` directly and delete the hand-copied
  structs, letting the compiler guarantee contract/implementation consistency (fixes the
  "hand-copied copy" defect).

## Contract Revision List

The rewrite may change contracts, but must **change the contract before the code** and go through the
`contract/` verification. This round needs the following revisions:

| Contract location | Revision | Reason |
|-------------------|----------|--------|
| `netlink.fwidl` `ListWhitelistQuery` | Add `offset` / `limit` fields | No pagination parameters today; the kernel always returns the first page. Needed to paginate (fixes J) |
| `netlink.fwidl` `ListWhitelistResponse` | Add `offset` / `total` | Today only `count` + `tail`; the daemon cannot detect truncation (fixes J) |
| `netlink.fwidl` `ListRatesQuery` | Add `offset` / `limit` fields | Same as above (fixes J) |
| `netlink.fwidl` `seq` semantics | Define explicitly as "request/response correlation sequence number," and require unmatched responses to be diagnosable | Today the field is decorative; correlation relies on a global single slot, and concurrent LISTs reset each other (fixes I) |
| `netlink.fwidl` `DaemonRegisterAck` | Define an observable contract for "registration refused" (the daemon must parse it and expose the state) | Today the daemon does not parse it at all and loss of contact is invisible (fixes K) |
| `http.fwidl` `/api/v1/stats/sse-status` | Add the log stream's limit and current value to the payload | Fixes `HTTP_SSE_STATUS_INCOMPLETE` (the two stream limits are independent; the diagnostic endpoint reflects only one) |
| `http.fwidl` `HTTP_BANS_DUAL_SHAPE` | Choose one: unify to a single shape, or explicitly define the trigger condition for each shape | Today "data is always an object" is broken by the raw-array vs paginated-object shapes |
| `http.fwidl` `HTTP_RECIDIVISM_RATE_UNIT` | Unify the unit (0–100 or 0–1) | The same-named field has two units |
| `http.fwidl` `HTTP_TODAY_BANS_EQUALS_TOTAL` | Define `today_bans`'s counting basis | It equals `total_bans`; the semantics are undefined |
| `http.fwidl` `HTTP_THRESHOLD_RECOMMENDATION_ZERO_AMBIGUOUS` | Define what 0 means (no recommendation vs recommendation 0) | Ambiguous today |
| `http.fwidl` `HTTP_SERVICE_PROBE_NO_TOTAL` | Add `total` | Truncation is undetectable |
| `http.fwidl` `HTTP_HEALTH_NOT_ENVELOPED` | Convert to the envelope, or explicitly record it as "intentional exception" | The only endpoint where the HTTP status carries semantics; the frontend special-cases it via `getRawJson` |
| `http.fwidl` `HTTP_LOG_SSE_LIMIT_DOC_DRIFT` | Fix the comment to match the implementation | The comment says "shared" while the implementation uses two independent counters |
| `http.fwidl` `HTTP_BAN_SORT_DOC_INCOMPLETE` | Complete the sort-field documentation | Sort semantics are undocumented |

Endpoints for later batches (prediction / collaborative / heatmap / distribution classes) are not
changed this round; they are handled when their own batches migrate.

## Defect Disposition

Defects in the contracts are **part of the contract** and must be updated alongside. This round covers
existing defects in `netlink.fwidl` and `http.fwidl`, plus daemon-side stability problems found now.

### Fixes and landing status

| Defect | Fix | Landing status |
|--------|-----|----------------|
| `HTTP_BANS_DUAL_SHAPE` (high) | Unify the shape per the contract revision; sync all three tiers | Done: `api/routes/bans.rs::handle_api_bans` always returns the paginated envelope |
| `HTTP_SSE_STATUS_INCOMPLETE` (medium) | `sse-status` reports both streams (see [SSE redesign](#sse-redesign)) | Done: `api/payloads.rs::SseStreamStatus` reports each of the two streams separately |
| `HTTP_LOG_SSE_LIMIT_DOC_DRIFT` (low) | Fix the comment to match the implementation | Done: the `log_viewer.rs` module doc now says "independent counters and limits" (10 / 5) |
| `HTTP_SSE_RESERIALIZES_EVERY_DOMAIN` (medium) | SSE serializes only the domains whose version changed | Done: `api/sse.rs::drive_events_stream` pushes on the `Versions` diff |
| `HTTP_RECIDIVISM_RATE_UNIT` (medium) | Unify the unit and sync frontend formatting | Not fixed (`status` stays `open`) |
| Whitelist parse limit 64 conflicts with kernel page 256 | Remove the hard-coded limit, use the contract's page limit; complete pagination (fixes J) | Done |
| Rate response silently truncated | Add pagination + read `total` + make truncation visible (fixes J) | Done |
| History-DB queue drops silently when full | Block the producer when full, never drop; drain before closing on shutdown; alarm when queue depth crosses the high-water mark (fixes G) | Done: the queue in `history_snapshot/mod.rs` now uses `runtime::channel`'s `Backpressure::Block`; all four discard paths (full / not assembled / writer thread gone / items queued at shutdown) are visible; `close_history_db` joins the writer to drain before closing the connection; 4 non-tautological unit tests lock the behavior (see the 2.F-1 evidence at the end) |
| Registration loss invisible | Introduce `Lease` + parse `RegisterAck` (fixes K) | New side in place (`kernel/{client,lease}.rs`), but `main.rs` and the write points still use the old `crate::netlink` — not wired into production |
| Two baseline/config dispatch paths | Converge on `client.set_config()` (fixes L) | Same: `kernel/client.rs::set_config` exists, production still runs the old `crate::netlink::sync_protocol_thresholds` |
| Whitelist CIDR key inconsistency | Single normalization function (fixes M) | Partial: `state/cidr.rs::CidrKey` is in place and the old write paths are retired, but the old `ban/mod.rs::build_cidr_key` still exists and `status` stays `open` |
| Read-path side effects (purge + stats) | Make purge an explicit method called by a dedicated scheduler task; the read path only reads (fixes E) | Done: `state/compose.rs::purge_expired_bans` + the periodic call in `runtime/scheduler.rs` + `main.rs` wiring `runtime::spawn_periodic`; `get_active_bans()`'s throttled purge and its throttle statics are gone, `status` flipped to `fixed` |
| Two idle periodic tasks | Both `write_stats_snapshot` and `check_and_handle_ddos` are now no-ops (a debug log only) | Done |
| `protocol.rs` comment "20 bytes" | Disappears when codec switches to the generated artifact | Not done: the new `kernel/codec` no longer hand-writes structs, but the "20 bytes" comment at `netlink/protocol.rs:94` is still there (the old module is not deleted) |

### Intentionally kept

| Item | Rationale |
|------|-----------|
| Signals exposed via atomic bools | Keep the "minimal handler, decision in the main loop" pattern, but switch to `signalfd` folded into `poll` so it no longer relies on `EINTR` |
| `HTTP_HEALTH_NOT_ENVELOPED` | Probe semantics: `handle_health` deliberately returns bare JSON (200 / 503 decided by `is_ready()`), and the contract now marks it `retained` rather than a defect. The frontend's `useHealth` reads it with `getRawJson` — an intentional exception |

## Test Debt

Today's `tests/` contain several **tautological assertions** that cannot serve as acceptance and must be
replaced this round:

| Location | Problem |
|----------|---------|
| `tests/config.py` | `MAX_BAN_CAPACITY = 4096`, `MAX_WHITELIST_CAPACITY = 64` are old-implementation constants |
| `tests/test_11_resource_mgmt.py:49-55` | Writes 200 entries then asserts `<= 4096` — a tautology |
| `tests/test_04_whitelist.py:107-108` | Writes 50 subnets then asserts `<= 64` — a tautology |
| `tests/test_19_netlink_comm.py` | Uses `WEBUI_PORT = 8080` and the non-versioned path `POST /api/bans`; every assertion is `>= 0` or skip-guarded |
| `tests/test_18_log_rotation.py` | Hard-codes `/etc/firewall/default.yaml` and `/var/log/firewall-test` |
| `tests/test_10_daemon_logparse.py` | Mostly `pytest.skip` |

Replacement principle: assertions must be able to fail. Capacity assertions become "fill to the new
limit and verify entry N+1 is refused"; path assertions read from config; netlink assertions assert
actual event fields.

**2.F-2 landing status** (commit `6d0bcb4`): the "tautological assertion" class above is fully
replaced — eight files (`test_04` / `test_11` / `test_14` / `test_15` / `test_16` / `test_19` /
`test_20` / `test_21`), and every replacement can now fail. **Still open** (other test debt, outside
2.F's "tautological assertion" scope): the stale capacity constants in `tests/config.py`, the
hard-coded paths in `test_18_log_rotation.py`, and the skip-heavy `test_10_daemon_logparse.py`.

Those three residual debts were closed in commit `bdb508f`, at the depth "align with the real limits
+ drop tautologies", and **without adding any kernel-level capacity test**:

| Location | Disposition |
|----------|-------------|
| `tests/config.py` | Deleted the stale `MAX_BAN_CAPACITY = 4096` / `MAX_WHITELIST_CAPACITY = 64` constants and replaced them with a comment: the real caps are the kernel module parameters `fw_max_ban_entries` / `fw_max_whitelist_entries` (default 65535, see `capacity:` in `config/default.yaml`); 4096 is the ban table's hash-bucket count and 64 the whitelist's — neither is a capacity |
| `test_04_whitelist.py` | Dropped `assert wl_count <= 64` (a tautology), kept `assert wl_count == before + len(added)`; skip text and docstring corrected accordingly |
| `test_11_resource_mgmt.py` | No longer imports `MAX_BAN_CAPACITY`; kept `assert 0 < stat_bans <= 200` — the upper bound is the per-second ban gate (`fw_max_bans_per_second`, default 200/s), not a table capacity |
| `test_18_log_rotation.py` | The hard-coded `/etc/firewall/default.yaml` became the in-repo `CONFIG_DIR / "default.yaml"`; the test log directory now uses `tmp_path`, and cleanup no longer `rmtree`s a fixed directory |
| `test_10_daemon_logparse.py` | `test_log_parse_function`'s silent branch became an explicit `assert PROC_BANS.exists()` + `assert ban_count >= 1`; `test_nonexistent_log`'s timeout branch went from skip to `pytest.fail` |

Verification: serial `python3 -m pytest tests/ -q -rA` (**68 passed / 24 skipped**); versus the
`6d0bcb4` baseline the skip set loses exactly one entry (`test_10::test_nonexistent_log`, skip ->
pass), with no assertion downgraded to a skip.

## Phased Implementation and Acceptance

Each phase is independently testable, independently committable, and independently revertible.
Prerequisite dependency is 0 (it can run in parallel with the Phase 1 kernel rewrite).

| Phase | Content | Acceptance |
|-------|---------|------------|
| **2.A** | Contract revisions (netlink pagination params + `seq` semantics + `RegisterAck`; http sse-status and defect entries) | `bash scripts/check_contract.sh` fully green; gates green |
| **2.B** | Runtime skeleton: `runtime/supervisor` + `signal` (`signalfd`) + `scheduler` (monotonic clock) + bounded-channel contract + shutdown order | Gates green; shutdown order has a test (stop netlink before flushing the DB); timers do not drift with event throughput (with a test) |
| **2.C** | Main-chain rewrite: `ingest` + `parse` + `decision` | Problems A/B/C eliminated (with tests); `decision` semantics match the old implementation case-by-case (comparison test) |
| **2.D** | `kernel` layer rewrite: `codec` (using the generated artifact) + `transport` + `reactor` (type+seq routing) + `client` + `lease`; all pagination | Problems I/J/K/L eliminated; a >1-page test case; registration loss visible. **As of 2.E-4c: J is eliminated; I's new reactor exists but production still runs the old routing; K/L likewise** (`kernel/` is not yet wired into `main.rs` -- see "Fixes and landing status") |
| **2.E** | `state` layer: single owner + snapshot hub; `api` thin adapter + zero read-path side effects | Problems E/F/M eliminated; SSE serializes per domain; a slow consumer does not slow the whole. **As of 2.E-4c: E and F are eliminated; M's new side is in place but the old function is not deleted** (`kernel/` is not wired into production, so M's old key rule still stands -- see "Fixes and landing status") |
| **2.F** | Persistence-queue backpressure rework (in place in `history_snapshot/mod.rs`, not a new `persist/`) + test-debt replacement | Problem G eliminated (backpressure tested); every tautological assertion replaced with one that can fail |
| **2.G** | Documentation rewrite: `docs/{zh,en}/architecture/daemon.md` fully rewritten to the new implementation; `docs/{zh,en}/architecture/data-flow.md` stale numbers corrected | Documentation matches the code item by item |

`docs/zh/architecture/daemon.md` diverges badly from the implementation; 2.G must handle: the module
table lists the no-longer-existing `ban/procfs.rs`; the failure counter is written as
`FailureCounter { ip, count, first_seen, last_seen }`; rotation is written as `IN_MOVED_TO`; it
contains a non-existent `<HOST>` substitution description and an old SQLite `bans` table schema; the
main loop is written as `epoll`.

**The first version of this list carried two items that turned out to be misjudgements**, recorded
here so no later pass "fixes" them in the wrong direction:

- "the port is written as `9119`" — `9119` is in fact the real default (`config/default.yaml:12`,
  `src/daemon/types/config.rs:180`), so the old doc was correct here;
- "the metric count is written as 24" — `src/daemon/http_exporter/metrics.rs` exposes exactly 24
  distinct `firewall_*` metric names (deduplicated `# HELP` lines), so the old doc was correct here
  too.

`docs/*/architecture/data-flow.md` is stale too ("full table (4096)", "whitelist (64)",
"linear scan", "~50ns/~100ns", and the old function name `nf_hook_func_ipv4`); that file was
corrected in commit `615fe16`, and the overview `docs/*/architecture/README.md` capacity and
concurrency claims were corrected in commit `929b52f`.

## Implementation Progress

| Phase | Status |
|-------|--------|
| 2.A Contract revisions | Done |
| 2.B Runtime skeleton | Done |
| 2.C Main-chain rewrite | Done |
| 2.D `kernel` layer rewrite | Done |
| 2.E-1 `state/cidr.rs` + `state/hub.rs` | Done |
| 2.E-2 `state/{bans,whitelist,rates,stats,mod}.rs` | Done |
| 2.E-3 Thin `api` layer + SSE | Done |
| 2.E-4a Composition root wiring (`state::compose` mirroring + `main.rs` injection) | Done |
| 2.E-4b-1 Ratchet groundwork (E/F/M recorded in the contract + status-aware anchors in `verify_http.py`) | Done |
| 2.E-4b-2 Retire the old read paths + mount the new router + flip four defects per `where` survival | Done (E stays `open` at that step; closed by 2.E-4c) |
| 2.E-4c Wire `runtime/`: the scheduler takes over periodic purge and the counter mirror + `main.rs` assembly; E flips to `fixed` | Done |
| 2.F-1 Queue backpressure (`history_snapshot/mod.rs`, queue behavior only) | Done |
| 2.F-2 Test-debt replacement (`tests/` tautological assertions) | Done |
| 2.G Documentation rewrite | Done |

### What 2.A Landed

The netlink wire format landed on all three sides (contract / kernel / daemon) in one step, with the
layout cross-checked by `verify_layout.py`:

| Struct | Change | Layout |
|--------|--------|--------|
| `ListWhitelistQuery` | `+ offset` `+ limit` | 12 → 20 |
| `ListRatesQuery` | `+ offset` `+ limit` | 12 → 20 |
| `ListWhitelistResponse` | `+ total` `+ offset` | fixed 16 → 24 (single-page cap 1927 → 1926) |
| `ListRatesResponse` | `+ offset` | fixed 36 → 40 |
| `MsgHdr.seq` / `DaemonRegisterAck` | pairing semantics and "a refusal must be observable" written as contract obligations | none (comments only) |

- Kernel: page responses now fill in `total` / `offset`; the `LIST_WHITELIST_QUERY` /
  `LIST_RATES_QUERY` cases parse `offset` / `limit` (previously hard-coded to `0, 0`).
- Daemon: the four structs are synced; `new_page` / `send_*_query_page` entry points added; the
  whitelist parse cap moved from "table capacity 64" to "single-page cap 1926".
- HTTP: all 9 defects carry a `resolution` (disposition locked), while `status` stays `open` —
  `verify_http.py`'s mechanical assertions are ratchets, so a fix must land in the same step as the
  code; the sse-status payload is therefore deferred to 2.E.
- Gate evidence: `make build`, `make format-check`, `cargo clippy --release --lib -- -D warnings`,
  `cargo test --release --lib` (81 passed), `make frontend-typecheck`, `bash scripts/check_contract.sh`,
  `bash scripts/verify_project.sh` all green.
- Outstanding: `make format-check` still exits 0 when clang-format fails (`exit 1` sits in a subshell
  and the recipe's last command is an `echo`); fixed in 2.B.

### What 2.B Landed

This phase adds only the shared skeleton; nothing is wired into `main.rs` yet (the old chain still
compiles, matching "keep it building, migrate in batches").

| File | Content | Problem removed |
|------|---------|-----------------|
| `runtime/shutdown.rs` | Cooperative stop token (atomic flag + condvar); `request()` wakes every waiter at once; `wait_until(deadline)` | Replaces the global AtomicBool plus the implicit `EINTR` protocol; shutdown no longer depends on a poll interval |
| `runtime/supervisor.rs` | Executor registry + **one-at-a-time serial** shutdown; each executor owns its token | "Netlink stopped before the DB flushes" becomes an ordering guarantee |
| `runtime/timers.rs` | Monotonic (`Instant`) timer table; `fire_due(now)` is pure | Structural problem A: timers no longer drift with event throughput |
| `runtime/channel.rs` | Bounded queue with the backpressure policy in the type; `Block` / `Reject` (rejects are counted) | "No silent drops" becomes a type constraint |
| `signal/mod.rs` | `signalfd`; signals become an ordinary fd polled alongside inotify | Replaces `sigaction` + async handler + `EINTR` |

Key trade-offs:

- **One-at-a-time serial shutdown.** Requesting stop for every executor at once and then joining
  them lets downstream and upstream wind down together, so "upstream is fully stopped" does not
  hold. `shutdown()` therefore walks the reverse order one segment at a time: `request()` the
  current segment, join it to completion, then stop the next. Registration order is dependency
  order (downstream registered first). This also removes a class of deadlock: while the upstream
  (stopped first) still delivers into a queue, the downstream (stopped last) is still consuming.
- **Timer catch-up is skipped.** A wakeup more than one period behind jumps to `now + period`
  rather than bursting a backlog of callbacks.
- **The `Makefile` `format-check` masked failure is fixed**: `exit 1` used to sit inside a subshell,
  so the recipe's trailing `echo` made it exit 0; it now uses a brace group, and `yamllint`'s exit
  status propagates too.

Gate evidence: `cargo test --release --lib` (106 passed),
`cargo clippy --release --lib --tests -- -D warnings`, `make build` / `make format-check` /
`make frontend-typecheck`, `bash scripts/check_contract.sh`, `bash scripts/verify_project.sh` all
green.

### What 2.C Landed

This phase rewrites the three main-chain layers and composes them into one executor. It is not yet
wired into `main.rs` (the old chain still compiles, matching "keep it building, migrate in
batches"). Four independently committed steps:

| Commit | Files | Content | Problem removed |
|--------|-------|---------|-----------------|
| 2.C-1 | `ingest/{watcher,registry,reader}.rs` | Watcher = fd + read buffer; registry = `SourceId ↔ (path, wd, inode)`; reader = long-lived per-source fd + reused buffer | A (partial) / B / C |
| 2.C-2 | `parse/{splitter,extract,rules}.rs` | Per-source partial line buffer; one shared predicate for reserved ranges in `extract_ip`; per-jail compiled regexes (immutable, `Arc`) | M (reserved-range predicate) |
| 2.C-3 | `decision/{policy,window}.rs` | Judgement arithmetic split into pure functions; the failure window is owned by the executor, lock-free | Hot-path lock contention (`Jail.failed_hash`) |
| 2.C-4 | `pipeline/mod.rs` | Composition of the three layers: new bytes → lines → IPs → failure counts → ban intents | A (maintenance entry point) |

Key trade-offs:

- **Identity is an explicit type, not an index.** `SourceId` is allocated once at registration and
  never changes again, decoupled from the inotify `wd`: rotation replaces the `wd` and the inode, and
  a reload adds and drops sources, yet the `SourceId` for a given path stays stable. The old code
  used a `Vec` index into `FILE_STATES` as identity, while `setup_inotify` rebuilt that whole `Vec`
  on every reload — so indices drifted and every read offset and partial buffer was left misaligned.
- **One `symlink_metadata` per event.** The old code repeated open / `metadata` / `seek` /
  `vec![0u8; 256*1024]` on every event; `SourceReader` keeps a long-lived fd and a single reused
  buffer, and detects rotation with one cheap stat (inode change, or `size < offset`).
- **The partial line buffer moved from the jail to the source.** The old `jail.partial_line_buffer`
  was shared by every log file of a jail, so one file's half line got appended to another's, and a
  reload wiped it entirely via `cleanup_partial_line_buffer`. With one `LineSplitter` per source the
  semantics become "each file's half line only ever joins its own later bytes", and reloads no longer
  discard them.
- **An oversized tail is dropped deterministically.** The old code's behaviour depended on exactly
  where the read chunk happened to end; the new implementation drops it deterministically and counts
  it as `oversized` (a behaviour fix).
- **`register_jail` preserves the failure window.** A reload replaces only the rule set and the
  policy; the window is runtime observation, not configuration — otherwise an attacker could clear
  its accumulated failure count with a single SIGHUP.
- **The maintenance entry point moved off `poll() == 0` to the scheduler.** `Pipeline::cleanup(now)`
  is driven by the monotonic-clock timer on a fixed period instead of being hung off "no events this
  round" (the fix for structural problem A).
- **Comparison tests can fail and retire with the old modules.** `extract_ip`, `RuleSet::parse`,
  `FailureWindow::observe` (against the legacy `count_recent`) and the ban arithmetic (against the
  legacy `BanHistory::calculate_progressive_duration` plus the inlined permanence / expiry formulas)
  all assert case-by-case equality with the old implementation over a shared corpus. One real
  divergence was found by such a test: the legacy `process_failed_timestamps` pruned expired
  timestamps **only when the buffer was full**, whereas the first version of the new code filtered
  every round using that event's own clock — under out-of-order events from a clock rollback it
  dropped timestamps still inside the window. It now mirrors the legacy branch exactly.

Gate evidence: `cargo test --release --lib` (174 passed, 68 of them in the 2.C layers and the
composition), `cargo clippy --release --lib --tests -- -D warnings`, `cargo fmt --check`,
`make build` / `make format-check` / `make frontend-typecheck`, `bash scripts/check_contract.sh`,
`python3 contract/verify_layout.py`, `bash scripts/verify_project.sh` all green; `make test`
(67 passed / 25 skipped).

### What 2.D Landed

This phase rewrites the five kernel netlink layers. The old `crate::netlink` stays for now (still
referenced by `ban/`, `web_ui/` and `config_reloader`) and retires in 2.E, matching "keep it
building, migrate in batches". Five independently committed steps:

| Commit | Files | Content | Problem removed |
|--------|-------|---------|-----------------|
| 2.D-0 | `contract/netlink.fwidl` + `netlink_contract.rs` | Contract revision landed (pagination params, `seq` correlation semantics, `DaemonRegisterAck`) | The contract surface from 2.A |
| 2.D-1 | `kernel/codec/{mod,messages}.rs` | The only escape layer: bytes ↔ semantic types, consuming the generated artifact directly | "Hand-copied structs" |
| 2.D-2 | `kernel/codec/messages.rs` (paged tails) | Tail parsing and `total`/`offset` pass-through for the three `List*Response` | J (silent truncation) |
| 2.D-3 | `kernel/{transport,reactor}.rs` | Sole socket owner + `(type, seq)` routing | I / K (partial) |
| 2.D-4 | `kernel/{client,lease}.rs` | Typed API + registration lease and a visible loss state | I / J / K / L |
| 2.D-5 | `contract/verify_layout.py` | Re-pointed: both the kernel and the daemon now have no hand-written structs, so the comparison becomes "the same artifact parsed by C vs by Rust" | Verifier stays in step with the implementation |

Key trade-offs:

- **"Delivered" and "executed" are separated by the type system.** `ban` / `unban` / whitelist
  add-remove have **no** reply on success; only failure unicasts a `CmdResult`. Their return value is
  therefore `Delivered`, not "success", while requests with a real reply return the decoded struct.
  The old code treated a successful `sendto` as successful execution; this makes that impossible to
  repeat by accident.
- **The correlation allow-list must be narrow, and the reason is in the kernel source.** The kernel
  has **two** sequence sources: `DaemonRegisterAck` / `ConfigAck` / `StatsResponse` /
  `AnalysisResponse` / the three `List*Response` echo the request's `seq`, whereas `DdosEvent` /
  `BanStateChange` / `WhitelistStateChange` / `ConfigChange` are sent with
  `atomic_inc_return(&fw_nl_seq)` and `CmdResult` likewise uses a self-incrementing seq. The two
  ranges must collide, so only the first group may take part in `(type, seq)` correlation —
  otherwise a "ban failed" notice gets swallowed as some LIST request's reply. `is_seq_echoed_reply()`
  is that allow-list, and the test's input is taken directly from the kernel's sender functions.
- **A duplicate registration is refused, not overwritten.** Overwriting the same `(type, seq)` would
  deliver the earlier reply to the later registrant — silent cross-talk. Refusal is counted
  (`seq_collisions`), and the three registration failures map to three distinguishable errors:
  `Full` → back off and retry, `LinkDown` → alert, `Duplicate` → hunt a logic bug.
- **Reactor death must be observable, or `LinkDown` is a dead state.** A `ReplyHandle` and the
  `PendingTable` jointly own the reply channel, so the reactor disappearing does **not** disconnect
  it and a waiter can only wait out its own timeout. The fix is `LivenessGuard` (owned solely by the
  `Reactor`) plus `ReactorLiveness` (a read-only handle): flipping the dead flag also clears the
  in-flight table, so new registrations are refused at once and existing waiters see "disconnected"
  immediately. The alive flag lives **inside** `PendingTable` so "check alive" and "insert" happen
  under one lock, closing the "insert into an emptied table and wait forever" race. It cannot be an
  `Arc` refcount check: the `Router` is shared long-term by the `Client`, so the count never reaches
  zero.
- **Pagination's terminator is the empty page, not `total`.** In the contract `limit == 0` means
  "kernel default page size (256)", not "unlimited"; the kernel returns an empty page once
  `offset >= total`, and `total` is read separately by the kernel so it need not agree with the
  entries collected so far. `drain()` therefore relies on the empty page as its only reliable
  terminator, with two defences: stop if the page origin did not advance (no infinite loop) and stop
  once `total` entries have been collected. Requests always use the contract's page cap rather than
  `limit = 0`.
- **The rate snapshot takes the last page's globals.** `global_pps` / `global_bps` are averages
  "since the previous query", so summing across pages distorts them — every page covers the same
  window. `RateSnapshot` therefore returns globals and entries together, taking the last page's
  values.
- **Registration must await confirmation, and the lease must be renewed.** The kernel answers
  accept/refuse explicitly via `DaemonRegisterAck.accepted`; the old code had neither the struct nor
  a parse arm, so after a refusal every command was silently dropped by the kernel while the UI
  looked fine. The lease bound is the kernel's `FW_NL_DAEMON_TIMEOUT = 30 * HZ`
  (`KERNEL_LEASE_TTL`), and renewal re-sends the registration because the kernel treats any packet
  from the owner portid as activity. The state machine is four-state `Idle`/`Held`/`Refused`/`Lost`,
  and a failed confirmation **always** becomes `Lost` rather than pretending the lease is held;
  `Refused` and `Lost` stay distinct — the former is the other side refusing normally, the latter is
  a link that cannot be judged.
- **The lease state machine is testable without a socket.** The kernel module is not loaded on this
  host (sending to portid 0 gives `ECONNREFUSED`), so "send and confirm" is abstracted behind the
  `Registrar` trait: `Client` in production, a scripted stand-in in tests. Likewise the `client`
  correlation tests all go through `await_reply` (register + wait, **no send**), with the real send
  path's error mapping asserted separately.
- **What the re-pointed verifier actually compares.** With both hand-written copies gone,
  "contract ↔ implementation" is already aligned by the compiler, so `verify_layout.py` now proves
  that **the same artifact parses to the same sizes and offsets under C and under Rust** (the packing
  of fields like `IcmpTypeItem.type` must agree), and asserts the mapping covers all 30 generated
  structs — a new message left out of the comparison fails outright. The probe compiles
  `kernel/codec/mod.rs` as-is, supplying only `crate::contract`, which also proves the layering claim
  that the codec depends on nothing but the contract. It surfaced one real trap: `type` is a Rust
  keyword but **not** a Python keyword, so the probe must add the `r#` prefix per the generator's own
  `RUST_KEYWORDS` list, or `offset_of!` fails to compile.

Gate evidence: `cargo test --release --lib` (257 passed, 73 of them in `kernel::`),
`cargo clippy --release --lib --tests -- -D warnings`, `cargo fmt --check`,
`make build` / `make format-check` / `make frontend-typecheck`, `bash scripts/check_contract.sh`,
`python3 contract/verify_layout.py`, `bash scripts/verify_project.sh` all green; `make test`
(67 passed / 25 skipped).

### What 2.E Landed

2.E lands in seven steps, and **retirement ships in the same step as the ratchet** (per "keep it
compiling, migrate in batches"): 2.E-1 through 2.E-3 plus 2.E-4a only add `state` / `api` modules and
connect the new state to the production write points; the old `web_ui/` and `http_exporter/handler.rs`
stay put. Only the last step (2.E-4b) deletes the old read paths, and it must land the rewritten
`verify_http.py` ratchet assertions **in the same commit as the code**. 2.E-4b itself is cut again —
**groundwork first, then retirement**: first write E/F/M and their `where` anchors into the contract
and make `verify_http.py` dispatch on `status` (`open` requires the anchor to still exist), then
delete code and flip `status`. Packing both into one commit makes `check_defect_claims()` turn the gate
red the instant an anchor disappears.

Before starting that last step it turned out a cut was required first: retiring the old read paths
requires **mounting the new router in the same commit** (`build_router()` has exactly one call site,
and axum panics on a duplicate method+path), yet the new router's 18 endpoints read
`Arc<state::State>` — and **nothing in production constructs or feeds it**. Retiring first would have
served empty bans/whitelist/rates/stats and an SSE stream that never fires. So 2.E-4 splits into these
commits:

| Step | Files | Content | Defects removed |
|------|-------|---------|-----------------|
| 2.E-1 | `state/{cidr,hub}.rs` | The single CIDR normalizer; the versioned snapshot publish point | M (key rules) / F (foundation) |
| 2.E-2 | `state/{bans,whitelist,rates,stats,mod}.rs` | Four data owners + the `State` aggregate, read paths free of side effects | E (read mutating state) / F (data plane) |
| 2.E-3 | `api/{envelope,payloads,ports,views,render,routes/*,sse,router,auth,adapters}.rs` | Thin adapters: one envelope and business-code table, ports for data whose owners have not migrated, SSE serializing only changed domains, a slow consumer that cannot block the rest | F (read path) / E (read-side criterion) |
| 2.E-4a | `state/compose.rs` (new) + `state/{mod,stats,bans,hub}.rs` + `main.rs` + each write point | Composition root: `main.rs` constructs `State` and injects it; existing write points **mirror** into it, the old globals stay for readers that have not migrated | Effectiveness (so the product still has real data after 2.E-4b retires) |
| 2.E-4b-1 | `contract/http.fwidl` + `contract/gen.py` + `contract/verify_http.py` | Ratchet groundwork: E/F/M recorded in the contract with `where` anchors; the verifier dispatches on `status` (a `fixed` entry requires the old anchor to be gone and the new `fix` to exist) | Makes "retirement" mechanically decidable |
| 2.E-4b-2 | Delete `web_ui/sse.rs` + `handler.rs`'s old read paths and the old SSE engine; mount the new router in `api/router.rs`; flip four defects per `where` survival | Retirement and ratchet close together | BANS_DUAL_SHAPE / SSE_STATUS_INCOMPLETE / LOG_SSE_LIMIT_DOC_DRIFT / SSE_RESERIALIZES_EVERY_DOMAIN (to `fixed`); F (router closure); **M partially** (old write paths deleted, old function still present); E — see below |
| 2.E-4c | `runtime/scheduler.rs` (new) + `runtime/mod.rs` + `state/compose.rs` + `main.rs` + `file_monitor/monitor_loop.rs` + `web_ui/ban_ops.rs` + the contract | Wire `runtime/`: the scheduler takes over periodic purge and the counter mirror, `main.rs` assembles the supervisor and shuts it down in order; E flips to `fixed` | E (read-path side effect); A (periodic tasks no longer drift with event throughput) |

2.E-4b-2's flip criterion is "did the `where` anchor actually disappear from the source", not "how do
we intend to fix it". All four entries that moved to `fixed` are cases where the **old implementation
was deleted wholesale** (the old `web_ui/sse.rs` re-serializing every domain, the dual-shape branch in
`handler.rs`, the misleading comment in `log_viewer.rs`), so asserting a positive anchor in the new
implementation is the right `fix`. At 2.E-4b-2, E's and M's original anchors **were both still alive**, so their `status` stayed `open`.
2.E-4c resolves E only: `web_ui/ban_ops.rs::get_active_bans()`'s throttled purge is gone and the
periodic cleanup is driven by the scheduler, so E flips to `fixed`. M stays `open` — the old
`ban/mod.rs::build_cidr_key` is still there because `kernel/` is not wired into production.
`HTTP_HEALTH_NOT_ENVELOPED` is an **intentional exception**, not a pending defect, so it becomes
`retained` with a `reason`.

#### What 2.E-4c Landed: E's Three-Part Fix

E's criterion is "the **read path mutates state**". The old code hung a throttled `purge_expired` off
`web_ui/ban_ops.rs::get_active_bans()`, and once 2.E-4b-2 deleted the `/api/v1/bans` handler that
function **had no mounted caller left** — i.e. 2.E-4b-2 had orphaned the legacy cache's only cleanup
entry point. That is not "E is still there" but "E changed shape": expired entries could only
self-heal via the kernel's `FW_BAN_ACTION_UNBAN`, so a single lost event left them in place forever,
and `total_unbans` / the ban-duration histogram **stopped being accounted** on the no-event path.

The fix therefore has to land all three parts; drop any one and you are back at the old deviation's
shape:

| Part | Location | Role |
|------|----------|------|
| Purge body's **dual purge** | `state/compose.rs::purge_expired_bans(now)` | Clears the old `ACTIVE_BAN_CACHE` *and* the new `Bans`: the legacy cache is still read by the Prometheus `active_bans` gauge, `/health` and `web_ui/stats.rs`, so purging only the new side would let the old table grow forever |
| **Schedule** | `runtime/scheduler.rs::spawn_periodic` | One 1 s base tick with sub-period gating: purge on `PURGE_INTERVAL` (5 s, same value as the old `PURGE_INTERVAL_SECS`), `mirror_stats_tick` on `webui.sse_push_interval` |
| **Assembly** | `main.rs` | `Supervisor::new()` + `runtime::spawn_periodic`, with `supervisor.shutdown()` ordered before `cleanup` |

The matching ratchet strengthening: when `HTTP_READ_PATH_WRITES_STATE` flips to `fixed`, the verifier
requires **more than** the old anchor disappearing — it also requires that `main.rs` assembles
`spawn_periodic` *and* that the scheduler callback actually calls `purge_expired_bans`. Anchor absence
alone is not enough; that was exactly the shape this defect was previously hung in. All three
conditions must hold, otherwise "the read path no longer purges and nobody else does either" keeps the
defect alive under a new coat.

Why "one base tick + per-task gating" rather than two independent timers: `TimerId`'s period is fixed
at registration and cannot be changed afterwards, while the `stats` mirror's period comes from the
**runtime-mutable** `webui.sse_push_interval` (1–60 s). Two independent timers would mean a config
change needs a restart to take effect; base tick + gating makes a change effective on the next round,
matching the old `monitor_loop` semantics. And precisely because SSE is purely version-driven
(`watch::Receiver::changed`), the `stats` mirror **must** be gated by the configured interval —
advancing the version every round would nullify the configured push interval.

Behavior fidelity: the accounting (`total_unbans` / duration histogram) is ported **verbatim**, not
invented; the overlap with the unban-event path's accounting is **pre-existing** (that path's
`total_unbans` increment is unconditional), and whoever removes the entry first wins the histogram
sample — this change neither introduces nor removes that. The net effect is strictly better than the
old behavior: cleanup used to run only when someone read; now it runs unconditionally every 5 s, while
readers (the Prometheus gauge, the dashboard, `/health`) actually see *fresher* data.

**Dead-code call (user's decision):** delete only the purge block inside `get_active_bans()` plus its
throttle statics (`LAST_PURGE_TIME` / `PURGE_INTERVAL_SECS`), and **keep the function itself**. It now
has no mounted caller (only a re-export in `web_ui/api.rs`); removing the whole function is left as a
separate follow-up.

#### What 2.E-4a Landed: the Mirror Bridge's Directions and Timing

`state/compose.rs` is a **transitional bridge**, not part of the new architecture. Both sides coexist
during migration, and the bridge has only three directions — deliberately asymmetric:

| Direction | Covers | Timing | Why it must exist |
|-----------|--------|--------|-------------------|
| Old -> new (mirror) | bans / whitelist / rates / counters | Adjacent to each write point; counters on a fixed period | netlink is already the main chain's write authority; its readings go straight into the new state, so the new SSE and REST have real data at once |
| New -> old (write-back) | **only** ban reconciliation | when `handle_list_bans_response` completes | The old `reconcile_with_kernel` only deletes "cache has, kernel hasn't" and never refills; the new state is the authoritative result of that reconciliation, and without the write-back the old SPA list stays permanently diverged from the kernel |
| External -> new (config) | `sse_push_interval` | startup + every config reload | The `stats` push period belongs to the config owner; the scheduler reads it every round, so a change takes effect immediately |

- **Why counters run on a fixed period rather than per write point.** The 9 counters' old write points
  are spread across the line-processing hot path, the regex-match hot path and the netlink receive
  thread. Rewriting them one by one would couple the hot paths to a transitional mirror and add one
  extra atomic write per log line and per packet. Mirroring on a period leaves every one of those write
  points untouched: the cost is a fixed "9 atomic `load`s + 9 atomic `store`s per period", independent
  of traffic; and because the period tracks `sse_push_interval`, the worst staleness the frontend can
  see is the push interval itself — mirroring more often would not update the screen any sooner.
- **`set_gauge`, not `add`.** The mirror must port each value **verbatim** (`mirror_stats_matches_legacy`
  pins this), and `add` would count the same delta twice. Hence `Stats::set_gauge`, plus a test that
  pins the positional correspondence between `legacy_counter_value` and `DAEMON_STATS`: adding or
  removing a counter on either side turns it red.
- **`Domain::Stats` was never published before.** The new `api/sse.rs` is driven purely by `watch` with
  no timed emission at all, yet the contract fixes `stats` as one of the six SSE events. So `Stats`
  gains `publish_tick` (advancing a blank version), called by the scheduler's periodic tick at
  `push_interval_secs` — `stats` is a **periodic event**, not a change event: the frontend wants "the
  latest cumulative reading", which must be re-sent even when nothing changed, or the numbers on
  screen freeze during quiet periods.
- **`GLOBAL_STATE` is a `OnceLock<Arc<State>>`, following the `set_global_netlink_ctx` convention**
  (a second call errors, so ordering mistakes about who assembles first surface at startup). Every
  mirror function tolerates not having been injected (returns `None`, i.e. a no-op), so unit tests
  that do not go through `main` need no special casing.
- **Unparseable IPs are skipped**, never falling back to `0.0.0.0`: the new state's key is `IpAddr`,
  and stuffing a fake key in would pollute the ban list and contradict the "addresses must parse"
  invariant.
- **The `main.rs` injection point must precede the netlink receive thread**: the startup burst of
  bans/whitelist/stats query responses lands in the new state from that thread, and injecting one step
  later would drop that batch.

Key decisions:

- **The CIDR rule is taken from the kernel, not invented**. `fw_addr_normalize` (`fw_types.h`)
  stores whitelist entries as **network addresses** (host bits zeroed), and `fw_wl_is_full_prefix`
  defines a host entry as IPv4 `/32` / IPv6 `/128`. The canonical form is therefore "host bits
  zeroed, `/prefix` always present" — `10.0.0.5/24` is stored as `10.0.0.0/24`, a bare address
  `10.0.0.1` as `10.0.0.1/32`. The cost is that the UI shows `10.0.0.1/32` where it showed
  `10.0.0.1` (the user accepted this; the frontend handles it in Phase 3). The investigation also
  found M was worse than recorded: the old code held **three** divergent rules (the LIST response
  path always appended `/prefix`; the event path dropped it for `/32`, `/128` and `/0`; and
  `ban/mod.rs::build_cidr_key` turned IPv6 `/0` into `/128`). The old code also never normalized
  host bits, so an HTTP-added `10.0.0.5/24` could never match the kernel's stored `10.0.0.0/24` —
  a second latent defect the document had not recorded.
- **The fix for M makes an unnormalized key unrepresentable**. The key's type is `CidrKey`, not
  `String`, and both constructors (`new` on the struct path, `parse` on the text path) run the same
  normalization, so no outside caller can store a bare key. That is M's actual root cause;
  `the_two_old_write_paths_now_cancel_each_other` asserts the old LIST-write and event-remove paths
  land on one key. `new` **clamps** an out-of-range prefix and `parse` **refuses** one — the former
  receives internal kernel values (predictable degenerate behavior beats an unmatchable key), the
  latter is external input that must be validated.
- **"A read may be cached" is separated from "a read mutates"**. Defect E's criterion is that a read
  *changed state*, not that a read cannot cache. So `snapshot()` memoizes a derived
  `Arc<BanSnapshot>` and invalidates only on real change, while purge becomes the explicit
  `Bans::purge_expired(now)`, which **returns** the removed entries so the caller decides about
  statistics. The old `web_ui/ban_ops.rs::get_active_bans()` purged (throttled) inside the read path
  and incremented `DAEMON_STATS.total_unbans` along the way — SSE read it every second, so statistics
  were rewritten by a read path every second.
  `reading_a_snapshot_does_not_purge_or_otherwise_mutate` and
  `reading_every_snapshot_leaves_the_versions_untouched` pin this down.
  The new method's **caller** is the scheduler's periodic task
  (`runtime/scheduler.rs::spawn_periodic`), now wired into production by `main.rs` (2.E-4c); the old
  `web_ui/ban_ops.rs::get_active_bans()` read-path side effect is removed along with it, and E flips
  to `fixed`. See "What 2.E-4c Landed" above.
- **Publishing takes the data lock first and publishes second**. The read side goes "read the
  version, then take the snapshot"; if the write side reached for the hub lock while holding the
  data lock, that would invert the lock order against the read side. `invalidate_and_publish()`
  drops the data lock before `publish`, and `hub.rs` updates the version before `send_replace`
  wakes subscribers (so a woken subscriber always reads a version >= the one in the notification).
- **A write that changes nothing does not advance the version**. The kernel re-broadcasts the same
  `BanStateChange`, reconciles the whole whitelist every 60 s, and pushes rates every 1 s — waking
  SSE when nothing changed is pure waste. All four owners compare before deciding to mutate:
  `Bans::insert`, `Whitelist::insert`/`replace_all` and `Rates::apply` return `false` and leave the
  version alone for identical input. That is why `Bans::insert` now **compares before inserting**
  (the old form inserted then read back, which cost an extra read and also borrowed `entry` after it
  had been moved).
- **The whitelist count no longer has a second source**. The old code kept its own approximate
  `whitelist_count`, which inevitably drifts from the table. The new `Counter` therefore holds **16**
  entries (no `whitelist_count`), the whitelist size is read from the `Whitelist` owner alone, and
  `start_time` moved out of the counter array into its own atomic.
- **Rates are overwrite, not queued**. "Kernel rate response -> state" may drop intermediate samples;
  the latest must arrive, which matches `watch` semantics — queueing would only show the reader a
  stale rate. The EWMA baseline keeps the old two-stage convergence (large alpha during warmup,
  small alpha afterwards) but **seeds directly from the first sample** instead of ramping from zero,
  and stops updating once frozen.
- **`watch` rather than a broadcast channel for wakeups**. `watch` keeps only the latest value, which
  matches snapshot semantics, and `send_replace` does not fail with no subscribers attached, so
  version advance is independent of who is watching
  (`publishing_without_any_subscriber_still_advances_the_versions`).
- **Ordering is stable**. `Versions::changed` iterates `Domain::ALL` rather than bump order, and
  snapshots order entries by IP / CIDR, so SSE and tests can rely on a reproducible order.
- **No service locator**. The old code held state in `OnceLock` / `LazyLock` globals
  (`ACTIVE_BAN_CACHE`, `WHITELIST_CACHE`, `RATE_CACHE`, `DAEMON_STATS`, ...) and maintained a
  documented "6-step lock acquisition order" to cope. The new `State` is constructed once by the
  composition root (`State::new() -> Arc<Self>`), and modules exchange **messages** or
  `Arc<immutable snapshot>`, so the lock-order protocol is no longer needed. `State: Send + Sync`
  is pinned by a test.

Decisions specific to 2.E-3:

- **SSE and REST share one set of views rather than each writing its own**. Every domain payload is
  derived by pure functions in `api::views`, and `StateRenderer` (SSE) calls exactly the same
  functions as `routes/*` (REST). The old code built payloads separately in `sse.rs` and
  `handler.rs`, which inevitably diverges; here the divergence is structurally impossible — there
  is only one place to change how a field is rendered.
- **"Serialize only changed domains" comes from a version diff, not from cache guesswork**. A
  connection holds the `Versions` it last sent and diffs against the current ones each round; only a
  brand-new connection sends all five domains. `CountingRenderer` counts how many times each domain
  was rendered, so this guarantee is a **failable assertion** rather than a reading conclusion:
  three consecutive `Rates` publishes must render once
  (`several_publishes_coalesce_into_one_render_of_the_latest_state`).
- **A slow consumer is disconnected, not waited on**. The write side (`state::hub`) only advances
  versions and sends a `watch` overwrite notification; it never waits for a subscriber.
  Serialization and sending happen in **each connection's own task**, behind a bounded buffer of
  depth 32; an overflow marks the consumer as too slow and ends that connection
  (`Disconnect::SlowConsumer`, with a `warn` log). This is structural, not best-effort: `watch`
  keeps only the latest value and `send_replace` never blocks, so "how many connections exist and
  which are stuck" is entirely invisible to the write side.
- **The disconnect reason is an explicit type**. `ConsumerGone` / `SlowConsumer` / `HubClosed` stay
  distinct: a slow-consumer disconnect is a runtime event that must be seen, and folding it into
  "the stream ended" makes it unobservable.
- **Connection slots are taken by atomic CAS and returned with the stream**. `SseStatus` keeps one
  counter per stream (limits 10 / 5) and `ConnectionGuard` does `fetch_sub` on drop. It loops on
  `compare_exchange_weak` rather than read-then-write, closing the window between the check and the
  increment. The two limits are **independent** — defect `HTTP_SSE_STATUS_INCOMPLETE` existed
  precisely because one stream's limit was inferred from the other's, so
  `/api/v1/stats/sse-status` reports both.
- **Data gaps are carried by ports rather than placeholder implementations**. Several payload fields
  are not determined by `state` (history trends and reputation, the jail config surface, Web UI
  config, runtime readiness, Prometheus text) and their owners have not been rewritten. Reaching
  directly for the old globals would leave `api` bound to the old modules after 2.E-4, so retirement
  would mean rewriting the routes. Instead they are narrowed into four traits — `ConfigPort` /
  `RuntimePort` / `HistoryPort` / `ControlPort` — and the composition root injects the production
  implementations (today `api::adapters`'s `Legacy*Port` bridges to the old owners, shrinking method
  by method until it is deleted), so as each owner is rewritten **only the implementation changes
  and the route code does not move**. Deliberately no "return empty for now" placeholder: fake data
  cannot be told apart from real data, and that branch would become permanent behavior; a port
  instead makes the gap **explicit in the type system**.
- **Side-effect-free reads are pinned by tests, not by convention**.
  `reading_paths_do_not_mutate_any_state` calls every read endpoint five times and asserts the hub
  versions, the stats snapshot, the ban table length and the whitelist length are all unchanged — the
  old `get_active_bans()` was exactly "listing bans also throttles a purge and increments
  `total_unbans`", so with SSE reading every second, statistics were rewritten every second.
  `reading_does_not_purge_expired_bans` additionally pins that expired entries survive a read
  untouched.
- **One pagination shape**. `GET /api/v1/bans` always returns the paginated envelope with no bare
  array branch — the resolution for defect `HTTP_BANS_DUAL_SHAPE` is "unify to a single shape", so
  `data` is an object under every parameter combination.
- **Write commands do not occupy tokio workers**. Ban / unban / whitelist add-and-remove wait for
  kernel confirmation (possibly hundreds of milliseconds), so they all go through `spawn_blocking`,
  keeping workers free for other APIs and SSE. The ports return "confirmed by the kernel" rather
  than "delivered", matching `kernel::client`'s type discipline.
- **Once a generated artifact is mounted via `#[path]`, `cargo fmt --check` descends into it**. The
  netlink side already guards its `impl` blocks with `#[rustfmt::skip]`; mounting
  `http_contract.rs` exposed that the `path` / `sse` const modules are equally subject to the
  line-length heuristic (six wraps decided by the rustfmt version). The fix belongs in the
  **generator**, not the artifact: `gen.py` now skips those two blocks, otherwise every
  `check_contract.sh` regeneration would turn `fmt` red again.

Gate evidence: `cargo test --release --lib` (391 passed, 55 of them in `api::`),
`cargo clippy --release --lib --tests -- -D warnings`, `cargo fmt --check`,
`make build` / `make format-check`, `bash scripts/check_contract.sh`,
`bash scripts/verify_project.sh` all green.

Gate evidence recorded at the time for 2.E-1 / 2.E-2: `cargo test --release --lib` (336 passed, 79
of them in `state::`), `cargo clippy --release --lib --tests -- -D warnings`, `cargo fmt --check`,
`make build` / `make format-check`, `bash scripts/check_contract.sh`,
`bash scripts/verify_project.sh` all green.

The gate evidence recorded at the time for 2.E-3 is the entry just above (the 55 `api::` cases are
exactly the adapter-layer tests this step added).

Gate evidence recorded at the time for 2.E-4a: `cargo test --release --lib` (399 passed, 87 of them
in `state::`), `cargo clippy --release --lib --tests -- -D warnings`, `cargo fmt --all --check`,
`cargo check --bins --lib` (no warnings), `bash scripts/check_contract.sh` all green.

Gate evidence recorded at the time for 2.E-4b-1: `bash scripts/check_contract.sh` green;
`verify_http.py` reports 12 defects and 15 where/fix anchors passing under the status dispatch, and
it says on its own that the three new entries (E/F/M) currently have anchor-only coverage with no
mechanical assertion -- that gap closes when 2.E-4b-2 flips them.

Gate evidence for 2.E-4b-2: `python3 contract/gen.py contract/http.fwidl` reports "12 defect records
(4 fixed / 1 retained / 7 open)"; `python3 contract/verify_http.py` passes (19 where/fix anchors, 57
payload types, 51 frontend interfaces, 37 frontend paths against 50 contract paths, with
`http_contract.rs` compiling and `http_contract.ts` passing `tsc`); `cargo test --release --lib`
(**400 passed / 0 failed**), `cargo clippy --all-targets -- -D warnings` (exit 0),
`cargo fmt --all --check` (clean), `make build` (`.ko` + daemon), `make format-check` (pass; one
pre-existing yamllint comment-indentation warning at `config/default.yaml:80`),
`make frontend-typecheck` (exit 0), `bash scripts/check_contract.sh` ("contract gate passed", 41
anchors), `bash scripts/verify_project.sh` (success), `python3 -m pytest tests/ -q` (67 passed / 25
skipped) -- all green.

Gate evidence for 2.E-4c: `python3 contract/gen.py contract/http.fwidl` reports "12 defect records
(5 fixed / 1 retained / 6 open)"; `python3 contract/verify_http.py` passes (**20** where/fix anchors,
57 payload types, 51 frontend interfaces, 37 frontend paths against 50 contract paths, with
`http_contract.rs` compiling and `http_contract.ts` passing `tsc`) and confirms E's strengthened
assertion -- "`get_active_bans` read path has no purge, periodic cleanup is driven by the scheduler
assembled in `main.rs`"; `cargo test --release --lib` (**400 passed / 0 failed**),
`cargo clippy --all-targets -- -D warnings` (exit 0), `cargo fmt --all`, `make build` (`.ko` +
daemon), `make format-check` (pass; same pre-existing yamllint warning),
`make frontend-typecheck` (exit 0), `bash scripts/check_contract.sh` (contract gate passed),
`bash scripts/verify_project.sh` (success) -- all green.

One rework in 2.E-4c: the first version of `runtime/scheduler.rs` used `Option::is_none_or` for
gating, and `cargo clippy --all-targets -- -D warnings` failed twice with `incompatible_msrv` (this
repo's MSRV is 1.75.0; that API needs 1.82.0). Switching to an explicit `match` with a comment noting
the MSRV reason made clippy exit 0. It is recorded here because this class of "a newer, nicer API
oversteps the MSRV" will recur in later batches.

### What 2.F Landed

Per the decision record, 2.F was narrowed to **fixing the queue behavior only**: do not create the
`persist/` module the design names, and do not touch modules outside the persistence path. Defect
**G** therefore lands in place, inside the existing `history_snapshot/mod.rs`.

The old code had four paths that discarded a write, three of them completely silent:

| Path | Old behavior | Now |
|------|--------------|-----|
| Queue full | `try_send` logged one warn then **dropped the write** | `Backpressure::Block`: the producer blocks, nothing is dropped |
| Not assembled / already shut down | silent `return`, no log at all | warns once per rising edge (`DB_WRITE_ABSENT_LOGGED`) |
| Writer thread gone | send error ignored | warns on every occurrence |
| Shutdown with items still queued | `close_history_db` sent a sentinel then **immediately** set the connection to `None`; the writer saw `Some(None)` and skipped the items with no log | drop the sender → join the writer (draining the queue) → **then** close the connection |

The fourth row is the one the design never recorded: the promised "stop netlink, then flush" ordering
had never actually held — the connection was pulled out from under the queue while it still had
contents.

**Backpressure choice**: persistence is audit data, so the producers (the netlink receive thread and
the main inotify/parse loop) now block rather than lose a write. So that blocking cannot become a
silent stall, queue depth is observable: `note_queue_depth` warns once when the depth crosses the
high-water mark (`DB_WRITE_HIGH_WATER`, three quarters of the 1024 capacity) and re-arms after the
writer catches up.

**G's ratchet is Rust tests** (it has no contract anchor and no mechanical assertion in
`verify_*.py`), all in `history_snapshot::tests`:

| Test | Behavior locked |
|------|-----------------|
| `saturated_queue_blocks_the_producer_and_loses_nothing` | 200 ops through a capacity-4 queue: asserts `stats.sent() >= 200`, `stats.rejected() == 0`, and that all 200 rows reach `ban_history` |
| `close_drains_ops_queued_before_the_writer_started` | 50 ops queued first, then the writer starts and is closed **immediately**: asserts all 50 land. Deterministic — reproduces the old silent drop with no timing dependence |
| `enqueue_without_assembly_is_a_no_op_and_reports_once` | Enqueue before assembly is a no-op, and `DB_WRITE_ABSENT_LOGGED` is set exactly once |
| `depth_alarm_fires_on_the_rising_edge_only` | The high-water alarm fires once per rising edge and re-arms after a drop |

**2.F-1 gate evidence**: `cargo test --release --lib` (**404 passed / 0 failed**, up from 400 at
2.E-4c), `cargo clippy --all-targets -- -D warnings` (exit 0), `cargo fmt --all --check` (clean),
`make build` (`.ko` + daemon), `make format-check` (passed; the same pre-existing yamllint
`config/default.yaml:80` warning), `make frontend-typecheck` (exit 0), `bash scripts/check_contract.sh`
(passed), `bash scripts/verify_project.sh` (passed) — all green.

**2.F-2** (replacing the tautological assertions in `tests/` with ones that can fail) is also done,
landed in commit `6d0bcb4`: eight test files, and every replacement now requires real evidence (an
exact count, a parsed YAML section, an actual Prometheus sample line, a non-zero exit code, a metric
increment). Verified serially with `python3 -m pytest tests/ -q -rA` (**67 passed / 25 skipped**),
identical to the pre-change baseline — the same 25 skip entries by file and reason, so no assertion
was quietly downgraded to a skip.

Both 2.F slices (2.F-1 queue backpressure + 2.F-2 test debt) have landed.

### 2.G Landing Detail: Documentation Aligned with the Code

`docs/{zh,en}/architecture/daemon.md` were fully rewritten against the **new implementation** (the two
files have 25 one-to-one headings and identical code-block and table-row counts, so they can be
compared section by section). This is not a polish pass: the old text described the generation of
"epoll main loop + `FailureCounter { ip, count, first_seen, last_seen }` + `ban/procfs.rs` +
`<HOST>` substitution + SQLite `bans` table", which no longer corresponds to anything in this
repository.

The discipline was **check every number back against the source**, never quoting the old document or
this document's own paraphrase. Result (the command is the evidence):

| Fact | Value | How it was checked |
|------|-------|--------------------|
| `unsafe { }` blocks | 73, across 13 files | `grep -rn 'unsafe {' src/daemon --include=*.rs` |
| Prometheus metrics | 24 (`# TYPE` lines = distinct metric names) | `grep -c '# TYPE firewall_' src/daemon/http_exporter/metrics.rs` |
| Routes | authenticated 18 (migrated) + 23 (not) = 41; unauthenticated 12 (10 public + 2 probes); 53 total | `contract/verify_http.py` (contract 53 / source 53) |
| SSE limits | events 10 / logs 5; keepalive 15 s; per-connection buffer 32; over-limit 503 | constants in `src/daemon/api/sse.rs` |
| Listen defaults | code `127.0.0.1:9119`; shipped YAML `0.0.0.0:9119` | `src/daemon/types/config.rs` / `config/default.yaml:12-13` |
| Default log path | code `/var/log/firewall-daemon.log`; shipped YAML `/var/log/firewall.log` | `src/daemon/logger.rs` / `config/default.yaml:16` |
| Not-wired modules | `ingest/` `parse/` `decision/` `pipeline/` `kernel/` `signal/` have zero production references | `grep -rn` under `src/daemon` (no call site beyond the `lib.rs` declaration) |

Three numeric problems were found and corrected during the rewrite; they are recorded here so they are
not reverted:

| Problem | Truth | Disposition |
|---------|-------|-------------|
| This design's first version claimed the old doc was wrong to say "24 metrics" | 24 is the truth (`# TYPE` count = distinct metric-name count = 24; the in-file comment "25 in total" in `metrics.rs` is the wrong one) | Retracted; the doc says 24 |
| This design's first version claimed the old doc was wrong to say "the port is 9119" | 9119 is the truth (`config/default.yaml:12`, `src/daemon/types/config.rs`) | Retracted; the doc says 9119 and adds the distinction that the code default binds loopback only while the shipped YAML binds all interfaces |
| The source comment "35 not yet migrated" | Truth is 23 (count of `.route()` inside `legacy_protected_routes`; 41 = 53 - 12) | Doc and source comments corrected in the same step |

That third row is this phase's only **code-side change** (comments only): three places in
`handler.rs` and one in `api/router.rs`. Fixing only the document would leave the source comment to
lead the next reader back to 35.

The stale numbers in `docs/*/architecture/data-flow.md` had already been corrected in commit
`615fe16` (buckets are not capacity, `fw_hook_ipv4` / `fw_hook_ipv6`, "the whitelist is not a linear
scan", and an explicit statement that `pipeline` is not wired), and the capacity and concurrency
claims in the overview `docs/*/architecture/README.md` in commit `929b52f`. This phase re-checked
both files against the implementation and found them consistent, so that part closed as "re-verified,
no change needed".

Gate evidence (actually run in this pass): `make daemon` (built), `python3 contract/verify_http.py`
(contract 53 routes / source 53, all checks pass), `bash scripts/check_contract.sh` (contract gate
passed), `bash scripts/verify_project.sh` (kernel module and daemon both compiled), `cargo test
--release --lib` (**404 passed / 0 failed**), `cargo fmt --all --check` (clean), `cargo clippy
--all-targets -- -D warnings` (exit 0).

## Judging Discipline

- Latency conclusions must give an **end-to-end latency distribution** (p50/p95/p99) and the
  measurement method; single-point numbers are not accepted.
- "Maintenance tasks are no longer starved" must be proven by the **timer on-time rate under high
  event throughput**, not by reading code.
- Each phase must end with a reviewable increment: gate output + contract verification result +
  comparison tests for that phase's structural problems.
- Before a later batch migrates, the frozen main-chain interface shapes must not be changed.
