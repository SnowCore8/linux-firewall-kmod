# Userspace Daemon

`firewall-daemon` is the userspace counterpart of the kernel module: it monitors logs, performs
failure counting and ban decisions, pushes commands to the kernel over netlink, and presents state to
operators and the frontend over HTTP / SSE. The kernel handles per-packet verdicts (rate, DDoS); the
daemon handles application-layer detection (for example SSH brute force) and the external
interfaces.

Two hard boundaries:

- The **only internal channel** between the daemon and the kernel is netlink; `/proc/firewall/*` is
  the user/operator interface, not the daemon's internal channel (`src/daemon/main.rs`).
- The threat model is **inbound-only defense**: no egress hook, no outbound detection, no outbound
  behaviour analysis (design document, "Decision Record").

Related documents:

- Packet decision path and the ban/unban event chain: `data-flow.md`
- Kernel internals, module parameters and hash table sizes: `kernel-module.md`
- Rewrite design (layer trade-offs, structural problems A-M, phased rollout and acceptance
  evidence): `../development/daemon-rewrite-design.md`
- Sources of truth for interfaces: `contract/netlink.fwidl`, `contract/procfs.fwidl`,
  `contract/http.fwidl`
- Configuration fields and semantics: `../configuration/yaml-config.md`

## Technology Stack

| Component | Purpose |
|-----------|---------|
| Rust | Implementation language (single crate binary, no workspace split) |
| serde / serde_yaml / regex | YAML configuration parsing, regex compilation and matching |
| axum / tokio | HTTP service: `/metrics`, `/api/v1/*`, two SSE streams, SPA static assets |
| inotify | Log file change monitoring (`inotify` crate bindings) |
| netlink | Bidirectional kernel communication: command dispatch, paged queries, event pushes |
| rusqlite | Time-series history, ban history and IP reputation persistence |
| slog + slog-json | Structured logging (JSON Lines) |
| rust-embed | Frontend build artifacts embedded into the binary (`src/daemon/web_ui/static/`) |

## Current Implementation Status

The Phase 2 rewrite proceeds as "keep it compiling, migrate in batches", so two generations of
implementation coexist in the repository. This document distinguishes them honestly:

| Layer | Status | Notes |
|-------|--------|-------|
| `runtime/` (supervisor, monotonic-clock scheduler, bounded channels) | **In production** | Assembled at startup by `main.rs`; periodic maintenance no longer hangs off `poll` timeouts |
| `state/` (`bans` / `whitelist` / `rates` / `stats` plus the versioned `hub`) | **In production** | Constructed and injected by the composition root; the new `api` routes read from it |
| `api/` | **Partially in production** | 18 routes mounted; 23 analytics/log routes still live in `http_exporter/handler.rs` |
| `history_snapshot/` write queue | **Reworked** | Blocks the producer when full instead of silently dropping |
| `ingest/`, `parse/`, `decision/`, `pipeline/` | Present, **not wired** | No production call site; the main chain still runs `file_monitor` + `line_processor` + `failed_tracker` |
| `kernel/` (codec / transport / reactor / client / lease) | Present, **not wired** | Production still uses the old `crate::netlink` |
| `signal/` (`signalfd`) | Present, **not wired** | Production still uses `signals.rs` (`sigaction` plus atomic booleans) |

The decision formulas (effective threshold, progressive duration) are already implemented as **pure
functions** in `decision/policy.rs`, cross-checked case by case against the old implementation; the
production path is still carried by the old `failed_tracker/tracking.rs`. The not-wired list and
"Gaps Against the Implementation" are at the end of this document.

## Component Relationships

| Component | Space | Responsibility |
|-----------|-------|----------------|
| Kernel Module | Kernel | Packet verdicts, ban/whitelist tables, rate and DDoS detection, procfs and netlink interfaces |
| Daemon | Userspace | Log monitoring, line parsing, failure counting and ban decisions, config dispatch, HTTP/SSE/metrics |
| netlink | Kernel <-> Userspace | The **only** daemon <-> kernel channel: commands, paged query responses, event pushes |
| ProcFS | Kernel <-> Userspace | Operator interface (12 entries); the daemon only checks existence at startup and never uses it for internal communication |
| History store | Userspace | SQLite: time-series stats, ban history, ban events, IP reputation (`history_snapshot/`) |

## Runtime Model

The design goal is **five kinds of executor divided by data shape**, not "all-tokio-async": the main
chain has the shape "blocking IO plus CPU regex work", and putting it inside an async reactor would
let parsing block the network; HTTP/SSE is naturally async, and carrying thousands of idle long-lived
connections on threads is wasteful.

| Executor | Carries | Blocking nature | Status |
|----------|---------|-----------------|--------|
| `ingest` thread | inotify fd ownership, `poll`, reading new bytes, rotation detection | Blocking IO | Module present, not wired |
| `pipeline` thread | Line splitting, regex matching, IP validation, failure counting, threshold decisions | CPU plus small allocations | Module present, not wired |
| `kernel reactor` thread | Sole owner of the netlink socket: sending commands, receiving events, request-response correlation | Blocking IO | Module present, not wired |
| `scheduler` thread | Monotonic-clock timers (periodic maintenance, reconciliation, rate queries) | Timed waiting | **Wired** |
| tokio runtime | HTTP routing, SSE long-lived connections, auth, static assets | async | **Wired** (2 workers) |

Stages are connected by **bounded channels**, and every stage must state its backpressure policy
explicitly (`runtime/channel.rs`):

```
inotify --LogChunk--> parse --Failure--> decide --BanIntent--> kernel reactor --> kernel
                                                                    ^                |
                                                                    +- BanStateChange +
                                                                            |
                                                                    state hub (versioned snapshot)
                                                                            |
                                                                       SSE / REST
```

| Queue | Behaviour when full | Rationale |
|-------|---------------------|-----------|
| ingest -> parse | Block ingest (lose no bytes) | Logs are the **evidence source**; dropping lines means missing a decision |
| parse -> decide | Block parse | Same as above; `decide` is pure in-memory O(1) and will not become the bottleneck |
| BanIntent -> kernel | Bounded queue plus counters; **reject visibly** when full, never silently | Bans must not be lost, but must not grow unbounded either; rejections must drive retries |
| events -> state hub | Overwrite-style publish (latest snapshot semantics) | SSE only needs the latest state; intermediate states may be dropped |
| state hub -> persistence | Bounded queue; **block the producer** when full, never drop | History is audit data |

In the old implementation every periodic task hung off the `poll` timeout branch of
`file_monitor::monitor_loop`. While inotify events keep arriving, `poll` keeps returning non-zero and
the 60 s / 300 s / 2 s task classes are postponed indefinitely (structural problem A). The
`scheduler` drives them from a **monotonic clock** (`Instant`) instead, fully decoupled from event
throughput and immune to clock jumps (`runtime/timers.rs`: `fire_due(now)` is a pure function, so
tests can verify the absence of drift with synthetic instants).

### Shutdown Order

The shutdown invariant is "**in-flight events may be written to the database only after netlink has
stopped**". For that to actually hold, the stop signal must not be broadcast to all executors at
once: that way upstream and downstream finish concurrently and "upstream has fully stopped" is not
established. `Supervisor::shutdown()` therefore stops **stage by stage, in reverse registration
order**: it calls `request()` on the current stage, `join`s it to completion, and only then stops the
next one (`runtime/supervisor.rs`). Registration order is dependency order (downstream registers
first).

Target order (design document, "Lifecycle"):

```
stop HTTP ingress -> stop scheduler -> stop kernel reactor (flush in-flight requests first)
  -> stop pipeline (drain queues) -> stop ingest -> flush persist -> clean up the PID file
```

The order in production today (not all executors are wired yet): stop the `runtime` executors (only
the scheduler so far) -> `cleanup()`: stop HTTP -> stop the netlink receive thread -> close inotify
-> close the history database -> remove the PID file (`src/daemon/main.rs`).

## Module Layout (by data ownership)

Every module **owns** its state; cross-module communication is messages or `Arc<immutable snapshot>`
only. `OnceLock` is allowed in exactly two places, the global logger and test fixtures; everything
else is injected at construction time.

| Module | State owned | Interface |
|--------|-------------|-----------|
| `main.rs` | None (composition root) | CLI parsing -> assembly -> start the main loop; no business logic |
| `runtime/supervisor.rs` | Executor lifecycle, shutdown tokens | `spawn()` / `shutdown(timeout)`, stopping stage by stage in reverse dependency order and joining each |
| `runtime/scheduler.rs` | Periodic task set | Base tick plus per-task gating (`stats` mirroring, expired-ban purge) |
| `runtime/timers.rs` | Monotonic-clock timer table | `fire_due(now)` (pure), periods rescheduled from the original instant |
| `runtime/channel.rs` | Bounded queue contract | `send` follows `Backpressure::{Block,Reject}`; `Reject` counts are observable |
| `runtime/shutdown.rs` | Cooperative shutdown token | `request()` / `is_shutdown()` / `wait_until(deadline)` |
| `ingest/watcher.rs` | Sole owner of the inotify fd | Event iteration; fd and read buffer are never lent out |
| `ingest/registry.rs` | `SourceId <-> (path, wd, inode)` | `resolve(wd)`; `SourceId` is a stable identity |
| `ingest/reader.rs` | Per-source fd, offset, reusable buffer | Read new bytes plus a cheap rotation check |
| `parse/splitter.rs` | Per-source partial line buffer | Bytes -> lines (the buffer is long-lived and reused across rounds) |
| `parse/rules.rs` | Per-jail compiled regexes (immutable, `Arc`) | On a match, scan capture groups backwards for the rightmost valid IP |
| `parse/extract.rs` | None (pure functions) | Recognise a valid IP in arbitrary text, returning `IpAddr` rather than `String` |
| `decision/window.rs` | Per-jail failure timestamp window | `observe(ip, ts) -> Verdict`, owned by one executor, lock-free |
| `decision/policy.rs` | None (pure functions) | Effective threshold, progressive duration, ban plan |
| `pipeline/mod.rs` | Per-jail rules/windows plus per-source splitters | `on_chunk(...)` -> `Vec<BanIntent>`; stops at the intent, does not send |
| `kernel/codec/` | None | Bytes <-> semantic types, consuming the contract generated code |
| `kernel/transport.rs` | netlink socket (single writer) | Send one payload, receive one datagram |
| `kernel/reactor.rs` | In-flight request table plus routing state machine | Route by **type + seq**; unknown, failed and unclaimed replies are all counted |
| `kernel/client.rs` | None (typed API over `Arc<Transport>`) | `ban` / `unban` / `list_*_all` / `set_config` |
| `kernel/lease.rs` | Registration lease state | Register and await the ack, renew periodically, make loss of contact visible (four states) |
| `state/bans.rs` | Active bans (sole owner) | `apply` / `snapshot` / `purge_expired(now)` |
| `state/whitelist.rs` | Whitelist (sole owner) | `apply` / `snapshot`; keys are `CidrKey` |
| `state/rates.rs` | Latest rate sample plus EWMA baseline | `apply` / `snapshot` / `baseline` |
| `state/stats.rs` | Atomic counters (typed enum, `inc` / `add` / `set_gauge`) | Reading a snapshot mutates nothing |
| `state/hub.rs` | Versioned publish point | `publish(Domain)` / `watch` subscription; holds versions and notifications, not data |
| `state/cidr.rs` | None (normalisation) | `CidrKey::new` / `CidrKey::parse`, the only construction entry point |
| `state/compose.rs` | Mirror directions and timing | **Transitional bridge** between old globals and the new state; deleted once old readers are migrated |
| `api/*` | None (thin adapter layer) | Take from snapshots, wrap in the envelope; read paths have zero side effects |
| `api/ports.rs` | Data-gap ports (narrow traits) | Four narrow trait groups: history / reputation / config / runtime plus control |
| `api/sse.rs` | Per-connection subscription and counters | Per-domain serialization, slow-consumer isolation |
| `contract.rs` | None | Mount the three contract artifacts as crate modules via `#[path]` |
| `runtime_status.rs` | None | One-shot read-only aggregation for `/health` and unit-test assertions |

### Still Carried by the Old Implementation (not migrated this round)

| Module | Responsibility today | Destination |
|--------|----------------------|-------------|
| `file_monitor/` | inotify watches, the `poll` main loop, reading new bytes by offset, re-arming after rotation | Split into `ingest/` + `parse/` |
| `line_processor.rs` | Split on `\n`, partial buffers, per-line length validation and counters | Split into `parse/` |
| `log_parser/` | Regex matching plus string fallback plus IP extraction and validation | Split into `parse/` |
| `failed_tracker/` | `Jail.failed_hash` sliding-window counting and threshold triggering | Split into `decision/` |
| `ban/` | Ban/unban entry points and IP validation (including the procfs-compatible path) | Moved out of the read path; dispatch belongs to `kernel/client` |
| `netlink/` | Send/receive thread, protocol codec, paged response handling, DDoS decision engine | Split into `kernel/` |
| `jail/` | Service-name matching, default inference, ReDoS protection, regex compilation | Config-face owner |
| `config/` | YAML parsing (strict key allowlist, three-layer path safety, rollback) plus CLI | Kept; produces immutable snapshots |
| `config_reloader.rs` | SIGHUP hot reload, diff merging, rollback, runtime config write-back | Kept |
| `history_snapshot/` | SQLite writes (now with backpressure) plus analytics-derived data | Later batch |
| `ip_reputation.rs` | Reputation store (scores, threshold multipliers) | Later batch |
| `log_rotation.rs` | The old rotation-detection implementation (paired with `file_monitor`) | Split into `ingest/reader` |
| `web_ui/` | Static asset embedding, log viewing and paging, analytics endpoints, legacy payload types | Split into `api/`; the frontend talks to `api` directly |
| `http_exporter/` | The 23 unmigrated routes, `/metrics`, Basic Auth and lockout, security-header middleware | Migrated into `api/` batch by batch |
| `types/` | Cross-module data structures and global atomic stats (`Jail` / `Config` / `DAEMON_STATS`) | Retired gradually as data faces migrate |
| `signals.rs` | `sigaction` plus global atomic booleans plus an `EINTR`-based main-loop exit protocol | Replaced by `signal/` (`signalfd`) |

## Startup Flow

The order in `main()` (`src/daemon/main.rs`):

```mermaid
graph TB
    A["CLI parsing (--help returns immediately / --rollback takes the rollback branch)"] --> B["Load config (file or directory) plus strict-mode validation"]
    B --> C["Smart defaults plus config_validate plus caching trusted_ips / capacity"]
    C --> D{"daemon mode?"}
    D -->|Yes| E["Double fork + setsid + chdir / + PID + fd redirection"]
    D -->|No| F["Initialise logging (after daemonization)"]
    E --> F
    F --> G["procfs pre-checks: /proc/firewall and /proc/firewall/bans must exist"]
    G --> H["setup_signals"]
    H --> I["setup_inotify (watch every log file of every enabled jail)"]
    I --> J["jail::init_log_patterns plus history_snapshot::init_history_db"]
    J --> K["NetlinkContext::new"]
    K --> L["Inject state::State plus assemble the Supervisor and the runtime scheduler"]
    L --> M["Start the netlink stats polling thread (1 s; a full LIST bans reconciliation every 60 ticks)"]
    M --> N["Start the HTTP service (when metrics_port > 0)"]
    N --> O["Enter file_monitor::monitor_loop"]
```

Ordering constraints that have explicit reasons, not habits:

- **Logging is initialised after daemonization**: `fork` loses the async logging thread, so the
  `cfg.daemon` branch runs `daemonize_process()` first and `logger::init_logger(cfg.log_file)`
  afterwards.
- **The state layer is injected before the netlink receive thread starts**: bans, whitelist and
  stats query responses arriving at startup land in the new state from inside that thread, and
  injecting one step later loses that batch (comment in the `main.rs` composition root).
- **A failed scheduler assembly only warns, it never panics**: without it the SSE `stats` domain
  stops refreshing on its own and expired bans can only self-heal through kernel `UNBAN` events,
  while the ban main chain keeps working.
- **A missing `/proc/firewall` or `/proc/firewall/bans` fails startup**: with the kernel module not
  loaded the daemon has no working decision and dispatch path.

## Decision Semantics (Frozen Surface)

These rules are an **external commitment** and must not change in the rewrite; `decision/policy.rs`
and the old `failed_tracker` are cross-checked case by case.

- **A whitelist hit means never banned** (the kernel also short-circuits on the whitelist; the daemon
  does not re-decide that an address "may be banned").
- **Effective threshold** = `max_retries x peak hours (x1.5) x internal source (x2.0) x reputation
  factor`, then `.ceil().max(1.0)` (`decision/policy.rs`).
- **Peak hours**: UTC `9..18` (`is_peak_hours(hour_utc)`, with the time source injected by the
  caller so fixed-hour tests cover it completely).
- **Reputation factor**: `>=80 -> 1.0`, `>=50 -> 0.8`, otherwise `0.5` (consistent with the
  threshold multipliers in `ip_reputation.rs`).
- **Progressive duration**: attempt 1 `base`, attempt 2 `1800`, attempt 3 `86400`, attempt 4 onwards
  permanent; `ban_time < 0` means permanent by configuration.
- **Failure window**: only timestamps satisfying `now - findtime <= ts <= now` count; the per-IP cap
  is `MAX_TIMESTAMPS_PER_IP = 100` (FIFO eviction of the oldest), aligned with the old
  `count_recent`.

## netlink Layer

The wire format has a **single** definition, the contract-generated code: protocol `NETLINK_USERSOCK`,
magic `0x46574C4E`, a 12-byte custom common header, all multi-byte integers big-endian, all structs
`packed`. `contract.rs` mounts `contract/generated/netlink_contract.rs` as a crate module with
`#[path]`, so the implementation reads the field names and offsets from the contract and the
"hand-copied struct" source of drift is eliminated by the compiler.

The new `kernel/` layer has five levels (present, not wired into production):

| Level | Responsibility | Key trade-off |
|-------|----------------|---------------|
| `codec` | Bytes <-> semantic types, the only escaping layer | Every multi-byte field goes through explicit `from_be` / `to_be`, never relying on the memory representation of `packed` structs; `decode_packed` converts field by field as it moves bytes, so raw bytes never leave the module |
| `transport` | Sole socket owner (single writer) | Length follows `nlmsghdr.nlmsg_len`, not the received byte count (netlink aligns datagrams to 4 bytes, so `recvmsg` can report up to 3 padding bytes more) |
| `reactor` | Receive loop plus `(type, seq)` routing | `Router` is a pure state machine and is unit-testable; the routing allowlist only covers the group that echoes the request `seq` |
| `client` | Typed request API | "Delivered" and "confirmed" are separated by type; `list_*_all` always requests the contract page size and follows pages to the end |
| `lease` | Registration lease | Registration awaits `DaemonRegisterAck`; four states `Idle` / `Held` / `Refused` / `Lost`, and a failed confirmation always moves to `Lost` |

Two semantics that are easy to get wrong, recorded here so a later implementation does not undo
them:

- **Only allowlisted types may be paired**. The kernel has **two** sequence sources:
  `DaemonRegisterAck` / `ConfigAck` / `StatsResponse` / `AnalysisResponse` / the three
  `List*Response` messages echo the request `seq`; while `DdosEvent` / `BanStateChange` /
  `WhitelistStateChange` / `ConfigChange` / `CmdResult` use a kernel-side counter. The two ranges
  necessarily collide, and pairing `CmdResult` as well would let a "ban failed" notification be
  swallowed as the reply to some LIST request.
- **The end-of-paging signal is an empty page, not `total`**. In the contract `limit == 0` means
  "the kernel default page size", not "unlimited"; the kernel returns an empty page directly when
  `offset >= total`, and `total` is read at a different moment, so it is not guaranteed to match the
  number of rows received. Continuation therefore stops only on an empty page, with an additional
  guard that stops when the page start did not advance.

Production still uses the old `crate::netlink`: a dedicated receive thread (100 ms `poll`) plus
direct `sendto` calls from the main loop, plus a 1 s stats/analysis polling thread and a full
`LIST_BANS` reconciliation every 60 ticks. The old implementation treats a successful `sendto` as
successful execution, parses and then discards `seq`, and reads only the first page of whitelist and
rate queries - precisely what the new layer removes (structural problems I / J / K / L in the design
document).

## State Layer and SSE

`state/` is **single-owner plus versioned snapshots**: the write side owns the data, the read side
takes an `Arc<immutable snapshot>` and can never observe half an update (publication is "build the
complete new snapshot -> atomically replace the `Arc`"). `state/hub.rs` holds only versions and
wakeups, never data; wakeups go through `watch` (latest value only, which matches snapshot semantics
and never fails when there are no subscribers).

| Domain | Event name | Notes |
|--------|-----------|-------|
| `Stats` | `stats` | Counter snapshot; a **periodic event** (must be re-sent at `sse_push_interval` even without changes, otherwise the numbers freeze during quiet periods) |
| `Bans` | `bans` | Active bans |
| `Jails` | `jails` | Jail list and state (config face) |
| `Whitelist` | `whitelist` | Whitelist (keys are normalised `CidrKey`) |
| `Rates` | `rates` | Rates and EWMA baseline |

"An unchanged write does not advance a version" is deliberate: the kernel re-broadcasts identical
`BanStateChange` messages, reconciles the whole whitelist every 60 s and pushes rates every 1 s, and
waking SSE when nothing changed is pure waste.

### SSE Constraints (contract)

| Item | Value | Source |
|------|-------|--------|
| `/api/v1/events` connection limit | 10 | `contract/generated/http_contract.rs` |
| `/api/v1/logs/stream` connection limit | 5 | same |
| `events` event set | `connected`, `stats`, `bans`, `jails`, `whitelist`, `rates` | same |
| keepalive | 15 s | `src/daemon/api/sse.rs` |
| Per-connection send buffer | 32 (overflow disconnects, never blocks the write side) | `src/daemon/api/sse.rs` |
| Response when over the limit | `503` | `src/daemon/api/sse.rs` |

Three structural guarantees:

- **Only changed domains are serialized**. A connection holds the version set it last sent and
  computes the difference each round; only new connections receive all five domains. This removes
  the old cost of "every tick x every connection re-serializing five full payloads".
- **SSE and REST share one set of views**. All domain payloads are derived by pure functions in
  `api/views`; the SSE renderer and the routes call the same functions, so changing how a field is
  displayed has exactly one place to change.
- **A slow consumer is disconnected rather than blocking the write side**. The write side only
  advances versions and notifies in overwrite style; serialization and sending happen in each
  connection's own task, and the reason for termination is an explicit type (`ConsumerGone` /
  `SlowConsumer` / `HubClosed`).

### Whitelist CIDR Normalisation

Keys are `CidrKey` rather than `String`, and both constructors (`new` for the structural path,
`parse` for the textual path) run the same normalisation, so an unnormalised key cannot be
expressed. The rules come from the kernel rather than from convention: the kernel stores whitelist
entries as **network addresses** (`fw_addr_normalize`) and the criterion for an exact host entry is
IPv4 `/32` / IPv6 `/128`. The key form is therefore fixed to "host bits cleared plus an always
present `/prefix`": `10.0.0.5/24` is stored as `10.0.0.0/24`, and the bare address `10.0.0.1` as
`10.0.0.1/32`. Showing `10.0.0.1` as `10.0.0.1/32` in the UI is a direct consequence of that rule.

## HTTP and API

A single axum service carries everything (Web UI, REST, SSE, metrics), listening on
`metrics_bind_address:metrics_port`: the code default is `127.0.0.1:9119`
(`src/daemon/types/config.rs`), while the shipped `config/default.yaml` uses `0.0.0.0:9119` (LAN
access needs that kind of bind, and then credentials are mandatory - see below).

### Route Layering

| Group | Auth | Contents |
|-------|------|----------|
| SPA shell and static assets | None | `/`, `/dashboard`, `/bans`, `/whitelist`, `/jails`, `/ddos`, `/logs`, `/settings`, `/static/*path`, `/sw.js` |
| Probes | None | `/health`, `/healthz` (deliberately not enveloped; `is_ready()` decides 200/503) |
| Migrated into `api` | Basic Auth | 18 routes: `/metrics`, `/api/v1/events`, `/api/v1/stats`, `/api/v1/bans` (GET/POST), `/api/v1/bans/:ip`, `/api/v1/bans/:ip/detail`, `/api/v1/bans/unban-temporary`, `/api/v1/bans/batch`, `/api/v1/jails`, `/api/v1/jails/:name`, `/api/v1/config` (GET/PUT), `/api/v1/whitelist` (GET/POST), `/api/v1/whitelist/:cidr`, `/api/v1/rates/current`, `/api/v1/stats/sse-status` |
| Not migrated (`http_exporter/handler.rs`) | Basic Auth | 23 routes: the analytics `/api/v1/stats/*`, `/api/v1/rates/history`, `/api/v1/rates/windows`, `/api/v1/whitelist/recommendations`, `/api/v1/logs`, `/api/v1/logs/stream`, and so on |

18 + 23 = 41 authenticated routes; on top of that, 10 public routes (SPA shell and static assets)
plus 2 probes = 12 unauthenticated, for 53 in total, matching the contract; `verify_http.py` reads
both files and checks the two lists together (the "35 routes" comment in the source was a stale
count and was corrected alongside this document).

### Envelope and Authentication

- **A single envelope shape**: `{code, data, message}`, with `code = 0` and an empty `message` on
  success, and `data = null` on failure; there is no `skip_serializing_if`, so both fields are
  always present in success and failure responses.
- **Business codes and HTTP status codes are two separate numberings**; `BusinessCode` carries both,
  preventing "right code, wrong status" drift.
- **Authentication**: `/metrics` and `/api/v1/*` require Basic Auth; credentials are read by the
  middleware **per request**, so SIGHUP can change them without a restart; **when no credentials are
  configured the middleware simply passes the request through** (only a loopback bind is allowed in
  that case, see the next bullet). No `WWW-Authenticate` header is emitted (that header triggers the
  browser's native dialog, which shows up as "the button spins forever after a wrong password");
  because EventSource cannot set request headers, the `?access_token=<base64(user:pass)>` form is
  also accepted.
- **Lockout**: consecutive failures beyond a threshold lock the source out for a configured period
  (contract constants).
- **Startup hard constraints**: binding to a non-loopback address with no credentials configured
  **refuses to start** the HTTP service (so the management API is never exposed to the whole
  network); configuring only one of `metrics_username` / `metrics_password` refuses startup as well.
- **Write commands do not occupy a tokio worker**: ban, unban and whitelist changes wait for kernel
  confirmation and always go through `spawn_blocking`.
- **Read paths have zero side effects**: read endpoints do not purge, do not add to statistics and do
  not rate-limit - the old `get_active_bans()` did all three, so reading once per second via SSE
  rewrote the statistics once per second.

## Configuration and Hot Reload

- **Sources**: a single file or a directory (`--config`); a missing path fails startup.
- **Strict mode**: any unknown key fails immediately (enabled by default).
- **Three-layer path safety**: `..` traversal, `%2e` / `%2f` / `%5c` encoding bypass, shell
  metacharacter injection.
- **Rollback on failure**: a mid-parse failure restores everything, leaving no half-applied config.
- **Runtime write-back**: bans, whitelist and thresholds changed in the Web UI are written back to
  the original YAML path by `persist_runtime_config()` (`set_config_target_path`), with
  `trusted_ips` and `capacity` cached at startup for that purpose.
- **SIGHUP hot reload**: re-read config -> diff -> add/remove source watches, recompile regexes,
  update the kernel whitelist; on failure the old snapshot is kept. A reload **only replaces rule
  sets and parameters and never resets failure windows** - otherwise a single SIGHUP would let an
  attacker clear accumulated failure counts.

Capacity fields (`capacity.max_ban_entries` / `max_whitelist_entries` / `max_rate_entries` /
`max_local_ip_cache`, all defaulting to 65535) are only persisted and displayed on the daemon side:
the **`SetConfig` message has no capacity fields**, and the real entry caps are the kernel module
parameters `fw_max_*` (see `kernel-module.md`).

## Persistence

`history_snapshot/` keeps four kinds of data in SQLite: time-series stats (`historical_stats`), ban
history (`ban_history`), ban events (`ban_events`) and IP reputation (`ip_reputation`), and derives
analytics data (attack prediction, coordinated detection, ban-duration recommendations) for the
unmigrated analytics endpoints.

The write queue behaviour was reworked this round, and all four drop paths are now visible
(`history_snapshot/mod.rs`):

| Path | Behaviour now |
|------|---------------|
| Queue full | `Backpressure::Block`: block the producer, lose nothing |
| Not assembled / already shut down | One `warn` on the rising edge |
| Writer thread already exited | One `warn` each time |
| Shutdown with items still queued | Drop the sender, `join` the writer thread to drain, **then** close the connection |

A `warn` is emitted when queue depth crosses the high-water mark and re-armed once the writer
catches up.

## Logging and Signals

**Logging**: structured logging on slog in JSON Lines format (one JSON object per line, field order
`ts -> level -> msg -> version -> others`), written to the path given by the `defaults.log_file`
configuration key; when unset or empty it falls back to `/var/log/firewall-daemon.log`. If the file
cannot be opened it falls back to stderr (using `dup` to copy fd 2, leaving the original stderr
untouched). The `log_destination` / `log_format` fields still exist in the configuration structs,
but the current logger only implements "JSON Lines to a file" and does not read them.

**Signals** (the implementation in production today, `signals.rs`):

| Signal | Behaviour |
|--------|-----------|
| `SIGTERM` / `SIGINT` | Set the exit flag; the main loop shuts down gracefully and cleans up |
| `SIGHUP` | Set the reload flag; the main loop triggers a config hot reload |
| `SIGUSR1` | Dump the current status to the log |
| `SIGPIPE` | Ignored (an HTTP client disconnecting must not kill the process) |

The old implementation deliberately avoids `SA_RESTART` and relies on `EINTR` interrupting `poll` to
hand control back to the main loop - an implicit protocol. The new `signal/` (`signalfd`) turns
signals into ordinary fds polled together with inotify, with `SignalFd` blocking the four signals and
restoring the mask on drop; that module is present but **not wired into production**.

## Observability

### Prometheus Metrics

`/metrics` exposes **24** metrics (`src/daemon/http_exporter/metrics.rs`, counted by `# TYPE` lines):

| Metric | Type | Description |
|--------|------|-------------|
| `firewall_kernel_banned_ips_current` | gauge | Currently banned IPs |
| `firewall_kernel_bans_total` | counter | Total ban operations |
| `firewall_kernel_unbans_total` | counter | Total unban operations |
| `firewall_kernel_whitelist_count` | gauge | Current whitelist entries |
| `firewall_daemon_lines_parsed_total` | counter | Lines parsed |
| `firewall_daemon_ips_extracted_total` | counter | IPs extracted |
| `firewall_daemon_ips_banned_total` | counter | IPs actually banned |
| `firewall_daemon_failed_attempts_total` | counter | Total failed attempts |
| `firewall_daemon_config_reloads_total` | counter | Successful config reloads |
| `firewall_daemon_inotify_events_total` | counter | inotify wakeups (not the event count) |
| `firewall_daemon_log_rotations_total` | counter | Rotations detected |
| `firewall_daemon_lines_skipped_total` | counter | Lines skipped as oversized or malformed |
| `firewall_daemon_regex_matches_total` | counter | Total regex matches |
| `firewall_daemon_uptime_seconds` | gauge | Uptime |
| `firewall_ddos_events_detected_total` | counter | DDoS events detected |
| `firewall_ddos_auto_bans_total` | counter | Bans issued by the DDoS decision engine |
| `firewall_ddos_tracked_ips_current` | gauge | IPs tracked for DDoS detection |
| `firewall_netlink_messages_sent_total` | counter | netlink messages sent |
| `firewall_netlink_messages_received_total` | counter | netlink messages received |
| `firewall_netlink_send_errors_total` | counter | netlink send failures |
| `firewall_netlink_recv_errors_total` | counter | netlink receive/parse failures |
| `firewall_reputation_tracked_ips` | gauge | IPs tracked by the reputation system |
| `firewall_reputation_low_count` | gauge | IPs scoring below 80 |
| `firewall_reputation_critical_count` | gauge | IPs scoring below 50 |

The four `firewall_kernel_*` metrics come from the in-process cache rather than live procfs reads
(`/proc/firewall/*` is the user interface). Entries found in earlier documentation such as
`firewall_ban_events_total` / `firewall_packets_*` / `firewall_hash_table_*` / `firewall_jail_*`
**do not exist**.

### Health and Diagnostics

- `/health`, `/healthz`: carry a `RuntimeSnapshot` (netlink readiness, `/proc/firewall` presence,
  whether the ban cache and history are initialised, current ban count); `status` is decided solely
  by "netlink ready and procfs present", returning 200 when ready and 503 otherwise.
- `/api/v1/stats/sse-status`: reports the current connection count and limit of **each** of the two
  SSE streams (10 / 5) - inferring one stream's limit from the other was the cause of an earlier
  defect.

## Memory Safety

Every `unsafe` block in the daemon carries an explicit `// SAFETY:` comment stating the
preconditions and which invariants still hold afterwards. There are currently **73** `unsafe { }`
blocks (counted per block), distributed as follows:

| File | Blocks | Purpose |
|------|--------|---------|
| `netlink/responses.rs` | 15 | Moving bytes into `packed` structs for paged responses |
| `netlink/mod.rs` | 15 | netlink socket operations and datagram splitting |
| `kernel/transport.rs` | 12 | socket creation, binding, sending and receiving |
| `signal/mod.rs` | 9 | `signalfd` and signal masking |
| `netlink/protocol.rs` | 7 | Wire-format codec |
| `daemonizer.rs` | 7 | `fork` / `setsid` / PID file / fd redirection |
| `kernel/codec/mod.rs` | 2 | Moving `packed` struct offsets |
| `signals.rs` | 1 | `sigaction` registration |
| `netlink/commands.rs` | 1 | Command encoding |
| `logger.rs` | 1 | `dup(2)` stderr fallback |
| `ip_utils.rs` | 1 | Raw address operations |
| `ingest/watcher.rs` | 1 | `inotify` fd ownership |
| `file_monitor/monitor_loop.rs` | 1 | `poll` syscall wrapper |

`Cargo.toml` provides three detection profiles: `dev-with-debug` (release-grade optimisation with
DWARF kept, so a field crash can be traced with `addr2line`), `asan` (AddressSanitizer, needs
nightly and `build-std`), and Miri (interprets `unsafe` code to catch pointer-arithmetic UB and
aliasing violations - the class ASAN cannot see).

## Gaps Against the Implementation

The following are the precise "present but not wired" boundaries, so a reader does not mistake the
design for the current state (per-item evidence is in the design document's "Fix items and their
landing status"):

| Item | State |
|------|-------|
| Main chain (`ingest` -> `parse` -> `decision` -> `pipeline`) | `pipeline` stops at `BanIntent` and has no production call site; production still runs `file_monitor` + `line_processor` + `failed_tracker` |
| `kernel/` layer | No production reference; production uses the old `crate::netlink`. The `Lease` visibility of registration, the single `client.set_config` entry point and single CIDR normalisation are therefore not yet live |
| `signal/` (`signalfd`) | No production reference; production uses `signals.rs` |
| Periodic maintenance | Already taken over by `runtime/scheduler.rs` (expired-ban purge plus counter mirroring), base tick 1 s with per-task gating |
| `api` routes | 18 of 41 authenticated routes migrated (the contract has 53 in total, 12 unauthenticated); 23 analytics and log routes remain in `http_exporter/handler.rs` |
| Old module removal | `web_ui/`, `netlink/`, `failed_tracker/`, `file_monitor/`, `line_processor.rs` and `log_rotation.rs` still compile as-is, to be retired once later batches migrate them |

Until later batches migrate, the frozen interface shapes of the main chain must not change; when an
interface must change, **change the contract first and the code afterwards**, then run
`bash scripts/check_contract.sh`.
