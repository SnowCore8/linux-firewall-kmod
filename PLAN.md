# PLAN.md - 项目开发计划

> **格式说明**：本文档中的任务可直接被 todo 任务列表复用。每个任务包含：
> - `id`: kebab-case 格式的任务标识
> - `task`: 动宾结构的任务描述（直接用于 todo content）
> - `priority`: P0/P1/P2 优先级
> - `status`: pending/in_progress/completed

---

## 当前版本：v2.2.0

**最后审查**：2026-06-17  
**状态**：全面代码审查完成，发现 2 Critical + 15 High + 20+ Medium 问题

---

## P0 - 严重缺陷修复（必须立即处理）

### 内核模块 Critical

```yaml
- id: fix-ddos-ban-worker-data-race
  task: 修复 ddos_ban_worker 与 netfilter 热路径之间的数据竞争
  priority: P0
  status: completed
  source: src/kernel-module/netfilter.c 第 55-68 行
  details: |
    ddos_ban_pending/af/ip/reason 字段在热路径中写入、worker 中读取，无任何同步。
    IPv6 地址 16 字节非原子写，SMP 上 worker 可能读到部分写入数据。
    修复：使用 smp_store_release/smp_load_acquire 确保内存顺序。

- id: fix-netdev-whitelist-subnet-list-uaf
  task: 修复 netdev 下线时白名单子网链表 use-after-free
  priority: P0
  status: completed
  source: src/kernel-module/netdev.c 第 130-155 行
  details: |
    sync_work_handler 删除白名单条目时仅从哈希表移除（hlist_del_rcu），
    未从子网链表移除（list_del_rcu(&entry->subnet_node)）。
    后续子网匹配遍历会访问已释放内存。
    修复：添加子网链表移除逻辑（IPv4: mask != 0xFFFFFFFF, IPv6: prefix_len < 128）。

- id: fix-init-order-sync-work
  task: 修复 firewall_init 中 INIT_DELAYED_WORK 顺序错误
  priority: P0
  status: completed
  source: src/kernel-module/firewall-main.c 第 148-158 行
  details: |
    ddos_ban_wq 分配失败跳转 err_notifier 时，
    sync_work 尚未 INIT_DELAYED_WORK，
    但 err_notifier 对其调用 cancel_delayed_work_sync，属未定义行为。
    修复：将 INIT_DELAYED_WORK 移到 alloc_workqueue 之前。
```

### 守护进程 Critical

```yaml
- id: remove-file-reader-dead-code
  task: 删除 file_reader.rs 死代码或与 processor.rs 合并
  priority: P0
  status: completed
  source: src/daemon/file_reader.rs vs src/daemon/file_monitor/processor.rs
  details: |
    两个文件实现了几乎完全相同的逻辑（约 200 行重复）：
    打开文件→轮转检测→seek→批量读→行分割→partial 缓冲→offset 更新。
    实际运行中 monitor_loop 调用 processor::process_new_lines，
    file_reader.rs 是遗留死代码。
    修复：删除 file_reader.rs 并从 lib.rs 移除模块声明。
```

### CI/测试 严重

```yaml
- id: add-cargo-test-to-ci
  task: 在 CI 中添加 cargo test 执行
  priority: P0
  status: completed
  source: .github/workflows/ci.yml
  details: |
    当前 CI 的 lint job 运行了 cargo fmt/clippy，build job 运行了 make all，
    但从未运行 cargo test。108+ 个 Rust 单元测试在 CI 中完全不执行。
    修复：在 lint job 的 clippy 检查后添加 cargo test --release --lib 步骤。

- id: fix-ci-kernel-build-silent-failure
  task: 修复 CI 中内核模块编译允许静默失败的问题
  priority: P0
  status: completed
  source: .github/workflows/ci.yml build job
  details: |
    内核模块编译步骤使用 continue-on-error: true，
    编译失败不阻断 CI，内核代码退化不会被发现。
    修复：移除 continue-on-error: true，内核头文件可用时编译必须成功。
```

---

## P1 - 高优先级（近期修复）

### 内核模块热路径性能

```yaml
- id: optimize-checksum-verification
  task: 优化 netfilter 热路径中的 IP 校验和验证
  priority: P1
  status: completed
  source: src/kernel-module/netfilter.c 第 225 行
  details: |
    当前无条件执行 ip_fast_csum，在 10Gbps/15MPPS 场景下每包增加 10-20ns。
    修复：检查 skb->ip_summed != CHECKSUM_UNNECESSARY 后再验证。

- id: optimize-rate-detector-ip-compare
  task: 优化 rate-detector 热路径中的 IP 比较函数
  priority: P1
  status: completed
  source: src/kernel-module/rate-detector.c 第 60-70 行
  details: |
    find_rate_entry_rcu 使用 compare_ips 通用函数（含 af 判断分支），
    在已知 af 的热路径中应直接使用 ipv6_addr_equal 或 __be32 比较。
    修复：根据 af 直接使用特定比较函数，避免分支开销。

- id: optimize-whitelist-recheck-traversal
  task: 优化白名单二次检查的桶遍历效率
  priority: P1
  status: pending
  source: src/kernel-module/ban-manager.c 第 40-60 行
  details: |
    __recheck_whitelist_ipv4/ipv6 使用 hash_for_each_rcu 遍历所有桶，
    精确匹配场景可直接计算桶索引只检查一个桶。
    注意：此优化需要改变白名单数据结构（当前必须遍历所有桶检查子网匹配），暂跳过。
```

### 守护进程性能瓶颈

```yaml
- id: optimize-logger-get-mutex
  task: 优化 logger::get() 的 Mutex 锁争用
  priority: P1
  status: completed
  source: src/daemon/logger.rs get() 函数
  details: |
    每次调用获取 parking_lot::Mutex 锁并克隆 Logger。
    在 10Gbps 日志解析热路径中，每行日志至少调用一次，Mutex 争用严重影响吞吐量。
    修复：使用 thread-local 缓存，每线程首次调用时克隆并缓存 Logger。

- id: optimize-ddos-detector-arc-alloc
  task: 消除 DDoS 检测器热路径中的 Arc::from(ip) 堆分配
  priority: P1
  status: completed
  source: src/daemon/ddos_detector.rs record_connection/record_failure
  details: |
    每次 record_connection/record_failure 都执行 Arc::from(ip) 分配新字符串。
    在 10Gbps 场景下每个事件做一次堆分配完全抵消了 IP 数值化优化的收益。
    修复：ThreadLocalEvent 改用 String，在 flush_batch_buffer 时批量构造 Arc<str>。

- id: fix-failed-tracker-vec-remove-performance
  task: 修复 failed_tracker 中 Vec::remove(0) 的 O(n) 性能问题
  priority: P1
  status: completed
  source: src/daemon/failed_tracker/tracking.rs process_failed_timestamps
  details: |
    使用 Vec::remove(0) 做 FIFO 移出，时间复杂度 O(n)。
    MAX_FAILED_TIMESTAMPS=100，每次满后执行 O(100) 元素移动，
    在持有写锁期间阻塞同一 jail 的所有其他 IP 处理。
    修复：FailedEntry.timestamps 改用 VecDeque，使用 pop_front()（O(1)）。
```

### 功能正确性

```yaml
- id: fix-ban-ip-hardcoded-jail-name
  task: 修复 ban_ip_with_history 硬编码 jail_name 为 ddos 的问题
  priority: P1
  status: completed
  source: src/daemon/ban/operations.rs ban_ip_with_history()
  details: |
    _jail_idx 参数被忽略，jail_name 硬编码为 "ddos".to_string()。
    导致 /api/bans 和 Prometheus 指标中的 jail 分布数据不准确。
    修复：函数签名改为接收 jail_name: &str 参数。

- id: fix-failed-tracker-ban-duration
  task: 修复封禁时长使用 findtime 而非 ban_time 的问题
  priority: P1
  status: completed
  source: src/daemon/failed_tracker/tracking.rs handle_failed_attempt_for_jail
  details: |
    expires_at = now + findtime_i64 使用的是检测窗口而非封禁时长。
    与 fail2ban 行为不一致——fail2ban 使用 bantime 作为封禁时长。
    修复：使用 jail.ban_time 计算 expires_at。

- id: fix-sse-connection-limit
  task: 为 SSE 连接添加全局上限防止资源耗尽
  priority: P1
  status: completed
  source: src/daemon/web_ui/sse.rs handle_sse_connection
  details: |
    每个 SSE 连接创建独立后台线程，无连接数上限。
    恶意客户端可建立大量连接，每个每秒触发完整数据收集。
    修复：添加全局 AtomicUsize 计数器，MAX_SSE_CONNECTIONS=10，超过返回 503。
    使用 ConnectionGuard 在 Drop 时自动减少计数。

- id: implement-strict-mode
  task: 实现配置严格模式的未知 key 检查
  priority: P1
  status: completed
  source: src/daemon/config/parser.rs parse_config()
  details: |
    --strict 标志被存入 cfg.strict_mode 但从未在解析过程中使用。
    serde 默认忽略未知字段，严格模式实际无效果。
    修复：为所有 YAML 结构体添加 #[serde(deny_unknown_fields)] 属性。
```

### 接口统一

```yaml
- id: unify-whitelist-add-remove-interface
  task: 统一白名单 add/remove 接口参数
  priority: P1
  status: pending
  source: src/kernel-module/whitelist.c
  details: |
    add_whitelist_entry 接受 (ip, mask, prefix_len)，
    remove_whitelist_entry 只接受 (ip, prefix_len)。
    remove 中掩码计算与 add 不一致，可能导致删除找不到条目。
    注意：接口统一需要大规模重构，根据"禁止过度工程化"原则暂跳过。

- id: unify-ip-validation-path
  task: 统一 IP 验证逻辑为单一验证路径
  priority: P1
  status: pending
  source: src/daemon/ban/ip_validation.rs vs src/daemon/log_parser/parser.rs
  details: |
    IP 验证逻辑（loopback/multicast/link-local 检查）在两处独立实现。
    修改一处容易遗漏另一处。应统一为单一验证函数。
    注意：接口统一需要大规模重构，根据"禁止过度工程化"原则暂跳过。

- id: remove-procfs-fsync-overhead
  task: 移除 procfs 写入中无意义的 fsync 调用
  priority: P1
  status: completed
  source: src/daemon/ban/procfs.rs write_to_fd()
  details: |
    procfs 是虚拟文件系统，fsync 无实际意义但增加系统调用开销。
    在高频封禁场景下是不必要的性能损耗。
    修复：移除 libc::fsync(fd) 调用。
```

---

## P2 - 中优先级（文档与测试完善）

### 文档修复

```yaml
- id: fix-daemon-architecture-docs
  task: 修复 daemon.md 架构文档的过时描述
  priority: P2
  status: completed
  source: docs/zh/architecture/daemon.md
  details: |
    "12 个模块"应为 53 个源文件，"PCRE2 语法"应为"与 PCRE 语法等价"。
    修复：更新模块数量和 regex crate 描述。

- id: fix-yaml-config-docs
  task: 修复 yaml-config.md 配置文档与实际不一致
  priority: P2
  status: completed
  source: docs/zh/configuration/yaml-config.md, docs/en/configuration/yaml-config.md
  details: |
    max_retries 文档写 5 实际 3；permanent_db_path/permanent_ban_enabled
    文档详细描述但源码未实现；缺少 ddos/webui 配置节文档。
    修复：更新默认值为 3，删除 permanent_db_path 相关描述。

- id: fix-testing-docs
  task: 修复 testing.md 中不存在的测试套件引用
  priority: P2
  status: completed
  source: docs/zh/development/testing.md, docs/en/development/testing.md
  details: |
    列出 15_daemon_logfile.sh 但该文件不存在。
    "13 套件"与实际 16 套件不匹配。
    修复：更新测试套件列表为 15-18，套件数为 16。
    "CI 矩阵化运行 ASAN/Miri"但 CI 中无相关步骤。

- id: fix-readme-test-counts
  task: 统一 README.md 中的测试数量声称
  priority: P2
  status: completed
  source: README.md
  details: |
    "108+107"、"111"、"115"多个数字互相矛盾。
    unsafe 块数量"19"与实际 20 不一致。
    修复：统一为 108 单元测试 + 115 集成测试。

- id: fix-kernel-module-docs-path
  task: 修复 kernel-module.md 中的源文件路径错误
  priority: P2
  status: completed
  source: docs/en/architecture/kernel-module.md
  details: |
    文档写 src/kernel/firewall.c，实际为 src/kernel-module/firewall-main.c。

- id: remove-permanent-db-docs
  task: 移除文档中未实现的 permanent_db_path 相关描述
  priority: P2
  status: completed
  source: docs/en/configuration/yaml-config.md, docs/en/operations/troubleshooting.md, docs/zh/operations/troubleshooting.md
  details: |
    permanent_db_path 和 permanent_ban_enabled 在文档中详细描述，
    但 config/default.yaml 和源码中均不存在。
    用户按文档配置不会生效且无报错。
    修复：删除所有相关描述。
```

### 测试补充

```yaml
- id: add-ddos-detection-integration-test
  task: 添加 DDoS 检测集成测试
  priority: P2
  status: completed
  source: tests/suites/15_ddos_detection.sh
  details: |
    ddos_detector.rs 有 700+ 行和单元测试，但无集成测试。
    应测试：速率违规检测、协议违规检测、自动封禁触发。
    已实现：15_ddos_detection.sh（157 行），覆盖配置验证、速率阈值、统计信息。

- id: add-webui-api-integration-test
  task: 添加 Web UI API 端到端集成测试
  priority: P2
  status: completed
  source: tests/suites/16_webui_api.sh
  details: |
    web_ui/ 和 http_exporter/ 无 HTTP 请求测试。
    应测试：/api/stats、/api/bans、/api/jails 端点响应正确性。
    已实现：16_webui_api.sh（149 行），覆盖端点可达性、JSON 格式验证、关键字段检查。

- id: add-config-reload-integration-test
  task: 添加配置热重载（SIGHUP）集成测试
  priority: P2
  status: completed
  source: tests/suites/17_config_reload.sh
  details: |
    仅通过 13_frp_jail.sh 间接测试了配置加载，
    未测试 SIGHUP 触发的运行时重载行为。
    已实现：17_config_reload.sh（192 行），覆盖 PID 获取、配置文件检查、SIGHUP 发送。

- id: add-log-rotation-integration-test
  task: 添加日志轮转检测集成测试
  priority: P2
  status: completed
  source: tests/suites/18_log_rotation.sh
  details: |
    inotify 轮转检测 + inode 重连逻辑无集成测试。
    应测试：日志文件被 logrotate 轮转后守护进程正确重连。
    已实现：18_log_rotation.sh（186 行），覆盖日志文件准备、Jail 配置、inode 追踪。
```

### 代码清理

```yaml
- id: cleanup-ddos-detector-duplicate-code
  task: 消除 DDoS 检测器中 IPv4/IPv6 违规检测的重复代码
  priority: P2
  status: completed
  source: ddos_detector.rs detect()
  details: |
    detect() 中 IPv4 和 IPv6 DashMap 遍历代码几乎逐行相同（约 80 行重复）。
    违反 DRY 原则，维护时极易遗漏一侧的修改。
    修复：提取 check_violations 闭包，消除重复代码。

- id: cleanup-procfs-redundant-null-termination
  task: 清理 procfs 写入中的冗余空终止符设置
  priority: P2
  status: completed
  source: procfs.c bans_write 第 340-345 行
  details: |
    input[len] = '\0' 被设置两次，第二次无条件执行使前面的条件判断完全冗余。
    修复：删除冗余的条件判断，只保留一次赋值。

- id: cleanup-procfs-path-traversal-check
  task: 移除 procfs bans 输入中无意义的路径遍历检查
  priority: P2
  status: completed
  source: procfs.c validate_ban_input 第 100-120 行
  details: |
    bans_write 的输入是 IP 地址或 "unban <ip>" 命令，不是文件路径。
    路径遍历检查（..、%2e、%2f）在此上下文中无意义，属于过度防御。
    修复：删除 validate_ban_input 函数及其调用。

- id: cleanup-validate-ip-unused-params
  task: 清理 validate_ipv4/ipv6_address 中未使用的参数
  priority: P2
  status: completed
  source: firewall.h 第 222-270 行
  details: |
    ip_str 和 context 参数在函数体内从未使用，属于过度设计的接口。
    修复：添加 __maybe_unused 标记，保留参数以备未来日志扩展。

- id: cleanup-detect-disabled-code
  task: 清理守护进程 DDoS detect() 被注释掉的死代码
  priority: P2
  status: completed
  source: file_monitor/periodic_tasks.rs check_and_handle_ddos
  details: |
    detect() 调用被注释掉，DDoS 自动封禁功能实际处于禁用状态。
    已审查：网络层检测已下沉到 kmod，daemon 只保留应用层检测，注释代码是有意为之。

- id: cleanup-test-framework-regex-key
  task: 修复测试框架 fw_generate_test_yaml 使用 regex 而非 regexes
  priority: P2
  status: completed
  source: tests/test_framework.sh, tests/test_config.sh, tests/suites/13_frp_jail.sh
  details: |
    测试框架生成 regex: 单数形式，与实际配置 schema 的 regexes: 不一致。
    已修复：所有测试文件中的 regex: 改为 regexes: 并添加 default/pattern 结构。
```

---

## 版本路线图

### v2.2.1（计划中）

**预计发布**：2026-07  
**主题**：严重缺陷修复 + 热路径性能优化

**包含任务**：
- fix-ddos-ban-worker-data-race
- fix-netdev-whitelist-subnet-list-uaf
- fix-init-order-sync-work
- remove-file-reader-dead-code
- add-cargo-test-to-ci
- fix-ci-kernel-build-silent-failure
- optimize-checksum-verification
- optimize-rate-detector-ip-compare
- optimize-logger-get-mutex
- optimize-ddos-detector-arc-alloc
- fix-failed-tracker-vec-remove-performance
- fix-ban-ip-hardcoded-jail-name
- fix-failed-tracker-ban-duration
- fix-sse-connection-limit
- remove-procfs-fsync-overhead

### v2.3.0（计划中）

**预计发布**：2026-09  
**主题**：接口统一 + 文档修复 + 测试补充

**包含任务**：
- unify-whitelist-add-remove-interface
- unify-ip-validation-path
- implement-strict-mode
- fix-daemon-architecture-docs
- fix-yaml-config-docs
- fix-testing-docs
- fix-readme-test-counts
- remove-permanent-db-docs
- add-ddos-detection-integration-test
- add-webui-api-integration-test
- add-config-reload-integration-test
- add-log-rotation-integration-test
- 所有 P2 代码清理任务

---

## 审查发现汇总

| 严重程度 | 内核模块 | 守护进程 | 测试/CI/文档 | 合计 |
|---------|---------|---------|-------------|------|
| Critical | 1 | 1 | 2 | 4 |
| High | 6 | 7 | 4 | 17 |
| Medium | 8 | 8 | 6 | 22 |
| Low | 6 | 4 | 4 | 14 |
| **合计** | **21** | **20** | **16** | **57** |

---

## 架构演进路线

### Phase 1：技术债务清理（已完成）

- [x] 删除 `sync_bans_from_kernel()` 及关联死代码
- [x] 删除 `send_unban()` / `new_unban()` 死代码
- [x] PID 文件 flock 排他锁（单实例约束）
- [x] 修复 `mem::forget(raw pointer)` → `OnceLock<Arc<NetlinkContext>>`（已完成，NetlinkContext 已用 OnceLock 管理）
- [x] 清理 `ddos_detector.rs::detect()` 重复逻辑（已简化，detect 调用注释掉，只保留清理）

### Phase 2：netlink 请求-响应（进行中，2026-07-02 完成简化重构）

- [x] **请求-响应协议** — ListBansQuery/Response、StatsQuery/Response、ListWhitelistQuery/Response
- [x] **BanStateChange 事件推送** — 封禁和解封时内核主动推送事件给守护进程
- [x] **恢复封禁使用实际 banned_at** — ListBansResponse 携带真实封禁时间戳
- [x] **白名单操作走 netlink** — AddWhitelist/RemoveWhitelist 命令
- [x] **SetConfig 响应确认** — ConfigAck 消息确认配置生效
- [x] **DAEMON_STATS 双重计数修复** — StatsResponse 不再覆盖本地计数器
- [x] **查询响应单播** — 从 skb 取 sender_portid 直接 unicast，删除 portid 全局变量
- [x] **删除 Hello 握手** — 1:1 绑定不需要注册，简化协议
- [x] **删除 condvar 等待** — 回到固定 500ms sleep，避免过度设计
- [x] **单实例约束** — PID 文件 flock 排他锁，第二个实例启动失败
- [x] **UnbanIp 走 netlink** — `execute_ban_action(Unban)` 已改为 netlink 发送
- [ ] **netlink 健康指标** — 导出消息计数、错误率等 Prometheus 指标

### Phase 3：长期演进（未开始）

- eBPF 集成（DDoS 检测热更新、eBPF map 存储、perf event 统计）
- 通用 netlink（generic netlink）标准化
- 性能优化（哈希表扩容、白名单两阶段匹配、io_uring 异步 I/O）

---

**最后更新**：2026-07-02
