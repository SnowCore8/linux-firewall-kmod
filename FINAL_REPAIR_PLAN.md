# 最终修复计划：系统化全面检查

**审计时间**: 2026-06-13
**审计方式**: 4 个并行探索 Agent（并发安全 / 错误处理 / 配置 API / 数据流完整性）
**审计范围**: `src/daemon/` 下 14 个 Rust 文件 + `grafana/` 配置

---

## 一、问题汇总

| 严重程度 | 数量 | 需立即修复 |
|----------|------|-----------|
| 🔴 Critical | 2 | 是 |
| 🟠 High | 4 | 是 |
| 🟡 Medium | 7 | 计划内 |
| 🟢 Low | 8 | 可选 |
| **合计** | **21** | **6** |

---

## 二、Critical 级别（必须立即修复）

### C-1: monitor_loop 日志轮转死锁
- **文件**: `file_monitor.rs:690-714`
- **发现者**: Agent 1（并发安全）
- **描述**: 持有 `INOTIFY_FD` 写锁（line 690）+ `FILE_STATES` 读锁（line 697）时调用 `handle_log_rotation`，后者尝试获取 `FILE_STATES` 写锁（line 579）和 `INOTIFY_FD` 写锁（line 586）。`parking_lot::RwLock` 不可重入，同线程读锁→写锁永久死锁。
- **触发条件**: 日志轮转产生 `DELETE` / `MOVED_FROM` inotify 事件时必定触发。
- **影响**: 主循环永久挂起，守护进程完全停止工作。
- **修复方案**:
```rust
// 1. 将 INOTIFY_FD 锁作用域缩小到仅 read_events，事件拷贝出来后立即释放
let events_buf = {
    let mut collected = Vec::new();
    if let Some(inotify) = INOTIFY_FD.write().as_mut() {
        let mut buf = [0u8; 4096];
        if let Ok(events) = inotify.read_events(&mut buf) {
            collected.extend(events);
        }
    }
    collected
}; // ← INOTIFY_FD 写锁在此释放

// 2. 事件分发前释放 FILE_STATES 读锁
for event in &events_buf {
    // 处理事件时不持有任何外层锁
    // handle_log_rotation 内部自行获取所需的写锁
}
```

### C-2: DDoS detect() violation_count 修改丢失
- **文件**: `ddos_detector.rs:174, 201`
- **发现者**: Agent 1 + Agent 4（双重确认）
- **描述**: `.cloned()` 创建 HashMap 条目副本，在副本上 `violation_count += 1`，副本在作用域结束后丢弃。原始 map 中 `violation_count` 永远为 0，`auto_ban_threshold` 比较永远基于 1，DDoS 自动封禁功能**完全失效**。
- **影响**: DDoS 攻击时不会触发自动封禁，安全防护形同虚设。
- **修复方案**:
```rust
// 两阶段：先读锁收集违规 IP，再写锁更新 violation_count
let mut violations: Vec<(String, String)> = Vec::new(); // (ip, event_type)
{
    let entries = self.entries.read();
    for entry in entries.values() {
        let conn_rate = entry.conn_count as f64;
        if conn_rate > config.per_ip_conn_rate as f64 {
            violations.push((entry.ip.clone(), "conn_rate".to_string()));
        }
        // 同样检查 fail_rate...
    }
}
// 写锁下更新
{
    let mut entries = self.entries.write();
    for (ip, event_type) in &violations {
        if let Some(entry) = entries.get_mut(ip) {
            entry.violation_count += 1;
            if entry.violation_count >= config.auto_ban_threshold {
                // 生成 DdosEvent, action_taken = "ban"
            }
        }
    }
}
```

---

## 三、High 级别（必须尽快修复）

### H-1: Prometheus Label 注入
- **文件**: `http_exporter.rs:203-209`
- **发现者**: Agent 3（配置 API）
- **描述**: Per-jail metrics 的 `jail` label 值直接插入 `jail_name`，未转义 `\` `"` `\n`。攻击者可通过构造含 `"` 的 jail 名称注入任意 Prometheus 指标行。
- **修复方案**:
```rust
fn escape_prometheus_label(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
}
// 所有 label 值通过此函数转义后再插入
```

### H-2: duration_since(UNIX_EPOCH).unwrap() 全局时间源 panic
- **文件**: `failed_tracker.rs:35`（`now_secs()` 函数）
- **发现者**: Agent 2（错误处理）
- **描述**: 系统时钟早于 1970-01-01 时（嵌入式设备 RTC 未同步）`.unwrap()` 会 panic。`now_secs()` 是所有时间戳的源头，影响 `count_recent`、`handle_failed_attempt_for_jail` 等关键路径。
- **修复方案**: 全局替换 `.unwrap()` → `.unwrap_or_default()`

### H-3: ips_banned 计数器双重累加
- **文件**: `ban.rs:631, 703`
- **发现者**: Agent 4（数据流完整性）
- **描述**: `ban_ip_with_history()` 先调 `ban_ip()` → `execute_ban_action()` → `log_ban_action()` 已累加 `DAEMON_STATS.ips_banned`，然后在 line 631 再次累加。Prometheus 指标 `firewall_daemon_ips_banned_total` 翻倍。
- **修复方案**: 删除 line 631 和 line 703 的重复 `fetch_add`

### H-4: JSON API 响应注入
- **文件**: `http_exporter.rs:468-479, 492-500`
- **发现者**: Agent 3（配置 API）
- **描述**: `generate_bans_json()` 和 `generate_jails_json()` 使用 `format!` 手动拼接 JSON，未转义 `jail_name`。含 `"` 的 jail 名称会破坏 JSON 结构。
- **修复方案**: 使用 `serde_json::json!` 宏序列化，或手动转义

---

## 四、Medium 级别（计划内修复）

| 编号 | 文件 | 描述 | 修复方案 |
|------|------|------|---------|
| M-1 | `http_exporter.rs:366` | `(now - last)` 时间戳下溢，NTP 回调导致永久锁定 | 改用 `now.saturating_sub(last)` |
| M-2 | `failed_tracker.rs:239-264` | 封禁失败只记 `"IP 封禁失败"`，丢失 `Err` 详情 | `match` + 日志记录 `error` |
| M-3 | `types.rs:478-498` | `ActiveBanCache` insert/remove 锁顺序不一致（ABBA） | 统一先 `bans` 后 `by_jail` |
| M-4 | `logger.rs:39` | `GLOBAL_LOGGER` 用 `std::sync::Mutex` 可中毒 | 替换为 `parking_lot::Mutex` |
| M-5 | `config_parser.rs:481` | `ddos.check_interval: 0` 未验证，导致 CPU 100% | 添加 `if v == 0 { bail!(...) }` |
| M-6 | `config_parser.rs:443` | `cleanup_interval_secs: 0` 未验证，导致 IO 耗尽 | 同上 |
| M-7 | `file_monitor.rs:818` | `uptime_seconds` 减法可能为负，`as u64` 产生极大值 | 改用 `.saturating_sub()` |

---

## 五、Low 级别（可选修复）

| 编号 | 文件 | 描述 |
|------|------|------|
| L-1 | `http_exporter.rs:675-700` | `EXPORTER_RUNNING` 跨线程信号用 `Relaxed`，ARM 上可能不成立 |
| L-2 | `ban.rs:109-134` | `get_cached_bans_fd` 持锁期间执行阻塞 IO |
| L-3 | `types.rs:547-548` | `purge_expired` 同时持有两个写锁（当前为死代码） |
| L-4 | `config_parser.rs:449-457` | Writer `channel_size`/`batch_size` 零值未验证 |
| L-5 | `jail.rs:619-625` | `ban_time: 0` 仅警告不拒绝 |
| L-6 | `jail.rs:386` | 正则执行无超时保护 |
| L-7 | `ban.rs:664, 732` | `ban_ip_permanent_with_history`/`unban_ip_with_history` 死代码 |
| L-8 | `log_parser.rs:144` | `extract_ipv4()` 仅测试使用 |

---

## 六、修复优先级与排期

### P0 — 立即修复（阻塞性 Bug，影响核心功能）

| 编号 | 描述 | 预计工作量 |
|------|------|-----------|
| **C-1** | monitor_loop 日志轮转死锁 | 30 分钟 |
| **C-2** | DDoS violation_count 修改丢失 | 45 分钟 |

### P1 — 尽快修复（安全风险 / 数据错误）

| 编号 | 描述 | 预计工作量 |
|------|------|-----------|
| **H-1** | Prometheus Label 注入 | 15 分钟 |
| **H-2** | `now_secs()` unwrap panic | 10 分钟 |
| **H-3** | ips_banned 双重累加 | 5 分钟 |
| **H-4** | JSON API 响应注入 | 20 分钟 |

### P2 — 计划内修复（健壮性改进）

| 编号 | 描述 | 预计工作量 |
|------|------|-----------|
| M-1~M-7 | 7 个 Medium 问题 | 60 分钟 |

### P3 — 可选改进（代码质量）

| 编号 | 描述 | 预计工作量 |
|------|------|-----------|
| L-1~L-8 | 8 个 Low 问题 | 45 分钟 |

**总预计工作量**: ~3.5 小时

---

## 七、修复后验证方案

```bash
# 1. 编译 + 静态检查
cargo clippy --all-targets -- -D warnings

# 2. 测试
cargo test --lib

# 3. C-1 死锁验证：触发日志轮转
touch /tmp/test_rotate.log
mv /tmp/test_rotate.log /tmp/test_rotate.log.1
# 观察守护进程是否继续响应（不应挂起）

# 4. C-2 DDoS 验证：模拟高频连接
for i in $(seq 1 200); do
  echo "Failed password from 10.0.0.99" >> /var/log/auth.log
  sleep 0.01
done
# 检查 violation_count 是否正确递增
sqlite3 /var/lib/firewall/bans.db "SELECT * FROM ddos_events;"

# 5. H-1 Label 注入验证：配置含特殊字符的 jail 名称
# 在 YAML 中添加 jail: 'test"inject'
curl http://127.0.0.1:9119/metrics | grep 'jail='
# 确认 label 值被正确转义

# 6. H-3 计数器验证
# 触发一次封禁后检查
curl -u admin:pass http://127.0.0.1:9119/metrics | grep ips_banned
# 确认每次封禁只累加 1 次
```

---

## 八、无问题确认项

以下检查项经 Agent 验证**无问题**：

- ✅ SQLite 全部使用参数化查询，无 SQL 注入风险
- ✅ procfs 路径三重验证（前缀 + `..` + 字符白名单），无路径遍历
- ✅ fd 重定向防护（readlink 验证）+ O_NOFOLLOW 符号链接防护
- ✅ ReDoS 防护完整（嵌套量词 / 占有量词 / 量化交替检查）
- ✅ OnceLock 使用正确，所有 `get()` 正确处理 `None`
- ✅ `VALID_DEFAULTS_KEYS` 白名单完整，包含所有合法配置键
- ✅ HTTP API 认证保护完整（/health 跳过是有意设计）
- ✅ Prometheus HELP/TYPE 注解完整
- ✅ 启动恢复链路完整（SQLite → load_active_bans → ban_ip → cache）
- ✅ 配置热重载链路完整（SIGHUP → reload → 正则重编译 → inotify 重建）
