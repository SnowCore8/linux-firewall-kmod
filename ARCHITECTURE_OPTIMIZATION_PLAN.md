# 架构优化计划：Firewall Daemon 重构路线图

## 一、现状分析

### 1.1 代码规模统计

| 文件 | 行数 | 函数数 | 测试数 | 问题 |
|------|------|--------|--------|------|
| file_monitor.rs | 1195 | 12 | 4 | ❌ 严重超标（>300行） |
| config_parser.rs | 1102 | 8 | 19 | ❌ 严重超标 |
| http_exporter.rs | 890 | 13 | 15 | ❌ 超标 |
| ban.rs | 890 | 19 | 19 | ❌ 超标 |
| jail.rs | 884 | 19 | 15 | ❌ 超标 |
| types.rs | 857 | 20 | 0 | ❌ 超标 + 无测试 |
| sqlite_store.rs | 843 | 18 | 12 | ❌ 超标 |
| sqlite_writer.rs | 453 | 16 | 0 | ⚠️ 无测试 |
| ddos_detector.rs | 269 | 7 | 0 | ⚠️ 无测试 |
| **总计** | **8837** | - | **107** | - |

### 1.2 核心问题识别

#### 🔴 Critical 问题

1. **文件严重超标**（违反 CLAUDE.md 300 行限制）
   - 7 个文件超过 300 行
   - file_monitor.rs (1195行) 超标 4 倍
   - config_parser.rs (1102行) 超标 3.7 倍

2. **单一职责违反**
   - `file_monitor.rs` 混合：文件监控 + 行处理 + 日志轮转 + 主循环 + 配置重载
   - `types.rs` 包含 18 个不同类型的定义（Jail/Config/Ban/Stats/DDoS）
   - `ban.rs` 混合：fd 缓存 + IP 验证 + procfs 安全 + 封禁操作
   - `sqlite_store.rs` 混合：连接管理 + 永久封禁 + 统计查询

3. **测试覆盖缺失**
   - types.rs: 0 测试（但包含大量逻辑）
   - sqlite_writer.rs: 0 测试（但包含关键持久化逻辑）
   - ddos_detector.rs: 0 测试（但包含安全关键逻辑）
   - main.rs: 0 测试（启动恢复逻辑未测）

#### 🟠 High 问题

4. **unwrap 泛滥**（130+ 处）
   - sqlite_store.rs: 43 次 unwrap
   - config_parser.rs: 28 次 unwrap
   - http_exporter.rs: 19 次 unwrap
   - 这些都是潜在 panic 点

5. **全局状态过多**
   - file_monitor.rs: 4 个 `pub static` 变量
   - types.rs: 多个全局 `OnceLock` 和 `AtomicBool`
   - 难以测试，难以推理并发

6. **并发模型复杂**
   - 混合使用 `RwLock`、`Mutex`、`AtomicBool`、`AtomicU64`、`OnceLock`
   - 锁顺序不一致（已修复 M-3，但架构层面仍有风险）
   - 缺乏统一的并发策略

#### 🟡 Medium 问题

7. **错误处理不统一**
   - 部分使用 `anyhow::Result`
   - 部分使用自定义错误类型
   - 错误上下文信息不完整

8. **配置管理复杂**
   - config_parser.rs 1102 行，逻辑复杂
   - 配置验证分散在多处
   - 默认值应用逻辑不清晰

---

## 二、优化目标

### 2.1 短期目标（3-6 个月）

- ✅ 所有文件 ≤ 300 行
- ✅ 每个模块单一职责
- ✅ 关键路径测试覆盖 ≥ 80%
- ✅ unwrap 使用 < 20 处（仅限已证明安全的位置）
- ✅ 统一错误处理策略

### 2.2 中期目标（6-12 个月）

- ✅ 减少全局状态 50%
- ✅ 引入依赖注入
- ✅ 并发模型简化
- ✅ 配置热重载改进

### 2.3 长期目标（12+ 个月）

- ✅ 考虑 async/await 改造
- ✅ 插件化架构
- ✅ 性能基准测试套件

---

## 三、重构路线图

### Phase 1: 紧急拆分（优先级：🔴 Critical，预计：4 周）

**目标**：将超标文件拆分到 300 行以内

#### 1.1 file_monitor.rs 拆分（1195 → 4×~300）

```
file_monitor.rs (1195)
├── file_monitor.rs (~300) - 主循环 + 公共 API
├── line_processor.rs (~250) - 行处理逻辑
│   ├── process_single_line
│   ├── process_lines_in_buffer
│   ├── store_partial_line
│   └── flush_partial_line
├── log_rotation.rs (~200) - 日志轮转检测
│   ├── handle_log_rotation
│   └── check_for_new_log_files
└── config_reloader.rs (~250) - 配置热重载
    ├── reload_configuration
    └── cleanup_partial_line_buffer
```

**关键**：提取 `FileState` 和相关全局状态到独立的 `file_state.rs`

#### 1.2 types.rs 拆分（857 → 5×~170）

```
types.rs (857)
├── types/mod.rs (~50) - 模块导出
├── types/jail.rs (~150) - Jail + RegexInfo + FailedEntry
├── types/config.rs (~200) - Config + 所有配置结构体
├── types/ban.rs (~150) - BanInfo + BanReason + BanStatus + ActiveBanCache
├── types/stats.rs (~150) - DaemonStats + JailStatsCounters + 快照结构体
└── types/ddos.rs (~150) - DdosConfig + ConnRateEntry + DdosEvent + DdosStats
```

#### 1.3 ban.rs 拆分（890 → 3×~300）

```
ban.rs (890)
├── ban/mod.rs (~50) - 模块导出 + 公共 API
├── ban/procfs.rs (~300) - procfs 安全写入
│   ├── get_cached_bans_fd / close_cached_bans_fd
│   ├── validate_procfs_path / verify_procfs_fd
│   ├── secure_procfs_write
│   └── write_to_fd
├── ban/ip_validation.rs (~200) - IP 验证
│   ├── validate_ipv4 / validate_ip
│   └── ValidatedIp 结构体
└── ban/operations.rs (~300) - 封禁操作
    ├── execute_ban_action / log_ban_action
    ├── ban_ip / ban_ip_permanent / unban_ip / unban_permanent_ip
    ├── ban_ip_with_history / ban_ip_permanent_with_history / unban_ip_with_history
    └── cleanup_expired_bans
```

#### 1.4 sqlite_store.rs 拆分（843 → 3×~280）

```
sqlite_store.rs (843)
├── sqlite/mod.rs (~50) - 模块导出
├── sqlite/connection.rs (~250) - 连接管理
│   ├── sqlite_init / sqlite_close
│   ├── get_conn / set_global_db / clear_global_db / with_global_db / get_global_db
│   ├── ensure_db_dir
│   └── init_db_schema
├── sqlite/permanent_bans.rs (~300) - 永久封禁操作
│   ├── sqlite_add_permanent_ban / sqlite_add_permanent_bans_batch
│   ├── sqlite_is_permanent_banned / sqlite_is_permanent_banned_ipv6
│   ├── sqlite_remove_permanent_ban
│   └── sqlite_load_all_permanent_bans
└── sqlite/stats.rs (~250) - 统计查询
    ├── sqlite_update_hit_stats
    ├── sqlite_get_stats
    └── sqlite_purge_deleted
```

#### 1.5 config_parser.rs 拆分（1102 → 4×~275）

```
config_parser.rs (1102)
├── config/mod.rs (~50) - 模块导出 + 公共 API
├── config/parser.rs (~300) - 配置解析
│   ├── parse_config_file / load_config_directory
│   ├── parse_config_args / parse_config
│   └── validate_yaml_keys
├── config/validator.rs (~250) - 配置验证
│   ├── validate_and_normalize_path
│   ├── config_validate
│   └── 各种验证函数
└── config/defaults.rs (~250) - 默认值应用
    ├── apply_smart_defaults_to_all / apply_smart_defaults_single
    └── 默认值逻辑
```

**Phase 1 交付物**：
- 所有文件 ≤ 300 行
- 模块职责清晰
- 现有测试全部迁移
- 无功能变更

---

### Phase 2: 测试补全（优先级：🟠 High，预计：3 周）

**目标**：关键路径测试覆盖 ≥ 80%

#### 2.1 补充单元测试

| 模块 | 当前测试 | 目标测试 | 新增重点 |
|------|---------|---------|---------|
| types.rs | 0 | 15 | BanInfo/ActiveBanCache 操作 |
| sqlite_writer.rs | 0 | 12 | 定时器同步 + 批量写入 |
| ddos_detector.rs | 0 | 10 | 速率检测 + 阈值判断 |
| main.rs | 0 | 5 | 启动恢复逻辑 |
| **总计** | **107** | **149** | **+42** |

#### 2.2 集成测试

新增 `tests/` 目录：

```
tests/
├── integration_test.rs - 端到端测试
│   ├── test_full_ban_cycle
│   ├── test_config_reload
│   └── test_ddos_detection
├── persistence_test.rs - 持久化测试
│   ├── test_ban_recovery
│   ├── test_stats_persistence
│   └── test_cleanup_retention
└── concurrency_test.rs - 并发测试
    ├── test_concurrent_bans
    ├── test_config_reload_during_ban
    └── test_ddos_detection_under_load
```

**Phase 2 交付物**：
- 149 个单元测试
- 10+ 个集成测试
- 测试覆盖率报告

---

### Phase 3: 错误处理改进（优先级：🟡 Medium，预计：2 周）

**目标**：unwrap 使用 < 20 处

#### 3.1 统一错误类型

```rust
// src/daemon/error.rs
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("配置错误: {0}")]
    Config(String),
    
    #[error("数据库错误: {0}")]
    Database(#[from] rusqlite::Error),
    
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("封禁失败: {ip} - {reason}")]
    BanFailed { ip: String, reason: String },
    
    #[error("DDoS 检测错误: {0}")]
    DdosDetection(String),
}

pub type Result<T> = std::result::Result<T, DaemonError>;
```

#### 3.2 逐步替换 unwrap

**优先级**：
1. 生产代码中的 unwrap（Critical）
2. 热路径中的 unwrap（High）
3. 测试代码中的 unwrap（Low，可接受）

**策略**：
- 使用 `?` 操作符透传错误
- 使用 `.unwrap_or_default()` 处理可恢复错误
- 使用 `.expect("详细原因")` 替代无信息的 `.unwrap()`
- 添加错误上下文：`.context("操作描述")?`

**Phase 3 交付物**：
- 统一错误类型
- unwrap 从 130+ 减少到 < 20
- 错误日志改进

---

### Phase 4: 并发模型简化（优先级：🟡 Medium，预计：3 周）

**目标**：减少全局状态 50%，简化并发模型

#### 4.1 引入应用状态结构体

```rust
// src/daemon/state.rs
pub struct DaemonState {
    pub config: Arc<RwLock<Config>>,
    pub ban_cache: Arc<ActiveBanCache>,
    pub jail_stats: Arc<RwLock<HashMap<String, JailStatsCounters>>>,
    pub ddos_tracker: Arc<ConnRateTracker>,
    pub sqlite_db: Arc<SqliteDb>,
}

impl DaemonState {
    pub fn new(config: Config, sqlite_db: Arc<SqliteDb>) -> Self {
        // 集中初始化所有状态
    }
}
```

#### 4.2 减少全局 static

**当前**：
```rust
pub static FILE_STATES: RwLock<Vec<FileState>> = RwLock::new(Vec::new());
pub static INOTIFY_FD: RwLock<Option<Inotify>> = RwLock::new(None);
pub static ACTIVE_BAN_CACHE: OnceLock<ActiveBanCache> = OnceLock::new();
pub static JAIL_STATS: OnceLock<RwLock<HashMap<...>>> = OnceLock::new();
```

**目标**：
```rust
// 所有状态集中在 DaemonState 中
pub struct DaemonState {
    pub file_states: RwLock<Vec<FileState>>,
    pub inotify_fd: RwLock<Option<Inotify>>,
    pub ban_cache: ActiveBanCache,
    pub jail_stats: RwLock<HashMap<String, JailStatsCounters>>,
    // ...
}
```

#### 4.3 统一锁策略

**规则**：
1. 锁顺序：`DaemonState.config` → `ban_cache` → `jail_stats` → `file_states`
2. 禁止在持锁时执行 IO
3. 使用 `parking_lot` 替代 `std::sync`（已完成 M-4）
4. 所有 `AtomicBool` 用于控制流的使用 `SeqCst`

**Phase 4 交付物**：
- DaemonState 结构体
- 全局 static 减少 50%
- 锁顺序文档化
- 并发测试通过

---

### Phase 5: 配置管理改进（优先级：🟢 Low，预计：2 周）

**目标**：简化配置解析，改进热重载

#### 5.1 配置分层

```rust
// src/config/mod.rs
pub struct Config {
    pub base: BaseConfig,        // 基础配置（jail 默认值）
    pub jails: Vec<JailConfig>,  // Jail 配置
    pub storage: StorageConfig,  // 存储配置
    pub ddos: DdosConfig,        // DDoS 配置
    pub metrics: MetricsConfig,  // Metrics 配置
}

// 每个子配置独立验证
impl BaseConfig {
    pub fn validate(&self) -> Result<()> { ... }
}
```

#### 5.2 配置验证器

```rust
// src/config/validator.rs
pub struct ConfigValidator {
    validators: Vec<Box<dyn Fn(&Config) -> Result<()>>>,
}

impl ConfigValidator {
    pub fn new() -> Self {
        Self {
            validators: vec![
                Box::new(validate_jails),
                Box::new(validate_storage),
                Box::new(validate_ddos),
                Box::new(validate_metrics),
            ],
        }
    }
    
    pub fn validate(&self, config: &Config) -> Result<()> {
        for validator in &self.validators {
            validator(config)?;
        }
        Ok(())
    }
}
```

**Phase 5 交付物**：
- 配置分层
- 验证器模式
- 配置热重载改进

---

## 四、风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 大规模重构引入回归 | High | 每个 Phase 独立分支，充分测试后合并 |
| 测试覆盖不足 | High | Phase 2 优先补全测试 |
| 并发模型变更引入死锁 | Critical | Phase 4 前完成并发测试套件 |
| 性能退化 | Medium | 添加性能基准测试，对比重构前后 |
| 团队适应成本 | Medium | 渐进式重构，每个 Phase 独立交付 |

---

## 五、时间线

```
Month 1-2: Phase 1（紧急拆分）
  Week 1-2: file_monitor.rs + types.rs 拆分
  Week 3: ban.rs + sqlite_store.rs 拆分
  Week 4: config_parser.rs 拆分 + 集成测试

Month 3: Phase 2（测试补全）
  Week 5-6: 单元测试补全
  Week 7: 集成测试
  Week 8: 覆盖率报告 + 性能基准

Month 4: Phase 3（错误处理）
  Week 9-10: 统一错误类型
  Week 11: unwrap 替换
  Week 12: 错误日志改进

Month 5-6: Phase 4（并发模型）
  Week 13-15: DaemonState + 全局状态迁移
  Week 16-17: 锁策略统一 + 并发测试
  Week 18: 性能优化

Month 7: Phase 5（配置管理）
  Week 19-21: 配置分层 + 验证器
  Week 22-23: 热重载改进
  Week 24: 文档 + 发布准备
```

---

## 六、成功标准

### Phase 1 完成标准

- [ ] 所有文件 ≤ 300 行
- [ ] 107 个现有测试全部通过
- [ ] 无功能变更（纯重构）
- [ ] 代码审查通过

### Phase 2 完成标准

- [ ] 149 个单元测试全部通过
- [ ] 10+ 个集成测试全部通过
- [ ] 关键路径测试覆盖率 ≥ 80%
- [ ] 测试覆盖率报告生成

### Phase 3 完成标准

- [ ] unwrap 使用 < 20 处
- [ ] 统一错误类型 DaemonError
- [ ] 错误日志包含完整上下文
- [ ] 无 panic 路径（除已证明安全的）

### Phase 4 完成标准

- [ ] 全局 static 减少 50%
- [ ] DaemonState 集中管理状态
- [ ] 锁顺序文档化
- [ ] 并发测试套件通过

### Phase 5 完成标准

- [ ] 配置分层清晰
- [ ] 验证器模式实现
- [ ] 配置热重载稳定
- [ ] 文档完整

---

## 七、下一步行动

**立即行动**（本周）：
1. 创建 `refactor/phase1-module-split` 分支
2. 开始 file_monitor.rs 拆分
3. 建立基准测试套件

**短期行动**（本月）：
1. 完成 Phase 1 所有拆分
2. 开始 Phase 2 测试补全
3. 建立代码审查流程

**中期行动**（3 个月内）：
1. 完成 Phase 1-3
2. 建立性能基准
3. 准备 Phase 4 并发模型改造

---

## 八、参考资源

- CLAUDE.md - AI Agent 行为规范
- FINAL_REPAIR_REPORT.md - 已修复问题报告
- Rust API Guidelines - https://rust-lang.github.io/api-guidelines/
- Rust Error Handling - https://doc.rust-lang.org/book/ch09-00-error-handling.html
