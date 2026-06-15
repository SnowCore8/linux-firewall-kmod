# Changelog

所有重要的项目变更记录都在此文件中。

## [Unreleased] - C→Rust 翻译 + 二进制优化 + CI 升级（v2.2.1）

### 新增
- **`make install` 自动化改进** - install 目标添加 build 依赖，`make clean && make install` 一步完成，无需手动 `make build`
- **安装流程标准化** - 新增 `install-verify` 目标，安装后自动验证关键组件（内核模块、守护进程、配置文件、状态目录、systemd 服务）
- **安装错误处理增强** - 关键步骤（daemon 启动、文件安装）失败时显式报错，不再静默忽略；服务启动检查验证 daemon 是否真正运行
- **安装完成提示优化** - 提供清晰的后续步骤（查看日志、检查状态），DESTDIR 模式下提示手动启用服务
- **守护进程 C→Rust 翻译** - 守护进程从 C 翻译为 Rust，58 个源文件，行为与 C 版严格等价。107 项集成测试以 `RUST=1` 全过，108 Rust 单元测试全过。Makefile 默认 `RUST=1`
- **`[profile.dev-with-debug]`** - 现场 crash 调试用 release 副本：32MB 带 DWARF + 符号表，配 `lto=true + opt-level=2`（继承 release），`addr2line` 可反推栈
- **`[profile.asan]`** - ASAN 内存错误检测 profile：仅 nightly 可用，检测堆/栈越界、UAF、double-free

### 变更
- **默认 release 二进制 30MB → 3.8MB（7.9× 缩）** - `Cargo.toml` 加 `lto=true + codegen-units=1 + debug=false + strip=true + panic="abort"`，消除 26MB 调试信息。`cargo build --release` 产物 3.8MB stripped
- **`build-deb.sh` 弃用 `VERSION=`** - 版本统一从 `Cargo.toml` 读取
- **`tests/run_tests.sh` 加 `source ~/.cargo/env`** - 修复 sudo 默认 `secure_path` 不含 `~/.cargo/bin` 导致 `make daemon` 报 "cargo: 没有那个文件或目录"
- **CI 工作流升级** - `代码质量检查` 步骤从 C daemon 的 `clang-format` 切换为 `cargo fmt --check` + `cargo clippy -- -D warnings`（Rust 后 `src/daemon/*.c` 已删，原 glob 报 "No such file or directory"）。CI 工作流自动 `rustup` 安装 stable toolchain
- **`tests/run_tests.sh` 加 `cargo fmt` 一次性 fix** - 翻译后 12 个 .rs 文件有 rustfmt 违规，PR 修一次后 CI 卡口生效

### 修复
- **`make deb` 目标缺失** - help 列了 `deb` 但 Makefile 无 `deb:` 规则（2026-06-11 移除后没同步 help），新增 `deb: build` 调 `./build-deb.sh`
- **`config/default.yaml` schema bug** - `permanent_db_path` / `permanent_ban_enabled` 误放顶层（`jails:` 之后），Rust parser 静默忽略，导致 systemd 模式下 `/var/lib/firewall/bans.db` 永不创建。修复：移到 `defaults:` 内部
- **`debian/control` 虚拟包声明** - 移除 `Build-Depends: linux-headers-amd64 | linux-headers-generic`（Azure 内核 apt 源中不存在），改用 `dkms` 显式依赖
- **`log::open_syslog` 参数** - `syslog` 调用从 `format_args!` 改为显式 `%s` 格式串 + NUL 结尾字面量
- **`http_exporter` 认证锁定** - `log_warn_ratelimited!` 改 `log_warn!`（原唯一外部调用点）

### 移除
- **日志限流层** - 删除 `RATELIMIT_STATE` / `RatelimitState` / `emit_ratelimited` / 4 个 `log_*_ratelimited!` 宏 / 1 个单元测试。全局 Mutex 与 60s 节流窗口不再需要，日志每条都真实 emit
- **`once_cell` 依赖** - `sqlite_store` 迁到 `std::sync::OnceLock`（Rust 1.70+）后 0 引用，删除 cargo 依赖

### 优化
- **代码质量** - 12 个 .rs 文件 `cargo fmt`（+472/-212 行），加 `cargo clippy` strict 检查后 CI 零警告
- **19 个 `unsafe` 块加 `// SAFETY:` 注释** - 涵盖 `ban.rs` (10) / `log.rs` (3) / `file_monitor.rs` (1) / `main.rs` (5)，逐块说明前置条件 / 后置不变量

### 测试
- 集成测试 **107 项**全部通过。`tests/run_tests.sh` 引入 `source ~/.cargo/env` 后 100% 可在 `sudo` 下跑通
- `cargo test --release`：**108 单元测试**全部通过
- GitHub Actions CI 全过：`代码质量检查` + `编译` + `运行测试` 三 job 全绿

### 文档
- `README.md` / `README.en.md` - 版本徽章 v2.1.1 → v2.2.0，"Python 运行时 + 依赖" 行（描述 fail2ban 不是本项目）移除
- 13 个 docs/{zh,en}/*.md - 同步 Rust daemon 描述、新 profile、`make deb` 重新可用、SAFETY 注释约定、sudo PATH 修复说明
- `CONTRIBUTING.md` - 测试数 12 套件/106 项 → 13 套件/115 项，新增 Rust unsafe SAFETY 注释约定 + Cargo release profile 章节

## v2.2.0 - 统计不变量修复与文档全面升级（2026-06-10）

### 修复
- **`/proc/firewall/stats` 重复封禁过度计数 Bug** - `__do_ban_ip_ipv4/ipv6` 在"已存在且仍有效"路径错误地既无操作又返回 0,导致上层 `__do_ban_ip` 盲目 `atomic_inc(&ban_count)` 与 `atomic_inc(&total_ban_count)`,每次重复 ban 都会污染 `total_bans`/`current_bans` 计数。修复方案:内层新增 `-EEXIST` 返回值明确区分"已有效封禁(no-op)"与"新插入"两种语义,刷新过期条目同样不再计入任一计数器(条目未离开表)。修复后统计不变量 `total_bans == current_bans + total_unbans + cleanup_expired_total` 严格成立
- **IPv6 封禁表桶错位严重 Bug** - `__do_ban_ip_ipv6` 使用 `hash_add_rcu(fw->ban_table_ipv6, &entry->hash, bkt6)`,但 `bkt6` 已是桶索引,`hash_add_rcu` 会以其为 key 重新 `hash_min` 落到错误桶,导致:(1) 重复 ban 检查失效,IPv6 表中出现 6+ 条重复条目;(2) 配对每桶锁保护的桶与实际存储桶不一致,存在 race 窗口。修复:直接用 `hlist_add_head_rcu(&entry->hash, &fw->ban_table_ipv6[bkt6])` 用已计算好的桶。IPv4 路径不受影响(其 key=ipv4,`hash_min(ipv4,...)` 巧合与 `bkt4` 一致)
- **同源 Bug 扩散修复**:
  - `state-persist.c:546` IPv6 封禁表恢复路径同样误用 `bkt6` 为 key,改为 `hlist_add_head_rcu(..., &ban_table_ipv6[bkt6])`
  - `whitelist.c:106` IPv6 白名单表使用 `hash_wl_ipv6` 结果作 key,`hash_min` 二次哈希落到错误桶,导致:(1) 重复 add 检查失效(白名单中 5 个重复 ::1);(2) netfilter 热路径查找 miss(白名单保护可能失效)。修复:改用 `hlist_add_head_rcu(..., &whitelist_table_ipv6[bkt])`
- **`fw_flush_cpu_stats()` 冗余调用** - `cleanup_expired_bans` 入口与 `cleanup_timer_callback` 在同一 tick 内先后各调用一次,合并为单次
- **`cleanup_last_bucket_ipv4/ipv6` 缺内存屏障** - 加 `READ_ONCE`/`WRITE_ONCE` 防御未来并发读取场景下的撕裂读
- **`atomic_t` 格式符误用** - `procfs.c` 中 `atomic_read` 结果用 `%u` 显示,改用显式 `(unsigned int)` 强转避免有符号/无符号误用

### 代码质量
- **`stats_show` 文档化** - 补充 `packets_dropped`/`packets_accepted` 统计范围注释(分片/非法源 IP 不计入)
- **统计不变量入代码注释** - `__do_ban_ip_ipv4/ipv6` 函数级注释记录 `total_bans == current_bans + total_unbans + cleanup_expired_total` 契约
- **运行时守护 `WARN_ON_ONCE`** - `cleanup_expired_bans` 末尾每秒检测不变量,采用 `±MAX_BAN_ENTRIES` (4096) 容差避免高并发误报,任何计数漂移超阈值即打印 backtrace + delta
- **API 一致性收敛** - `ban-manager.c`/`whitelist.c`/`state-persist.c` 所有桶插入统一改用 `hlist_add_head_rcu(node, &table[bkt])` 直写预计算桶,彻底消除 `hash_add_rcu(table, node, KEY)` API 误用面(IPv4 路径此前为"巧合正确",重构风险高)

### 测试
- **回归测试 03.5** - 验证 IPv4 重复 ban 3 次后 `total_bans`/`current_bans` 仅 +1
- **回归测试 03.6** - 验证 IPv6 重复 ban 3 次后 `total_bans`/`current_bans` 仅 +1(覆盖 `__do_ban_ip_ipv6` 路径)
- **测试 04.3 增强** - 验证 `whitelist_rejects` 计数器在白名单保护下正确递增
- **测试 04.2/12.5 鲁棒性提升** - 在白名单容量(64/64)满的测试环境下优雅跳过而非失败
- **测试框架加固** - `fw_assert_ip_not_banned` 改用 `grep -qF` 固定字符串匹配,避免 IPv6 展开形式(`0000:0000:...`)中的"0.0.0.0"子序列被正则元字符 `.` 误命中
- **守恒律实测** - 模块重载后立即满足 `0=0+0+0`,操作后保持平衡
- **压力与并发测试** - 通过套件 07(并发 4/4)与套件 08(压力 5/5),`WARN_ON_ONCE` 在压力下无误报

### 文档
- **`docs/{en,zh}/configuration/procfs.md`** - 统计接口从 5 字段文档更新到完整 12 字段,补充不变量说明
- **`docs/{en,zh}/operations/monitoring.md`** - 补充缺失的 8 个 Prometheus 指标映射

### 安全修复
- **守护进程 9 项中高危代码缺陷修复** - 包括 pthread_rwlock 自死锁、分离线程无法 join、Use-After-Free 竞态、clone_jail 失败路径状态不一致、严格模式静默失效、procfs 写入长度限制过松、strtoul 无 errno 检查、Base64 解码越界风险、strdup OOM 未处理
- **procfs 接口输出统一为英文** - 修复国际化兼容性问题

### 代码质量
- **内核模块统一命名** - 模块名称统一为 `firewall`，移除 `firewall_mod` 历史遗留
- **SQLite 数据持久性增强** - `synchronous=FULL` 模式确保断电后数据不丢失
- **Prometheus Basic Auth 认证** - 支持 `metrics_username` / `metrics_password` 配置，防止未授权访问

### 测试
- **测试框架全面重构** - 新增 15+ 共享辅助函数，12 个测试套件全部重构，消除大量重复代码
- **YAML 配置测试** - 12/12 配置文件审查通过
- **测试结果**: 94/94 通过（100% 通过率），0 失败

## v2.1.1 - 配置加载修复与 CI 质量提升（2026-05-07）

### 修复
- **回环地址白名单自动发现** - 移除 `auto_discover_system_ips` 中的 `IFF_LOOPBACK` 跳过逻辑，`validate_ipv4_address` 添加 `allow_loopback` 参数区分封禁和白名单场景
- **配置目录加载 jail 覆盖问题** - `load_config_directory` 改为解析到临时配置后累加 jail，修复 `parse_config_file` 重置 `jail_count` 导致只保留最后一个文件的问题
- **同名 jail 检测** - 采用"后到优先"策略，避免重复监控和封禁
- **YAML 配置文件正则引号** - 修复 mysql/postfix/frp/vsftpd 四个配置文件的单引号转义问题，改为双引号使 PCRE2 正确编译
- **deb 包卸载脚本** - postrm 脚本正确卸载 `firewall` 内核模块

### 代码质量
- **clang-format 集成** - 添加 `format-check` 和 `format` Makefile 目标，编译前自动检查代码格式
- **代码格式修复** - 格式化 10 个源文件，消除 20+ 处 clang-format 违规，确保 CI 通过
- **内存泄漏修复** - `free_config_partial` 添加 `metrics_bind_address` 释放，`config_clone` 添加对应字段复制

### 测试
- 12/12 YAML 配置文件审查通过
- deb 包安装/卸载完整流程验证通过

## v2.1 - 安全加固与性能优化（2026-05-06）

### 严重安全修复
- **整数溢出漏洞修复** - 内核模块 `1U << 32` 未定义行为，改用 `1ULL` 确保64位运算
- **Use-After-Free 漏洞修复** - HTTP exporter 配置重载时访问已释放内存，持锁期间复制字符串到本地缓冲区
- **strncpy 缓冲区溢出修复** - procfs 接口 IP 解析添加长度验证，防止内核栈溢出
- **RCU 读取一致性修复** - 所有共享字段使用 `READ_ONCE`/`WRITE_ONCE` 防止编译器重排序和撕裂读
- **TOCTOU 竞态条件修复** - `copy_from_user` 后立即在本地副本操作，避免二次引用用户空间数据

### 并发安全增强
- **非原子字段写入修复** - `ban_time`、`unban_time`、`is_permanent` 读写端配对使用原子操作
- **白名单 RCU 竞态修复** - 白名单遍历中 `mask` 和 `ip` 字段使用 `READ_ONCE` 保护
- **配置热重载双缓冲** - 锁外解析配置，锁内仅执行指针交换，写锁持有时间从 ~340 行降至 ~50 行

### 性能优化
- **哈希表容量扩容** - `BAN_HASH_BITS` 从 10 提升到 12，封禁表容量 1024 → 4096 条目
- **白名单两阶段匹配** - 精确匹配 O(1) + 子网遍历，常见查询从 O(n) 降至 O(1)
- **SQLite prepared statement 缓存** - 缓存 9 个预编译语句，避免高频操作时重复编译 SQL
- **正则匹配移出写锁** - file-monitor 中 PCRE2 匹配在锁外执行，减少配置重载阻塞

### 代码质量改进
- **提取通用配置解析函数** - 6 个通用函数消除 60% 代码重复
- **统一 goto cleanup 模式** - 修复配置解析器内存泄漏，所有错误路径正确释放资源
- **路径验证增强** - `O_NOFOLLOW` + `/proc/self/fd/` 验证防止符号链接绕过
- **IP 解析标准化** - 使用 `inet_pton` 替代手动解析，消除边界情况遗漏
- **字符串匹配精确化** - 服务名匹配使用精确/前缀/后缀/包含模式，防止 `strstr` 误判
- **ReDoS 防护增强** - 使用 `PCRE2_MATCH_LIMIT` 限制回溯次数和递归深度

### 函数重构
- 拆分 14 个超长函数为 ≤50 行子函数（`ban-manager.c` 已 100% 达标）
- 提取辅助函数：`validate_and_copy_ip`、`parse_unban_command`、`execute_permanent_ban` 等

### 测试
- 102/105 测试通过（97.1% 通过率）
- 新增并发安全测试、压力测试、永久封禁测试

## v2.0 - 严格配置校验模式（2026-05-04）

### 新增
- **严格配置校验模式**：默认启用，配置中存在未知参数或无效值时报错拒绝加载
- **`--strict` / `-s` 参数**：显式启用严格模式
- **`--permissive` / `-p` 参数**：切换为宽松模式，未知参数仅警告

### 变更
- 配置加载器增加参数白名单校验（`is_valid_defaults_key()`, `is_valid_jail_key()`）
- 所有数值参数增加严格范围校验（`max_retries: 1-100`, `findtime: 1-3600`, `ban_time: 0/1-86400` 等）
- 统一错误消息格式：`Invalid config parameter '{key}' with value '{value}' at {location}`

### 安全改进
- 防止配置拼写错误导致的安全策略遗漏（如 `max_retrys: 999` 被静默忽略）
- 配置注入防护：未知参数直接拒绝加载

## [v1.9] - 2026-05-04

### Critical 安全/并发修复
- **内核模块锁一致性** - `__do_ban_ip`/`ban_ip_with_duration` 改用 RCU 读取 whitelist，消除并发竞态
- **RCU 删除安全** - `hash_del` → `hlist_del_rcu`，防止 RCU 读取期间内存访问错误
- **状态保存/恢复** - 修复永久 ban 剩余时间下溢 + `is_permanent` 字段正确初始化
- **khash 悬空指针** - 使用 `strdup` 存储 key，销毁时正确释放，防止 use-after-free
- **配置重载并发安全** - 锁内复制数据防 use-after-free + `parse_config_file` 双缓冲模式（持锁 ~340→~50 行）
- **HTTP 线程优雅退出** - `atomic_bool` 标志控制，防止线程泄漏
- **SQLite 线程安全** - 添加 `pthread_mutex_t` 保护，防止并发数据库访问

### 代码质量改进
- 统一 IPv4 地址验证为 `validate_ipv4_address()`
- 删除无意义的 `tot_len > 0xFFFF` 检查
- 分片包添加 ratelimited 日志监控
- `secure_procfs_write` close 返回值与注释统一

### 测试
- 测试脚本路径修复：`/tmp` → `/var/log`
- 147/147 测试全部通过

## [v1.8] - 2026-05-03

### 库替换
- **HTTP 服务器 → libmicrohttpd**
  - 替换 586 行自定义 socket/select() 实现为 ~350 行 libmicrohttpd 代码
  - RFC 合规 HTTP 解析，自动处理连接管理
  - 内置连接超时和限制（MHD_OPTION_CONNECTION_TIMEOUT/LIMIT）
  - 支持 HTTPS（可选，编译时启用）
  - 移除自定义 HTTP 解析、响应构建、速率限制代码
- **POSIX Regex → PCRE2**
  - 替换 regex.h 为 libpcre2-8
  - JIT 编译支持，性能提升 2-10x
  - 内置超时机制（防 ReDoS）
  - 更好的错误信息和 Unicode 支持
  - 使用 pcre2_compile/pcre2_match/pcre2_match_data 替代 regcomp/regexec

### 代码重构
- **内核模块 Ban 函数族统一**
  - 提取 `__do_ban_ip()` 统一 ban_ip/ban_ip_permanent/ban_ip_with_duration
  - 提取 `__do_unban_ip()` 统一 unban_ip/unban_permanent_ip
  - 提取 `__find_ban_entry_rcu()` 统一 RCU 查询模式
  - firewall.c 从 2425 行减少到 2350 行（-75 行）
- **构建系统简化**
  - 单 `make` 即可编译内核模块和守护进程
  - 设置 `.DEFAULT_GOAL := all`
  - 修复内核递归 make 的 jobserver 冲突

### 测试扩展
- 修复测试套件 14-16 的路径和函数调用问题
- 总测试数量：147 项（原 113 + 修复 36 项）
- 所有测试通过，零失败

### 依赖变更
- **新增**: libmicrohttpd-dev, libpcre2-dev
- **保留**: libyaml-dev, libsqlite3-dev

## [v1.7] - 2026-05-03

### 安全加固
- **整数溢出防护** - 内核模块 ban 时间计算全面防护
  - 添加 `check_mul_overflow()` 检查所有 `seconds * HZ` 运算
  - 新增 `MAX_BAN_TIME` (365天) 和 `MIN_BAN_TIME` (30秒) 常量
  - 修复 `ban_ip()`, `ban_ip_with_duration()`, `bans_write()` 中的溢出风险
- **SQLite 安全修复** - 修复 use-after-free 漏洞
  - 所有 `SQLITE_STATIC` 替换为 `SQLITE_TRANSIENT`
  - 涉及 `sqlite_add_permanent_ban()`, `sqlite_add_permanent_bans_batch()`, `sqlite_remove_permanent_ban()`
- **路径遍历纵深防御** - 多层验证防止目录穿越
  - 扩展拒绝字符集：`|;&`$(){}<>!~*?[]`
  - 拒绝 URL 编码的遍历尝试：`%2e`, `%2f`
  - 移除 `/tmp/` 作为允许的路径前缀
  - 简化路径验证逻辑，拒绝非标准位置
- **ReDoS 防护** - 自定义 regex 安全检查
  - 拒绝嵌套量词：`)+`, `)*`, `){`, `}?`, `++`, `*+`
  - 限制交替数量：最多 50 个 `|`
  - 限制模式长度：最多 1024 字节
- **HTTP Exporter 加固**
  - 添加请求截断检测
  - 添加 URI 路径遍历防护
  - 新增 `exporter_log_warn` 宏
- **YAML 解析边界防护**
  - 单值长度限制：1024 字符
  - 保持 jail 数量限制：16 个
  - 保持日志文件限制：10 个/jail

### 部署脚本改进
- 移除硬编码默认 IP (`43.100.123.123`)
- 添加部署前确认提示
- SSH 增加 `-o StrictHostKeyChecking=accept-new`
- 统一注释为英文

### 测试
- 新增测试套件 14：整数溢出防护 (6 项测试)
- 新增测试套件 15：路径遍历防护 (6 项测试)
- 新增测试套件 16：ReDoS 防护 (7 项测试)
- 总测试数量：147 项（持续扩展）

## [v1.6] - 2026-04-22

### 新增
- **Jail 系统** - 类似 fail2ban 的多服务隔离配置
  - 每个 Jail 独立监控日志文件
  - 每个 Jail 有独立的失败计数器和封禁阈值
  - 支持最多 16 个 Jail，每个最多 10 个日志文件
  - 新 YAML 配置格式：`defaults:` + `jails:` 结构
  - 多配置文件可定义不同的 Jail，不会互相覆盖
- **安全加固**
  - 安全编译选项（-fstack-protector-strong, -D_FORTIFY_SOURCE=2, PIE）
  - systemd 服务安全加固（NoNewPrivileges=yes, ProtectSystem=strict 等 15 项）
  - 内核态 TOCTOU 竞态修复（O_NOFOLLOW + inode 一致性检查）
  - 正则匹配边界检查（防止越界读取）
  - 永久 ban 容量检查（防止拒绝服务）
- **配置热重载** - SIGHUP 信号触发完整配置重载
  - 自动清理旧 Jail 资源
  - 重新解析配置并重新设置 inotify 监控
- **SQLite 批量事务支持** - `sqlite_add_permanent_bans_batch()` 提升批量导入性能
- **HTTP exporter 改进** - 准确的 current_bans 指标（从 /proc/firewall/stats 读取）
- **代码质量**
  - 全局变量 `fw_info` 改为 static，通过 `get_fw_info()` 导出受控访问
  - 移除旧格式配置兼容代码
  - 零编译警告

### 改进
- 配置解析使用 `strsep` 替代 `sscanf`（更健壮的参数解析）
- 配置目录加载使用 `qsort` 替代冒泡排序（O(n log n) + 50 文件限制）
- `process_new_lines()` 加锁保护 Jail 配置访问（防止并发竞态）
- 正则捕获组动态检测（支持自定义正则，不再硬编码索引）
- `extract_ipv4()` 添加单词边界检查（防止误匹配如 1.2.3.4.5）

### 修复
- TOCTOU 变量遮蔽问题（`save_state_to_file()` 中 `saved_dev`/`saved_ino`）
- 配置重载内存泄漏（添加 `cleanup_all_jails()` 释放旧资源）
- HTTP exporter 错误处理（检查 `read_procfs_int()` 返回值）
- 所有 94 项测试通过

### 变更
- 配置文件格式：从旧格式迁移到 Jail 格式
- 移除旧格式配置兼容，要求显式 `jails:` 配置
- 移除内置的 vsftpd/nginx 正则模式（用户可通过自定义 regex 添加）
- `-l` 参数标记为废弃（提示使用 Jail 配置）

## [v1.5] - 2026-04-21

### 新增
- YAML 配置文件支持（替换原有的 INI 格式）
- 使用 libyaml 库进行配置解析
- 支持嵌套配置结构（log_files 数组、regex_patterns 映射）
- 配置目录自动加载功能（`-C/--config-dir`）
- 默认自动加载 `./config/` 或 `/etc/firewall/` 下所有 yaml 文件
- 多配置文件合并支持（按字母顺序加载，后加载的覆盖前面的）
- 模块化测试框架（95+ 项测试）
  - 统一测试入口 `run_tests.sh`
  - 测试框架核心 `test_framework.sh`
  - 11 个独立测试套件
  - 支持按类别运行测试
  - 支持生成测试报告
- Prometheus metrics 导出（HTTP exporter）
- frp 日志解析支持

### 改进
- 重构测试脚本为模块化框架
- 更新项目文档反映最新功能
- 更新 QWEN.md 项目上下文

### 变更
- 配置文件从 `firewall.conf` 移至 `config/default.yaml`
- 配置文件从 `firewall-frps.conf` 移至 `config/frps.yaml`
- `make test` 使用新测试框架，旧脚本保留为 `make test-legacy`
- systemd 服务文件重命名：`frps-firewall.service` → `firewall-daemon.service`（与可执行文件名保持一致，体现通用防火墙守护进程定位）

## [v1.4] - 2026-04-19

### 新增
- 哈希表优化的 IP 封禁查找（1024 容量）
- POSIX 正则表达式日志解析（减少误判 90%+）
- 自动 IP 白名单保护（自动发现系统 IP）
- 洪泛保护机制
- 综合测试套件（13 项测试覆盖）
- 配置文件支持（firewall.conf）
- 构建脚本和项目验证脚本

### 改进
- 优化 `nf_hook_func` 函数，实现快速路径
- 改进哈希表查找性能
- 优化白名单查找效率
- 优化守护进程链表操作算法
- 改进日志文件监控的 I/O 效率
- 整合项目结构为标准布局

### 修复
- 修复 `auto_discover_system_ips` 函数中的 RCU 使用问题
- 修复守护进程中 inotify 事件处理的整数溢出漏洞
- 增强 IP 地址和日志数据的验证机制
- 修复白名单子网 IP 保护功能
- 修复内存边界检查问题

### 安全
- 实现 RCU 并发机制提高安全性
- 防止整数溢出和下溢
- 强化输入验证（IP 地址、日志数据）
- 自动白名单保护防止自锁
- 数据包完整性验证
- 内存操作边界检查

## [v1.0.0] - 2026-04-19

### 新增
- 初始版本发布
- 内核模块实现（netfilter hooks）
- 用户态守护进程（日志监控）
- 通过 procfs 的 IP 封禁/解封接口
- 白名单功能