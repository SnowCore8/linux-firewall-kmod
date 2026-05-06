# Changelog

所有重要的项目变更记录都在此文件中。

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