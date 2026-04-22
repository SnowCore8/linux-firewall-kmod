# Changelog

所有重要的项目变更记录都在此文件中。

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
  - systemd 服务安全加固（NoNewPrivileges=yes, ProtectSystem=strict 等 14 项）
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
- 默认自动加载 `./config/` 或 `/etc/firewall/config/` 下所有 yaml 文件
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