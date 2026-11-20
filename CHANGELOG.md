# Changelog

所有重要的项目变更记录都在此文件中。

## v2.6.0 - 2026-11-21 全栈稳定性大修（287 commits, 380 files, +34123/-3961）

本轮以 AI 协作多轮扫描驱动，系统性修复内核模块竞态、守护进程并发安全、情报源可靠性、前端实时性与 CI 门禁。DEFECTS.md 从 97 条已知缺陷归零至无已知可复现缺陷；集成测试 22 例在 QEMU + 7.0.0-43 上全过。

### 内核模块（30 commits）
- **RCU 竞态全面修复** - 封禁表摘链改用 `hlist_del_init_rcu`，到期与删除竞态堵住；清表标志用 `WRITE_ONCE/smp_mb` 发布；速率表清空不再重挂节点，分桶摘链后统一回收；自决封禁不再在软中断取休眠锁，改用 trylock 补发事件
- **IPv6 解析加固** - 扩展头解析失败时丢包避免绕过判定；分片首片仍解析传输层；AH 扩展头按 4 字节步进；悬空头与卸载竞态修复
- **IPv4 短报文不再绕过封禁与速率判定**，空设备名不再被当作自动白名单
- **封禁时长改按绝对秒记账**，并封住状态文件与白名单注入
- **容量参数拒绝超过 INT_MAX 的取值**；速率分页只采信首页全局计数
- **netlink 守护进程注册竞态修复**；多播事件广播失败累计计数并随告警输出；发送统一走发送锁
- **IP 头缓冲扩到 60 字节**；状态保存按恢复端字节预算截断
- **状态恢复守卫改用原子操作**，避免并发恢复；状态快照不可用时拒绝加载，恢复失败不再静默降级
- **动态阈值按维度生效**，无基线维度不参与判定
- **分析表满时淘汰最旧条目**
- **白名单移除路径添加 `prefix_len` 边界验证**
- **关停期 netlink 丢弃指令**，封禁时长按上限拒绝

### 守护进程核心（40+ commits）
- **并发安全** - 配置文件实例读写加进程级闸，消除重载与 API 写入的数据竞争；配置原子替换，并发局部更新不再丢字段；`jail` 统计返回结构拷贝，避免解锁后读共享对象
- **关停顺序修正** - 链路断开致命退出；封禁镜像保留 jail 与真实前缀；PID 文件校验属主存活避免多实例覆盖
- **日志轮转与采集** - 分割器按 jail 隔离，共享日志文件的第二个 jail 不再串行漏行；轮转重挂迁移全部 jail 归属，共享文件不再有一分钟监控空窗；轮转先读完旧 inode 未读尾巴不再整段丢行；`poll` 只认 `POLLIN` 并加固日志器、出口探测与清理事务
- **风险引擎** - 默认开启；缓存增加容量上限防无界 OOM；目录遍历检测改为大小写不敏感；风险向量衰减接入调度；信誉分定期回读库，失败计数按条累加
- **持久化** - 重试队列串行化，未知 op 不再永久重试；落盘失败欠账并入索引现存条目；`BatchDecayVectors` 先读完再写避免单连接死锁；调度器返回 done 通道支持优雅关停；`facts` 缓存逐出落盘移到锁外避免持锁期间 DB I/O
- **情报源熔断器** - 连续失败的情报源自动暂停刷新；源 TTL、跨源置信度与失败判定按实际生效路径修正；调度抖动夹紧到间隔一半；缓存键归一 IPv4-mapped 前缀
- **情报命中接入封禁判定** - 端口位图仅在变化时下发；并发守卫；缓存合并竞态修复；条目上限
- **DB 写入重试队列与启动同步**
- **启动时检测出厂默认口令并告警**，覆盖用户名维度

### HTTP / API（19 commits）
- **错误响应不再泄露内部路径与数据库细节**；IP 解析错误内部细节隐藏
- **配置文件更新加锁防并发覆盖**，修正同步冲突响应码
- **封禁时长超过 uint32 上限时静默回绕修复**
- **SSE 长连接写超时取消**；7 天活动行按 30 秒缓存，窗口查询失败不再把零当读数
- **解封先确认内核再撤镜像**，永久封禁不再虚报已解封
- **日志流跟随日志轮转并在生产者退出时结束连接**；跨轮持续跟随文件不再被首轮 EOF 终止
- **`ListRiskVectors` 加 LIMIT** 避免无界查询导致内存耗尽
- **推荐阈值改在子网聚合后判定**，风险事件分页下推，metrics 锁外写出
- **`jail` 名校验、DDoS 字段边界**；YAML 别名炸弹防护

### 前端（55 commits）
- **实时性** - 后台刷新不再用遮罩挡住表格点击；表格后台刷新时显示加载遮罩；实时页面数据陈旧时显示页级提示
- **封禁倒计时** - 收敛到单元级组件；本地走秒；不再短暂显示负数
- **SSE** - 达上限降级后可手动重连；`useSse` 添加卸载保护防止组件卸载后异步回调触发状态更新；重连加上限，超限后显示已断开与手动重连入口
- **命令面板** - 补齐 ARIA 活动项关联；Enter 执行与高亮项一致；底栏文案修正；快捷键标签按平台显示 Ctrl/⌘
- **登录** - 锁定计数只认 401 且到期清残留提示；登录后回到登录前页面而非固定概览
- **无障碍** - 通知行支持键盘激活；日志容器关闭读屏自动播报
- **日志流** - 暂停期间丢弃行数可见；丢弃计数改 ref 累加+定时同步；关键词输入改为受控
- **设置页** - 未保存修改时拦截离开
- **通知中心** - 清空前二次确认；清空时同步销毁残留 toast
- **其他** - 侧边栏底部展示全局热键提示；时间戳按毫秒换算；详情抽屉解封失败时不再关闭；威胁情报列表 60s 轮询；停用越狱规则前二次确认；日志页首连徽标不再显示"重连中"；异常检测数据时刻卡片防溢出；概览页小屏时网格降为单列并防溢出；Top 复发攻击源渲染错误态；智能分析页补全刷新加载反馈；威胁情报深链同步守卫可重复触发；运行时状态刷新失败时内联报错；概览卡片载入失败时显示 — 而非 0；DataTable 循环引用崩溃修复；StrictMode 重挂断流修复

### 配置校验（9 commits）
- **YAML 边界验证全覆盖** - `risk_engine` 段解析与校验补全；`webui/capacity` 段边界验证；日志文件路径校验与历史保留天数边界；威胁情报源 URL 格式校验防 SSRF；`jail` 名校验与 DDoS 字段边界
- **日志轮转和 DDoS 配置添加范围校验**
- **配置实例读写加进程级闸**

### 分析与日志（10+ commits）
- **分析** - 偶数长度数组中位数计算错误修复；IPv4 映射 IPv6 子网提取失败修复；NaN 传播、切片别名与截断偏差修复；窗口条件下推 SQL 去掉截断；趋势口径对齐契约；推荐方向与推荐值不再自相矛盾
- **日志解析** - IPv4-mapped IPv6 地址保留段/内网判定修复；日志源注册表 Iterate 深拷贝 Owners 切片
- **GeoIP** - 按 MMDB 规范解析指针与扩展类型；数据记录内指针基准跳过 16 字节分隔区
- **网络端口** - 回环变体判定与不可读套接字表修复

### CI / 构建 / 打包（12+ commits）
- **AI 协作闸门** - 分派与巡检判断脚本接入四个 AI 同事；合并交给闸门脚本判；闸门不再把自己这次运行当成还在跑的检查
- **版本门禁** - 版本探测改用 `grep -oE` 去掉 PCRE 依赖
- **DKMS** - 按目标内核编译，不再一律用运行内核头文件；多内核编译内存要求文档
- **e2e 作业安装前端依赖**；集成测试失败时输出封禁表与守护进程日志
- **覆盖率与漏洞扫描改为阻塞门禁**；测试依赖装进独立 venv
- **发布前校验门禁** - 产物带声明与校验和
- **CI 阶段串行化**

### 安全加固
- **错误响应清理内部细节** - 多处 HTTP 错误响应不再泄露内部路径、数据库细节
- **配置文件与日志文件权限收紧**
- **SSRF DNS rebinding 修复**；数据竞争与溢出崩溃修复
- **威胁情报源 URL 格式校验**防 SSRF
- **缓存合并竞态**、条目上限

### 治理与文档（40+ commits）
- **缺陷驱动开发** - DEFECTS.md 多轮迭代，从 97 条已知缺陷归零至无已知可复现缺陷；每轮修复均有对应文档登记与复核
- **行为准则、支持、治理与维护者文件补齐**
- **分支门禁描述与实际保护规则对齐**；squash-only 与自审记录写清
- **许可证统一** - 内核模块双许可 SPDX 与打包声明
- **依赖清单** - 用可核对的 Go 与前端依赖清单替换过时的 Rust 声明
- **GitBook 导航** - 补齐缺失的七篇文档
- **.editorconfig 与 .gitattributes 补齐**
- **多次依赖更新** - actions、frontend、@playwright/test、golang.org/x/sys、pytest 等

### 测试（9+ commits）
- **新增集成测试** - 认证锁定（test_23）、并发重载与封禁（test_24）
- **修复不稳定测试** - 日志解析测试改用轮询等待避免固定 sleep；集群扫描用例关闭情报源避免外部名单短路判据；`max_retries` 夹具对齐 95 上限
- **补充单元测试** - 最近 8 个修复的单元测试覆盖；关停时 DB 不可用仍落盘重试快照

### 验证
- DEFECTS.md 归零：清单清空并写明验证边界
- QEMU + 7.0.0-43-generic：22 个集成用例全过（daemon-down 全量 + daemon-up 功能用例）
- 内核模块加载、procfs 13 条目、dmesg 无异常
- 本地守护进程门禁：`gofmt -l` 为空、`go vet` 通过、`go test ./...` 全绿、`make contract-check` 通过
- 文档自检：md 文件相对链接 0 条断链


## v2.5.0 - 2026-11-06 部署流程统一

### 部署体验
- **部署入口收敛为 `scripts/deploy.sh`** - 位置参数 `<host> [user] [--mode deb|script]`，不再包一层 make 目标（make 只负责构建/打包，运维动作直接调脚本）
- **脚本参数只认显式传值** - 环境变量不再影响目标：远程用户省略即 `root`，模式省略即 `deb`；`MODE=script` 只能通过 `--mode` 指定
- **`deploy.sh` 参数校验** - 支持 `<用户@主机>` 单参数写法；位置参数写反（用户在前、主机在后）时直接报错并给出正确写法，不再拼成 `<IP>@<用户名>` 让 ssh 报 `Could not resolve hostname`
- **部署串行化** - `deploy.sh` 用 `flock` 独占锁；两个部署同时重建 `build/deb` 时，先完成的那个会因产物被后者删掉而在打包末尾失败，现在第二次调用直接退出
- **守卫只认命令行授权** - 环境变量里残留的 `FIREWALL_REMOTE_DEPLOY=1` 不再能静默放行本机安装
- **`scripts/deploy.sh` 双模式合一** - `deb`（默认，DKMS 远端编译，跨内核版本可用）/ `script`（预编译 .ko，要求 vermagic 一致）。deb 模式自动安装远端 DKMS 依赖、清理脚本模式残留、同版本 `--reinstall` 强制重装、失败回滚半配置状态、正确识别 Basic 认证下的面板可达性
- **deploy.sh 改用 vermagic 校验** - 不再对比本地/远端 `uname -r`，远程编译的 .ko 也能正确放行
- **修复 `kmod-remote`** - `$$$` 变量展开吞掉 PID、rsync 缺 `--relative` 导致 `src/` 前缀丢失，产物同时写入 `firewall.ko` 标准路径
- **修复 DKMS 打包** - `build-deb.sh` 的 DKMS 源码树补上 `contract/generated/*.h`；去掉每次全量 `make clean`（改 `CLEAN=1` 按需）
- **防路径冲突** - deb postinst 清理 `/etc/systemd/system/` 脚本模式残留；deploy.sh 检测 deb 已装时询问是否卸载
- **修复 deb 装完守护进程起不来（`status=226/NAMESPACE`）** - `ProtectSystem=strict` 下 systemd 要把 `ReadWritePaths` 每一项 bind-mount 回可写，条目缺失就在 `ExecStart` 之前装配失败，守护进程没机会自行创建日志文件；`Restart=on-failure` 让它无限重启。单元去掉无人写入的 `/var/log/firewall-daemon.log`（`logger.go` 的 `defaultLogPath` 与 `config/default.yaml` 均为 `/var/log/firewall.log`），deb postinst 幂等预创建 `/var/log/firewall.log`（0640 root:adm，已存在不覆盖，避免升级清空历史日志）。放 postinst 而非 `debian/rules`：`build-deb.sh` 自行 `dpkg-deb --build`，不经 `debian/rules`，那里预创建日志文件的步骤从未执行
- **deb postinst 不再静默吞掉启动失败** - `systemctl start firewall-daemon || true` 改为启动后轮询 `is-active`，非 active 即打印 `status`/`journal` 诊断并 `exit 1`。`Type=simple` 下 `start` 在 fork 成功即返回 0、进程随后崩溃不会被发现，而沙箱装配错误又会让 `start` 直接非 0，两类都要覆盖
- **`deploy.sh` 验证步骤改为断言** - deb 的 `[4/4]`、script 的 `[5/5]` 原本只打印状态从不断言，守护进程死掉也照样输出 "Deployment complete!"。现断言 `is-active=active`、内核模块已加载、面板 9119 可达，任一不满足即输出诊断并 `exit 1`（script 模式由此触发既有 ERR trap 回滚）；面板探测改为轮询，避开守护进程刚起时 HTTP 尚未监听的假失败
- **`make install` 同步补上日志文件创建** - 新增 `install-log` 目标，与既有 `uninstall-state` 里删除 `/var/log/firewall.log` 的动作对应（此前只删不建），纳入 `install` 聚合。DESTDIR 模式下跳过：日志文件一旦进包，每次升级 dpkg 都会用空文件覆盖掉现有日志
- **文档同步** - `docs/zh/operations/troubleshooting.md` 的 `ReadWritePaths` 取值与单元对齐，并新增 `status=226/NAMESPACE` 症状小节（区分运行期 `os error 30` 回退 stderr 继续跑、与运行前装配失败进程根本不存在）；`architecture/daemon.md`、`operations/management.md`、`operations/monitoring.md` 中残留的 `/var/log/firewall-daemon.log` 回落路径改为 `/var/log/firewall.log`

### 构建清理
- **源码 / 中间产物 / 最终产物隔离** - 内核模块改在 `build/obj/kernel-module/<kernel.release>/tree/` 的源码副本上编译（`M=` 指向副本），`src/kernel-module/` 不再产生 `.o`/`.cmd`；vite 输出改到 `build/obj/frontend/`（`emptyOutDir: true`），`make daemon` 仅在 `go build` 期间把面板临时拷入 `src/daemon/web_ui/static/` 并由 `trap` 清理，构建后源码树零残留
- **`make clean` 补全并修正** - 补清散落产物：`src/daemon/firewall-daemon`、`scripts/bench/{blast2,sink}`、`test-results/`、`playwright-report/`、`blob-report/`、`.playwright-mcp/`、`.pytest_cache/`、`__pycache__/`；不再删除入库的 `contract/generated/*` 与 `http_contract.go`（此前 clean 后工作区变脏，且 `go build` 会因缺生成文件失败）
- **`make distclean`** - 在 `clean` 基础上额外清内核中间文件、clangd 缓存 `.cache/` 与 `compile_commands.json`

### 打包（debhelper）
- **打包改由 `debian/rules` 驱动** - 真实路径从 `build-deb.sh` 手拼目录 + `dpkg-deb --build` 改为 `debian/rules` + `dpkg-buildpackage`；`build-deb.sh` 退化为薄壳：生成 `debian/changelog`、调用 `dpkg-buildpackage`、把产物从上级目录搬到 `build/deb/` 并恢复 `linux-firewall-kmod-<版本>.deb` 文件名。原 `debian/rules` 是 0644、从未被执行，且会把本机预编 `.ko` 塞进 `lib/modules/$(uname -r)/extra`（vermagic 陷阱）；现在只编守护进程
- **维护者脚本落盘到 `debian/`** - `postinst`/`prerm`/`postrm` 从 heredoc 变成真实文件。`postinst` 走 `dkms add`/`build`/`install`、加载模块、预创建 `/var/log/firewall.log`，随后由 `dh_installsystemd` 展开的片段启用并启动服务，末尾仍断言 `is-active`；`prerm` 的 rmmod 只在 remove/deconfigure 时执行
- **版本单一真相源** - `debian/changelog` 由 `CHANGELOG.md` 在构建期生成且不入库，删除过期的被跟踪文件（2.2.0-1）；`debian/compat` 由 `debhelper-compat (= 13)` 取代
- **控制文件修正** - 删除从未实现的 `linux-firewall-kmod-source` 二进制包；`dkms` 从 Build-Depends 移到运行时 Depends；`/etc` 下配置由 debhelper 自动登记为 conffiles；`/etc/firewall` 保持 0700、`*.yaml` 保持 0600（`dh_fixperms` 会放宽权限，`override_dh_fixperms` 还原）
- **升级时真正更换内核模块** - `postinst` 在 `dkms install` 前无条件卸载已加载的旧模块。此前只在「同版本残留」分支里 rmmod，版本号变化时 `lsmod` 命中会跳过 `modprobe`，新编的 `.ko` 实际不生效
- **升级时清理旧版本 DKMS 条目** - dpkg 升级会删掉旧包的 `/usr/src/linux-firewall-kmod-<旧版本>`，旧版本在 `/var/lib/dkms` 的条目却会留下悬空 `source` 链接，使 `dkms status` 与 `dkms autoinstall` 整体报错。`postinst` 现在先移除所有非当前版本的 DKMS 条目及悬空符号链接
- **构建依赖与入口同步** - `release.yml` 安装 `debhelper`，tag 版本经环境变量传入；`make deb`、本机安装守卫提示、`docs/zh/development/building.md`、`docs/zh/getting-started/installation.md` 一并更新

## [Unreleased] - 2026-11-05 公开规范整改（17 项）

全面扫描并修复 FHS 路径合规、安全加固、文档一致性、CI/CD 规范、版本号管理五个维度的不规范项。

### 安全相关（3 项）
- **明文凭据被 git 跟踪** - `config/default.yaml` 中 `metrics_username: "snow"` / `metrics_password: "9420"` 是真实凭据。清空为注释示例，引导用户使用 `/etc/firewall/credentials.env`（0600）覆盖
- **metrics_bind_address 文档默认值错误** - `docs/zh/configuration/yaml-config.md:35` 声称默认 `127.0.0.1`，实际 `config/default.yaml:13` 为 `0.0.0.0`。安全相关：用户以为只监听本地，实际暴露所有网卡。修正文档为 `0.0.0.0`
- **systemd 单元缺少安全指令** - 添加 `ProtectKernelLogs=yes`、`ProtectClock=yes`、`PrivateDevices=yes`、`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`、`UMask=0077`

### FHS 路径合规（4 项）
- **debian/rules daemon 路径错误** - `/usr/local/sbin` → `/usr/sbin`（Debian Policy 10.4）
- **debian/rules systemd 单元路径错误** - `/etc/systemd/system` → `/lib/systemd/system`（Debian Policy 9.1.1）
- **deploy.sh 硬编码路径** - `SBINDIR="/usr/local/sbin"` → `/usr/sbin`
- **service 模板默认路径** - `ExecStart=/usr/local/sbin/firewall-daemon` → `/usr/sbin`

### CI/CD 规范（3 项）
- **gofmt lint 形同虚设** - `gofmt -l` 只列文件名不返回非零码。改为 `test -z "$(gofmt -l ./cmd ./internal)"` 确保失败时步骤报错
- **CI 缺少 shellcheck** - 在 lint job 添加 `shellcheck build-deb.sh scripts/*.sh`
- **CI Go 版本未固定** - 添加 `actions/setup-go@v5` 并指定 `go-version: '1.26'`

### 版本号管理（2 项）
- **CHANGELOG 版本号不一致** - `[Unreleased]` vs README badge `v2.4.0` vs deb fallback `2.2.0`。将已合并的 `[Unreleased]` 改为正式版本号 `v2.4.0`，更新 deb fallback 到 `2.4.0`
- **build-deb.sh 版本号提取失败** - `auto_version()` 用 `grep -m1 '^## v'` 但 CHANGELOG 用 `## [Unreleased]`。改为跳过 `[Unreleased]` 取第一个带版本号的条目；支持 `VERSION_ENV` 环境变量；提升 fallback 到 `2.4.0`

### 文档一致性（5 项）
- **Node.js 版本文档错误** - `docs/zh/development/building.md:12` 写 `22`，CI 用 `24`。改文档为 `24`
- **日志文件命名不一致** - `config/default.yaml:21` 用 `firewall.log`，`src/daemon/internal/logger/logger.go:18` 默认 `firewall-daemon.log`。统一为 `firewall.log`
- **building.md 状态目录出处不精确** - "出处"列写 `STATEDIR`，但 `STATEDIR ?= /var/lib`，实际路径是 `$(STATEDIR)/firewall`。改为 `$(STATEDIR)/firewall`
- **AGENTS.md 未说明 kmod 别名** - 补充说明 `kmod` 是 `kernel-module` 的快捷别名
- **redis.yaml 注释不准确** - 智能推断值写 `max_retries=3, findtime=300, ban_time=3600`，但实际生效的是 defaults 的 3/600/900。修正注释

## v2.4.0 - 2026-10-22 凭据来源、关停刷盘、strict 贯通与两处门禁盲区

工作树里带着一份未提交的 WIP（认证凭据走环境变量），它引用了 `bindsBeyondLoopback`
却没有实现，`go build ./...` 停在 undefined——这条链从编译不过开始，把这处接完，
再补运行期三处、门禁两处。以下改动均未提交，故本轮不带提交号。

### 修复
- **组合根引用了不存在的函数** - WIP 在 `run()` 里调用 `bindsBeyondLoopback(cfg.MetricsBindAddress)`
  来决定「绑定到非回环地址又没配凭据」要不要告警，函数没有实现，整个包编译失败。
  补 `cmd/firewall-daemon/bind_address.go`：空串、`localhost`、`127.0.0.1`、`::1`、`[::1]`
  判为只在回环，`0.0.0.0`、`::`、局域网地址、主机名判为越过回环（主机名解析不了时按
  「可能对外」处理，宁可多报一条告警）。15 例表驱动测试。
- **凭据只能写在被 git 跟踪的 YAML 里** - `config/default.yaml` 入库且在公开仓库，
  把可用凭据写在那里等于把钥匙和锁一起发出去。`internal/config/credentials_env.go`
  那两个环境变量原先只是解析出来没人用：`applyEnvCredentials` 没有调用点、
  `AuthEnabled`/`CredentialSources` 没有消费者。现在覆盖发生在 YAML 应用成功之后
  （`parser.go`，所以「解析失败不改 cfg」的原子性仍然成立），`PUT /config` 写回的
  仍是 webui 段补丁、不会把环境变量值抄进配置文件。随包单元加
  `EnvironmentFile=-/etc/firewall/credentials.env`（前缀 `-`：文件缺失照常启动、
  凭据回落 YAML），`make install` 新增 `install-credentials` 目标——只准备 0600、
  属主 root 的空模板，两行键都是注释掉的，**不生成任何口令**。
  `credentialSource` 同时改掉一处误报：把环境变量显式设成空串原先报「未配置」，
  而契约的语义是「两项都空即放行」，显式设空是有意关闭认证的决定，现在报「环境变量」。
  启动日志打印两项凭据各自的来源与「认证是否启用」，永不打印值；绑定越过回环且无凭据时
  额外一条 Warn 并给出三种修法。
  **这是安全相关变更**：暴露面与凭据是否配置从此一起被报告，凭据也有了一条不入库的来源。
- **`trusted_ips` 的下发点判断错了** - 「`ClaimLease` 没报错」不等于「内核已接受注册」：
  链路超时或模块刚重载时注册只是失败，`ClaimLease` 返回 nil，组合根照旧往下走并下发白名单，
  而内核在收到 `DAEMON_REGISTER` 之前丢弃一切指令——这批地址静默不进表，续约成功也不会重发。
  现在下发挪到 `PumpDeps.OnLeaseClaimed` 回调里，由事件泵在 `register()` 确认
  `ack.Accepted` 之后触发，`sync.Once` 保证只发一次（续约不代表可以重发启动期配置）。
  回调读的是启动时复制的一份列表，不在回调里并发读 `*cfg`（热重载会替换它）。
- **关停时最后一笔信誉分会丢** - `Facts.StartFlusher` 收到 stop 信号后调 `Flush()`，
  但调用方 `defer close(dbStopCh)` 之后紧跟着 `defer db.Close()`，LIFO 顺序下库先关、
  刷盘协程还在写：`RecordFailure` 撞上已关闭的连接，那批脏账无声消失。
  `StartFlusher` 现在返回 done 通道，组合根等它关闭之后才关库
  （`persist/facts.go`、`cmd/firewall-daemon/main.go`），与 DB 自带两个调度器共用同一条 stop 通道。
- **`--no-strict` 不生效** - `Config.StrictMode` 一路被赋值、一路没人读：
  `ParseConfig` 里写死 `dec.KnownFields(true)`，未知顶层键在两种模式下都拒。
  而 `args.go` 的帮助文本、`SECURITY.md`、`docs/zh/configuration/yaml-config.md`、
  `docs/zh/getting-started/installation.md` 四处都写「加 `--no-strict` 才忽略未知字段名」。
  现在 strict 贯通到解析器与重载器（`FileReloader` 由组合根带上 `parsed.Strict`，
  SIGHUP、文件热重载、启动三条路径同一口径）。
  **这是行为变更**：照文档挂 `--no-strict` 的部署从此真的能带着未知键启动。
  随之改写一条断言：`TestUnknownFieldAlwaysRejected` 把上述坏行为当成契约（名字叫「恒被拒绝」），
  换成 `TestUnknownFieldRejectedOnlyInStrictMode` 分别验两种模式，未知键在严格模式下仍被拒。

### 变更
- **契约漂移门禁不再漏掉在模块里的那份产物** - `make contract-drift` 原先只 diff
  `contract/generated/`，而 `src/daemon/internal/httpcontract/http_contract.go` 也是生成物
  （AGENTS 明列），手改它没人查。生成器加 `--no-in-module`，把产物整体写到临时目录，
  先比 `contract/generated`（排除该 Go 文件），再单独比模块内那份，两处各报各的差异。
- **前端不再出现契约路径字面量** - `verify_http.py` 加 `check_frontend_route_literals()`：
  扫 `frontend/src` 全部 `.ts`/`.tsx`（`endpoints.ts` 与 `api/contract.ts` 除外），
  剥离注释后出现 `'/api/v1…'` 即报错；一条 `const DRIFT_PROBE = '/api/v1/probe'` 探针
  验证过它确实在拦。5 个视图/组件（`Jails.tsx`、`Whitelist.tsx`、`Settings.tsx`、
  `AnomalyPanel.tsx`、`RecidivismPanel.tsx`）改用生成的 `ROUTES` 常量。
- **netlink 的 `seq` 口径按实现改写** - `contract/netlink.fwidl` 原文让读者以为所有消息
  都按 seq 配对，实现却是两类：守护进程发起的请求用非零且唯一的 seq，应答
  （`DaemonRegisterAck`/`ConfigAck`/`STATS`/`ANALYSIS`/`LIST_*`）按 (type, seq) 配对，
  内核主动推的事件（`DdosEvent`/`BanStateChange`/`WhitelistStateChange`/`ConfigChange`/
  `CmdResult`）带内核自己的自增 seq、不参与配对。补上「seq=0 的应答是协议违例」。

### 测试
- 新增单元规格：`cmd/firewall-daemon/bind_address_test.go` 15 例（含 `[::1]`、`localhost`、
  空串、主机名）；`internal/config/credentials_env_test.go` 6 条（环境变量盖 YAML、
  显式设空即关认证、混合来源、来源标签区分显式空、回落 YAML、解析失败不改 cfg，
  夹具用 `os.Unsetenv` + `t.Cleanup` 恢复进程原值）；`internal/kernel/consumer_test.go`
  一条（接受后回调恰好一次、续约不再触发、被拒与链路失败各 0 次）；
  `internal/persist/facts_test.go` 一条（脏账只有在 done 通道关闭后才在库里可见）；
  `internal/runtime/file_reloader_test.go` 一条（非严格模式的热重载接受未知键、严格模式失败且不改 cfg）。

### 文档
- `SECURITY.md` 的认证表与「监听地址与凭据存放」补环境变量来源、`install-credentials`
  只装空模板、以及「越过回环且无凭据会进日志」这条。README 的面板段同步指向该来源。
- `docs/zh/configuration/yaml-config.md` 的凭据说明补环境变量覆盖与「显式设空 ≠ 没设」。
- `docs/zh/getting-started/installation.md` 的 `make install` 步骤从八件改九件（插入
  `install-credentials`）、位置表加凭据文件一行，并写明卸载按 `rm -rf /etc/firewall`
  连 `credentials.env` 一起删，先备份。
- `AGENTS.md` 四处：`--no-strict` 与解析器/重载器的贯通、`trusted_ips` 的下发时机改成
  「内核确认注册之后」、契约流程写明 `contract-drift` 要比两处产物与前端字面量扫描、
  netlink `seq` 口径；`jail.Finalize` 那条从「当前改动方向、未提交前以工作树为准」
  改成对现状的描述（`15357dfe` 已提交）。

### 验证与未验证
- 跑过：`go build ./...`、`go vet ./cmd/... ./internal/...`、`gofmt -l ./cmd ./internal`（空）、
  `go test ./...`（全部包 ok）、`make contract-drift`、`make contract-check`
  （三个校验器全通过，含生成物 `go build` 自检）、`tsc --noEmit`、
  `python3 -m py_compile contract/gen.py contract/verify_http.py`。
- 没跑：`make format-check`（本机无 clang-format）、`yamllint`（同上，未装）、
  `make test` 与 pytest 集成套件（需要 root 且要能 `insmod`，本轮不加载模块）、
  `npx playwright test`（依赖集成环境）。

## [Unreleased] - 2026-10-14 ~ 10-15 构建链、内核兼容、文档对齐与守护进程落地

本轮把「CI 红着但没人看得见」的几处一次性修直：CI 自 2026-09-18 后首次六任务全绿，并且第一次在能
`insmod` 的机器上真跑了集成套件。

### 修复
- **CI 编译任务：产物落点错** - `daemon` 目标先 `cd src/daemon` 再 `go build -o build/daemon/firewall-daemon`，
  相对路径按当前工作目录解析，二进制被写进 `src/daemon/build/`，仓库根的产物始终为空（`make install`、
  deb 与 CI 的产物检查都取后者）。改为 `-o $(PWD)/$(DAEMON_BIN)`。（`00f987f0`）
- **CI 编译任务：面板目标循环依赖** - `frontend` 与 `src/daemon/web_ui/static` 互为依赖，make 丢弃该依赖
  （日志 `Circular ... dependency dropped`）导致 `npm ci` 从不执行。现在面板产物目标只依赖真实输入
  （`frontend-install` + 前端源文件清单）。同时 `clean` 里的 `go clean -cached` 是非法参数，会让 `make clean`
  以 exit 2 中断，改为 `$(GOC) clean`。（`6343770`）
- **前端依赖与 JSX 运行时** - `frontend/package.json` 的 `dependencies` 整段丢失，CI 的 `npm ci` 按
  package.json 裁剪安装，react/antd-mobile 装不上；`tsconfig` 的 `jsxImportSource` 又指向自研 `@fw/jsx`
  （JSX 求值成 DOM 节点），而入口用的是 `react-dom/client`，两套类型体系对撞（本地 `tsc` 486 个错）。
  现按 package-lock 根节点补回依赖、统一到 React，并修掉被这堵墙挡住的 5 个真实类型错误。（`7b82e1c`）
- **`vite build` 会删掉 go:embed 的持有文件** - `emptyOutDir: true` 清空输出目录时连已入库的
  `src/daemon/web_ui/static/assets.go` 一起删除，随后 `go build` 因包内无 `.go` 文件失败。改为
  `emptyOutDir: false` + 构建前 `find … ! -name assets.go -delete` 清陈旧产物。（`6343770`）
- **契约请求体的可选字段** - 生成器把请求侧 `Option<T>` 一律写成 `field: T | null`（必填可空），
  于是 `PUT /api/v1/config` 的局部更新被迫凑齐 19 个字段。现生成 `field?: T | null`，与 Go 侧
  「字段缺席与 null 都合法」的反序列化一致。（`e5a68dd`）
- **内核 API 断层：`timer_container_of`** - 该名字是较新内核的改名，Ubuntu 24.04 GA 的 6.8.0-146 只有旧名
  `from_timer`，编译直接停在 `implicit declaration`。按「宏是否存在」适配，不比 `LINUX_VERSION_CODE`
  （发行版会 backport，按版本号判断在这类内核上正好判反）。（`1096a920`）
- **内核 API 断层：per-CPU 32KiB 上限** - 速率槽表原先一次 `alloc_percpu` 84KB（实测
  `sizeof(fw_rate_pcpu)=86016`），`mm/percpu.c` 对超限请求 WARN 并返回 NULL：6.8 上
  `illegal size (86016) or align (64) for percpu allocation` → 初始化失败 `-12` → `insmod` 报
  `Cannot allocate memory`，模块在该内核根本加载不进去。现按 128 槽 × 4 块分别申请，索引空间仍是
  0..511、`slot_idx` 语义与探测回绕逻辑不变。（`6797b851`）
- **PWA 清单以 `application/octet-stream` 发出** - Go 的内建 MIME 表没有 `.webmanifest`（清单的规范扩展名），
  `mime.TypeByExtension` 回空串，`writeAsset` 于是落到二进制流：设备拿不到可读清单，装不上图标与启动方式。
  这项能力在旧实现里有，迁到 Go 时丢了，而 E2E 的内容类型断言一直空跑（runner 加载不了模块 → 整套跳过）。
  内核侧解掉 per-CPU 上限后 E2E 第一次真跑就把它暴露了。改在包初始化处注册扩展名，让扩展名推断仍是
  唯一决定这个头的地方。（`4c461d12`）
- **SIGTERM 之后要等满每段关停超时** - 组合根给 `http-server` 登记了关停令牌却没人看它，
  `http.Server.Stop` 一个调用点都没有：信号到达后那个执行体仍卡在 `Serve` 里，监督器只能等满它自己的
  5 秒并记「执行体关停未在超时内完成」，旧进程带着监听套接字迟迟不退，紧接着的重启撞
  `bind: address already in use`。现在执行体同时等「Serve 返回」与「停机令牌」，置位时先停两条 SSE 流
  再关服务器（`Shutdown` 要等连接变空闲，而 SSE 连接永远不空闲）；`SSEStream/SSEBroker.Stop` 可重复调用
  并与扇出循环在同一把锁下互斥（原先 `select` 可能在 stopCh 已关后仍向已关闭的通道发送而 panic），
  `Server.Stop` 预算用尽后强制 `Close`。（`561650d3`）
- **`-C` 目录模式的配置热重载拿到的是空路径** - 随包 systemd 单元用 `-C /etc/firewall` 启动，而组合根
  把 `cfg.ConfigFile` 交给重载器；目录加载会显式清空这个字段，于是每次 SIGHUP 都停在
  `stat : no such file or directory`——改了文件、重发了信号，配置一个字没变，重载计数器也永远不自增
  （集成规格 17.4 的现场）。改为组合根算出唯一的「配置来源」，PUT /config 与重载器共用；顺带把
  `Rollback` 的备份位置改成「配置来源旁边」，目录路径再取一次 Dir 会爬到父级去。（`ef685130`）
- **出厂默认写 plain 日志** - 集成规格 `test_15.4` 与 `docs/zh/operations/monitoring.md` 都说守护进程
  写 JSON Lines，而 `Default().LogFormat` 是 plain、`config/default.yaml` 没写 `log_format`：照默认配置
  部署的进程输出的是一行行 `time=… msg=…`，两处说法同时落空。默认改为 `json`，`plain` 仍是合法取值。
  **这是行为变更**：不改任何配置就部署的进程，日志文件格式随之改变。（`3172c3a4`）
- **`--help` 描述的 schema 与实际不符** - 帮助文本说 jails 是「列表」且每个 jail 至少要有 `name` 字段，
  实际 `parser.go` 里 jails 是 `map[string]yamlJail`、名字就是键，`jail.Validate` 唯一的必填项是
  `log_files`。照旧文本写配置的人会多塞一个被严格模式判为未知键的 `name`。（`ebe428fa`）

### 变更
- **CI 依赖补齐** - 「运行测试」任务此前连 `pytest` 都没有（`No module named pytest`），补装
  `python3-pytest` 与 `python3-yaml`；「浏览器端到端测试」的 `setup-node` 缓存指向被 `.gitignore` 排除的
  根 `package-lock.json`，该锁文件现改为入库（`npm ci` 也依赖它）。（`90585ab0`、`d2db83e2`）
- **依赖告警** - frontend `source-map-js` 1.2.1→1.2.2；docs 侧 `overrides` 补 `brace-expansion ^1.1.21`
  与 `moment ^2.31.0`。`braces`（latest 3.0.3 仍在漏洞区间）与 `sprintf-js`（无 first_patched）上游没有
  可用补丁，按可接受风险在 Dependabot 记处置理由，面板 open 归零。（`621a269`）
- **代码风格** - 内核 C 源码 17 处 clang-format（18）违规清零。（`a4ef7e4`）
- **README 定位** - 项目不再以「内核版 fail2ban」自我描述；README 的概述改写为可验收的目标三条判据
  （防护真的在跑 / 装得进普通 Linux / 分得开扫描器与正常访客）+ 非目标 + 内核版本口径。（`3a664275`）
- **配置正则编译失败被当致命错误** - 契约说「正则缺失或全部编译失败」是**告警 + 该 jail 退化为
  关键字回退**，实现却在四条路径（启动、SIGHUP、文件热重载、PUT /config）上把它当中止理由，
  虚机上 6 条用例连带失败（test_09 自定义配置目录、test_10 日志不存在、test_20 启动与崩溃接管）。
  `jail.Finalize` 现在只把「配置校验不通过」返回 error，正则失败返回 warnings，四个调用点逐条告警
  后照常运行。（`15357dfe`）
- **`metrics_port` 与 `metrics_bind_address` 没有消费者** - HTTP 面绑的是 `Config.HTTPAddress`，
  而该字段只在 `Default()` 赋过一次值，YAML 没有任何键能改它：自起 daemon 的测试把空闲端口写进
  配置却永远等不到就绪（test_18 两条 setup 报「端口未在 8.0s 内就绪」），`config/default.yaml`
  声明的 `0.0.0.0`（局域网开面板）被静默降级成只听回环。删掉该字段，改为 `Config.ListenAddress()`
  现场合成；`metrics_port: 0` 按契约关闭整个 HTTP 面。热重载不重绑端口，故地址变了时留一条告警。
  **这是行为变更**：用 `config/default.yaml` 部署的进程从此真的监听 `0.0.0.0:9119`。（`39cb3ea4`）
- **第二个实例不退出也不停手** - 单实例约束在内核（portid 独占 + 注册前探活），守护进程这边只把
  「注册被拒」记进快照并原地重试，于是第二个进程照样开面板、显示「自己下发过的那一小撮」，而它的
  每一条下发都被内核丢弃。事件泵新增 `ClaimLease`：只有内核**明确拒绝**才让组合根以非零码退出，
  链路问题（超时、模块刚重载）仍交给续约周期。（`e16a0319`）
- **集群网段封禁静默不下发** - 判定是对的，下发错了：线上原因写成 `jail + Summary()`（中文带 CIDR
  与统计，72 字节），而 `BanIp.reason` 是 `str[32]`，编码阶段报错，封禁表始终为空（test_22.3）。
  生产者改发 `<jail>: cluster scan`，投递侧加 `contract.ClampFixedString` 兜底——标签超长不该把
  封禁判死，日志/SSE/历史库仍留原文。（`f0398232`）
- **历史库在任何部署里都建不起来** - `history_db_path` 与 `history_retention_days` 只存在于
  `config.Config` 结构里，`parser.go` 没有对应键，而 `KnownFields(true)` 会让写了这两个键的配置直接
  加载失败：`main.go` 的 `if cfg.HistoryDBPath != ""` 永远为假，面板的复发统计、分级成效、封禁时长
  直方图与三类调参建议一律回 503「依赖未就绪：历史库未初始化」，而这是 README 列出的能力。现补上两个
  键（显式写空串就是关库，不被当成「没写」而回落默认），内置默认仍为关；`config/default.yaml` 打开它
  （`/var/lib/firewall/history.db`，保留 7 天），`scripts/e2e-daemon.sh` 的临时配置同步带上。
  **这是行为变更**：按 `config/default.yaml` 部署的进程从此会写历史库。（`5509e5b3`）
- **`trusted_ips` 从此真的有消费者** - 配置文件那段注释承诺「启动时自动加入内核白名单，防止误封」，
  实现里却只有解析与保存：`cfg.TrustedIPs` 没有任何读取者，以为自己不会被封的运维实际照封。组合根在拿到
  内核守护进程租约之后逐条下发（注册之前内核丢弃一切指令），裸 IP 与 CIDR 都接受，键的归一化收进
  `internal/bans/whitelist_prefix.go` 与 HTTP 写入侧共用一份；一条写错只跳过并告警，不中止启动。
  只在启动时下发一次，改这一段要重启。（`da7b9253`）
- **删掉没有消费者的 Storage 配置组** - `RetentionConfig` / `WriterConfig` / `StorageConfig` 及其
  Default 函数：`parser.go` 里没有对应 YAML 键（写了会被严格模式拒），全仓库也没有一处读 `cfg.Storage`；
  保留策略真正生效的旋钮是 `defaults.history_retention_days`。默认值表里那两条断言随实现一起删除。
  （`9b76dc20`）

### 测试
- **夹具按部署配置带上 Basic 认证** - 守护进程在位时那五套 16 passed / 11 failed，11 条全是 401：
  `config/default.yaml` 带着凭据，装好的进程启用了认证，而用例用裸 `curl` 取 `/metrics` 与
  `/api/v1/**`。**断言一字未改**，改的是取数通道：`conftest.daemon_credentials()` 与
  `daemon_http_port()` 同源，从夹具一直使用的那份 `config/default.yaml` 读凭据（虚机上
  `/etc/firewall` 正是这一份装出来的）；`run_curl()` 经 `curl --config -` 从 stdin 注入
  `Authorization: Basic`（`-u` 与 `?access_token=` 都会把凭据放进 argv，而 pytest 失败时会打印命令行）；
  `http_request()` 成为唯一入口，test_16 的 `curl_get`、test_19 的 `_curl`、test_21.3 自带的那段
  `subprocess.run(["curl", …])` 都收敛过来。凭据不落任何文件、测试常量或断言消息。（`cbfc99a8`）
- **认证项不再拿部署凭据当期望值** - `TestParseDefaultYaml` 原先比对 `config/default.yaml` 里的真实
  用户名与口令，失败分支还把两者 `%q` 打进输出（CI 日志会原样收下）。现在出厂那份只断言「配了没有」
  （`metrics_bind_address` 是 `0.0.0.0`，而契约把「两项都空」定义为不认证并放行整个面板），
  「读得进来」交给新增的 `TestMetricsCredentialsParseFromYaml`，用夹具值覆盖四种形态。全仓扫描确认
  凭据只出现在 `config/default.yaml` 一处（`tests/`、`tests/e2e/`、`.github/`、`frontend/src` 均无）。
  **仍待处置**：本仓库在 GitHub 上是 PUBLIC，那份凭据已随历史公开，轮换与是否重写历史都是运维决定。
  （`cc9fbda1`）
- **新增的单元规格** - 关停：`internal/http/shutdown_test.go` 四条（流停后服务器立刻收敛、预算用尽时
  强制关闭且不留下还在忙的连接、关停中的流回 503 且不占名额、broker 重复 Stop 安全）；
  停机令牌：`internal/runtime/shutdown_test.go` 两条；可信地址：`cmd/firewall-daemon/trusted_ips_test.go`
  四条与 `internal/bans/whitelist_prefix_test.go` 三条；默认日志格式：`TestDefaultConfigWritesJSONLines`。

### 文档
- **全库文档重写并去参照系** - README、AGENTS、CONTRIBUTING、SECURITY、STANDARDS、两个 issue
  模板与 docs/zh 全部 25 篇同步到现状；删除 `docs/zh/migration/from-fail2ban.md`，SUMMARY 与
  book.json 同步。（`b8f86664`、本轮 docs(zh) 提交）
- **删掉没有实现的承诺** - 「所有 unsafe 块均带 SAFETY 注释」（纯 Go，无 cgo）、PIE/RELRO、
  URL 编码检测、API 限速；信任边界改为逐条带出处（procfs 3×0600 + 10×0400 按虚机 `ls -l` 实测、
  认证失败 10 次锁 60 秒出自 `contract/http.fwidl`）。
- **`_guard_local_install` 改述为现状** - 该目标写好了「禁止直接部署到本机」的拒绝文案，但没有
  挂进 `install` / `uninstall` 的依赖链，`make -n install` 看不到任何输出，旧文档却写成「会被拒」。
- **包描述与模块 description** - `apt show` / `modinfo` / PWA manifest 四处对外文案同步，并删掉
  「1024/4096 容量的哈希表」（上限是模块参数）、`PCRE2 + JIT`（实际是 Go `regexp`）、
  「SQLite 持久化永久封禁」（永久封禁在内核表，重启由状态快照还原）。（`97c34951`）
- **两处随代码变更补的落点** - `installation.md` 的状态目录表补 `history.db`（路径留空则不建），
  `frontend.md` 的 PWA 表补清单内容类型一行，并写明这处丢失是 Go 迁移造成的。（`8f09414f`）
- **文档措辞撞了契约的旧缺陷锚点** - `make contract-check` 报「`PROC_CONFIG_DOC_SAYS_READONLY`
  status=fixed 但旧文档现场仍在」：重写后的 procfs 文档在讲展示行数上限时写出「只读文件」四个字，
  被按子串匹配的锚点当成旧缺陷回潮。改成同文其余处对这批条目的叫法「0400 条目」，语义不变。（`5b2edf67`）
- **内核口径改成实测表** - README 的平台徽章原写 `Linux 5.x | 6.x`，而 5.x 从未验证过：换成实测范围
  `Linux 6.8 loaded | 7.0 builds`，「内核版本口径」一节改为三行表（6.8.0-146 编译 + insmod + 13 条目 +
  dmesg 无 percpu WARN；7.0.0-38 仅编译；5.x 未验证），并明写「6.x 不等于每个 6.x 内核都验证过」；
  AGENTS.md 里那句「CI 徽章写的 5.x 只是意图」随徽章一起改掉。（`250e3ffa`）
- **deb 元数据去掉不成立的说法** - `debian/changelog` 里的 PCRE2 + JIT、SQLite 持久化永久封禁、
  内核版 fail2ban 换成有出处的现状（Go 标准库 `regexp`、每 jail 最多 10 条正则、容量是模块参数、
  永久封禁在内核表并由 `state_file` 快照还原）；版本头与日期同步到 v2.2.0（原 `2.0.0-1` 与
  「Mon, 05 May 2026」这个不存在的星期几一起修掉）。同时记下 `debian/` 服务的是
  `dpkg-buildpackage` 那条路，`make deb` 走的 `build-deb.sh` 自己生成 `DEBIAN/control`。
  （`250e3ffa`）
- **配置文档随实现同步** - `yaml-config.md` 的 `trusted_ips` 行由「只被解析保存，没有消费方」改为实际
  行为，`log_format` 的默认列由 `plain` 改为 `json`；`examples.md` 里那条「未验证：`src/daemon` 没有读
  `cfg.TrustedIPs` 的地方」按现状改写；`config/default.yaml` 的可信地址段补一句「改这一段要重启」。

### 验证
- CI run `38593578717`：契约一致性 / 前端构建 / 代码质量检查 / 编译 / 运行测试 / 浏览器端到端测试 六项全
  success。这轮 runner **第一次能 `insmod`**（日志 `✓ 内核模块加载成功`），集成套件按 97 条收集
  （`collected 97 items` → `74 passed, 23 skipped in 279.65s`），浏览器套件不再空跳（`19 passed (12.4s)`）。
- 6.8.0-146 虚机：`make kernel-module` 通过、`insmod` 成功、`/proc/firewall/` 13 个条目齐全、dmesg 无
  percpu WARN；7.0.0-38：`make kernel-module` 通过。
- 同一虚机首次真跑完整集成套件（`sudo python3 -m pytest tests/`）：64 passed / 5 failed / 26 skipped /
  2 errors，用例数量与结果一律以命令输出为准。其中 6 条同一根因（配置后处理把 warn 当致命错误），
  修复在途；`test_22` 集群判定那条为独立的待查项。
- **修复后同一套件复跑：74 passed / 23 skipped / 0 failed / 0 errors（280.16s）**。23 条跳过全部是
  「守护进程未运行」（test_16 8 条、test_17 7 条、test_15 4 条、test_19 3 条、test_12 1 条数据库缺失）：
  这几套要求**外部已装好并起好** daemon，不像 test_18/20/21/22 那样自起进程。
- **daemon-up 形态（同一虚机按 `/etc/firewall` 手工起 daemon 后跑这五套）**：修完上述各项后为
  **16 passed / 11 failed / 1 skipped（58.78s）**。11 条失败全部是同一处耦合，不是功能坏：仓库的
  `config/default.yaml` 带着 `metrics_username` / `metrics_password`，照它装好的进程启用了 Basic 认证，
  而这几套用裸 `curl` 取 `/metrics` 与 `/api/v1/*`，于是 `/api/v1/stats 返回 HTTP 401`、
  `SIGHUP 未触发重载（计数仍为 0.0）`、`firewall_netlink_* 指标缺失` 全是读不到而非不存在
  （用例自己的提示就是「daemon 是否以回环免鉴权配置运行？」）。**待定**：夹具按配置带认证，还是
  测试环境装一份不带凭据的配置。此前两条真 bug 已修并有独立验证：`/api/v1/nonexistent` 返回 303
  （根路径重定向是子树模式，把未匹配路径全接住了），契约期望框架自产的 404（`156dba62`）；
  清单与四个分析端点分别由 `curl -D -` 看到 `application/manifest+json`、带认证一律 200
  （`4c461d12`、`5509e5b3`）。
- **认证耦合修掉后同一形态复跑：27 passed / 1 skipped / 0 failed（55.15s）**（虚机按 `/etc/firewall`
  起真实进程）。唯一的 skip 是 `test_15.3 DDoS 自动封禁指标不存在`，用例自己按指标缺席跳过。
  不带凭据访问 `/api/v1/stats` 与 `/metrics` 仍回 401，认证没有被削弱。
- **停掉守护进程复跑完整套件：75 passed / 22 skipped（223.41s）**，比改前多通过一条——历史库那条
  从「守护进程未创建数据库」跳过转为实际执行（`defaults.history_db_path` 现在真的建得起库）。
- **关停实测（虚机）**：SIGTERM 到进程退出 **0.459 秒**（改前同一台机上信号到达后 5.4 秒才记
  「执行体关停未在超时内完成 name=http-server」，日志里这类告警累计 7 条，新二进制运行期间零新增）；
  带一条真实活跃的 `/api/v1/events` 流（首帧 `event: connected`，随后收到速率帧）时 SIGTERM→退出
  **0.525 秒**，SSE 客户端随服务器关闭而结束；关停后立即重启第二次 `health=200`，本轮无
  `bind: address already in use`。
- **`-C` 目录模式热重载实测**：`sudo kill -HUP` 后日志出现
  `{"msg":"configuration reloaded successfully"}`，本轮再无 `stat : no such file`
  （历史日志里那 85 条都是改前的）。
- **trusted_ips 实测**：在虚机 `/etc/firewall/default.yaml` 的 `trusted_ips:` 下临时加一条
  `198.51.100.233`，重启进程后 `sudo cat /proc/firewall/whitelist` 显示
  `198.51.100.233/32`（Total: 1 entries），日志
  `{"msg":"trusted_ips 已下发内核白名单","configured":1,"pushed":1,"skipped":0}`；测完已还原该配置。
  顺带证伪一条子代理报告：旧日志的相邻重复行对数为 0，「每条启动记录写两遍」不成立。
- **默认日志格式实测**：新二进制按默认配置起进程后，`/var/log/firewall.log` 尾行是
  `{"ts":"…","level":"INFO","msg":"入站主链路已就绪","version":"dev","sources":1,"jails":12}`。
- 本地守护进程门禁：`gofmt -l` 为空、`go vet` 通过、`go test ./...` 全绿、`make contract-drift` 与
  `make contract-check` 通过（其中 `http_contract.ts tsc --noEmit` 由跳过转为 OK）。
- 文档自检：31 个 md 文件相对链接 0 条断链；`fail2ban` / `leptos` / `pcre2` / Rust 时代词汇在
  README、AGENTS、CONTRIBUTING、SECURITY、STANDARDS 与 docs/zh 命中 0 行；`yaml-config.md` 的字段表与
  `internal/config` 的 66 个 yaml tag 双向比对零缺失、零多余。

## [Unreleased] - 守护进程日志：整行一次写出

### 修复
- **JSONL 行撕裂** - 每条记录在内存里拼成完整一行（含换行，`internal/logger/json.go`），再由
  `fileSink.Write` 在进程内 `Mutex` 保护下**单次**写入（`internal/logger/file.go`）。轮转与写入共用同一把锁：
  改名、开新文件、重置字节计数都在锁内完成，并发写者看不到中途 inode。换行必须与正文同处一次写入，
  否则多写者（重启期新旧进程并存、pytest 起的实例）追加同一文件会拼出「两条记录并成一行 + 空行」的非法行。
- **字段顺序** - 手工编码按插入顺序输出，守住文档承诺的 `ts → level → msg → 其余`。

### 测试
- `internal/logger` 的 `_test.go` 覆盖：并发写保持整行（`TestConcurrentWritesStayWhole`）、多进程追加保持
  整行（`TestMultiProcessAppendStaysWhole`）、轮转后每片仍是合法 JSONL（`TestRotatedSlicesRemainValidJSONL`）、
  目的地降级与 fanout 行为；用例数量以 `go test ./internal/logger` 输出为准。

## [Unreleased] - 前端全新重写：React 19 + TypeScript + Vite + Ant Design 6（桌面优先 + 响应式 + PWA）

### 新增
- **前端按桌面控制台范式全新重写** - 技术栈定为 **React 19 + TypeScript + Vite + Ant Design 6（`antd`）+ @ant-design/icons + ECharts 6（`echarts-for-react`）+ react-router-dom 7（hash 路由）**。桌面优先、响应式：常驻可折叠侧边栏 + 顶栏（命令面板入口、实时连接状态灯、主题/密度切换、通知中心、账户菜单），窄屏降级为抽屉导航。信息架构单一真相源是 `src/app/nav.ts` 的 `NAV_GROUPS`（总览 / 防护 / 智能 / 运维），驱动侧边栏、命令面板与面包屑。**不复用任何旧前端代码**：此前一轮 antd-mobile 5 移动优先实现（底部 TabBar + 卡片列表 + 手写 SVG 图表）从未发布即被本次重写整体取代，更早的 Leptos WASM 与 Vue 3 实现亦已删除
- **迷你设计系统** - 建于 AntD token 之上：语义色 + 威胁等级色阶、等宽字体承载 IP/速率/计数、暗/亮双主题（默认跟随系统、首屏内联防闪烁）、标准/紧凑双密度；偏好落 localStorage 且跨标签同步
- **命令面板与全局快捷键** - `Ctrl/⌘+K` 唤出命令面板（页面跳转 + 快捷动作，↑↓/Enter/Esc 全键盘可达），`Ctrl/⌘+J` 切主题、`R` 刷新当前页
- **智能分析新页** - 新增风险引擎、威胁情报、智能分析三页，消费既有后端端点；配套把后端 `analysis/summary` 与 `analysis/ip/{ip}` 桩填成真实数据
- **PWA 支持** - 新增 `frontend/public/manifest.webmanifest`（`display: standalone`、`start_url: /dashboard#/dashboard`、192/512 图标）与手写零依赖 Service Worker `frontend/public/sw.js`。SW 安装即 `skipWaiting`，激活时清理旧版本缓存并 `clients.claim`；fetch 策略：页面导航网络优先、失败回退缓存外壳，`/static/*` 缓存优先 + 后台刷新，**`/api/*` 一律不拦截**（实时封禁与统计数据不得读缓存）
- **`GET /sw.js` 路由** - 守护进程新增公开（无认证）路由返回嵌入的 `sw.js`，响应带 `Service-Worker-Allowed: /` 与 `Cache-Control: no-cache`。走根路径而非 `/static/sw.js` 是因为 Service Worker 的作用域上限由脚本路径决定，`/static/sw.js` 只能接管 `/static/`，无法处理页面导航
- **`.webmanifest` MIME** - `get_static_asset` 补 `.webmanifest` → `application/manifest+json`（原先落到 `application/octet-stream`）

### 变更
- **构建链路改为 npm/vite** - `make frontend` 为 `npm ci` + `vite build`，产物输出到 `src/daemon/web_ui/static/` 供 `go:embed` 嵌入（持有文件是该目录下的 `assets.go`）；`make daemon` / `make all` 会先构建前端。`make frontend-typecheck` 走 `tsc --noEmit`（不再有 trunk / WASM 工具链）
- **CI 前端 job** - Node 22 + `npm ci` + `tsc --noEmit` + `vite build`，并断言产物存在（`index.html` / `app.js` / `style.css` / `sw.js` / `manifest.webmanifest` / 192 与 512 图标）、校验 manifest 必需字段与 `sw.js` 语法
- **安全头中间件** - 已自行声明 `Cache-Control` 的响应不再被统一覆盖成 `no-store`，否则 `/sw.js` 的 `no-cache` 会被吃掉、SW 更新检查失去回源保证；`/sw.js` 纳入 Web UI 的宽松 CSP 范围，避免 `default-src 'none'` 被当作 Service Worker 自身策略而禁掉其内部 fetch
- **`.gitignore`** - 前端产物规则收敛为 `src/daemon/web_ui/static/*`（含 `sw.js` / `manifest.webmanifest` / `icons/`），`node_modules/` 为 Node 依赖；`frontend/package-lock.json` 保持入库以配合 `npm ci`
- **`vite` 抬到 `^8.3.5`** - 8.3.0–8.3.2 带 dev-server / launch-editor 高危审计告警（GHSA-698v-4r3x-3vcv、GHSA-r825-w8mm-5pxw 等），把新装下限抬到已修复的 8.3.5，`npm audit` 归零。仅影响开发期 dev server：交付产物是 Go 守护进程服务的预构建静态文件，Vite 不在线上运行
- **显式声明 `dayjs` 与 `tslib`** - `dayjs` 被 `ThemeProvider`/`Settings` 直接 import，`tslib` 补 `echarts-for-react`（`importHelpers`）的打包缺口；两者原先只靠 antd 提升解析，现写进 `frontend/package.json` 的 `dependencies`
- **E2E 套件重写** - `tests/e2e/`（Playwright + Desktop Chrome）改为匹配全新桌面前端：全量 hash 路由渲染、认证闸门、写操作回环（封禁/解封落内核再复原）、外壳交互 UX（主题/密度/命令面板/`Ctrl+K`/侧栏折叠，均含落盘 + 刷新保持）、控制台洁净度守卫

### 移除
- **3D 地图页与 three.js** - 删除 Globe（`frontend/src/views/Globe.tsx`）与 three.js 依赖及其契约路由 `RouteGetGlobe`。去掉地图后 GeoIP 无 UI 消费者：`attack-geo` 端点作为契约完整性桩保留（恒 `geoip_enabled=false`、`points=[]`），并退休了 `HTTP_GEOIP_NOT_IMPLEMENTED` 缺陷记录（其叙述锚定已删除的 Globe 页）；端点仍如实标注「无 GeoIP 读库」
- **死路由 `/more`** - 旧移动实现的「更多」页收纳 Jails / 日志 / 设置，桌面重写后由侧边栏分组直接承载，`/more` 已无对应视图；删除契约 `route GET "/more"`、生成的 `RouteGetMore` 与 `static.go` 注册行（SPA 页面壳由 8 条收敛为 7 条）
- **antd-mobile 与旧前端源码** - 移除 `antd-mobile`(-icons) 依赖、手写 SVG 图表、`src/state/*` 死代码；以及更早的 Leptos（`frontend/{Cargo.toml,Cargo.lock,Trunk.toml}`、`frontend/src/**/*.rs`）与 Vue 3 实现遗留（含曾被复用的 `frontend/src/styles/global.css`）

> 二进制体积：前端产物变化后尚未统一核算，本文不再沿用旧的 `5.6MB` 数字。需要写具体数值时以 `stat -c %s build/daemon/firewall-daemon` 实测为准。

## [Unreleased] - C→Rust 翻译 + 二进制优化 + CI 升级（v2.2.1）

### 新增
- **Netlink 深度联动架构** - 内核模块与守护进程通过 netlink socket 双向实时通信。内核检测到 DDoS 后推送事件给守护进程，守护进程决策引擎判断后下发封禁指令。消除状态同步问题，实现真正的深度联动
- **DDoS 决策引擎** - 守护进程新增 `DdosDecisionEngine`，接收内核 netlink 事件后根据违规次数决定是否封禁，通过 netlink 下发封禁指令。封禁同步到 `ACTIVE_BAN_CACHE`，Web UI 实时可见
- **Leptos WASM 前端** - 从 Vue 3 + npm + Vite 迁移到 Leptos 0.6 + trunk。纯 Rust 前端，无 Node.js 依赖。产物：WASM 639KB + JS 55KB + CSS 19KB = 713KB。7 个页面（仪表盘、封禁管理、白名单、Jails、DDoS 监控、系统日志、设置）+ 原生 SVG 图表组件（折线图、饼图）。Hash 路由模式，SPA fallback 路由
- **`make install` 自动化改进** - install 目标添加 build 依赖，`make clean && make install` 一步完成，无需手动 `make build`
- **安装流程标准化** - 新增 `install-verify` 目标，安装后自动验证关键组件（内核模块、守护进程、配置文件、状态目录、systemd 服务）
- **安装错误处理增强** - 关键步骤（daemon 启动、文件安装）失败时显式报错，不再静默忽略；服务启动检查验证 daemon 是否真正运行
- **安装完成提示优化** - 提供清晰的后续步骤（查看日志、检查状态），DESTDIR 模式下提示手动启用服务
- **守护进程 C→Rust 翻译** - 守护进程从 C 翻译为 Rust，58 个源文件，行为与 C 版严格等价。107 项集成测试以 `RUST=1` 全过，108 Rust 单元测试全过。Makefile 默认 `RUST=1`
- **`[profile.dev-with-debug]`** - 现场 crash 调试用 release 副本：32MB 带 DWARF + 符号表，配 `lto=true + opt-level=2`（继承 release），`addr2line` 可反推栈
- **`[profile.asan]`** - ASAN 内存错误检测 profile：仅 nightly 可用，检测堆/栈越界、UAF、double-free

### 变更
- **HTTP 框架迁移：tiny_http → axum** - HTTP 服务从同步的 `tiny_http` 迁移到异步的 `axum` + `tokio`。SSE 从短连接（每次发送后关闭）改为**长连接不间断推送**，前端状态指示器更准确。二进制体积从 3.8MB 增至 4.6MB（+0.8MB，来自 tokio runtime）。路由使用 axum 的 Router 分层 merge 实现认证排除（`/health` 跳过认证）。新增依赖：`axum 0.7`、`tokio`、`tower-http`、`tokio-stream`、`async-stream`
- **前端框架迁移：Vue 3 → Leptos WASM** - 完全消除 npm/Node.js 依赖。构建工具从 Vite 切换到 trunk。图表库从 ECharts (500KB) 切换到原生 SVG 组件（零依赖）。状态管理从 Pinia 切换到 Leptos signals。路由从 vue-router 切换到 leptos_router（hash 模式）。Daemon 二进制从 4.6MB 增至 5.2MB（+0.6MB 嵌入 WASM 前端）
- **默认 release 二进制 30MB → 5.2MB** - HTTP 框架迁移后体积略有增加（tokio runtime + WASM 前端），但仍保持轻量
- **`build-deb.sh` 弃用 `VERSION=`** - 版本统一从 `Cargo.toml` 读取
- **`tests/run_tests.sh` 加 `source ~/.cargo/env`** - 修复 sudo 默认 `secure_path` 不含 `~/.cargo/bin` 导致 `make daemon` 报 "cargo: 没有那个文件或目录"
- **CI 工作流升级** - `代码质量检查` 步骤从 C daemon 的 `clang-format` 切换为 `cargo fmt --check` + `cargo clippy -- -D warnings`（Rust 后 `src/daemon/*.c` 已删，原 glob 报 "No such file or directory"）。CI 工作流自动 `rustup` 安装 stable toolchain
- **`tests/run_tests.sh` 加 `cargo fmt` 一次性 fix** - 翻译后 12 个 .rs 文件有 rustfmt 违规，PR 修一次后 CI 卡口生效

### 修复