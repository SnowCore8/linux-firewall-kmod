# 测试

三层测试，互相不能替代。

| 层 | 命令 | 需要 root | 覆盖 |
|----|------|----------|------|
| 单元 | `cd src/daemon && go test ./...` | 否 | Go 包内 `_test.go` |
| 集成 | `make test` | 是 | `tests/test_*_*.py` |
| 端到端 | `npx playwright test` | 需要能起守护进程 | `tests/e2e/*.spec.ts` |

**用例数量一律以命令实时输出为准，本文不写死数字。**
`go test ./...`、`sudo python3 -m pytest tests/ --collect-only -q`、
`npx playwright test --list` 各自会给出计数。

## 第一层：Go 单元测试

守护进程是 Go module `src/daemon`
（模块名 `github.com/snowcore8/linux-firewall-kmod/daemon`，见 `src/daemon/go.mod`）。

```bash
cd src/daemon && go test ./...                # 全部
cd src/daemon && go test ./cmd/... -v         # 只看组合根
cd src/daemon && go test ./internal/kernel/ -run TestXxx -v
cd src/daemon && go vet ./cmd/... ./internal/...   # lint，等价 CI 的同款命令
cd src/daemon && gofmt -l ./cmd ./internal         # 格式，输出须为空
```

组合根的可测入口是 `cmd/firewall-daemon/main.go` 的 `run(args []string) error`，
`main` 只是它的一层包装。

契约生成的 `http_contract.go` 另有自检：`contract/verify_http.py` 会把它真编一遍，
所以跑校验时要传 `GO` 环境变量（`make contract-check` 已传）。

## 第二层：集成测试（pytest）

```bash
make test                       # 实际执行 sudo python3 -m pytest tests/ -v
sudo python3 -m pytest tests/ -v
sudo python3 -m pytest tests/test_03_ban_unban.py -v    # 单个套件
sudo python3 -m pytest tests/ -k "ban" -v               # 关键字过滤
sudo python3 -m pytest tests/ --tb=short --collect-only # 只列出，不执行
```

框架入口：`tests/conftest.py`（fixtures 与辅助函数）、`tests/config.py`
（路径与参数配置）。需要 root 的动作是 insmod / rmmod 和 procfs 写入。

`make test` 依赖 `$(KERNEL_MODULE)` 与 `$(DAEMON_BIN)`，所以要先编译。

### 套件清单

按 `ls tests/` 核对。编号不连续（05、06 缺失，重构时已合并进现有套件）。

| 编号 | 文件 | 覆盖 |
|------|------|------|
| 01 | `test_01_module_lifecycle.py` | 模块加载/卸载、带参数加载、sysfs 参数可读 |
| 02 | `test_02_procfs_interface.py` | `/proc/firewall/{bans,whitelist,config,stats}` 读写 |
| 03 | `test_03_ban_unban.py` | 封禁、解封、临时/永久封禁、到期清理 |
| 04 | `test_04_whitelist.py` | 精确匹配、CIDR 子网匹配、容量上限 |
| 07 | `test_07_concurrency.py` | 多进程并发读写、RCU 正确性 |
| 08 | `test_08_stress_perf.py` | 满表操作、延迟统计 |
| 09 | `test_09_daemon_config.py` | YAML 加载、严格模式校验、jail 解析 |
| 10 | `test_10_daemon_logparse.py` | 日志监听、正则匹配、jail 触发 |
| 11 | `test_11_resource_mgmt.py` | 内存、句柄、procfs 资源生命周期 |
| 12 | `test_12_permanent_ban.py` | 永久封禁 |
| 13 | `test_13_frp_jail.py` | frp jail 的配置加载与触发 |
| 14 | `test_14_ban_netfilter.py` | 封禁后的 netfilter 行为（真实可路由 IP） |
| 15 | `test_15_ddos_detection.py` | DDoS 检测（PPS / SYN / UDP / ICMP 速率违规） |
| 16 | `test_16_webui_api.py` | Web UI API 端点 |
| 17 | `test_17_config_reload.py` | 配置热重载（SIGHUP） |
| 18 | `test_18_log_rotation.py` | 日志轮转检测 |
| 19 | `test_19_netlink_comm.py` | netlink 内核 ↔ 守护进程通信 |
| 20 | `test_20_daemon_lifecycle.py` | 守护进程启动/停止/重启 |
| 21 | `test_21_multi_jail.py` | 多 jail 并发、独立日志、隔离性 |
| 22 | `test_22_cluster_scan.py` | 集群扫描：配置接受、单高频 IP 不触发、同 /24 多源触发 |

「需要模块可加载」与「只测守护进程」的分组以 `.github/workflows/ci.yml` 里
`运行测试` 任务打印的那两行为准。

### 集成测试是行为规格

`tests/` 与 `scripts/e2e-daemon.sh` 描述的是接口契约。
规格与实现冲突时先确认哪一侧错，**不要改测试迁就刚改的实现**。

### 在 sudo 下运行

`make test` 内部就是 `sudo python3 -m pytest tests/ -v`。

`sudo` 默认 `secure_path` 可能不含用户目录下的 Go 安装位置，
`sudo make daemon` 会以 `make: go: 没有那个文件或目录`（错误 127）失败。
仓库 CI 的写法是保留当前 PATH：

```bash
go version                                      # 先确认
sudo env "PATH=$PATH" make test                 # 与 CI 一致
sudo --preserve-env=PATH make daemon
```

Python 侧的 pytest 装在系统站点目录：`--user` 安装对 root 不可见。

## 第三层：浏览器端到端（Playwright）

跑在真实守护进程的 Web UI 上，配置在仓库根 `playwright.config.ts`，
`testDir` 是 `./tests/e2e`。

```bash
sudo bash scripts/e2e-daemon.sh start     # insmod + 起守护进程 + 等 procfs 就绪
eval "$(bash scripts/e2e-daemon.sh env)"  # 打印连接参数，不需要 root
npx playwright test
sudo bash scripts/e2e-daemon.sh stop      # 停进程并 rmmod，释放内核 portid 租约
```

前置条件是**加载了内核模块的守护进程**：`cmd/firewall-daemon/main.go`
启动期先做 `checkProcfs`，`/proc/firewall` 与 `/proc/firewall/bans`
缺失即以启动错误退出。

内核把单守护进程实现为 portid 独占 + 30 秒活动超时，且无注销消息。
整条夹具因此独立成 `scripts/e2e-daemon.sh`，本地与 CI 共用同一份逻辑。
`scripts/e2e-daemon.sh probe` 只探测模块能否加载，不启动任何进程。

### 断言范围

| 类别 | 内容 | 出处 |
|------|------|------|
| 路由 | 逐一访问每个页面路径，断言区块标题与顶栏标题 | `tests/e2e/routes.spec.ts` |
| 写操作回环 | 封禁 → 解封，界面 / 接口 / 内核三层状态同步翻转 | `tests/e2e/write-flow.spec.ts` |
| 仪表盘 | 首屏渲染与实时数据 | `tests/e2e/dashboard.spec.ts` |
| 控制台洁净度 | 整个用例期间无 `console.error` / `console.warn` / 未捕获异常 | `tests/e2e/support.ts`（共享夹具） |
| PWA 上下文对照 | 安全上下文下 SW 可注册；局域网 IP 下该 API 不存在但界面照常 | `tests/e2e/pwa-context.spec.ts` |

新增用例默认继承夹具里的洁净度门槛，不各自重复断言。

### 两处配置取舍

| 配置 | 值 | 原因 |
|------|-----|------|
| `retries` | 0 | 重试会把间歇性缺陷（偶发告警、偶发 503）洗成绿 |
| `workers` | 1 | 每个页面实例建一条 `/api/v1/events` SSE 长连接，而守护进程对管理流有连接位硬上限；多 worker 叠加本地已开的标签页会随机触顶 503 |

要提速应先调大服务侧的连接位配额，而不是把不确定性带进 CI。

局域网一侧的对照由 `E2E_LAN_ORIGIN=http://<局域网IP>:<port>` 开启；
不设置则该侧显式跳过（CI 即如此）。

## CI 的六个任务

任务名取自 `.github/workflows/ci.yml` 的 `name:` 字段。

| 任务名 | job id | 做什么 |
|--------|--------|--------|
| 代码质量检查 | `lint` | `clang-format --dry-run --Werror`、`gofmt -l`、`go vet`、`go test ./cmd/... ./internal/...`、`yamllint config/` |
| 契约一致性 | `contract` | `make contract-drift` + `verify_layout` / `verify_procfs` / `verify_http` |
| 前端构建 | `frontend` | `npm ci`、`tsc --noEmit`、`vite build`、产物与 PWA 清单校验、`node --check sw.js` |
| 编译 | `build` | 编内核模块与守护进程，上传产物 |
| 浏览器端到端测试 | `e2e` | `scripts/e2e-daemon.sh` 起真守护进程后跑 Playwright |
| 运行测试 | `test` | 装 `sqlite3`、`python3-pytest`、`python3-yaml`，跑 pytest |

六项全过才允许合入。

### 必须知道的实测结论

**CI 的 runner 加载不了内核模块。**
GitHub Actions 的 Azure VM 用自定义内核，`insmod` 编出的 `.ko` 会失败。
`运行测试` 与 `浏览器端到端测试` 两个任务都先探测：

```bash
if sudo insmod build/kernel-module/firewall.ko 2>&1; then compatible=true
else compatible=false; fi
```

`compatible=false` 时：

| 任务 | 降级行为 |
|------|---------|
| 运行测试 | 只跑守护进程子集：`-k "daemon or logparse or frp or ddos or webui or config_reload or log_rotation or netlink or lifecycle or multi_jail"` |
| 浏览器端到端测试 | 整段带 `::warning::` 注解跳过（环境限制，非代码问题） |

**结论：CI 绿不代表内核模块套件跑过。**
要验证内核侧，必须在真能 `insmod` 的机器上跑 `make test`。

**编译通过不等于加载得进去。** 这两件事的检查点不同：

| 阶段 | 检什么 | 漏检的后果 |
|------|--------|-----------|
| `make kernel-module` | 符号、头文件、类型 | 编得过 |
| `insmod` | vermagic、每 CPU 申请上限、init 路径返回值 | 报 `Unknown symbol` / `Invalid module format` / `Cannot allocate memory` |

实测撞过的一个例子：per-CPU 单次申请超 32 KiB 上限时，
编译完全正常，`insmod` 才报 `Cannot allocate memory`。
细节见 [内核模块](../architecture/kernel-module.md)「两处内核适配」。

## 代码检查

| 检查 | 命令 | 要求 |
|------|------|------|
| C 格式 | `make format-check` | 通过 |
| Go 格式 | `cd src/daemon && gofmt -l ./cmd ./internal` | 输出为空 |
| Go lint | `cd src/daemon && go vet ./cmd/... ./internal/...` | 通过 |
| TS 类型 | `make frontend-typecheck` | 通过 |
| 契约 | `make contract-check` | 三个校验器全绿 |

`make format` 只格式化 C，不管 Go 和 YAML。三件事互相独立。

### 关于 `unsafe`

守护进程是纯 Go、无 cgo（全仓无 `import "C"`）。
代码里有两处 `unsafe.Pointer`，都不跨 FFI 边界：

| 位置 | 用途 |
|------|------|
| `src/daemon/internal/bans/endian.go` | 字节 ↔ 数值的搬移 |
| `src/daemon/internal/ingest/watcher.go` | inotify 事件结构的封装 |

可执行的检查是 `gofmt -l` 与 `go vet ./cmd/... ./internal/...`（CI 同款命令）。
本仓库不使用逐行论证式的注释。

### Valgrind（可选）

用于「二进制不变、只换分析器」的场景：

```bash
cd src/daemon && go build -o /tmp/firewall-daemon ./cmd/firewall-daemon
sudo valgrind --leak-check=full /tmp/firewall-daemon -c config/default.yaml
```

本机跑过没有：未验证。

## 写新测试

新文件放 `tests/`，命名 `test_NN_description.py`，NN 取下一个可用编号。
辅助函数从 `tests/conftest.py` 导入。

| 函数 / fixture | 用途 |
|------|------|
| `ban_ip(ip)` / `ban_ip_with_time(ip, seconds)` / `ban_ip_permanent(ip)` | 封禁 |
| `unban_ip(ip)` | 解封 |
| `ip_is_banned(ip)` | 查封禁列表 |
| `whitelist_add(subnet)` / `whitelist_remove(subnet)` | 白名单 |
| `get_stat(name)` | 取 procfs 统计值 |
| `count_bans()` / `count_whitelist()` | 数行数 |
| `reset_all_data()` | 重置测试数据 |
| `load_module()` / `unload_module()` | 加载 / 卸载模块 |
| `session_setup`（fixture） | 会话级设置，确保模块加载 |
| `test_isolation`（fixture） | 每个测试前后的数据隔离 |
| `clean_bans`（fixture） | 确保封禁列表为空 |
| `daemon_binary`（fixture） | 确保守护进程二进制存在 |
| `tmp_config`（fixture） | 创建临时配置目录 |

清单以 `tests/conftest.py` 为准，上表按其中的定义与 fixture 核对过。

## 环境受限时的做法

集成测试需要 root 与可加载的模块。当前开发机若两条都不满足，就**不能**把「没跑」
写成「通过」。可执行的闸门是：

```bash
cd src/daemon && gofmt -l ./cmd ./internal      # 须为空
cd src/daemon && go vet ./cmd/... ./internal/...
cd src/daemon && go test ./...
make format-check
make contract-check
```

能 `insmod` 的机器上再跑 `make test`。这是唯一能验证内核套件的途径。

## 相关文档

- [构建](building.md)：门禁命令与 CI 依赖
- [性能基线](perf-baseline.md)：热路径口径
- [Web 前端](../architecture/frontend.md)：端到端断言的对象
