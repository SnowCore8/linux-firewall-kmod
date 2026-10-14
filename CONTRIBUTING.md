# 贡献指南

本文说清三件事：怎么把改动跑通、提交成什么形状、评审看什么。
项目机制与目录说明见 [AGENTS.md](AGENTS.md)。

## 开始之前

- 读 [README.md](README.md) 了解目标与非目标。
- 读 [AGENTS.md](AGENTS.md) 了解构建入口与质量门禁。
- 翻一遍 [docs/zh/](docs/zh/) 的相关章节。
- 查现有 [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues)，避免重复。

## 开发环境

### 系统要求

- Linux，x86_64。
- 内核：已验证 6.8.0-146（Ubuntu 24.04 GA），可编译可加载。
  7.0.0-38 可编译。5.x 未验证。
  口径见 README 的「内核版本口径」。
- 要真验证 `insmod`，得在一台能加载模块的机器上跑集成测试。
  CI runner 用自定义内核，编译过不代表加载得了。

### 装依赖

```bash
# Debian/Ubuntu
sudo apt install build-essential linux-headers-$(uname -r) git clang-format

# RHEL/CentOS/Fedora
sudo dnf install gcc make kernel-devel kernel-headers git clang-format
```

另外需要：

- Go：`src/daemon/go.mod` 写 `go 1.26.0`。
- Node.js 22 + npm：前端构建用，CI 也是 22。
- Python 3 + pytest + PyYAML：集成测试用。
- sqlite3 命令行：集成测试强制要求，缺了不许跳过。

Go 依赖全是纯 Go，无 cgo，不需要系统开发库。

### 克隆与编译

```bash
git clone https://github.com/SnowCore8/linux-firewall-kmod.git
cd linux-firewall-kmod

make                 # 格式检查 + 内核模块 + 守护进程
make kernel-module   # 只编内核模块
make daemon          # 只编守护进程（先出面板产物）
make frontend        # 只构前端
make build-quick     # 跳过格式检查
```

`make kernel-module` 需要内核头文件。缺了会打印可用目录并退出 1。
也可以显式指定：

```bash
make kernel-module KDIR=/lib/modules/$(uname -r)/build
```

### 装到机器上

`make install` 与 `make uninstall` 直接在本机跑会被守卫拒。
三条合规路径：

```bash
./scripts/deploy.sh <远程主机> [远程用户]        # 远程部署，有审计轨迹
make install DESTDIR=$(pwd)/build/stage         # 打包暂存，不写本机
make install FIREWALL_REMOTE_DEPLOY=1           # 显式授权，只用于沙箱
```

## 跑测试

| 层 | 命令 | 需要 root |
|----|------|-----------|
| Go 单元 | `cd src/daemon && go test ./...` | 否 |
| 集成 | `make test` | 是 |
| 单套件 | `sudo python3 -m pytest tests/test_03_ban_unban.py -v` | 是 |
| 端到端 | `npx playwright test` | 见下 |

端到端要真守护进程，走 `scripts/e2e-daemon.sh` 的
probe / start / stop / env 四个子命令。
内核模块加载不了时用例显式跳过。

调试构建（保留 DWARF 与符号表）：

```bash
cd src/daemon && go build -o firewall-daemon-debug ./cmd/firewall-daemon
```

产物是仓库自己的目录里的临时文件，别提交。
注意 `go build` 不检查面板产物，缺面板时二进制能编出来但启动会报错。
发版或对比体积请用 `make daemon`，它带 `-ldflags "-s -w=1"`。

## 提交前必过的门禁

```bash
make format-check
make contract-check
cd src/daemon && gofmt -l ./cmd ./internal   # 输出必须为空
cd src/daemon && go vet ./cmd/... ./internal/...
cd src/daemon && go test ./...
make test
```

`make format` 只格式化 C。Go 要单独 `gofmt -w ./cmd ./internal`。
跑了一件不等于另外两件，常见漏检就在这里。

## 代码规范

### C 内核模块

以 `.clang-format` 为准。

| 规则 | 要求 |
|------|------|
| 命名 | 函数与变量 `snake_case`，宏 `UPPER_CASE`，统一 `fw_` 前缀 |
| 缩进 | 2 空格，禁 Tab |
| 行宽 | 80 |
| 括号 | K&R，左括号不换行 |
| 函数长度 | 不超过 50 行 |
| 注释 | 中文，解释为什么 |

内核侧两条要注意：

- 跨内核版本的 API 差异按「宏或符号是否存在」适配，
  不比 `LINUX_VERSION_CODE`。已有例子：`timer_container_of`
  与 `from_timer` 的改名，见 `src/kernel-module/fw_ban.c`。
- 单次 per-CPU 申请有 32 KiB 上限，超了拿到 NULL。
  已有例子：速率槽表按 128 槽 × 4 块分块申请，
  见 `src/kernel-module/fw_rate.c` 与 `fw_types.h`。
  索引空间和 `slot_idx` 语义不变。

### Go 守护进程

- `gofmt` 干净（CI 卡 `gofmt -l ./cmd ./internal` 为空）。
- `go vet ./cmd/... ./internal/...` 通过。
- 错误用 `fmt.Errorf("...: %w", err)` 包装，保留可判定性。
- 注释写中文，包括包注释与导出符号注释。
- 纯 Go，无 cgo，无 `unsafe`。别引入需要 cgo 的依赖，
  那会打破单文件静态二进制的交付形态。

### 前端 TypeScript

- `frontend/tsconfig.json` 开了 `strict`、`noUnusedLocals`、
  `noUnusedParameters`，别绕过。
- 类型检查用 `make frontend-typecheck`，等价于 `tsc --noEmit`。
- JSX 运行时是 React 自动运行时：`jsx: "react-jsx"` +
  `jsxImportSource: "react"` + `@vitejs/plugin-react`。
  这三处必须成对维护，否则 tsc 与打包器各解析一套实现。
- 装依赖只用 `npm ci`。`frontend/package.json` 与
  `frontend/package-lock.json` 必须同步提交，只改一个 CI 装不全。
- 别把 `vite.config.ts` 的 `emptyOutDir` 改成 true。
  输出目录里住着 `//go:embed` 的持有文件
  `src/daemon/web_ui/static/assets.go`，清空会连它一起删。

### 契约

改动涉及下面任一项，先改契约再改实现：

- HTTP 路由、载荷字段、SSE 事件、错误码。
- `/proc/firewall/*` 的节点、权限、读写文法。
- netlink 消息的线格式与字段。

流程：

1. 改 `contract/*.fwidl`。
2. 跑 `python3 contract/gen.py`。
3. 跑 `make contract-drift`。
4. 跑 `make contract-check`。

请求体的 `Option<T>` 生成 TS 的 `field?: T | null`。
缺席和 `null` 都合法，表示「可以整个不提交」。

HTTP 未接线条目基线在 `contract/http_gap_baseline.txt`，只减不增。
补上一个缺口要删一行，新增缺口必须加一行并说明原因。

## 注释约定

- 全仓库统一中文注释。
- 注释解释为什么，不解释是什么。
- 危险路径、并发模型、失败取值语义要写清楚为什么这样定。
- 不写「这是某某函数」这类废话注释。

## 提交信息

遵循 Conventional Commits，格式：

```text
类型(范围): 简短描述

可选的详细说明

可选的关联 issue
```

| 类型 | 用途 | 例子 |
|------|------|------|
| `feat` | 新功能 | `feat(kmod): 受保护端口位图支持空集语义` |
| `fix` | 修缺陷 | `fix(build): daemon 的 -o 改绝对路径` |
| `docs` | 文档 | `docs(readme): 补内核版本口径` |
| `style` | 格式，不改行为 | `style(kmod): clang-format 18 清零` |
| `refactor` | 重构，不改行为 | `refactor(daemon): 删除无消费者的死代码` |
| `perf` | 性能 | `perf(kmod): 速率槽表分块申请避开 percpu 上限` |
| `test` | 测试 | `test(ci): 运行测试任务补装 pytest 与 PyYAML` |
| `chore` | 构建与工具 | `chore(deps): 修掉有补丁的依赖告警` |

范围用 `kmod`、`daemon`、`web`、`build`、`contract`、`ci`、`docs` 这类真实层次。

一次提交只做一件事。重构与功能分开提。格式改动与逻辑改动分开提。

## 分支与 PR

主干分支是 `master`。CI 触发条件写在
`.github/workflows/ci.yml` 的 `on.push` 与 `on.pull_request`。

```bash
git checkout master
git pull
git checkout -b feature/short-name

# 开发，跑门禁
git add <文件>
git commit -m "feat(daemon): 描述"
git push origin feature/short-name
```

在 GitHub 上向 `master` 发 Pull Request。
模板见 [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)。
维护者会在 48 小时内响应。合并后功能分支可删。

### PR 检查清单

- [ ] 上面六条门禁都跑过，输出贴进 PR。
- [ ] 只改了本 PR 声明范围内的文件。
- [ ] 新功能有对应测试；边界情况至少覆盖一个。
- [ ] 契约、生成物、实现、文档四者一致。
- [ ] 没有留下调试代码、`TODO`、`FIXME`。
- [ ] 没有硬编码的路径、端口、凭据。
- [ ] 文档同步更新（改了接口或配置字段时）。
- [ ] 提交信息符合上表类型。
- [ ] 没提交任何密钥或明文凭据。

## 评审看什么

| 维度 | 关注点 |
|------|--------|
| 正确性 | 判定方向对不对；空值、越界、错误返回都处理了没有 |
| 并发 | RCU 读端与写端的配合；释放路径会不会提前回收 |
| 包路径 | 钩子里有没有分配、阻塞、系统调用 |
| 契约 | 字段、权限、状态码、错误码是否四处一致 |
| 失败语义 | 拿不到数据时报空还是报零；会不会把未知说成结论 |
| 兼容性 | 内核 API 断层按存在性适配了没有 |
| 构建 | 有没有绕过 Makefile；产物落点对不对 |
| 可读性 | 命名看得出用途；函数只做一件事 |
| 测试 | 关键路径有测试；没删测试、没跳过测试 |
| 安全 | 输入校验、权限位、凭据处理 |

几条硬性回退理由：

- 门禁没过。
- 改了测试预期来迁就实现。
- 契约改了但生成物没重跑。
- 引入 cgo 依赖。
- 在文档里留下没跑过的命令输出。

## 报告问题

- Bug 用 [.github/ISSUE_TEMPLATE/bug_report.md](.github/ISSUE_TEMPLATE/bug_report.md)：
  写清内核版本、发行版、项目版本、复现步骤、期望与实际、相关日志。
- 功能请求用
  [.github/ISSUE_TEMPLATE/feature_request.md](.github/ISSUE_TEMPLATE/feature_request.md)：
  写清使用场景、替代方案、期望行为。
- 安全问题走 [SECURITY.md](SECURITY.md) 的渠道，不要开公开 Issue。

## 行为准则

- 讨论针对问题，不针对人。
- 反对某个方案时给理由和替代方案。
- 尊重他人的时间，评审意见一次说清。

## 许可证

本项目用 [MIT License](LICENSE)。提交代码即同意以 MIT 发布。
