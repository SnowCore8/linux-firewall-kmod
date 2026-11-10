---
kind: build_system
name: 构建系统：Makefile 统一编排内核模块、守护进程、前端与 deb 包
category: build_system
scope:
    - '**'
source_files:
    - Makefile
    - build-deb.sh
    - Makefile.dkms
    - dkms.conf
    - scripts/build-kmod-multi-version.sh
    - .github/workflows/ci.yml
    - .github/workflows/release.yml
    - firewall-daemon.service
---

## 1. 使用的系统与工具

- **顶层 Makefile**（`Makefile`，约 1100 行）是单一入口，编排 C 内核模块、Go 守护进程、React/Vite 前端、Python 契约生成器、测试与 deb 打包。
- **内核模块**通过 kbuild（`make -C $(KDIR) M=... modules`）编译为 `firewall.ko`，由 `src/kernel-module/Makefile` 描述源文件。
- **守护进程**使用 Go 1.23+（`GOVER ?= 1.23`），`go build ./cmd/firewall-daemon`，并启用 `-ldflags "-s -w=1"` 裁剪符号表。
- **前端**基于 Vite + React 19 + TypeScript，产物经 `go:embed` 嵌入守护进程二进制。
- **deb 包**走 Debian 标准流程：`debian/rules` + `dpkg-buildpackage`，由 `build-deb.sh` 驱动；内核模块在目标机通过 DKMS 编译。
- **CI** 基于 GitHub Actions（`.github/workflows/ci.yml`、`release.yml`、`gitbook.yml`），运行在 `ubuntu-26.04` runner。
- **辅助脚本**：`scripts/build-kmod-multi-version.sh`（多版本内核头文件编译）、`scripts/deploy.sh`（远程部署）、`scripts/test-kernel-compat.sh`、`scripts/fetch-geoip.sh`。

## 2. 关键文件与位置

| 角色 | 路径 |
|---|---|
| 顶层构建入口 | `Makefile` |
| DKMS 构建入口 | `Makefile.dkms` |
| DKMS 配置 | `dkms.conf` |
| deb 构建包装壳 | `build-deb.sh` |
| 多版本内核编译 | `scripts/build-kmod-multi-version.sh` |
| CI 流水线 | `.github/workflows/ci.yml` |
| Release 流水线 | `.github/workflows/release.yml` |
| GitBook 文档构建 | `.github/workflows/gitbook.yml` |
| 内核模块源码 Makefile | `src/kernel-module/Makefile` |
| 守护进程 Go module | `src/daemon/go.mod` |
| 前端构建配置 | `frontend/vite.config.ts` |
| systemd 单元模板 | `firewall-daemon.service` |

## 3. 架构与设计约定

### 3.1 Out-of-tree 构建隔离
所有中间产物与最终产物均落在 `build/` 目录（`BUILD_DIR := build`），源码树保持干净。内核模块的 kbuild 中间对象不写回 `src/kernel-module/`，而是先拷贝到 staging 树 `build/obj/kernel-module/<kernel.release>/tree/src/kernel-module/`，再 `M=` 指向该目录编译，最后把 `firewall.ko` 复制回 `build/kernel-module/`。

### 3.2 前端嵌入策略
Vite 产物输出到 `build/obj/frontend`，`make daemon` 时临时拷贝到 `src/daemon/web_ui/static/` 供 `//go:embed` 读取，并在 shell trap EXIT 中清理，仅保留 `assets.go` 入库。这保证源码树不包含前端构建产物。

### 3.3 依赖检查分层
`check-deps` 拆分为 `check-deps-kmod` / `check-deps-daemon` / `check-deps-frontend`，分别校验 gcc/make/linux-headers、Go ≥ 1.23、Node.js ≥ 18。CI 中 lint 任务固定 Go 1.26、Node 24，构建任务安装 ccache + linux-headers-generic 作为回退。

### 3.4 契约即构建门禁
`contract/*.fwidl` 是线格式与文本协议的单一真相源。`make contract` 调用 `contract/gen.py` 生成 C/TS/JSON 绑定；`make contract-drift` 比较生成器输出与已提交产物是否一致；`make contract-check` 依次执行 `verify_layout`、`verify_procfs`、`verify_http` 三个 Python 校验器，任一失败即中断 CI。

### 3.5 本地安装守卫
`install` / `uninstall` 目标通过 `_guard_local_install` 强制要求 `DESTDIR` 非空或显式传入 `FIREWALL_REMOTE_DEPLOY=1`（且必须来自命令行 origin），防止开发者误把未审版本直接装到本机根文件系统。所有实机安装应走 `./scripts/deploy.sh` 或 `.deb`。

### 3.6 多版本内核支持
`scripts/build-kmod-multi-version.sh` 扫描 `/lib/modules/*/build`，按主/次版本判断兼容性，支持智能模式（优先当前运行内核）、`--all`、指定版本、`--list`、`--check`。Makefile 暴露 `kmod-all` / `kernel-module-multi` 别名，以及 `kmod-remote` 通过 ssh/rsync 远程编译后 scp 回产物。

### 3.7 deb 包与 DKMS 分工
`build-deb.sh` 从 `CHANGELOG.md` 自动提取版本号（跳过 `[Unreleased]`），生成 `debian/changelog`，调用 `dpkg-buildpackage -b -us -uc`，并把产物重命名为 `linux-firewall-kmod-<version>.deb` 放入 `build/deb/`。DKMS 侧由 `dkms.conf` + `Makefile.dkms` 定义，`BUILT_MODULE_LOCATION=src/kernel-module`，`DEST_MODULE_LOCATION=/updates/dkms`，`AUTOINSTALL=yes`——内核模块不在构建机编译，而是在目标机安装 .deb 时由 DKMS 编译。

### 3.8 CI 流水线结构
- **lint**：clang-format（C）、gofmt（Go）、shellcheck（Shell）、yamllint（YAML）、go vet、单元测试、覆盖率、契约漂移校验。
- **frontend**：独立 job，npm ci → typecheck → vite build → 产物存在性校验 → manifest.webmanifest 字段校验 → Service Worker 语法检查。
- **build**：并行于 lint，安装 ccache + linux-headers，缓存 go/pkg/mod、ccache，编译守护进程 + 内核模块，上传 `build-artifacts`。
- **e2e**：下载 build 产物，针对本机内核重编 firewall.ko，探测可加载性，启动守护进程，跑 Playwright，报告归档。
- **test**：下载 build 产物，针对本机内核重编模块，insmod 验证兼容性，兼容则全量 pytest，不兼容则只跑守护进程相关用例（daemon/logparse/frp/ddos/webui/config_reload/log_rotation/netlink/lifecycle/multi_jail）。
- **release**：tag `v*` 触发，`VERSION=${GITHUB_REF#refs/tags/}`，调用 `./build-deb.sh "$VERSION"`，通过 `softprops/action-gh-release@v3` 发布到 GitHub Releases。

## 4. 约定与约束

- **构建产物不出源码树**：所有中间产物位于 `build/`，源码树只含源码与 `assets.go` 等受控文件（见 `Makefile` 注释与 `clean` 目标行为）。
- **Go 版本下限**：`GOVER ?= 1.23`，`check-deps-daemon` 用 `sort -V` 比较 `$(GOC) version` 与 `$(GOVER)`，低于此版本直接 exit 1。
- **Node.js 版本下限**：`check-deps-frontend` 解析 `node --version` 的主版本，小于 18 退出。
- **C 代码风格**：默认 `all` 目标包含 `format-check`，调用 `clang-format --dry-run --Werror`；可通过 `SKIP_FORMAT_CHECK=1` 跳过（用于紧急调试）。
- **YAML 配置风格**：若 `yamllint` 可用，`ci-format` 对 `config/` 执行 yamllint。
- **Shell 脚本质量**：CI lint 阶段对 `build-deb.sh scripts/*.sh` 执行 shellcheck。
- **守护进程静态链接**：CI 注释明确守护进程为纯 Go 构建（modernc.org/sqlite 等均为纯 Go），无 libyaml/libsqlite3/libmicrohttpd/libpcre2 等系统库依赖。
- **内核模块不可本地直装**：`_guard_local_install` 在未设置 `DESTDIR` 且未传 `FIREWALL_REMOTE_DEPLOY=1`（且必须来自 command line origin）时拒绝执行 install/uninstall。
- **契约一致性强制**：`contract-drift` 与 `contract-check` 是 CI 必经阶段，任何 .fwidl 变更都必须重新生成并提交对应产物，否则 CI 失败。
- **deb 版本号来源**：`build-deb.sh` 从 `CHANGELOG.md` 首行匹配 `^## (v|[0-9])` 提取版本，不以 git tag 为准；release 流水线才用 `${GITHUB_REF#refs/tags/}` 覆盖 `VERSION`。
- **内核模块 DKMS 安装路径**：`dkms.conf` 规定 `DEST_MODULE_LOCATION=/updates/dkms`，而非 `/lib/modules/$KVER/extra`。
- **前端 PWA 清单约束**：CI frontend job 校验 manifest.webmanifest 必须包含 name/short_name/start_url/display/background_color/theme_color/icons 字段，display 必须为 standalone，icons 必须包含 192x192 与 512x512 尺寸。
- **Service Worker 语法校验**：CI 对 `build/obj/frontend/sw.js` 执行 `node --check`。
- **E2E 环境限制处理**：GitHub Actions Azure VM 使用自定义内核，编译出的 .ko 可能与 e2e/test runner 的内核 vermagic 不匹配，因此这两个 job 会尝试 insmod 探测，失败则跳过内核相关用例而非让 CI 变红。