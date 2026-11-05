# 构建

本文与根 `Makefile`、`src/kernel-module/Makefile` 逐条对齐。
`make help` 只列了部分目标，完整清单见下文。

## 依赖

| 依赖 | 版本要求 | 出处 |
|------|---------|------|
| Go | `src/daemon/go.mod` 声明 `go 1.26.0` | `src/daemon/go.mod` |
| Makefile 的 Go 引导检查 | `GOVER ?= 1.23`，只保证有 Go 可用 | 根 `Makefile` |
| Node.js + npm | CI 用 `node-version: '24'` | `.github/workflows/ci.yml` 的 `frontend` / `build` / `e2e` |
| clang-format | 本仓库以 18 为准；`CHANGELOG.md` 记有一次「clang-format（18）违规清零」 | `.github/workflows/ci.yml`、`CHANGELOG.md` |
| 内核构建目录 | `KDIR ?= /lib/modules/$(shell uname -r)/build` | 根 `Makefile` |
| yamllint | 可选；缺失时 `format-check` 打印跳过 | 根 `Makefile` 的 `format-check` |
| Python 3 | 契约生成与校验 | `Makefile` 的 `PYTHON ?= python3` |

Go 依赖全为纯 Go，无 cgo，不需要系统开发库。
依赖清单见 `src/daemon/go.mod`。

> **clang-format 版本要对齐。** 不同大版本的排版规则不同，
> 本机版本与 CI 不一致时 `make format-check` 会误报。
> 本机没有系统包时可用 `pip install clang-format==18.1.8` 对齐。
> 该安装方式：未验证。

## 目标清单

| 目标 | 做什么 | 出处 |
|------|--------|------|
| `make` / `make all` | `.DEFAULT_GOAL := all`，`all: format-check build` | `Makefile` |
| `make build` | `kernel-module` + `daemon` | `Makefile` |
| `make build-quick` | 同上，不跑 `format-check` | `Makefile` |
| `make kernel-module` | 编内核模块，产物 `build/kernel-module/firewall.ko`（中间文件在 `build/obj/kernel-module/`） | `Makefile` |
| `make daemon` | 先出面板产物，再临时拷入 embed 目录 `go build`，退出即清理 | `Makefile` |
| `make frontend` | 面板构建，产物写入 `build/obj/frontend/` | `Makefile` |
| `make frontend-install` | 只装依赖：`npm ci --no-audit --no-fund` | `Makefile` |
| `make frontend-typecheck` | 只跑 `tsc --noEmit`，不产出文件 | `Makefile` |
| `make format` | `clang-format -i src/kernel-module/*.c *.h` | `Makefile` |
| `make format-check` | `clang-format --dry-run --Werror` + `yamllint config/` | `Makefile` |
| `make contract-drift` | 生成物必须等于生成器当前输出 | `Makefile` |
| `make contract-check` | 先 `contract-drift`，再跑三个校验器 | `Makefile` |
| `make test` | `sudo python3 -m pytest tests/ -v` | `Makefile` |
| `make ci` | `format-check` + `build` + `test` | `Makefile` |
| `make deb` | `build` 之后调 `./build-deb.sh` | `Makefile` |
| `make install` / `make uninstall` | 见下文「安装与卸载」 | `Makefile` |
| `make clean` | 清 `build/`、`target/`、`go clean`、面板产物（留 `assets.go`）、bench 二进制、Playwright/pytest 产物；不动入库的契约生成物 | `Makefile` |
| `make distclean` | `clean` + 内核源码目录中间文件 + clangd 缓存与 `compile_commands.json` | `Makefile` |
| `make help` | 打印目标列表 | `Makefile` |

跳过格式检查有两种方式：

```bash
make build-quick                 # 通过目标
make SKIP_FORMAT_CHECK=1 all     # 通过变量
```

## 编译内核模块

```bash
make kernel-module
```

产物 `build/kernel-module/firewall.ko`。构建时把 `src/kernel-module/*.{c,h}`、
`Makefile` 与 `contract/generated/*.h` 拷进
`build/obj/kernel-module/$(KERNEL_RELEASE)/tree/`，再在该副本上跑
`$(MAKE) -C $(KDIR) M=<副本>/src/kernel-module modules`，最后把 `.ko` 复制到
`build/kernel-module/`。`src/kernel-module/` 只放源码，不产生 `.o`、`.cmd`、
`Module.symvers` 等中间文件。

### Kbuild 描述

`src/kernel-module/Makefile`：

| 项 | 值 |
|----|-----|
| 模块名 | `obj-m := firewall.o` |
| 参与编译的 `.o` | 12 个，逐个对应一个 `fw_*.c` |
| 头文件搜索路径 | `ccflags-y += -I$(src)/../../contract/generated` |
| 警告 | `ccflags-y += -Wall -Wextra -Wno-unused-parameter` |

生成物（`netlink_uapi.h` / `procfs_uapi.h`）是线格式与文本协议的真相源，
模块只读不改。

> 表里没有 `-Werror`，也没有 `-DLINUX_VERSION_CODE` 这类版本宏定义。
> 内核适配按「宏是否存在」判断，见
> [内核模块](../architecture/kernel-module.md)「两处内核适配」。

### 内核构建目录缺失

`Makefile` 会打印一段说明并以 1 退出，列出三种处理方式和所有可用目录：

```bash
sudo apt install linux-headers-$(uname -r)
make build KDIR=$(find /lib/modules -maxdepth 2 -name build -type d | head -n1)
make daemon          # 只要守护进程时跳过内核模块
```

## 构建面板产物

面板产物落在 `build/obj/frontend/`（源码树之外），由 stamp 文件记录新鲜度：

```make
FRONTEND_OUT   := $(BUILD_OBJ_DIR)/frontend
FRONTEND_STAMP := $(BUILD_OBJ_DIR)/.frontend.stamp

frontend: $(FRONTEND_STAMP)

$(FRONTEND_STAMP): frontend-install $(FRONTEND_SRCS)
	cd frontend && npm run build
	touch $@
```

三条要点：

1. **依赖方向单一。** `frontend-install` 与前端源码是 stamp 的前置；面板目录不再与 `frontend` 互相依赖，
   make 不会丢弃依赖边，`npm ci` 一定先于 `npm run build`。
2. **构建目录在源码树之外。** `vite.config.ts` 的 `outDir` 是
   `../build/obj/frontend`，因此 `emptyOutDir: true` 安全——它只清构建目录，
   不会碰 `src/daemon/web_ui/static/` 里已入库的 `assets.go`。
   见 `frontend/vite.config.ts` 的注释与 [Web 前端](../architecture/frontend.md)。
3. **验证前端要走 `npm ci`。** 本地已存在的 `node_modules` 会掩盖
   `frontend/package.json` 里缺的依赖声明。

`npm run build` 等价于 `tsc --noEmit && vite build`
（`frontend/package.json` 的 `scripts`）。只要类型检查时跑 `make frontend-typecheck`。

## 构建守护进程

```bash
make daemon
```

`//go:embed` 只认包目录内的文件，所以 `make daemon` 在 `go build` 期间把面板
临时拷进 `src/daemon/web_ui/static/`，并用 `trap` 保证退出时清干净：

```make
daemon: $(FRONTEND_STAMP)
	@set -e; \
	    webui="$(PWD)/$(WEBUI_STATIC_DIR)"; \
	    cleanup() { find "$$webui" -mindepth 1 ! -name assets.go -delete; }; \
	    trap cleanup EXIT; \
	    cleanup; \
	    cp -a $(PWD)/$(FRONTEND_OUT)/. "$$webui"/; \
	    cd $(PWD)/$(DAEMON_SRCS_DIR) && go build -ldflags "-s -w=1" \
	        -o $(PWD)/$(DAEMON_BIN) ./cmd/firewall-daemon
```

| 要点 | 说明 |
|------|------|
| `-o` 必须是绝对路径 | 那一行先 `cd $(DAEMON_SRCS_DIR)`。相对写法会把二进制写到 `src/daemon/build/daemon/` 下（Go 还会顺手建出这个目录），仓库根的 `$(DAEMON_BIN)` 始终是空的，`install` / `deb` 与 CI 的产物检查都拿不到文件 |
| `-ldflags "-s -w=1"` | 链接期去掉符号表，产物即最终 stripped 二进制 |
| 面板必须先产出 | `//go:embed *`（`src/daemon/web_ui/static/assets.go`）才有东西可嵌；`go build` 本身不检查面板内容 |
| 拷贝必须可回滚 | `trap cleanup EXIT` 在成功、失败、Ctrl-C 下都执行；`assets.go` 由 `! -name assets.go` 保留，否则 `go build` 报「包内无 .go 文件」 |
| 体积 | `stat -c %s build/daemon/firewall-daemon` 实测 |

手动分步执行等价于：

```bash
make frontend
cp -a build/obj/frontend/. src/daemon/web_ui/static/
cd src/daemon && go build -ldflags "-s -w=1" \
    -o "$PWD/../../build/daemon/firewall-daemon" ./cmd/firewall-daemon
cd ../.. && find src/daemon/web_ui/static -mindepth 1 ! -name assets.go -delete
```

## 契约门禁

`contract/*.fwidl` 描述「应该是什么」。两条目标把它与实现对账：

| 目标 | 做什么 |
|------|--------|
| `make contract-drift` | 用 `python3 contract/gen.py --out-dir tmp/fw_gencheck` 重新生成，与 `contract/generated` 逐字节比对 |
| `make contract-check` | 先跑 `contract-drift`，再依次跑 `verify_layout`、`verify_procfs`、`verify_http`，**三个都跑完**再汇总退出码 |

三个校验器不短路：短路会让后两侧的问题在同一次 CI 里看不见。

`contract-check` 把 `GO=$(GOC)` 显式传进环境：`verify_http.py` 用它把生成物
`http_contract.go` 真编一遍，拿不到就打印「跳过」并当通过——
生成物编不过这种事故不能靠「环境里有没有 go」决定。

改契约的顺序固定：

```bash
# 1) 改 .fwidl
# 2) 重新生成
python3 contract/gen.py
# 3) 校验
make contract-check
```

## 测试与 CI 目标

| 目标 | 实际命令 |
|------|---------|
| `make test` | `sudo python3 -m pytest tests/ -v`；依赖 `$(KERNEL_MODULE)` 与 `$(DAEMON_BIN)` |
| `make ci` | `format-check` + `build` + `test` |

`Makefile` 只暴露 `make test`。按套件或关键字过滤请直接调 pytest，
见 [测试](testing.md)。

## 安装与卸载

`make install` 与 `make uninstall` 都挂了本机部署守卫：`_guard_local_install` 是两者
的第一个前置依赖。`DESTDIR` 为空且 `FIREWALL_REMOTE_DEPLOY != 1` 时它以 1 退出，打印
「禁止直接部署到本机」与三条合规路径，**不会进入 `build`**，宿主机根文件系统不被触碰。

守卫只在串行 make 下保证先于其它前置执行；`make -j install` 不保证前置顺序。

想「装但不碰本机」，用 `DESTDIR`：所有 `install -D` 都落在暂存目录下，而
`depmod` / `insmod` / `systemctl` 那几步按 `[ -z "$(DESTDIR)" ]` 跳过。

```bash
./scripts/deploy.sh <主机> [用户] [--mode deb|script]  # 推荐：deb 模式远端编译
make install DESTDIR=$(pwd)/build/stage           # 只暂存，不写本机
sudo env "PATH=$PATH" make install FIREWALL_REMOTE_DEPLOY=1   # 显式授权直写本机
```

部署不包成 make 目标：make 只负责构建/打包，运维动作直接调 `deploy.sh`。
主机也可以写成 `用户@主机` 单参数形式；位置参数顺序是「主机在前、用户在后」，
写反会直接报错，不会去连错地址。
脚本默认 `--mode deb`（远端 DKMS 编译，跨内核版本可用），`--mode script` 上传
本地预编译 `.ko`（要求 vermagic 与远端一致）；远程用户省略时默认 `root`。

`install` 的顺序：`_guard_local_install` → `build` → `install-kernel-module` →
`install-daemon` → `install-config` → `install-state` → `install-systemd` →
`install-start` → `install-verify`。

| 产物 | 默认路径 | 出处 |
|------|---------|------|
| `firewall.ko` | `/lib/modules/$(uname -r)/extra/` | `KERNEL_MODDIR` |
| `firewall-daemon` | `/usr/local/sbin/` | `PREFIX ?= /usr/local`、`SBINDIR` |
| YAML 配置 | `/etc/firewall/`，目录 0700、文件 0600 | `FIREWALLETC` |
| 状态目录 | `/var/lib/firewall/`，0700 | `$(STATEDIR)/firewall` |
| systemd 单元 | `/etc/systemd/system/firewall-daemon.service` | `install-systemd` |
| 模块自动加载 | `/etc/modules-load.d/firewall.conf` | 同上 |

`install-systemd` 用 `sed` 把 `firewall-daemon.service` 里的 `__SBINDIR__`
替换成 `$(SBINDIR)`，所以改 `PREFIX` 会一起带上。
想让 `make install` 也装到 `/usr/sbin/`：`make install PREFIX=/usr`。

`uninstall` 的顺序：`uninstall-stop` → `uninstall-kernel` → `uninstall-systemd` →
`uninstall-modload` → `uninstall-files` → `uninstall-config` → `uninstall-state` →
`uninstall-verify`。

## 构建 Debian 软件包

```bash
sudo apt install debhelper   # 构建机一次性依赖
make deb
# 或
./build-deb.sh [版本号]
```

打包走 debhelper：`build-deb.sh` 先由 `CHANGELOG.md` 生成临时的 `debian/changelog`，
再调用 `dpkg-buildpackage -b -us -uc`，最后把产物从项目上级目录搬到 `build/deb/`，
并按 `linux-firewall-kmod-<版本>.deb` 命名。`debian/rules` 只编译守护进程（含前端）；
内核模块由 DKMS 在目标机安装时编译。

`debian/changelog` 是生成物且不入库，版本只有一个来源：`CHANGELOG.md`。

版本号行为（`build-deb.sh`）：

| 情况 | 行为 |
|------|------|
| 不传参数 | 从 `CHANGELOG.md` 第一条 `## v` 记录提取；取不到直接报错退出 |
| 位置参数 | `./build-deb.sh 2.4.0` 显式指定 |
| `VERSION_ENV` 环境变量 | 优先级高于位置参数（`VERSION` 本身不生效） |
| 前缀 `v` | 会被剥掉（`VERSION="${VERSION#v}"`） |

维护者脚本在 `debian/linux-firewall-kmod.{postinst,prerm,postrm}`：`postinst` 依次执行
`dkms add` / `dkms build` / `dkms install`，加载模块、预创建 `/var/log/firewall.log`，
并在 `#DEBHELPER#` 展开（启用并启动服务）之后断言服务进入 active。

## 清理

```bash
make clean      # 删 build/、target/、面板产物（留 assets.go）、bench 二进制、测试产物；契约生成物保持入库状态
make distclean  # clean + 内核中间文件 + .cache/ 与 compile_commands.json
```

`clean` 不会删除 `contract/generated/*` 与 `httpcontract/http_contract.go`：它们是入库
文件，`contract-drift` 以入库内容为基线。需要重新生成用 `make contract`，要清空
重来用 `make contract-clean`。

`clean` 里那行是 `$(GOC) clean`，**不带参数**。
`go clean -cached` 不是合法参数（合法的是 `-cache`，那是清全局构建缓存，
不该由本仓库的 `clean` 触发）；写错时那一行会以 exit 2 中断整个 `clean`。

清理面板产物的两条命令都保留 `assets.go`：

```
find $(WEBUI_STATIC_DIR) -mindepth 1 ! -name assets.go -delete
```

## 交叉编译

内核模块按 Kbuild 的常规变量传：

```bash
make kernel-module KDIR=/path/to/kernel/source
```

`ARCH` / `CROSS_COMPILE` 由 `$(MAKE) -C $(KDIR)` 继承环境，
`Makefile` 本身不设置这两个变量。
本仓库未做过交叉编译验证：未验证。

守护进程是 Go，交叉编译走 Go 自己的变量：

```bash
cd src/daemon && GOOS=linux GOARCH=arm64 \
    go build -ldflags "-s -w=1" -o /tmp/firewall-daemon-arm64 ./cmd/firewall-daemon
```

面板经 `//go:embed` 进二进制，不需要单独部署。

## 构建产物

| 文件 | 说明 |
|------|------|
| `build/kernel-module/firewall.ko` | 内核模块（最终产物） |
| `build/daemon/firewall-daemon` | 守护进程二进制（stripped，内嵌面板） |
| `build/deb/*.deb` | Debian 包（最终产物） |
| `build/obj/kernel-module/<kernel.release>/tree/` | kbuild 中间产物：源码副本 + `.o`/`.cmd`/`Module.symvers` 等 |
| `build/obj/frontend/` | vite 产物：`index.html`、`app.js`、`chunk-*.js`、`style.css`、`sw.js`、`manifest.webmanifest`、`icons/` |
| `src/daemon/web_ui/static/assets.go` | `//go:embed` 持有文件（入库；面板文件只在 `make daemon` 期间临时出现在同目录） |

`build/` 与 `target/` 都不入库。源码树（`src/**`）在构建后保持零中间产物。

## 常见构建问题

| 症状 | 原因与处理 |
|------|-----------|
| `make: go: 没有那个文件或目录`，错误 127 | `sudo` 默认 `secure_path` 不含用户目录下的 Go 安装位置。先 `go version` 确认，再 `sudo --preserve-env=PATH make daemon`，或 `sudo env "PATH=$PATH" make ...` |
| `ERROR: Kernel configuration is invalid.` | 内核头文件与运行内核不匹配：`sudo apt install --reinstall linux-headers-$(uname -r)` |
| `没有规则可制作目标 'deb'` | 当前根 `Makefile` 已有 `deb:` 目标；确认在仓库根执行 `make deb` |
| `dpkg-buildpackage` 报 `debhelper-compat (= 13) but it is not installable` | 构建机缺 debhelper：`sudo apt install debhelper` |
| 面板改了但界面上看不到 | 只跑了 `make frontend`，没重跑 `make daemon`；二进制里嵌的还是旧包 |
| `go build` 报「包内无 .go 文件」 | `assets.go` 被清理动作删掉了。检查那条 `find` 是否带了 `! -name assets.go` |
| CI 的 `tsc` 全线找不到 `react` | `npm ci` 没执行，或 `frontend/package.json` 缺依赖声明。见上文面板目标的第 1、3 条要点 |
| `make format-check` 在与 CI 不同的行数上报错 | 本机 clang-format 大版本与 CI 不一致。对齐到 18 |

## 相关文档

- [测试](testing.md)：三层测试与 CI 六个任务
- [内核模块](../architecture/kernel-module.md)：源码文件清单与内核适配
- [Web 前端](../architecture/frontend.md)：Vite 配置与嵌入目录约束
