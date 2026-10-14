# 构建

本文与根 `Makefile`、`src/kernel-module/Makefile` 逐条对齐。
`make help` 只列了部分目标，完整清单见下文。

## 依赖

| 依赖 | 版本要求 | 出处 |
|------|---------|------|
| Go | `src/daemon/go.mod` 声明 `go 1.26.0` | `src/daemon/go.mod` |
| Makefile 的 Go 引导检查 | `GOVER ?= 1.23`，只保证有 Go 可用 | 根 `Makefile` |
| Node.js + npm | CI 用 `node-version: '22'` | `.github/workflows/ci.yml` 的 `frontend` / `build` / `e2e` |
| clang-format | 本仓库以 18 为准；`CHANGELOG.md` 记有一次「clang-format（18）违规清零」 | `.github/workflows/ci.yml`、`CHANGELOG.md` |
| 内核构建目录 | `KDIR ?= /lib/modules/$(shell uname -r)/build` | 根 `Makefile` |
| yamllint | 可选；缺失时 `format-check` 打印跳过 | 根 `Makefile` 的 `format-check` |
| Python 3 | 契约生成与校验 | `Makefile` 的 `PYTHON ?= python3` |

Go 依赖全为纯 Go，无 cgo，不需要系统开发库。
依赖清单见 `src/daemon/go.mod`。

> **clang-format 版本要对齐。** 不同大版本的排版规则不同，
> 本机版本与 CI 不一致时 `make format-check` 会误报。
> 本机没有系统包时可用 `pip install clang-format==18.1.8` 对齐。
> 该安装方式：未验证（本次未执行）。

## 目标清单

| 目标 | 做什么 | 出处 |
|------|--------|------|
| `make` / `make all` | `.DEFAULT_GOAL := all`，`all: format-check build` | `Makefile` |
| `make build` | `kernel-module` + `daemon` | `Makefile` |
| `make build-quick` | 同上，不跑 `format-check` | `Makefile` |
| `make kernel-module` | 编内核模块，产物 `build/kernel-module/firewall.ko` | `Makefile` |
| `make daemon` | 先出面板产物，再 `go build` | `Makefile` |
| `make frontend` | 面板构建，产物写入 `src/daemon/web_ui/static/` | `Makefile` |
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
| `make clean` | 清 `build/`、`target/`、`go clean`、清面板产物但留 `assets.go` | `Makefile` |
| `make distclean` | `clean` + 清内核源码目录的中间文件 | `Makefile` |
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

产物 `build/kernel-module/firewall.ko`。构建过程在 `src/kernel-module/` 里跑
`$(MAKE) -C $(KDIR) M=$(PWD)/src/kernel-module modules`，随后把 `.ko` 复制到
`build/kernel-module/`，并清掉源码目录里的中间文件
（`.o`、`.ko`、`.mod.c`、`.mod.o`、`.mod`、`.*.cmd`、`modules.order`、
`Module.symvers`、`.module-common.o`）。

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

面板产物的真实依赖是两件事：装好的依赖，和全部前端源文件。

```make
FRONTEND_SRCS := frontend/package.json frontend/package-lock.json \
    frontend/tsconfig.json frontend/vite.config.ts frontend/index.html \
    $(shell find frontend/src frontend/public -type f)

$(WEBUI_STATIC_DIR): frontend-install $(FRONTEND_SRCS)
	mkdir -p $(WEBUI_STATIC_DIR)
	find $(WEBUI_STATIC_DIR) -mindepth 1 ! -name assets.go -delete
	cd frontend && npm run build
```

三条要点：

1. **依赖方向不能反过来。** 早期写法让 `frontend` 与面板目录互为依赖，
   make 会丢弃其中一条（CI 日志
   `Circular frontend <- src/daemon/web_ui/static dependency dropped`），
   结果是 `npm ci` 从不执行、`tsc` 因找不到 `react` / `vite/client` 类型而全线报错。
2. **重建前清陈旧产物，但必须留下 `assets.go`。**
   它是 `//go:embed` 的持有文件，删掉后 `go build` 报「包内无 .go 文件」。
   Vite 侧配 `emptyOutDir: false` 正是因为同一个目录里住着它。
   见 `frontend/vite.config.ts` 的注释与 [Web 前端](../architecture/frontend.md)。
3. **验证前端要走 `npm ci`。** 本地已存在的 `node_modules` 会掩盖
   `frontend/package.json` 里缺的依赖声明。

`npm run build` 等价于 `tsc --noEmit && vite build`
（`frontend/package.json` 的 `scripts`）。只要类型检查时跑 `make frontend-typecheck`。

## 构建守护进程

```bash
make daemon
```

`make daemon` 的前置是面板产物目录，再跑 `go build`：

```make
@cd $(DAEMON_SRCS_DIR) && go build -ldflags "-s -w=1" \
        -o $(PWD)/$(DAEMON_BIN) ./cmd/firewall-daemon
```

| 要点 | 说明 |
|------|------|
| `-o` 必须是绝对路径 | 那一行先 `cd $(DAEMON_SRCS_DIR)`。相对写法会把二进制写到 `src/daemon/build/daemon/` 下（Go 还会顺手建出这个目录），仓库根的 `$(DAEMON_BIN)` 始终是空的，`install` / `deb` 与 CI 的产物检查都拿不到文件 |
| `-ldflags "-s -w=1"` | 链接期去掉符号表，产物即最终 stripped 二进制 |
| 面板必须先产出 | `//go:embed *`（`src/daemon/web_ui/static/assets.go`）才有东西可嵌；`go build` 本身不检查面板内容 |
| 体积 | `stat -c %s build/daemon/firewall-daemon` 实测 |

手动分步执行等价于：

```bash
make frontend
cd src/daemon && go build -ldflags "-s -w=1" \
    -o "$PWD/../../build/daemon/firewall-daemon" ./cmd/firewall-daemon
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

`make install` 没有本机部署守卫：`DESTDIR` 为空时它直接写宿主机的根文件系统。
`Makefile` 里定义了 `_guard_local_install`（打印「禁止直接部署到本机」与三条合规
路径），但它既不是 `install` 也不是 `uninstall` 的依赖，`make -n install` 里看不到
它的任何输出，`FIREWALL_REMOTE_DEPLOY` 因此也只是那个未挂接目标自己的变量。

想「装但不碰本机」，用 `DESTDIR`：所有 `install -D` 都落在暂存目录下，而
`depmod` / `insmod` / `systemctl` 那几步按 `[ -z "$(DESTDIR)" ]` 跳过。

```bash
./scripts/deploy.sh <远程主机> [远程用户]          # 推荐：本地编译，只上传产物
make install DESTDIR=$(pwd)/build/stage           # 只暂存，不写本机
sudo env "PATH=$PATH" make install                # 直接写本机（当前无守卫）
```

`install` 的顺序：`build` → `install-kernel-module` → `install-daemon` →
`install-config` → `install-state` → `install-systemd` → `install-start` →
`install-verify`。

| 产物 | 默认路径 | 出处 |
|------|---------|------|
| `firewall.ko` | `/lib/modules/$(uname -r)/extra/` | `KERNEL_MODDIR` |
| `firewall-daemon` | `/usr/local/sbin/` | `PREFIX ?= /usr/local`、`SBINDIR` |
| YAML 配置 | `/etc/firewall/`，目录 0700、文件 0600 | `FIREWALLETC` |
| 状态目录 | `/var/lib/firewall/`，0700 | `RUNSTATEDIR` |
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
make deb
# 或
./build-deb.sh [版本号]
```

`make deb` 依赖 `build`，再调 `./build-deb.sh`。中间目录是 `build/deb`。

版本号行为（`build-deb.sh`）：

| 情况 | 行为 |
|------|------|
| 不传参数 | 从 `CHANGELOG.md` 第一条 `## v` 记录提取；取不到则回退默认值 `2.2.0` |
| 位置参数 | `./build-deb.sh 2.2.0` 显式指定 |
| `VERSION=` 环境变量 | **不生效**：脚本只解析 `$1`，不读 `VERSION` |
| 前缀 `v` | 会被剥掉（`VERSION="${VERSION#v}"`） |

包是 DKMS 模式：安装时由 dkms 针对当前内核编译模块，
脚本模板里 `dkms add` / `dkms build` / `dkms install` 三条按顺序执行。

## 清理

```bash
make clean      # 删 build/ 与 target/，cd src/daemon && go clean，清面板产物并保留 assets.go
make distclean  # clean + 清内核源码目录的 .*.cmd / .*.o / .*.d / .tmp_versions / *.symversions
```

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
| `build/kernel-module/firewall.ko` | 内核模块 |
| `build/daemon/firewall-daemon` | 守护进程二进制（stripped，内嵌面板） |
| `src/daemon/web_ui/static/` | 面板产物：`index.html`、`app.js`、`style.css`、`sw.js`、`manifest.webmanifest`、`icons/`、`earth-night.webp`，另有已入库的 `assets.go` |
| `src/kernel-module/Makefile` | Kbuild 描述（12 个 `.o`） |

`build/` 与 `target/` 都不入库。

## 常见构建问题

| 症状 | 原因与处理 |
|------|-----------|
| `make: go: 没有那个文件或目录`，错误 127 | `sudo` 默认 `secure_path` 不含用户目录下的 Go 安装位置。先 `go version` 确认，再 `sudo --preserve-env=PATH make daemon`，或 `sudo env "PATH=$PATH" make ...` |
| `ERROR: Kernel configuration is invalid.` | 内核头文件与运行内核不匹配：`sudo apt install --reinstall linux-headers-$(uname -r)` |
| `没有规则可制作目标 'deb'` | 用的是旧版 `Makefile`；当前仓库已有 `deb:` 目标 |
| 面板改了但界面上看不到 | 只跑了 `make frontend`，没重跑 `make daemon`；二进制里嵌的还是旧包 |
| `go build` 报「包内无 .go 文件」 | `assets.go` 被清理动作删掉了。检查那条 `find` 是否带了 `! -name assets.go` |
| CI 的 `tsc` 全线找不到 `react` | `npm ci` 没执行，或 `frontend/package.json` 缺依赖声明。见上文面板目标的第 1、3 条要点 |
| `make format-check` 在与 CI 不同的行数上报错 | 本机 clang-format 大版本与 CI 不一致。对齐到 18 |

## 相关文档

- [测试](testing.md)：三层测试与 CI 六个任务
- [内核模块](../architecture/kernel-module.md)：源码文件清单与内核适配
- [Web 前端](../architecture/frontend.md)：Vite 配置与嵌入目录约束
