# 构建

本文档介绍 Linux Firewall 内核模块的构建系统和编译选项。

## Makefile 目标

> 与 `make help` 一一对齐。`make` 默认行为 = `make all`（含格式检查）。

### 主要目标

| 目标 | 说明 |
|------|------|
| `make` / `make all` / `make build` | 编译全部（前端 + 内核模块 + 守护进程，默认含 clang-format 检查） |
| `make build-quick` | 同上但跳过格式检查（CI 增量构建友好） |
| `make kernel-module` | 仅编译内核模块 |
| `make daemon` | 仅编译守护进程（会先执行 `make frontend`） |
| `make frontend` | 仅构建前端（`npm ci` + `vite build`），产物写入 `src/daemon/web_ui/static/` |
| `make frontend-typecheck` | 仅做前端类型检查（`tsc --noEmit`），不产出构建物 |
| `make install` | 安装到系统 |
| `make uninstall` | 从系统卸载 |
| `make help` | 显示完整帮助 |

> 前端为 React 19 + TypeScript + Vite + antd-mobile 5（移动优先，hash 路由，
> 支持 PWA），构建需要 **Node.js ≥ 20 + npm**。
> `make frontend` 用 `npm ci` 安装依赖，锁文件 `frontend/package-lock.json`
> 已入库以保证可复现。产物落在 Go 守护进程的嵌入目录
> `src/daemon/web_ui/static/`（vite 的 `outDir` 就指向它，文件名固定以便
> [go:embed](https://go.dev/ref/mod#go-gcimport) 按名查找，见
> `src/daemon/web_ui/static/assets.go`：面板文件在守护进程编译前已到位，
> `assets.go` 由 vite 输出自然覆盖）。

### 前端与 PWA

- **产物命名固定**：vite 输出 `app.js` / `style.css`（文件名不含内容哈希），
  Service Worker 缓存需按"缓存优先 + 后台刷新"实现，避免守护进程升级后旧 JS
  配新 HTML 导致白屏
- **`/api/*` 不缓存**：Service Worker 完全不拦截 `/api/*`，保证封禁列表与统计
  数据始终来自网络
- **PWA 安装受安全上下文限制**：Service Worker 仅在安全上下文（HTTPS 或
  `localhost`）注册。通过局域网 `http://<ip>:9119` 访问时，Chrome 会**静默
  拒绝**注册 SW，界面可用但无法"添加到主屏幕"；需要 PWA 安装能力时请用 HTTPS
  或本机 `localhost` 访问

### 构建目标

| 目标 | 说明 |
|------|------|
| `make` / `make all` / `make build` | 编译全部（前端 + 内核模块 + 守护进程，默认含 clang-format 检查） |
| `make kernel-module` | 仅编译内核模块 |
| `make daemon` | 仅编译守护进程（会先执行 `make frontend`） |
| `make frontend` | 仅构建前端（`npm ci` + `vite build`），产物写入 `src/daemon/web_ui/static/` |
| `make deb` | 构建 Debian 软件包（调用 `./build-deb.sh`，产物在 `build/deb/`） |

### 维护目标

| 目标 | 说明 |
|------|------|
| `make format` | 自动格式化全部 C 代码（应用 clang-format） |
| `make format-check` | 检查 C 代码格式（CI 默认调用，不合规则失败） |
| `make clean` | 清理 `build/` 产物 |
| `make distclean` | 清理所有生成文件（含内核模块 `.ko` / `.o` / `Module.symvers`） |

### 测试与 CI 目标

| 目标 | 说明 |
|------|------|
| `make test` | 运行所有测试（`sudo python3 -m pytest tests/ -v`） |
| `make ci` | CI 完整构建：format-check + build + test |

> Makefile 仅暴露 `make test`；按套件或类别过滤请直接调用
> `python3 -m pytest tests/test_NN_*.py -v` / `-k "关键词"`，
> 详见 [测试](testing.md)。

### 跳过格式检查

格式检查（clang-format）首次构建可能下载工具链较慢。两种跳过方式：

```bash
# 通过目标
make build-quick

# 通过变量
make SKIP_FORMAT_CHECK=1 all
```

## 构建内核模块

### 标准编译

```bash
make kernel-module
```

输出：

```
make -C /lib/modules/$(uname -r)/build M=$(PWD)/src/kernel-module modules
make[1]: Entering directory '/usr/src/linux-headers-...'
  CC [M]  src/kernel-module/fw_main.o
  LD [M]  src/kernel-module/firewall.ko
  MODPOST modules
make[1]: Leaving directory '/usr/src/linux-headers-...'
```

### 调试编译

```bash
make debug DL=2
```

调试级别说明：

| DL 值 | 输出内容 |
|-------|----------|
| 0 | 无调试输出 |
| 1 | 关键事件（模块加载/卸载） |
| 2 | 详细事件（封禁/解封操作） |
| 3 | 全部事件（包含数据包处理） |

## 构建守护进程

守护进程由 Go module `src/daemon` 构建（v2.2.0 起 Rust 实现被 Go 取代，
见 [架构设计 - 用户态守护进程](../architecture/daemon.md)）。`make daemon`
的先后顺序是「先前端、后 Go」：

```bash
# 先产出去面板文件（npm ci + vite build）
cd frontend && npm run build:only

# 再编译守护进程；go:embed 携带已落盘的静态面板进二进制
cd src/daemon && go build -ldflags "-s -w=1" \
    -o build/daemon/firewall-daemon ./cmd/firewall-daemon

# go 版本（源码内即 `run`）可测试入口
go test ./...
```

- 前端构建产物**不是**编译输入，而是**嵌入内容**：vite 的 `outDir` 直接指向
  `src/daemon/web_ui/static/`，文件固定为 `index.html` / `app.js` / `style.css` /
  `sw.js` / `manifest.webmanifest` / `icons/`，由
  `src/daemon/web_ui/static/assets.go`（`package webuiassets` + `//go:embed .`）
  声明携带。改动静态文件后必须重新跑 `make daemon`，否则守护进程仍提供旧面板。
- `go build -ldflags "-s -w=1"`：产出即最终 strip 二进制，`target/` 下没有原始输出；
  体积用 `stat -c %s build/daemon/firewall-daemon` 实测即可（内嵌前端大小随版本变化）。

## 完整构建

```bash
# 清理之前的构建
make clean

# 编译全部
make

# 安装
sudo make install
```

## 构建 Debian 软件包

`make deb` 依赖 `build` 目标（先编译内核模块与守护进程），再调用
`./build-deb.sh` 生成 `.deb` 包：

```bash
make deb
# 产物：build/deb/linux-firewall-kmod-<VERSION>.deb
ls -lh build/deb/
```

包内布局（`build-deb.sh` 模板目录，DKMS 模式）：

| 路径 | 内容 |
|------|------|
| `/usr/sbin/firewall-daemon` | 守护进程二进制（已 `strip`，内嵌前端产物） |
| `/usr/src/linux-firewall-kmod-<VERSION>/` | DKMS 源码（首次安装时由 dkms 编译） |
| `/etc/firewall/*.yaml` | YAML 配置 |
| `/etc/systemd/system/firewall-daemon.service` | systemd 单元 |
| `/var/log/firewall.log` | 守护进程独立日志（`logrotate` 30 天） |
| `/var/lib/firewall/` | 运行时状态目录 |

### 版本号行为

- **不传参数**：`build-deb.sh` 自动从 `CHANGELOG.md` 第一条
  `## v` 记录提取（如 `## v2.2.0` → `2.2.0`），找不到则回退
  硬编码默认值
- **位置参数**：`./build-deb.sh 2.2.0` 显式指定
- **不接受 `VERSION=` 环境变量形式**——`build-deb.sh` 只解析
  `$1`，不读 `VERSION` 环境变量。试图 `make deb VERSION=2.2.0`
  不会改变产物版本

> 守护进程在 .deb 中安装到 `/usr/sbin/`，而 `make install` 默认
> 走 `PREFIX=/usr/local` → `/usr/local/sbin/`。两者路径不同是因为
> .deb 走系统包约定（`/usr/sbin/`），而 `make install` 走 FHS
> 兼容约定。如需 `make install` 也装到 `/usr/sbin/`：
> `sudo make install PREFIX=/usr`

## 交叉编译

### 为目标架构编译

```bash
export ARCH=x86_64
export CROSS_COMPILE=x86_64-linux-gnu-

make kernel-module
```

### 指定内核源码路径

```bash
make kernel-module KDIR=/path/to/kernel/source
```

## 编译标志

### 内核模块标志

| 标志 | 说明 |
|------|------|
| `-Wall` | 启用所有警告 |
| `-Wextra` | 启用额外警告 |
| `-Werror` | 将警告视为错误 |
| `-O2` | 优化级别 2 |
| `-DLINUX_VERSION_CODE` | 内核版本检测 |

### 守护进程（Go）构建参数

编译行为由 `src/daemon/go.mod` 与 Makefile 的 `go build` 行决定：
`-ldflags "-s -w=1"` 在链接期直接去掉符号表，产物即最终 strip 二进制；
仓库里不再有 `[profile.release]` / `[profile.asan]` 这类 Cargo profile。

## 构建产物

### 内核模块

| 文件 | 说明 |
|------|------|
| `firewall.ko` | 内核模块（`build/kernel-module/firewall.ko`） |
| `firewall.mod.c` | 模块元数据 |
| `Module.symvers` | 符号版本 |
| `modules.order` | 模块顺序 |

### 守护进程

| 文件 | 说明 |
|------|------|
| `build/daemon/firewall-daemon` | 守护进程二进制（带 `-ldflags "-s -w=1"`，即 strip 版；内嵌前端产物） |
| `src/daemon/cmd/firewall-daemon/main.go` + `src/daemon/internal/*` | Go module 源码；组合根是 `cmd/firewall-daemon/main.go` |
| `src/daemon/web_ui/static/assets.go` | `//go:embed .`，携带面板文件进二进制（`index.html` / `app.js` / `style.css` / `sw.js` / `manifest.webmanifest` / `icons/`） |

## 安装位置

| 文件 | 安装路径 |
|------|----------|
| `firewall.ko` | `/lib/modules/$(uname -r)/extra/` |
| `firewall-daemon`（`make deb` 产物） | `/usr/sbin/firewall-daemon` |
| `firewall-daemon`（`make install` 产物） | `/usr/local/sbin/firewall-daemon`（默认 `PREFIX=/usr/local`） |
| `default.yaml` | `/etc/firewall/` |
| `firewall-daemon.service` | `/etc/systemd/system/` |

## 构建问题排查

### 内核头文件不匹配

```
ERROR: Kernel configuration is invalid.
```

解决方案：

```bash
sudo apt install --reinstall linux-headers-$(uname -r)
```

### `go: not found` under sudo / Go 不在 PATH

守护进程现在由 Go 构建，同样依赖 PATH 里有 Go（仓库要求 **Go 1.23+**）：

```
sudo make daemon
make: go: 没有那个文件或目录
make: *** [Makefile] 错误 127
```

`src/daemon/go.mod` 声明 MSRV 为 Go 1.23，旧工具链编译会失败（不是行为差异）：

```bash
go version   # 确认 PATH；如没有则安装 https://go.dev/dl/
sudo --preserve-env=PATH make daemon
# 或先 export PATH=$(printf '%s\n' "$PATH" ~/.go/bin) 再 sudo
```

## 构建问题排查（续）

### Go 编译产物不存在 / `go test ./...` 报错

`make daemon` 依赖前端产出；若面板目录没有落盘，go:embed "." 取不到任何文件而启动器
以错误退出。先确认产物齐全：

```bash
ls src/daemon/web_ui/static/          # index.html app.js style.css sw.js manifest.webmanifest icons/
make frontend && make daemon          # 前端缺失时跑这条补齐
go test ./...                        # Go module 自带单元测试，无需 sudo
```

### 权限不足

```
make install: Permission denied
```

解决方案：

```bash
sudo make install
```