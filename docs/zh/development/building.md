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
> 已入库以保证可复现；守护进程通过 `rust-embed` 把 `index.html` / `app.js` /
> `style.css` / `sw.js` / `manifest.webmanifest` / `icons/` 编进二进制，
> 运行期不需要 Node.js。

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

### 调试 / Sanitizer 目标

| 目标 | 说明 |
|------|------|
| `make debug` | 编译调试版本（`DL=1`） |
| `make debug DL=2` | 编译调试版本（级别 2，更详细） |
| `make asan` | 编译 AddressSanitizer 版本 |
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

守护进程（v2.2.0 起）已翻译为 Rust，由 `cargo` 构建。`make daemon`
实际命令：

```bash
cargo build --release
cp target/release/firewall-daemon build/daemon/firewall-daemon
```

### Rust release profile（`Cargo.toml`）

`Cargo.toml` 预定义 `release` / `dev` / `dev-with-debug` / `asan` 等 profile，对应不同用途：

| Profile | 构建产物 | 用途 | 编译命令 |
|---------|----------|------|----------|
| `release`（默认） | `strip` 的紧凑二进制 | 生产部署 | `cargo build --release` |
| `dev-with-debug` | 未 strip，含 DWARF + 符号 | 现场 crash 分析，配合 `addr2line` 反推栈 | `cargo build --release --profile dev-with-debug` |
| `asan` | 含 ASAN 运行时 | 内存安全检测，需 nightly | `cargo +nightly build --profile asan` |

#### release（默认）

```toml
[profile.release]
opt-level = 2
lto = true            # 链接时优化
codegen-units = 1     # 单代码生成单元，更好的内联
debug = false
strip = true
panic = "abort"       # 减小体积、避免 unwinding 表
```

产出 `strip` 后的紧凑二进制（内嵌前端产物，具体数值随前端产物大小变化，
可用 `stat -c %s build/daemon/firewall-daemon` 实测），适合 `make deb` /
`make install` 分发。

#### dev-with-debug

```toml
[profile.dev-with-debug]
inherits = "release"
debug = true
strip = false
```

继承 release 全部优化（`opt-level=2` + `lto=true`），**保留 DWARF +
符号表**。生产等效速度但可定位 crash：

```bash
cargo build --profile dev-with-debug
addr2line -e build/daemon/firewall-daemon 0x401a23
```

#### asan（nightly opt-in）

```toml
[profile.asan]
inherits = "dev"
opt-level = 1
debug = true
lto = false
```

**需要 nightly toolchain**（`rustup install nightly`），用于
AddressSanitizer 内存检测。`make asan` 目标会自动选择该 profile。

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

### 守护进程（Rust）profile

守护进程已无 C 标志配置项，编译行为完全由 `Cargo.toml` 的
`[profile.*]` 控制。详见 [构建守护进程 → Rust release profile](#rust-release-profile-cargotoml)。

- `release`：`lto=true` + `strip=true` + `debug=false` + `panic="abort"`
  → `strip` 后的紧凑二进制
- `dev-with-debug`：继承 release，保留 DWARF + 符号
- `asan`：nightly opt-in，含 ASAN 运行时

## 构建产物

### 内核模块

| 文件 | 说明 |
|------|------|
| `firewall.ko` | 内核模块 |
| `firewall.mod.c` | 模块元数据 |
| `Module.symvers` | 符号版本 |
| `modules.order` | 模块顺序 |

### 守护进程

| 文件 | 说明 |
|------|------|
| `build/daemon/firewall-daemon` | 守护进程二进制（已 `strip`，内嵌前端产物，默认 `release` profile；体积用 `stat -c %s build/daemon/firewall-daemon` 实测） |
| `target/release/firewall-daemon` | `cargo` 原始输出位置（`make daemon` 复制到 `build/daemon/`） |
| `build/daemon/firewall-daemon-asan` | ASAN 版本（`make asan` 产物，体积较大含 ASAN 运行时） |

> `dev-with-debug` profile 的产物不通过 `make daemon` 复制到
> `build/daemon/`，需手动从 `target/dev-with-debug/` 取。

### 安装位置

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

### `cargo: not found` under sudo

`sudo` 默认 `secure_path` 不含 `~/.cargo/bin`，常见于 rustup 用户级
安装。`make test` 内部已 `sudo python3 -m pytest tests/ -v`，
pytest 运行环境会继承当前 PATH（包含 `~/.cargo/bin`），
问题自动规避。但如果手动 `sudo make daemon` 直接调用会失败：

```
sudo make daemon
make: cargo: 没有那个文件或目录
make: *** [Makefile:101: daemon] 错误 127
```

解决方案（任选其一）：

```bash
# 1) sudo 前先 source
source ~/.cargo/env
sudo make daemon

# 2) 用 --preserve-env 显式带 PATH
sudo --preserve-env=PATH make daemon

# 3) 装到系统路径（不推荐，与 rustup 用户隔离理念冲突）
sudo cp ~/.cargo/bin/cargo /usr/local/bin/
```

### 库版本不兼容

```
error[E0432]: unresolved import `regex`
```

解决方案：

```bash
cargo build
# cargo 会自动下载并编译依赖
```

### 权限不足

```
make install: Permission denied
```

解决方案：

```bash
sudo make install
```