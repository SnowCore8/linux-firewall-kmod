# 安装

本文给出编译、安装、启动、卸载的真实命令。
所有命令都与仓库的 `Makefile` 和 `.github/workflows/ci.yml` 核对过。

## 一、需要的环境

| 项目 | 要求 | 依据 |
|------|------|------|
| 内核头文件 | 与运行内核一致 | `Makefile` 检查 `/lib/modules/$(uname -r)/build` |
| C 编译工具链 | build-essential | CI build 作业安装它 |
| clang-format | 必装（默认目标会跑格式检查） | `Makefile` 的 `format-check` |
| Go | 1.26 以上 | `src/daemon/go.mod` 声明 `go 1.26.0` |
| Node.js + npm | Node 22 | CI 用 `setup-node` 装 22 |
| root 权限 | 加载模块、装服务都需要 | `insmod`、`systemctl` |

前端依赖锁在 `frontend/package-lock.json`，构建用 `npm ci`。

跑集成测试还需要：`python3-pytest`、`python3-yaml`、`sqlite3` 命令行工具（CI 的 test 作业装的就是这三个）。

### 内核版本

仓库的实测记录：

| 内核 | 编译 | 加载 |
|------|------|------|
| 6.8.0-146 | 通过 | 通过 |
| 7.0.0-38 | 通过 | 未验证 |
| 5.x | 未验证 | 未验证 |

不要把这行当成保证清单。做法是：先按你自己的内核编译，再试着加载。
编译或加载过不去，看 [故障排查](../operations/troubleshooting.md) 的「模块无法加载」。

## 二、装编译依赖

Debian / Ubuntu：

```bash
sudo apt update
sudo apt install -y build-essential clang-format \
    linux-headers-$(uname -r)
```

Go、Node、npm 请装到上面的版本，并确保它们在 `PATH` 里。
`sudo` 默认会换掉 `PATH`，所以安装命令里要显式带上它（见第四节）。

## 三、编译

```bash
git clone https://github.com/SnowCore8/linux-firewall-kmod.git
cd linux-firewall-kmod
```

| 命令 | 产出 |
|------|------|
| `make` | 格式检查 + 内核模块 + 守护进程（默认目标） |
| `make build-quick` | 同上，跳过格式检查 |
| `make SKIP_FORMAT_CHECK=1 all` | 同上，用变量跳过 |
| `make kernel-module` | 只编内核模块 |
| `make daemon` | 只编守护进程（先跑 `npm ci` 和 vite 构建） |
| `make frontend` | 只构建前端 |
| `make frontend-typecheck` | 只跑前端类型检查 |
| `make clean` | 清掉构建产物 |

产物路径固定两个：

| 产物 | 路径 |
|------|------|
| 内核模块 | `build/kernel-module/firewall.ko` |
| 守护进程 | `build/daemon/firewall-daemon` |

### 内核头文件不在标准位置

CI 的 Azure 机器就是这个情况。指定构建目录即可：

```bash
make kernel-module KDIR=/lib/modules/$(uname -r)/build
```

不知道有哪些目录可用时：

```bash
find /lib/modules -maxdepth 2 -name build -type d
```

只要守护进程，不编内核模块，用 `make daemon`。

## 四、安装到系统

```bash
sudo env "PATH=$PATH" make install
```

`env "PATH=$PATH"` 是把当前 `PATH` 带进 root 环境，让 `make` 找到 Go 和 npm。

这条命令按固定顺序做八件事（与 `Makefile` 的 `install` 目标一致）：

1. `build`：编译内核模块和守护进程
2. `install-kernel-module`：装模块，然后跑 `depmod -a`
3. `install-daemon`：装守护进程
4. `install-config`：装 `config/*.yaml`
5. `install-state`：建状态目录
6. `install-systemd`：装服务单元和开机加载配置，跑 `daemon-reload`
7. `install-start`：加载模块、enable 并 start 服务
8. `install-verify`：逐项检查文件和服务是否就位

装出来的位置：

| 内容 | 位置 |
|------|------|
| 内核模块 | `/lib/modules/$(uname -r)/extra/firewall.ko` |
| 守护进程 | `/usr/local/sbin/firewall-daemon` |
| 配置文件 | `/etc/firewall/`（目录 0700，YAML 0600，属主 root:root） |
| 状态目录 | `/var/lib/firewall/`（0700）；内核侧写 `state`，守护进程写 `history.db`（由 `defaults.history_db_path` 决定，留空则不建库） |
| 服务单元 | `/etc/systemd/system/firewall-daemon.service` |
| 开机加载 | `/etc/modules-load.d/firewall.conf` |

`/etc/firewall/` 里装的是 `config/` 目录下全部 `*.yaml`，当前 13 份。

### 关于本机安装守卫

`Makefile` 里另有一个 `_guard_local_install` 目标，注释写着禁止直接装本机，
并给出三条路径：`./scripts/deploy.sh <远程主机>`、`make install DESTDIR=<目录>`、
`make install FIREWALL_REMOTE_DEPLOY=1`。

按当前 `Makefile`，`install` 和 `uninstall` 都没有依赖这个守卫目标
（`make -n install` 里看不到它的任何输出），所以直接 `sudo make install` 不会被拦。
想走审计轨迹就用上面三条之一；只想暂存不写本机时，`DESTDIR` 非空会让 `depmod` /
`insmod` / `systemctl` 这些动本机的步骤按 `[ -z "$(DESTDIR)" ]` 跳过。

### 只想打包，不写本机

```bash
make install DESTDIR=$(pwd)/build/stage
```

DESTDIR 模式下服务不会启动。装完包后要自己 enable 和 start。

### 打成 .deb

```bash
make deb
```

它调用 `./build-deb.sh`，产物在 `build/deb/linux-firewall-kmod-<版本>.deb`。
内核模块走 DKMS：在目标机器安装时才编译，内核升级后自动重编。

## 五、systemd 服务

服务单元的执行命令是：

```text
/usr/local/sbin/firewall-daemon -C /etc/firewall
```

`-C` 是配置目录，目录下所有 `.yaml` / `.yml` 按文件名字母序合并。
热重载靠 `systemctl reload firewall-daemon`，单元里写的是给主进程发 `HUP`。

| 命令 | 作用 |
|------|------|
| `sudo systemctl start firewall-daemon` | 启动 |
| `sudo systemctl stop firewall-daemon` | 停止 |
| `sudo systemctl enable firewall-daemon` | 开机自启 |
| `sudo systemctl status firewall-daemon` | 看状态 |
| `sudo journalctl -u firewall-daemon -f` | 追日志 |

开机自动加载模块由 `/etc/modules-load.d/firewall.conf` 负责，里面一行：`firewall`。

## 六、手动加载模块

不装服务，直接试：

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
```

验证：

```bash
lsmod | grep firewall
ls /proc/firewall/
sudo cat /proc/firewall/config
```

`ls /proc/firewall/` 应列出 13 个条目，清单见 [ProcFS 接口](../configuration/procfs.md)。

装好之后改用 `modprobe` 也行：

```bash
sudo modprobe firewall
```

卸载模块：

```bash
sudo rmmod firewall
```

### 模块参数

参数名与默认值以 `src/kernel-module/fw_main.c` 为准：

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `fw_ban_time` | 600 | 默认封禁时长（秒） |
| `state_file` | `/var/lib/firewall/state` | 封禁与白名单的状态文件 |
| `fw_max_bans_per_second` | 200 | 每秒最多新增多少条封禁 |
| `fw_max_ban_entries` | 65535 | 封禁表条目上限 |
| `fw_max_whitelist_entries` | 65535 | 白名单条目上限 |
| `fw_max_rate_entries` | 65536 | 速率表条目上限，可用范围 1024–262144 |
| `fw_max_local_ips` | 256 | 本机地址集合的容量下界，不够时按需扩容 |
| `fw_static_threshold` | 1 | 静态阈值检测开关 |
| `fw_dynamic_threshold` | 0 | 动态阈值检测开关 |
| `fw_ddos_detection` | 1 | DDoS 检测总开关 |

## 七、前台试跑守护进程

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml
```

常用参数（来自 `src/daemon/internal/config/args.go`）：

| 参数 | 作用 |
|------|------|
| `-c`、`--config <文件>` | 单文件配置，缺省路径 `/etc/firewall-daemon/config.yml` |
| `-C`、`--config-dir <目录>` | 目录配置，按名字母序合并 |
| `-d`、`--daemon` | 后台运行并写 PID 文件 |
| `--no-strict` | 忽略未知配置键（默认严格，未知键直接报错） |
| `--rollback` | 回滚到上一个配置版本，要求守护进程在跑 |
| `-h`、`--help` | 打印帮助 |

## 八、跑测试

```bash
# 集成测试（只跑 pytest，需要 root）
make test

# 守护进程单元测试
cd src/daemon && go test ./...
```

`make test` 展开成 `sudo python3 -m pytest tests/ -v`。
它先依赖内核模块和守护进程两个产物。

## 九、卸载

```bash
sudo make uninstall
```

顺序是：停服务 → 卸模块并删模块文件 → 删服务单元 → 删开机加载配置 → 删二进制和运行期文件 → 删 `/etc/firewall` → 删 `/var/lib/firewall` 和 `/var/log/firewall.log*` → 复查。

系统日志（`/var/log/auth.log`、journal）不归本项目管，不会被删。

## 十、装完之后

打开面板：`http://<主机地址>:9119/dashboard`。
端口来自配置的 `defaults.metrics_port`，默认 9119。
配了 `metrics_username` 和 `metrics_password` 就要先登录，细节见 [YAML 配置](../configuration/yaml-config.md)。

封禁和白名单的手工操作见 [ProcFS 接口](../configuration/procfs.md)。
