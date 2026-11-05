# 构建系统指南

本文档说明项目的标准化构建流程、依赖管理和多版本内核模块编译。

## 目录

- [快速开始](#快速开始)
- [依赖检查](#依赖检查)
- [契约生成](#契约生成)
- [构建目标](#构建目标)
- [多版本编译](#多版本编译)
- [远程编译](#远程编译)
- [构建产物](#构建产物)
- [故障排查](#故障排查)

## 快速开始

**标准构建流程**（推荐新手）：

```bash
# 1. 检查依赖
make check-deps

# 2. 编译内核模块（自动生成契约文件）
make kmod

# 3. 编译守护进程（含前端）
make daemon

# 4. 运行测试
make test
```

**一键构建**（跳过格式检查）：

```bash
make build-quick
```

## 依赖检查

构建系统提供细粒度的依赖检查，在编译前发现环境问题。

### 全量检查

```bash
make check-deps
```

检查所有组件的依赖：gcc、make、内核头文件、Go 1.23+、Node.js 18+、npm。

### 分类检查

```bash
make check-deps-kmod         # 仅内核模块：gcc、make、内核头文件
make check-deps-daemon       # 仅守护进程：Go 1.23+
make check-deps-frontend     # 仅前端：Node.js 18+、npm
```

### 依赖要求

| 组件 | 依赖 | 最低版本 | 安装命令 |
|------|------|---------|---------|
| 内核模块 | gcc | - | `sudo apt install gcc` |
| 内核模块 | make | - | `sudo apt install make` |
| 内核模块 | 内核头文件 | 匹配运行内核 | `sudo apt install linux-headers-$(uname -r)` |
| 内核模块 | clang-format | 推荐 | `sudo apt install clang-format` |
| 守护进程 | Go | 1.23 | `sudo apt install golang-go` |
| 前端 | Node.js | 18 | `sudo apt install nodejs` |
| 前端 | npm | - | `sudo apt install npm` |

## 契约生成

契约文件定义内核模块、守护进程、前端之间的通信协议。

### 自动生成

内核模块编译时自动生成契约文件：

```bash
make kmod    # 自动依赖 contract 目标
```

### 手动生成

```bash
make contract              # 生成所有契约文件
make contract-clean        # 清理生成的契约文件
```

### 生成的文件

```
contract/generated/
├── netlink_uapi.h         # Netlink 协议头文件（内核模块）
├── netlink_layout.json    # Netlink 布局定义
├── netlink.d.ts           # Netlink TypeScript 定义
├── procfs_uapi.h          # Procfs 协议头文件（内核模块）
├── procfs_layout.json     # Procfs 布局定义
├── http_layout.json       # HTTP API 布局定义
└── http_contract.ts       # HTTP API TypeScript 定义
```

### 契约校验

```bash
make contract-check        # 完整校验（含漂移检查）
make contract-drift        # 仅检查契约漂移
```

## 构建目标

### 内核模块

```bash
make kmod                  # 编译当前内核版本的模块
make kernel-module         # 同上（完整名称）
```

**指定内核版本**：

```bash
make kmod KVER=6.8.0-147-generic
```

**指定内核构建目录**：

```bash
make kmod KDIR=/lib/modules/6.8.0-147-generic/build
```

### 守护进程

```bash
make daemon                # 编译守护进程（含前端）
```

### 前端

```bash
make frontend              # 仅构建前端
make frontend-typecheck    # 仅做类型检查
```

### 完整构建

```bash
make all                   # 格式检查 + 内核模块 + 守护进程
make build                 # 同上（不含格式检查）
make build-quick           # 跳过格式检查的快速构建
```

### 代码质量

```bash
make format                # 自动格式化 C 代码
make format-check          # 检查代码格式
```

## 多版本编译

Linux 内核模块**不跨版本兼容**（符号版本校验），必须为目标内核单独编译。

### 使用 Makefile 目标

```bash
make kmod-all              # 编译所有已安装内核版本的模块
```

### 使用构建脚本

```bash
# 智能模式（优先编译当前运行内核）
./scripts/build-kmod-multi-version.sh

# 编译所有已安装头文件的版本
./scripts/build-kmod-multi-version.sh --all

# 列出可用版本与兼容性
./scripts/build-kmod-multi-version.sh --list

# 仅检测兼容性
./scripts/build-kmod-multi-version.sh --check

# 指定版本
./scripts/build-kmod-multi-version.sh 6.8.0-147-generic
./scripts/build-kmod-multi-version.sh 7.0.0-42-generic
```

### 兼容性检测

脚本自动检测：
- 当前运行内核版本
- 已安装的内核头文件
- 版本兼容性（主版本和次版本匹配）
- 符号兼容性（通过实际编译验证）

### 产物位置

```
build/kernel-module/
├── firewall.ko                    # 当前内核版本（make kmod）
├── 6.8.0-147-generic/
│   └── firewall.ko                # 指定版本
└── 7.0.0-42-generic/
    └── firewall.ko                # 指定版本
```

## 远程编译

在远程机器上编译内核模块（交叉编译支持）。

### 基本用法

```bash
make kmod-remote HOST=192.168.8.119 USER=ubuntu
```

### 工作流程

1. 上传源码到远程机器（`/tmp/firewall-build-$$`）
2. 在远程机器上编译
3. 下载编译产物到本地
4. 清理远程临时文件

### 产物命名

远程编译的产物按内核版本命名：

```
build/kernel-module/firewall-6.8.0-147-generic.ko
build/kernel-module/firewall-7.0.0-42-generic.ko
```

### 前提条件

- SSH 免密登录已配置
- 远程机器已安装内核头文件
- rsync 已安装

## 构建产物

### 目录结构

```
build/
├── kernel-module/
│   ├── firewall.ko                    # 当前内核版本
│   ├── <kernel-version>/
│   │   └── firewall.ko                # 指定内核版本
│   └── firewall-<kernel-version>.ko   # 远程编译产物
├── daemon/
│   └── firewall-daemon                # 守护进程二进制
└── frontend/                          # 前端构建产物
    └── ...                            # 静态文件（嵌入守护进程）
```

### 内核模块信息

```bash
# 查看模块信息
modinfo build/kernel-module/firewall.ko

# 查看依赖的内核符号
modinfo build/kernel-module/firewall.ko | grep depends

# 查看 vermagic（内核版本校验）
modinfo build/kernel-module/firewall.ko | grep vermagic
```

### 守护进程信息

```bash
# 查看版本
build/daemon/firewall-daemon --version

# 查看帮助
build/daemon/firewall-daemon --help
```

## 故障排查

### 依赖检查失败

**问题**：`make check-deps` 报错

**解决**：
```bash
# 查看具体缺失的依赖
make check-deps-kmod      # 或 check-deps-daemon, check-deps-frontend

# 安装缺失的依赖
sudo apt install <package-name>
```

### 内核头文件不存在

**问题**：`KDIR does not exist`

**解决**：
```bash
# 安装当前内核的头文件
sudo apt install linux-headers-$(uname -r)

# 或指定其他版本
make kmod KDIR=/lib/modules/<version>/build

# 查看可用的内核构建目录
ls -d /lib/modules/*/build
```

### 契约生成失败

**问题**：`contract/gen.py` 报错

**解决**：
```bash
# 检查 Python 3 是否安装
python3 --version

# 手动运行生成器查看详细错误
python3 contract/gen.py

# 检查 .fwidl 文件语法
cat contract/*.fwidl
```

### 符号不匹配

**问题**：`Unknown symbol` 或 `disagrees about version of symbol`

**原因**：模块为不同内核版本编译

**解决**：
```bash
# 为目标内核重新编译
make kmod KDIR=/lib/modules/<target-version>/build

# 或使用多版本编译
./scripts/build-kmod-multi-version.sh <target-version>
```

### 远程编译失败

**问题**：`kmod-remote` 报错

**排查**：
```bash
# 1. 检查 SSH 连接
ssh USER@HOST "uname -r"

# 2. 检查远程内核头文件
ssh USER@HOST "ls -d /lib/modules/*/build"

# 3. 手动远程编译查看详细错误
ssh USER@HOST "cd /tmp/firewall-build-$$ && make kmod"
```

### 清理不彻底

**问题**：残留文件影响新编译

**解决**：
```bash
# 标准清理（构建 / 测试产物；入库的契约生成物保持不动）
make clean

# 深度清理（额外清内核中间文件、clangd 缓存、compile_commands.json）
make distclean

# 清空契约生成物以强制重新生成（会弄脏工作区，随后 make contract 恢复）
make contract-clean
```

## 最佳实践

1. **先检查依赖**：`make check-deps` 在编译前发现问题
2. **使用 kmod 而非 kernel-module**：简短且包含契约依赖
3. **多版本编译**：为每个目标内核版本单独编译
4. **远程编译**：在目标机器上编译确保兼容性
5. **定期清理**：`make clean` 避免陈旧文件干扰
6. **契约校验**：提交前运行 `make contract-check`

## 相关文档

- [多版本内核模块编译](multi-version-kmod.md)
- [内核 API 兼容性检查](kernel-api-compatibility.md)
- [契约系统](contract.md)
- [开发指南](README.md)
