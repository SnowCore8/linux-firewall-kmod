# 内核模块多版本编译与兼容性指南

## 概述

本模块支持 Linux 5.x、6.x 和 7.x 系列内核，提供：

1. **多版本编译**：为不同内核版本编译独立的 .ko 文件
2. **自动兼容性检查**：模块加载时自动检测内核版本和 API 可用性
3. **智能构建脚本**：自动检测当前内核并推荐编译版本

## 快速开始

### 智能模式（推荐）

```bash
# 自动检测当前运行内核并编译
./scripts/build-kmod-multi-version.sh
```

智能模式会：
1. 检测当前运行的内核版本
2. 检查对应的内核头文件是否已安装
3. 自动编译当前内核版本的 .ko
4. 提供加载和测试的下一步操作指引

### 兼容性检测

```bash
# 查看已安装的内核头文件与兼容性
./scripts/build-kmod-multi-version.sh --check
```

输出示例：
```
═══════════════════════════════════════════════════════════
内核兼容性检测
═══════════════════════════════════════════════════════════

当前运行内核: 6.8.0-147-generic

已安装的内核头文件 (2 个):
  ~ 6.8.0-146-generic (兼容，可编译)
  ✓ 6.8.0-147-generic (当前运行)

兼容性摘要:
  可直接加载测试: 2 个版本
  仅可编译: 0 个版本

✓ 当前运行内核的头文件已安装，可以直接编译和测试
```

## 内核兼容性检查

### 检查策略

模块采用**API 可用性检查**而非**版本号限制**的策略：

- **内核版本号**：仅作参考信息，记录日志但不阻止加载
- **关键 API**：硬性要求，任何一个 API 不可用都会拒绝加载

这种设计的优势：
- 不依赖版本号，适应不同发行版的内核定制
- 直接检测模块实际依赖的功能
- 对于新版本内核，只要 API 兼容就能正常工作

### 自动检查机制

模块在加载时会自动执行以下检查：

1. **内核版本信息记录**
   - 记录当前内核版本号
   - 对于过低（< 5.0）或过高（>= 8.0）版本给出警告
   - 不阻止加载

2. **API 可用性检查**（硬性要求）
   - netfilter 钩子 API（`nf_register_net_hook` 等）
   - netlink 通信 API（`netlink_kernel_create` 等）
   - procfs 文件系统 API（`proc_create` 等）

3. **检查结果**
   - 所有 API 可用：允许加载
   - 任一 API 不可用：拒绝加载并输出详细错误

### 检查输出示例

```bash
$ sudo insmod firewall.ko
$ dmesg | grep firewall
[90604.864395] firewall: 开始内核兼容性检查...
[90604.864396] firewall: 内核版本: 7.0.14
[90604.864397] firewall: 开始检查关键 API 可用性...
[90604.864398] firewall: netfilter API: 可用
[90604.864399] firewall: netlink API: 可用
[90604.864400] firewall: procfs API: 可用
[90604.864401] firewall: 所有关键 API 检查通过
[90604.864402] firewall: 兼容性检查完成，模块可以加载
[90604.865025] firewall: netlink socket 已创建（proto=2）
[90604.865235] firewall: 模块初始化完成
```

### API 检查失败处理

如果关键 API 不可用，模块会拒绝加载并输出错误信息：

```bash
$ sudo insmod firewall.ko
insmod: ERROR: could not insert module: Operation not supported
$ dmesg | grep firewall
[12345.678] firewall: 开始内核兼容性检查...
[12345.678] firewall: 内核版本: 5.15.0
[12345.678] firewall: 开始检查关键 API 可用性...
[12345.678] firewall: netfilter API: 可用
[12345.678] firewall: netlink API: 不可用
[12345.678] firewall: 关键 API 检查失败，模块无法正常工作
[12345.678] firewall: 内核兼容性检查失败，模块加载终止
```

**可能原因**：
- 内核配置禁用了 netlink 支持
- 内核配置禁用了 procfs 支持
- 内核版本过旧，缺少某些 API

**解决方案**：
- 重新编译内核，启用相关配置
- 升级内核到支持所需 API 的版本

## 使用方式

### 1. 智能模式（默认）

```bash
./scripts/build-kmod-multi-version.sh
```

优先编译当前运行内核，适合开发测试场景。

### 2. 编译所有版本

```bash
./scripts/build-kmod-multi-version.sh --all
```

为所有已安装内核头文件的版本编译 .ko，适合发布打包。

### 3. 指定版本

```bash
# 编译单个版本
./scripts/build-kmod-multi-version.sh 6.8.0-147-generic

# 编译多个版本
./scripts/build-kmod-multi-version.sh 6.8.0-146-generic 6.8.0-147-generic
```

### 4. 查看帮助

```bash
./scripts/build-kmod-multi-version.sh --help
```

## 兼容性规则

脚本使用以下规则判断兼容性：

- **兼容**：主版本和次版本相同（如 `6.8.0-146` 与 `6.8.0-147`）
  - 编译后可直接加载测试
  - vermagic 可能不同，但 ABI 兼容
  
- **不兼容**：主版本或次版本不同（如 `6.8` 与 `7.0`）
  - 只能编译，加载时可能因 vermagic 不匹配而失败
  - 需要对应版本的内核头文件才能编译

## 输出结构

```
build/
├── kernel-module-6.8.0-146-generic/
│   └── firewall.ko
├── kernel-module-6.8.0-147-generic/
│   └── firewall.ko
└── kernel-module-7.0.0-38-generic/
    └── firewall.ko
```

每个 .ko 文件的 vermagic 与对应内核版本匹配。

## 安装内核头文件

### Ubuntu/Debian

```bash
# 安装当前运行内核的头文件
sudo apt install linux-headers-$(uname -r)

# 安装指定版本的头文件
sudo apt install linux-headers-6.8.0-147-generic
```

### CentOS/RHEL

```bash
sudo yum install kernel-devel-$(uname -r)
```

## 加载与测试

### 加载模块

```bash
# 加载指定版本的 .ko
sudo insmod build/kernel-module-6.8.0-147-generic/firewall.ko

# 验证加载
lsmod | grep firewall

# 查看模块信息
modinfo build/kernel-module-6.8.0-147-generic/firewall.ko

# 查看兼容性检查日志
dmesg | grep firewall
```

### 运行集成测试

```bash
# 确保 .ko 已复制到标准位置
cp build/kernel-module-$(uname -r)/firewall.ko build/kernel-module/firewall.ko

# 运行测试
sudo make test
```

### 卸载模块

```bash
sudo rmmod firewall
```

## Makefile 集成

```bash
# 使用 Makefile 目标
make kernel-module-multi

# 等同于
./scripts/build-kmod-multi-version.sh --all
```

## 故障排查

### 问题：未找到内核头文件

```
[ERROR] 未找到任何已安装的内核头文件
[ERROR] 请先安装: sudo apt install linux-headers-$(uname -r)
```

**解决**：安装对应版本的内核头文件。

### 问题：编译失败

```
[ERROR] 编译失败: 6.8.0-147-generic
```

**排查**：
1. 检查内核头文件是否完整：`ls /lib/modules/6.8.0-147-generic/build`
2. 检查 gcc 版本是否与编译内核时一致
3. 查看完整编译日志，定位具体错误

### 问题：加载失败 - Invalid module format

```
insmod: ERROR: could not insert module: Invalid module format
```

**原因**：vermagic 不匹配，.ko 为其他内核版本编译。

**解决**：为当前运行内核重新编译：
```bash
./scripts/build-kmod-multi-version.sh $(uname -r)
```

### 问题：加载失败 - Operation not permitted

```
insmod: ERROR: could not insert module: Operation not permitted
```

**解决**：使用 sudo 加载：
```bash
sudo insmod build/kernel-module-$(uname -r)/firewall.ko
```

### 问题：API 检查失败

```
firewall: 关键 API 检查失败，模块无法正常工作
```

**排查**：
1. 查看 dmesg 获取具体哪个 API 不可用：`dmesg | grep firewall`
2. 检查内核配置是否禁用了相关功能
3. 确认内核版本是否支持所需 API

**解决**：
- netfilter 不可用：启用 `CONFIG_NETFILTER` 内核配置
- netlink 不可用：启用 `CONFIG_NETLINK` 内核配置
- procfs 不可用：启用 `CONFIG_PROC_FS` 内核配置
- 升级内核到支持所需 API 的版本

## CI/CD 集成

在 CI 环境中自动编译多个版本：

```yaml
# .github/workflows/build.yml
- name: Build kernel modules for all versions
  run: |
    sudo apt update
    sudo apt install -y linux-headers-6.8.0-146-generic linux-headers-6.8.0-147-generic
    ./scripts/build-kmod-multi-version.sh --all
    
- name: Upload artifacts
  uses: actions/upload-artifact@v3
  with:
    name: kernel-modules
    path: build/kernel-module-*/firewall.ko
```

## 性能优化

### 使用 ccache

```bash
# 安装 ccache
sudo apt install ccache

# 脚本会自动使用 ccache（如果可用）
./scripts/build-kmod-multi-version.sh --all
```

### 并行编译

```bash
# 设置 MAKEFLAGS 启用并行编译
export MAKEFLAGS="-j$(nproc)"
./scripts/build-kmod-multi-version.sh --all
```

## 技术细节

### 兼容性检查实现

兼容性检查在 `fw_compat.h` 中实现，采用**API 可用性检查**策略：

1. **版本信息记录**：使用 `LINUX_VERSION_CODE` 宏获取版本，仅记录日志
2. **API 检查**：逐一检查模块依赖的关键 API
3. **检查时机**：在 `fw_init()` 最开始执行
4. **失败处理**：API 检查失败时返回错误码，阻止模块加载

### 检查的关键 API

模块依赖以下内核 API，任何一个不可用都会拒绝加载：

**Netfilter API**：
- `nf_register_net_hook()` / `nf_unregister_net_hook()`
- `struct nf_hook_ops`
- 用于网络数据包过滤和拦截

**Netlink API**：
- `netlink_kernel_create()` / `netlink_kernel_release()`
- `struct netlink_kernel_cfg`
- 用于内核模块与用户空间守护进程通信

**Procfs API**：
- `proc_create()` / `proc_remove()`
- `struct proc_dir_entry`
- 用于提供 `/proc/firewall/*` 接口

### 设计理念

**为什么不用版本号限制？**

1. **版本号不可靠**：
   - 不同发行版的内核可能版本号相同但 API 不同
   - 同一版本号可能有不同的配置选项
   - 内核 backport 会导致 API 与版本号不匹配

2. **API 检查更准确**：
   - 直接检测模块实际依赖的功能
   - 不受版本号命名规则影响
   - 对于新版本内核，只要 API 兼容就能工作

3. **更好的用户体验**：
   - 不会因为版本号"看起来不支持"而拒绝加载
   - 错误信息更具体（哪个 API 不可用）
   - 便于问题诊断和解决

## 相关文档

- [AGENTS.md](../AGENTS.md) - 项目工作指令
- [docs/zh/development/](../docs/zh/development/) - 开发规范
- [contract/](../contract/) - 接口契约定义

## 维护者

如需添加对新内核版本的支持：

1. 更新 `fw_compat.h` 中的版本范围宏
2. 测试新内核版本的 API 兼容性
3. 更新本文档的支持版本说明
4. 在 CI 中添加新版本的测试矩阵
