# CI 流程指南

本文档说明项目的持续集成（CI）流程、各阶段任务和配置选项。

## 目录

- [快速开始](#快速开始)
- [CI 阶段详解](#ci-阶段详解)
- [配置选项](#配置选项)
- [本地运行 CI](#本地运行-ci)
- [CI 集成](#ci-集成)
- [故障排查](#故障排查)

## 快速开始

**运行完整 CI 流程**：

```bash
make ci
```

**跳过测试的 CI**（仅验证构建）：

```bash
make ci SKIP_TESTS=1
```

**跳过格式检查的 CI**（紧急修复）：

```bash
make ci SKIP_FORMAT_CHECK=1
```

## CI 阶段详解

CI 流程分为 6 个阶段，每个阶段独立可运行，失败时立即停止。

### 阶段 1：环境检查 (ci-setup)

**目标**：验证构建环境满足所有依赖要求。

**检查项**：
- ✓ gcc、make（内核模块编译）
- ✓ 内核头文件（匹配运行内核或指定版本）
- ✓ Go 1.23+（守护进程编译）
- ✓ Node.js 18+、npm（前端编译）
- ✓ clang-format（代码格式检查，推荐）
- ✓ yamllint（YAML 检查，可选）

**运行**：
```bash
make ci-setup
# 或完整检查
make check-deps
```

**失败处理**：
- 根据错误提示安装缺失的依赖
- 使用 `make check-deps-kmod/daemon/frontend` 分类检查

### 阶段 2：代码格式检查 (ci-format)

**目标**：确保代码风格统一，发现潜在问题。

**检查项**：
- ✓ C 代码格式（clang-format）
- ✓ Go 代码格式（gofmt）
- ✓ Go 静态分析（go vet）
- ✓ YAML 配置格式（yamllint）

**运行**：
```bash
make ci-format
```

**自动修复**：
```bash
# C 代码
make format

# Go 代码
cd src/daemon && gofmt -w ./cmd ./internal
```

**跳过**：
```bash
make ci-format SKIP_FORMAT_CHECK=1
```

### 阶段 3：契约验证 (ci-contract)

**目标**：确保契约文件与实现一致，防止接口漂移。

**验证项**：
- ✓ 契约文件生成（netlink、procfs、http）
- ✓ 契约漂移检查（生成物 vs 生成器）
- ✓ 契约一致性校验（内核/daemon/前端实现）

**运行**：
```bash
make ci-contract
# 或分步运行
make contract              # 生成契约
make contract-drift        # 检查漂移
make contract-check        # 完整校验
```

**失败处理**：
```bash
# 重新生成契约
python3 contract/gen.py

# 检查修改了哪些 .fwidl 文件
git diff contract/*.fwidl
```

### 阶段 4：构建 (ci-build)

**目标**：编译所有组件，验证构建成功。

**构建项**：
- ✓ 内核模块（firewall.ko）
- ✓ 守护进程（firewall-daemon）
- ✓ 前端（嵌入守护进程）

**运行**：
```bash
make ci-build
# 或分步构建
make kmod                  # 仅内核模块
make daemon                # 仅守护进程
```

**产物验证**：
```bash
# 检查内核模块
modinfo build/kernel-module/firewall.ko

# 检查守护进程
build/daemon/firewall-daemon --version
```

**指定内核版本**：
```bash
make ci-build KDIR=/lib/modules/6.8.0-147-generic/build
```

### 阶段 5：测试 (ci-test)

**目标**：运行单元测试和集成测试，验证功能正确性。

**测试项**：
- ✓ Go 单元测试（src/daemon）
- ✓ 集成测试（tests/，需要 root）

**运行**：
```bash
make ci-test
# 或分步运行
cd src/daemon && go test ./...     # 单元测试
sudo make test                      # 集成测试
```

**跳过**：
```bash
make ci SKIP_TESTS=1
```

**详细输出**：
```bash
cd src/daemon && go test ./... -v
sudo python3 -m pytest tests/ -v
```

### 阶段 6：清理 (ci-cleanup)

**目标**：清理临时文件，保留构建产物。

**清理项**：
- ✓ 临时目录（tmp/）
- ✓ 编译中间文件
- ✗ 构建产物（保留）

**运行**：
```bash
make ci-cleanup
# 完全清理
make clean
```

## 配置选项

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SKIP_FORMAT_CHECK` | 跳过格式检查 | `0` |
| `SKIP_TESTS` | 跳过测试 | `0` |
| `VERBOSE` | 详细输出 | `0` |
| `KDIR` | 内核构建目录 | `/lib/modules/$(uname -r)/build` |
| `KVER` | 内核版本 | 当前运行版本 |

### 使用示例

```bash
# 快速 CI（跳过格式和测试）
make ci SKIP_FORMAT_CHECK=1 SKIP_TESTS=1

# 仅构建内核模块
make ci-build KVER=6.8.0-147-generic

# 详细输出
make ci VERBOSE=1

# 指定内核构建目录
make ci KDIR=/custom/kernel/build
```

## 本地运行 CI

### 完整流程

```bash
# 1. 检查依赖
make check-deps

# 2. 运行 CI
make ci

# 3. 查看产物
ls -lh build/kernel-module/firewall.ko
ls -lh build/daemon/firewall-daemon
```

### 分阶段运行

```bash
# 逐阶段运行，便于定位问题
make ci-setup
make ci-format
make ci-contract
make ci-build
make ci-test
make ci-cleanup
```

### 修复问题后重跑

```bash
# 修复格式问题
make format

# 修复契约问题
python3 contract/gen.py

# 重跑 CI
make ci
```

## CI 集成

### GitHub Actions

示例工作流（`.github/workflows/ci.yml`）：

```yaml
name: CI

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt update
          sudo apt install -y linux-headers-$(uname -r)
          sudo apt install -y golang-go nodejs npm
          
      - name: Run CI
        run: make ci
```

### GitLab CI

示例配置（`.gitlab-ci.yml`）：

```yaml
stages:
  - build
  - test

ci:
  stage: build
  script:
    - make check-deps
    - make ci SKIP_TESTS=1
    
test:
  stage: test
  script:
    - make ci-test
```

### Jenkins

示例流水线（`Jenkinsfile`）：

```groovy
pipeline {
    agent any
    stages {
        stage('CI') {
            steps {
                sh 'make check-deps'
                sh 'make ci'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'build/**/*', fingerprint: true
        }
    }
}
```

## 故障排查

### CI 在某阶段失败

**查看失败阶段**：
```bash
# 单独运行该阶段
make ci-<stage>

# 例如格式检查失败
make ci-format
```

### 依赖检查失败

**问题**：`make ci-setup` 报错

**解决**：
```bash
# 查看具体缺失的依赖
make check-deps-kmod
make check-deps-daemon
make check-deps-frontend

# 安装缺失的依赖
sudo apt install <package-name>
```

### 格式检查失败

**问题**：`make ci-format` 报 C 代码格式错误

**解决**：
```bash
# 自动修复 C 代码格式
make format

# 自动修复 Go 代码格式
cd src/daemon && gofmt -w ./cmd ./internal
```

### 契约验证失败

**问题**：`make ci-contract` 报契约漂移

**解决**：
```bash
# 重新生成契约
python3 contract/gen.py

# 检查 .fwidl 文件是否有未提交的修改
git diff contract/*.fwidl

# 验证契约一致性
make contract-check
```

### 构建失败

**问题**：`make ci-build` 编译错误

**排查**：
```bash
# 单独构建内核模块
make kmod

# 单独构建守护进程
make daemon

# 查看详细错误
make kmod VERBOSE=1
```

### 测试失败

**问题**：`make ci-test` 测试失败

**排查**：
```bash
# 运行单元测试（详细输出）
cd src/daemon && go test ./... -v

# 运行集成测试（详细输出）
sudo python3 -m pytest tests/ -v

# 运行特定测试
cd src/daemon && go test -v ./internal/risk/...
sudo python3 -m pytest tests/test_ban.py -v
```

### CI 输出不完整

**问题**：CI 输出被截断

**解决**：
```bash
# 使用详细模式
make ci VERBOSE=1

# 将输出重定向到文件
make ci 2>&1 | tee ci-output.log

# 查看特定阶段的输出
make ci-build 2>&1 | tee build.log
```

## CI 最佳实践

1. **本地先跑 CI**：提交前运行 `make ci` 确保通过
2. **分阶段调试**：失败时单独运行该阶段定位问题
3. **自动修复格式**：使用 `make format` 和 `gofmt` 自动修复
4. **及时更新契约**：修改 .fwidl 后立即运行 `python3 contract/gen.py`
5. **保留构建产物**：CI 完成后保留 .ko 和二进制用于部署
6. **定期清理**：运行 `make clean` 避免陈旧文件干扰

## 相关文档

- [构建系统](build-system.md)
- [契约系统](contract.md)
- [测试指南](testing.md)
- [开发流程](README.md)
