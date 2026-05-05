# Contributing to Firewall

感谢你关注 Firewall 项目！本文档将指导你如何参与开发。

## 🚀 快速开始

### 1. Fork 并克隆

```bash
# Fork 仓库后，克隆到本地
git clone https://github.com/YOUR_USERNAME/linux-firewall-kmod.git
cd linux-firewall-kmod

# 添加上游仓库
git remote add upstream https://github.com/SnowCore8/linux-firewall-kmod.git
```

### 2. 设置开发环境

```bash
# Debian/Ubuntu
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev

# RHEL/CentOS/Rocky
sudo yum install -y gcc make kernel-devel kernel-headers \
  libyaml-devel sqlite-devel libmicrohttpd-devel pcre2-devel
```

### 3. 编译与测试

```bash
# 编译
make

# 运行测试
sudo ./tests/run_tests.sh
```

## 📝 代码规范

### C 语言编码规范

- 遵循 [Linux 内核编码风格](https://www.kernel.org/doc/html/latest/process/coding-style.html)
- 使用 4 个空格缩进（内核模块使用 Tab）
- 函数名使用小写下划线分隔（如 `handle_failed_attempt`）
- 宏定义使用全大写（如 `MAX_BAN_ENTRIES`）
- 结构体成员对齐，注释使用 `/* ... */`

### 注释规范

- 所有注释使用中文
- 注释应解释"为什么"而不仅仅是"做什么"
- 公共函数必须在头文件中声明并添加文档注释

### 提交信息规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Type 类型**：
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式（不影响功能）
- `refactor`: 重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具链相关

**示例**：
```
feat(kernel): 添加 RCU 并发机制
fix(daemon): 修复配置热重载内存泄漏
docs: 更新架构设计文档
```

## 🧪 测试指南

### 运行测试

```bash
# 运行所有测试
sudo ./tests/run_tests.sh

# 运行单个测试套件
sudo ./tests/run_tests.sh --suite 03

# 按类别运行
sudo ./tests/run_tests.sh --category daemon

# 生成测试报告
sudo ./tests/run_tests.sh --report
```

### 编写测试

1. 在 `tests/suites/` 创建 `XX_name.sh`（XX 为两位编号）
2. 在 `run_tests.sh` 的 `SUITE_FILES` 和 `SUITE_CATEGORIES` 中添加映射
3. 使用框架断言函数编写测试

## 🔀 Pull Request 流程

1. **创建功能分支**

```bash
git checkout -b feature/your-feature-name
```

2. **开发与测试**

- 实现功能
- 添加/更新测试
- 确保所有测试通过

3. **提交变更**

```bash
git add .
git commit -m "feat: your feature description"
```

4. **推送并创建 PR**

```bash
git push origin feature/your-feature-name
```

5. **填写 PR 模板**

- 清晰描述变更内容
- 链接相关 Issue
- 提供测试步骤

### PR 审查清单

- [ ] 代码遵循编码规范
- [ ] 已添加必要的注释
- [ ] 已更新相关文档
- [ ] 无硬编码敏感信息
- [ ] 所有测试通过

## 🏗️ 开发指南

### 内核模块开发

- 内存分配/释放必须配对
- 正确使用 RCU 和锁机制
- 避免在原子上下文中睡眠
- 所有用户输入必须验证

### 守护进程开发

- 模块化设计，单一职责
- 错误处理与日志记录
- 线程安全（使用 mutex）
- 资源泄漏防护

### 配置文件

- 新参数需加入白名单校验
- 设置合理的值范围限制
- 更新 `CONFIGURATION.md`

## ❓ 获取帮助

- 查看 [文档](docs/)
- 提交 [Issue](https://github.com/SnowCore8/linux-firewall-kmod/issues)
- 参与 [Discussions](https://github.com/SnowCore8/linux-firewall-kmod/discussions)

## 📄 许可证

参与本项目即表示你同意遵循 [GPL v2](LICENSE) 许可证。

感谢你的贡献！🎉
