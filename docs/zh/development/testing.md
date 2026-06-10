# 测试

本文档介绍 Linux Firewall 内核模块的测试框架和测试用例。

## 测试类型

| 类型 | 位置 | 说明 |
|------|------|------|
| 单元测试 | `tests/unit/` | 测试单个函数和模块 |
| 集成测试 | `tests/integration/` | 测试组件间交互 |
| 压力测试 | `tests/stress/` | 测试性能和极限情况 |

## 运行测试

### 运行所有测试

```bash
make test
```

### 运行特定测试

```bash
# 仅单元测试
make test-unit

# 仅集成测试
make test-integration

# 运行单个测试文件
./tests/unit/test_hash_table
```

## 单元测试

### 哈希表测试

测试内核哈希表的插入、查找、删除操作。

```bash
./tests/unit/test_hash_table
```

测试用例：

| 用例 | 说明 |
|------|------|
| `test_insert` | 插入单个 IP |
| `test_lookup` | 查找已存在的 IP |
| `test_delete` | 删除 IP |
| `test_duplicate` | 插入重复 IP |
| `test_capacity` | 测试 4096 容量上限 |
| `test_expiry` | 测试过期清理 |

### 白名单测试

测试白名单的添加、删除、匹配操作。

```bash
./tests/unit/test_whitelist
```

测试用例：

| 用例 | 说明 |
|------|------|
| `test_add` | 添加单个 IP |
| `test_remove` | 移除 IP |
| `test_match` | 匹配 IP |
| `test_cidr` | CIDR 网段匹配 |
| `test_capacity` | 测试 64 容量上限 |

### 正则表达式测试

测试 PCRE2 正则编译和匹配。

```bash
./tests/unit/test_regex
```

测试用例：

| 用例 | 说明 |
|------|------|
| `test_compile` | 编译正则表达式 |
| `test_host_placeholder` | `<HOST>` 占位符替换 |
| `test_match_ipv4` | 匹配 IPv4 地址 |
| `test_no_match` | 不匹配的情况 |
| `test_invalid_regex` | 无效正则处理 |

### 配置解析测试

测试 YAML 配置文件解析。

```bash
./tests/unit/test_config
```

测试用例：

| 用例 | 说明 |
|------|------|
| `test_parse_global` | 解析全局配置 |
| `test_parse_jail` | 解析 jail 配置 |
| `test_parse_whitelist` | 解析白名单 |
| `test_invalid_yaml` | 无效 YAML 处理 |
| `test_missing_fields` | 缺少必需字段处理 |

## 集成测试

### 完整封禁流程测试

测试从日志匹配到内核封禁的完整流程。

```bash
sudo ./tests/integration/test_full_ban
```

测试步骤：

```
1. 启动测试环境
2. 加载内核模块
3. 启动守护进程
4. 写入测试日志行
5. 等待 inotify 触发
6. 验证 PCRE2 匹配
7. 验证计数器累加
8. 验证阈值触发
9. 验证内核封禁
10. 验证数据包被丢弃
11. 清理测试环境
```

### 自动解封测试

测试封禁过期自动解封。

```bash
sudo ./tests/integration/test_auto_unban
```

测试步骤：

```
1. 封禁测试 IP（短时长）
2. 验证封禁生效
3. 等待过期
4. 验证自动解封
5. 验证数据包恢复通过
```

### ProcFS 接口测试

测试 ProcFS 读写操作。

```bash
sudo ./tests/integration/test_procfs
```

测试用例：

| 用例 | 说明 |
|------|------|
| `test_read_status` | 读取模块状态 |
| `test_read_banned` | 读取封禁列表 |
| `test_write_ban` | 写入封禁命令 |
| `test_write_unban` | 写入解封命令 |
| `test_write_clear` | 写入清空命令 |

## 压力测试

### 哈希表压力测试

测试 4096 容量下的性能。

```bash
sudo ./tests/stress/test_hash_table_stress
```

测试场景：

| 场景 | 说明 |
|------|------|
| 满表插入 | 插入 4096 个 IP |
| 满表查找 | 在满表中查找 |
| 满表删除 | 从满表删除 |
| 混合操作 | 插入/查找/删除混合 |

### 并发测试

测试多 CPU 并发访问。

```bash
sudo ./tests/stress/test_concurrent
```

测试场景：

| 场景 | 说明 |
|------|------|
| 并发读 | 多 CPU 并发查找 |
| 并发写 | 多 CPU 并发插入 |
| 读写混合 | 并发读 + 写 |

### 数据包压力测试

测试高流量下的性能。

```bash
sudo ./tests/stress/test_packet_stress
```

使用 `hping3` 或 `nping` 生成高流量：

```bash
# 安装 hping3
sudo apt install hping3

# 生成测试流量
hping3 --flood -p 22 -S <target_ip>
```

## 测试覆盖率

### 生成覆盖率报告

```bash
# 安装 lcov
sudo apt install lcov

# 编译带覆盖率标志
make clean
CFLAGS="--coverage" make

# 运行测试
make test

# 生成报告
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-html
```

### 查看报告

```bash
# 在浏览器中打开
xdg-open coverage-html/index.html
```

## 内存检测

### Valgrind

检测守护进程内存问题：

```bash
# 编译带调试信息
make daemon CFLAGS="-g -O0"

# 运行 valgrind
sudo valgrind --leak-check=full --show-leak-kinds=all \
    ./firewall-daemon start

# 运行一段时间后停止，查看报告
```

### AddressSanitizer

```bash
# 编译 ASan 版本
make asan

# 运行
sudo ./firewall-daemon asan

# 检查 ASan 输出
```

## 内核模块测试工具

### 使用 kselftest

Linux 内核自测试框架：

```bash
# 运行网络相关自测试
sudo make -C tools/testing/selftests run_tests=net
```

### 使用 ktap

内核 TAP 测试：

```bash
sudo modprobe firewall
./tests/kernel/test_firewall.ktap
```

## CI/CD 集成

### GitHub Actions 示例

```yaml
name: Tests
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          sudo apt update
          sudo apt install -y \
            build-essential \
            linux-headers-$(uname -r) \
            libyaml-dev \
            libsqlite3-dev \
            libmicrohttpd-dev \
            libpcre2-dev

      - name: Build
        run: make

      - name: Run tests
        run: sudo make test

      - name: Run ASan tests
        run: sudo make asan
```

## 编写新测试

### 单元测试模板

```c
#include <stdio.h>
#include <assert.h>
#include "../src/include/common.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    void test_##name(void)

#define ASSERT(cond) \
    do { \
        if (cond) { tests_passed++; } \
        else { tests_failed++; printf("FAIL: %s\n", #cond); } \
    } while(0)

TEST(my_feature) {
    // 设置
    ...

    // 执行
    ...

    // 验证
    ASSERT(result == expected);
}

int main(void) {
    printf("Running tests...\n");

    test_my_feature();

    printf("\nResults: %d passed, %d failed\n",
           tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
```