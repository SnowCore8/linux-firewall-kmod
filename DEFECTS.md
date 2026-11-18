# 功能缺陷清单

当前已覆盖的代码路径中未发现仍可复现的缺陷。

## 验证边界

- 22 个 `tests/test_*.py` 在 QEMU 虚拟机 + `7.0.0-43-generic` 内核上以 root 跑通：daemon-down 全量用例、daemon-up 的功能用例（`test_15/16/17/19`），覆盖模块加载/卸载、procfs、netlink、封禁/白名单、守护进程生命周期、PID 文件与单实例约束。
- `test_16` 的 1 秒响应时间断言未在 TCG 模拟下执行（其余 `test_16` 用例通过）；真实硬件应单独复跑。
- Playwright e2e 未跑。
- IPv6 扩展头悬空指针与 netlink 卸载竞态做了代码审查与编译验证，未构造 KASAN 复现；其余内核修复有集成用例覆盖。
