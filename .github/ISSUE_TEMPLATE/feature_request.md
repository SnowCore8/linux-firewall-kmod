---
name: "功能请求"
about: "提一个新能力或改进"
title: "[FEATURE] "
labels: enhancement
assignees: ""
---

## 想要什么

一句话讲清核心需求。

<!-- 例：给 jail 加一条按请求路径过滤的规则。 -->

## 现在会怎样

不做这件事，你会卡在哪。写具体场景。

<!-- 例：同一台机器上的两个服务共用一份日志，只能一起封。 -->

## 影响范围

可多选。

- [ ] 内核模块（`src/kernel-module/`）
- [ ] 守护进程（`src/daemon/`）
- [ ] 面板（`frontend/`）
- [ ] 配置文件（`config/*.yaml`）
- [ ] 契约（`contract/*.fwidl`）
- [ ] 构建与 CI（`Makefile`、`.github/workflows/`）
- [ ] 文档（`docs/zh/`）

## 会动到对外接口吗

- [ ] 不会
- [ ] 会动 procfs（`/proc/firewall/*`）
- [ ] 会动 netlink 线格式
- [ ] 会动 HTTP 或 SSE

选中任一项，就要改 `contract/` 下对应的 `.fwidl`，重跑
`python3 contract/gen.py`，再跑 `make contract-check` 与
`make test`。这一步不能省。

## 优先级

按 `STANDARDS.md` 的任务定级选一项。

- [ ] P0：挡住核心功能，要立刻处理
- [ ] P1：本迭代要做完
- [ ] P2：计划内改进
- [ ] P3：有空再做

## 验收标准

写能验证的条件。别写「体验更好」。

- [ ] 例：命中后 `/proc/firewall/stats` 的 `packets_dropped` 会增加
- [ ] 例：`tests/` 里新增一条覆盖该行为的用例
- [ ] 例：`make contract-check` 与 `make test` 全过

## 建议做法

有思路就写。没有也照样能提。

<!-- 可以写：动哪个模块、接口怎么变、数据从哪来到哪去。 -->

## 替代方案

你想过但没选的做法，以及为什么。

<!-- 例：只想在面板上加个开关，因为改内核风险更大。 -->

## 兼容性

- [ ] 完全兼容：不改现有接口、配置和行为
- [ ] 新增项：加字段或加参数，默认行为不变
- [ ] 破坏性变更：要改现有配置或接口

选了破坏性变更，请写清迁移办法和影响面。

## 其他参考

相关的 Issue、设计文档、外部资料。

<!-- 例：docs/zh/development/cluster-detection-design.md 里没覆盖的这一维。 -->

## 你是否愿意实现

- [ ] 愿意提 PR
- [ ] 只能提供测试和反馈
- [ ] 想先讨论方案
