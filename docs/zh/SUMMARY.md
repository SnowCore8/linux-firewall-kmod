# Summary

* [简介](README.md)

* [快速开始](getting-started/README.md)
  * [安装](getting-started/installation.md)
  * [快速上手](getting-started/quick-start.md)

* [配置指南](configuration/README.md)
  * [YAML 配置](configuration/yaml-config.md)
  * [配置示例](configuration/examples.md)
  * [ProcFS 接口](configuration/procfs.md)
  * [威胁情报源](configuration/threat-feeds.md)

* [架构设计](architecture/README.md)
  * [内核模块](architecture/kernel-module.md)
  * [用户态守护进程](architecture/daemon.md)
  * [Web 前端](architecture/frontend.md)
  * [数据流](architecture/data-flow.md)

* [运维管理](operations/README.md)
  * [管理命令](operations/management.md)
  * [监控](operations/monitoring.md)
  * [故障排查](operations/troubleshooting.md)

* [开发指南](development/README.md)
  * [构建](development/building.md)
  * [构建系统](development/build-system.md)
  * [测试](development/testing.md)
  * [契约系统](development/contract.md)
  * [性能口径与测量方法](development/perf-baseline.md)
  * [内核模块设计](development/kernel-module-design.md)
  * [内核 API 兼容性](development/kernel-api-compatibility.md)
  * [多版本内核模块编译](development/multi-version-kmod.md)
  * [集群扫描检测设计](development/cluster-detection-design.md)
  * [CI 流程](development/ci-workflow.md)

* [迁移指南](migration-api-v2.md)
  * [API v2](migration-api-v2.md)
  * [多维风险引擎 v2](migration-risk-engine-v2.md)
  * [威胁情报源系统](migration-threat-feeds.md)

* [AI 协作](development/agent-architecture.md)
  * [合并闸门](development/merge-gate.md)
  * [引擎层](development/qwen-cli-runner.md)
