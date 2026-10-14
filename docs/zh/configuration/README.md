# 配置指南

三篇文档，各管一层。

| 文档 | 管什么 |
|------|--------|
| [YAML 配置](yaml-config.md) | 守护进程读的那个配置文件：字段、类型、默认值、会被拒的值 |
| [配置示例](examples.md) | `config/` 目录里现成的几份配置，可以整份抄走 |
| [ProcFS 接口](procfs.md) | 内核模块暴露在 `/proc/firewall/` 的条目：权限、写法、字段 |

## 两者是什么关系

YAML 配的是守护进程。守护进程通过 netlink 把配置下发进内核。
`/proc/firewall/` 是内核自己的一面镜子，绕过守护进程直接读写它。

改 YAML 要走重载或重启。改内核的默认封禁时长，写 `config` 条目就行。

## 配置文件的来源

安装后落在 `/etc/firewall/`，服务用 `-C /etc/firewall` 加载。
`-c` 只给一个文件时，缺省路径是 `/etc/firewall-daemon/config.yml`。
目录模式下按文件名字母序合并，`_` 开头的文件最后读。

## 改配置要跑什么

YAML 的字段和 procfs 的命令文法都有契约与测试兜着。
改这两处必须跑完整测试：

```bash
make test
cd src/daemon && go test ./...
```
