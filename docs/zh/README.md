# Linux Firewall 内核模块

实时 IP 封禁。日志判定在用户态，丢包在内核里。

## 文档地图

| 目录 | 一句话 |
|------|--------|
| [快速开始](getting-started/README.md) | 装环境、编译、安装、五步跑通 |
| [配置指南](configuration/README.md) | YAML 字段、配置示例、`/proc/firewall` 接口 |
| [架构设计](architecture/README.md) | 内核模块、守护进程、前端、数据怎么流 |
| [开发指南](development/README.md) | 构建、测试、契约与设计文档 |
| [运维管理](operations/README.md) | 日常管理、监控接入、故障排查 |

## 三句话说清这个项目

- 守护进程用 inotify 跟日志，正则或关键字取出地址，在窗口内数失败次数。
- 判定成立后经 netlink 下发，内核在 netfilter 钩子上查封禁表，命中就丢包。
- 封禁状态存在内核里，用户态进程被调度走也不影响丢包。

## 从哪儿开始读

只想跑起来：[快速上手](getting-started/quick-start.md)。
要装到机器上长期跑：[安装](getting-started/installation.md)。
要看某个字段能不能这么写：[YAML 配置](configuration/yaml-config.md)。
要绕过守护进程直接操作内核：[ProcFS 接口](configuration/procfs.md)。

## 内核版本口径

实测记录：6.8.0-146 可编译、可加载；7.0.0-38 可编译，加载未验证；5.x 未验证。
先按你自己的内核编，编不过看 [故障排查](operations/troubleshooting.md)。

## 接口真相源

条目、权限、写文法、HTTP 路由都由契约生成，文档只描述不定义：

- `contract/procfs.fwidl` → `contract/generated/procfs_uapi.h`
- `contract/http.fwidl` → `contract/generated/http_contract.ts`
- `contract/netlink.fwidl` → `contract/generated/netlink_uapi.h`

改接口先改 `.fwidl`，再跑 `python3 contract/gen.py`，然后 `make contract-check`。

## 守护进程与 HTTP 面

- 面板与 API 同端口，默认 9119，路由前缀 `/api/v1`，共 57 条路由。
  完整清单看生成物，别在这里抄。
- 认证是 HTTP Basic，凭据来自配置的 `metrics_username` / `metrics_password`。
  连续失败 10 次锁定 60 秒，锁定期内正确凭据同样被拒。
- SSE 不能设请求头，凭据走 `?access_token=<令牌>`。

细节见 [用户态守护进程](architecture/daemon.md)。
