# 契约系统

本文描述项目的契约驱动开发方法。`contract/*.fwidl` 是线格式与文本协议的单一真相源。

## 契约文件

| 文件 | 管什么 | 生成物 |
|------|--------|--------|
| `contract/http.fwidl` | HTTP 路由、JSON 形状、错误模型、SSE 事件 | `contract/generated/http_contract.ts`、`src/daemon/internal/httpcontract/http_contract.go` |
| `contract/procfs.fwidl` | `/proc/firewall/*` 的节点、权限、读写文法 | `contract/generated/procfs_uapi.h` |
| `contract/netlink.fwidl` | 内核模块 ↔ 守护进程的 netlink 线格式 | `contract/generated/netlink_uapi.h`、`contract/generated/netlink.d.ts` |

生成器：`contract/gen.py`
校验器：`contract/verify_layout.py`、`verify_procfs.py`、`verify_http.py`

## 改动流程

改契约相关的代码时，必须按以下顺序：

1. 改 `contract/*.fwidl`。
2. 跑 `python3 contract/gen.py` 重新生成。
3. 跑 `make contract-drift`（生成物必须等于生成器输出）。
   它把生成器写到临时目录（`gen.py --out-dir tmp/fw_gencheck --no-in-module`），
   先比 `contract/generated/`，再单独比落在模块里的那份
   `src/daemon/internal/httpcontract/http_contract.go`——两处都要比，
   否则改契约、手改 Go 路由常量的漂移没人查。
4. 跑 `make contract-check`（三个校验器全跑完再汇总退出码）。

## HTTP 契约

### 信封格式

所有 HTTP 响应走统一信封：

```typescript
{
  code: number;      // 业务码，0 成功，非 0 失败
  message: string;   // 人话描述
  data?: T;          // 业务数据，可选
}
```

出处：`contract/http.fwidl` 的 `envelope` 段。

### 状态码

| HTTP 状态 | 何时用 |
|-----------|--------|
| 200 | 成功，业务码在信封里 |
| 400 | 请求参数错，业务码标具体原因 |
| 401 | 未认证或认证失败 |
| 403 | 认证通过但权限不足 |
| 404 | 路由不存在 |
| 500 | 服务端内部错误 |

401 不带 `WWW-Authenticate` 头（避免浏览器弹原生对话框）。
出处：`contract/http.fwidl` 的 `auth` 段。

### 认证

HTTP Basic，凭据来自配置的 `metrics_username` / `metrics_password`。
连续失败 10 次锁定 60 秒，锁定期内正确凭据同样被拒。
出处：`contract/http.fwidl` 的 `auth` 段。

SSE 不能设请求头，凭据走 `?access_token=<令牌>`。

### 路由

完整路由清单看生成物 `contract/generated/http_contract.ts` 的 `ROUTES` 常量。
前端调 HTTP 路径只走这个常量，不手写字符串字面量。
`contract/verify_http.py` 会扫 `frontend/src` 全部 `.ts`/`.tsx`（`endpoints.ts`、`api/contract.ts` 除外），
出现 `'/api/v2…'` 这类字面量就报错。

## netlink 契约

### 线格式

netlink 消息走通用头 + 载荷布局：

```c
struct fw_nl_msg {
    __u32 magic;       // 0x46574E4C ("FWNL")
    __u16 version;     // 协议版本，当前 1
    __u16 type;        // 消息类型
    __u32 seq;         // 序列号
    __u32 flags;       // 标志位
    __u32 payload_len; // 载荷长度
    __u8  payload[];   // 变长载荷
};
```

出处：`contract/netlink.fwidl` 的 `header` 段。

### seq 配对规则

- 守护进程发出的请求一律用非零且唯一的 seq。
- 应答（`DaemonRegisterAck`、`ConfigAck`、`STATS`、`ANALYSIS`、`LIST_*`）按 (type, seq) 配对。
- 内核主动推的事件（`DdosEvent`、`BanStateChange`、`WhitelistStateChange`、`ConfigChange`、`CmdResult`）用内核自己的自增 seq，不参与配对。
- seq=0 的应答是协议违例。

出处：`contract/netlink.fwidl` 的 `seq` 段。

### Option<T> 字段

请求体里的 `Option<T>` 生成 TS 的 `field?: T | null`。
缺席和 `null` 都合法，语义是「可以整个不提交」，不是「必填但可为 null」。
出处：`contract/gen.py` 的请求侧生成逻辑。

## procfs 契约

### 条目与权限

完整条目清单看 `contract/procfs.fwidl` 的 `entries` 段，生成到 `contract/generated/procfs_uapi.h`。

| 条目 | 权限 | 说明 |
|------|------|------|
| `bans` | 0600 可写 | 封禁与解封 |
| `whitelist` | 0600 可写 | 白名单增删 |
| `config` | 0600 可写 | 写 `ban_time <秒>`，读当前配置 |
| `stats` | 0400 | 13 个计数器，每行 `<key> <value>` |
| 其余 9 个 | 0400 | 只读统计 |

### 写文法

`bans` 的写入语法：

```text
<ip>              # 默认时长
<ip> <秒>         # 自定义时长
<ip> 0            # 永久
unban <ip>        # 解封
```

`whitelist` 的写入语法：

```text
<ip>              # 添加
<ip>/<前缀长度>   # 添加 CIDR
un<ip>            # 删除
```

完整文法定义在 `contract/procfs.fwidl` 的 `write` 段。

## 校验器

| 校验器 | 查什么 |
|--------|--------|
| `verify_layout.py` | 生成物目录结构、文件存在性 |
| `verify_procfs.py` | procfs 条目、权限、容量与 `.fwidl` 一致 |
| `verify_http.py` | HTTP 路由、信封、认证与 `.fwidl` 一致；把生成的 `http_contract.go` 真编一遍 |

校验器由 `make contract-check` 统一调用。

## 相关文档

- 开发流程中的契约门禁：[开发指南](development/README.md) 的「质量门禁」
- procfs 接口详解：[ProcFS 接口](configuration/procfs.md)
- 内核模块 netlink 侧：[内核模块](architecture/kernel-module.md) 的「Netlink 接口」
