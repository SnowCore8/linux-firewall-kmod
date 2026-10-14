# YAML 配置

守护进程读一个 YAML 文件，或者一个目录。
字段名、类型、默认值、会被拒的值，全部照 `src/daemon/internal/config/parser.go` 和 `types.go` 写。

## 一、顶层结构

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `defaults` | 映射 | 否 | 给所有 jail 兜底的值 |
| `jails` | 映射 | 否 | 键是 jail 名，值是 jail 定义 |
| `ddos` | 映射 | 否 | 速率与 DDoS 参数，下发给内核 |
| `webui` | 映射 | 否 | 面板推送与告警阈值 |
| `trusted_ips` | 字符串数组 | 否 | 想放行自己的地址优先用内核白名单条目，见 [ProcFS 接口](procfs.md)。这一段现在只被解析保存，没有消费方（未验证：`src/daemon` 里没有读到它的地方） |
| `capacity` | 映射 | 否 | 四张表的条目上限 |
| `geoip_db_path` | 字符串 | 否 | 城市级 GeoIP 库路径 |
| `server_latitude` | 数值或字符串 | 否 | 本机纬度，必须与经度成对 |
| `server_longitude` | 数值或字符串 | 否 | 本机经度，必须与纬度成对 |
| `geoip_detect_egress` | 布尔 | 否 | 启动时探测出口 IP，默认关 |
| `geoip_egress_probe_url` | 字符串 | 否 | 探测地址，默认走内置地址 |

顶层写不认识的字段的后果见第七节。

## 二、`defaults` 段

16 个字段。缺省表示用内置默认值。

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `max_retries` | 整数 | 否 | 3 | 窗口内失败几次就封 |
| `findtime` | 整数 | 否 | 600 | 失败计数窗口（秒） |
| `ban_time` | 整数 | 否 | 600 | 封禁时长（秒），负数是永久 |
| `interval` | 整数 | 否 | 1 | 检查间隔（秒） |
| `metrics_port` | 整数 | 否 | 9119 | 面板与指标的监听端口 |
| `metrics_bind_address` | 字符串 | 否 | `127.0.0.1` | 监听地址，`0.0.0.0` 表示所有网卡 |
| `metrics_username` | 字符串 | 否 | 空 | 面板登录用户名 |
| `metrics_password` | 字符串 | 否 | 空 | 面板登录密码 |
| `log_file` | 字符串 | 否 | 空 | 独立日志文件路径 |
| `log_level` | 整数 | 否 | 3 | 0 无、1 错误、2 警告、3 信息、4 调试 |
| `log_destination` | 字符串 | 否 | `both` | `syslog` / `file` / `both` / `journal` |
| `log_format` | 字符串 | 否 | `plain` | `plain` 或 `json` |
| `history_db_path` | 字符串 | 否 | 空 | SQLite 历史库路径；留空即关闭整个分析面 |
| `history_retention_days` | 整数 | 否 | 7 | 历史行保留天数，清理调度器按它删旧记录 |
| `log_max_size_mb` | 整数 | 否 | 10 | 单个日志文件上限 |
| `log_max_files` | 整数 | 否 | 10 | 保留几个轮转文件 |

关于凭据的两条：

- 两项都留空才是「没配认证」，面板对所有能连上的人开放。
- 只填一项判为配置失败，不会退化成开放状态。
- 绑到非回环地址时必须配凭据。
- 凭据在文件里是明文。这个文件如果进了版本库，不要把真实凭据提交进去。

## 三、`jails` 段

jail 名是 `jails` 的键，本身不占字段。
一个 jail 支持 9 个字段。

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `enabled` | 布尔 | 否 | 新建即 true | 关掉它，jail 保留但不监控 |
| `log_files` | 字符串数组 | 实际要监控就得写 | 无 | 监控哪些日志文件 |
| `max_retries` | 整数 | 否 | 取 `defaults` | 见第二节 |
| `findtime` | 整数 | 否 | 取 `defaults` | 见第二节 |
| `ban_time` | 整数 | 否 | 取 `defaults` | 负数是永久封禁 |
| `regex` | 字符串 | 否 | 无 | 单条正则写法 |
| `regex_name` | 字符串 | 否 | `custom` | 给 `regex` 那条起名字 |
| `regexes` | 映射 | 否 | 无 | 多条命名正则：`名字: {pattern: 串}`，`pattern` 是唯一子字段 |
| `cluster` | 映射 | 否 | 见第五节 | 集群扫描检测 |

`regex` 和 `regexes` 两种写法都支持，可以同用，正则按追加顺序进列表。

### 只写 log_files 就能用

数值字段没写时，有两轮推断。

第一轮在解析阶段。只对新出现的 jail 生效，没显式写的字段才补：

| 情况 | 补上的值 |
|------|----------|
| 没写 `findtime` | 600 |
| 没写 `ban_time`，且 `findtime` 不超过 7200 | 3600 |
| 没写 `ban_time`，且 `findtime` 大于 7200 | 86400 |
| 没写 `max_retries`，且 `findtime` 小于 300 | 2 |
| 没写 `max_retries`，其余情况 | 3 |

第二轮在装配阶段，由 `jail.ApplySmartDefaults` 做，按 jail 名查一张内置的服务名表：

| 服务类型 | 匹配的名字 | `max_retries` | `findtime` | `ban_time` |
|----------|------------|---------------|------------|------------|
| SSH | `ssh`、`sshd` | 5 | 600 | 900 |
| WEB | `nginx`、`apache`、`http` | 10 | 300 | 1800 |
| FTP | `ftp`、`vsftpd`、`proftpd` | 5 | 600 | 1800 |
| MAIL | `postfix`、`dovecot`、`mail` | 5 | 300 | 1800 |
| FRP | `frp` | 10 | 300 | 1800 |
| DB | `mysql`、`mariadb`、`postgres` | 3 | 300 | 3600 |

名字匹配规则：完全相同，或者以 `-` 连接的前缀、后缀、整词。
`myhttpd` 里的 `http` 不算命中，因为没有词边界。
一个名字命中多类时按 SSH > WEB > FTP > MAIL > FRP > DB 的固定顺序取。

两点要说清：

- 这一轮只补「用户没显式写过」的字段，判断依据是 `*_Set` 标记，所以重复调用不会改掉你写下的值。
- 第一轮补的值不会置上 `*_Set` 标记，因此装配阶段会再按这张表覆盖一遍。
  名字命中表里的服务时，最终生效的是表里的数；名字不命中时，生效的是 `defaults` 段的三个默认值。
  推断值以这张表为准来看，别拿第一轮的数当结论（未验证：这条覆盖链没有测试专门断言）。

### 合并规则

- 同一个 jail 名出现两次：后到的赢，并且只覆盖它显式写出的字段。
- 目录模式（`-C`）按文件名字母序合并，后读的能覆盖先读的。
- 下划线 `_` 开头的文件是守护进程自己写回的运行期覆盖，永远最后读。
- 这类覆盖文件里出现未定义的 jail 名，会被忽略并记一条告警，不会凭空造出一个缺 `log_files` 的 jail。

## 四、`ddos` 段

18 个字段。这些值会被下发进内核模块。

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `enabled` | 布尔 | 否 | true | DDoS 防护段总开关 |
| `global_conn_rate` | 整数 | 否 | 100000 | 全局每秒最大连接数 |
| `auto_ban_duration` | 整数 | 否 | 3600 | 超阈值自动封禁的时长（秒） |
| `auto_ban_threshold` | 整数 | 否 | 3 | 超阈值几次才封 |
| `check_interval` | 整数 | 否 | 5 | 检测间隔（秒） |
| `baseline_warmup_samples` | 整数 | 否 | 50 | 动态阈值建立基线需要的样本数 |
| `max_syn_per_second` | 整数 | 否 | 2000 | SYN 速率阈值 |
| `max_udp_per_second` | 整数 | 否 | 10000 | UDP 速率阈值 |
| `max_icmp_per_second` | 整数 | 否 | 500 | ICMP 速率阈值 |
| `max_ack_per_second` | 整数 | 否 | 20000 | ACK 速率阈值 |
| `max_rst_per_second` | 整数 | 否 | 2000 | RST 速率阈值 |
| `max_fin_per_second` | 整数 | 否 | 2000 | FIN 速率阈值 |
| `static_threshold` | 布尔 | 否 | true | 静态阈值检测 |
| `dynamic_threshold` | 布尔 | 否 | false | 动态阈值检测 |
| `ddos_detection` | 布尔 | 否 | true | DDoS 检测总开关 |
| `max_bans_per_second` | 整数 | 否 | 200 | 每秒最多新增封禁数，泛洪保护 |
| `max_rate_entries` | 整数 | 否 | 65536 | 速率表条目数 |
| `protect_open_ports` | 布尔 | 否 | true | 本机对外监听端口自动纳入速率判定 |

`protect_open_ports` 关掉以后下发的是全零位图，速率判定面为空。
这和「守护进程没跑」不一样，后者内核按全端口受保护处理。

## 五、`cluster` 段

这一段挂在某个 jail 下面，控制集群扫描检测：同网段里地址多、每个地址次数少时判成扫描。
8 个字段，整段不写就等于默认值。默认是关的。

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `enabled` | 布尔 | 否 | false | 是否启用检测 |
| `audit_only` | 布尔 | 否 | true | 只记审计，不下封禁 |
| `prefix_v4` | 整数 | 否 | 24 | IPv4 聚合前缀长度 |
| `prefix_v6` | 整数 | 否 | 48 | IPv6 聚合前缀长度 |
| `window` | 整数 | 否 | 60 | 统计窗口（秒） |
| `min_ips` | 整数 | 否 | 5 | 段内至少几个地址才算 |
| `max_per_ip` | 整数 | 否 | 3 | 单个地址最多几次才算「次数少」 |
| `ban_time` | 整数 | 否 | 3600 | 判定成立后的封禁时长（秒） |

写法：

```yaml
jails:
  sshd:
    log_files:
      - /var/log/auth.log
    cluster:
      enabled: true
      audit_only: true
      prefix_v4: 24
      window: 120
      min_ips: 6
```

段里只覆盖写出来的字段，没写的保持默认。
边界值是硬校验，只在 `cluster.enabled: true` 时查：

| 字段 | 允许范围 | 为什么 |
|------|----------|--------|
| `window` | 不能为 0 | 0 会让检测直接返回空，你以为开着其实永不触发 |
| `min_ips` | 不能为 0 | 同上 |
| `prefix_v4` | 16 到 32 | 命中后封的是整个聚合网段，前缀过短波及范围远超预期 |
| `prefix_v6` | 32 到 128 | 同上 |

`max_per_ip` 大于 `min_ips` 不会被拒，但会记一条警告。
这时「每个地址失败次数少」这条判据失去区分度，CGNAT 这类高频出口会被当成低频而误封。

设计细节见 [集群扫描检测设计](../development/cluster-detection-design.md)。

## 六、`webui` 与 `capacity` 段

`webui` 19 个字段，只管面板推送和告警线。

| 字段 | 类型 | 必填 | 默认 | 说明 |
|------|------|------|------|------|
| `sse_push_interval` | 整数 | 否 | 1 | SSE 推送间隔（秒） |
| `rate_warning_pps` | 整数 | 否 | 50000 | 速率警告线（包每秒） |
| `rate_critical_pps` | 整数 | 否 | 200000 | 速率严重告警线 |
| `rate_warning_syn` | 整数 | 否 | 1000 | SYN 速率警告线 |
| `rate_critical_syn` | 整数 | 否 | 5000 | SYN 速率严重告警线 |
| `max_syn_per_second` | 整数 | 否 | 2000 | 与 `ddos` 同名，写在面板段里 |
| `max_udp_per_second` | 整数 | 否 | 10000 | 同上 |
| `max_icmp_per_second` | 整数 | 否 | 500 | 同上 |
| `max_ack_per_second` | 整数 | 否 | 20000 | 同上 |
| `max_rst_per_second` | 整数 | 否 | 2000 | 同上 |
| `max_fin_per_second` | 整数 | 否 | 2000 | 同上 |
| `static_threshold` | 布尔 | 否 | true | 同上 |
| `dynamic_threshold` | 布尔 | 否 | false | 同上 |
| `ddos_detection` | 布尔 | 否 | true | 同上 |
| `max_ban_entries` | 整数 | 否 | 65535 | 封禁表上限 |
| `max_whitelist_entries` | 整数 | 否 | 65535 | 白名单上限 |
| `max_rate_entries` | 整数 | 否 | 65535 | 速率表上限 |
| `max_local_ip_cache` | 整数 | 否 | 65535 | 本机地址缓存上限 |
| `clear_logs_at` | 字符串 | 否 | 空 | 面板日志页的过滤起点，空串表示不过滤 |

`capacity` 4 个字段，默认都是 65535：
`max_ban_entries`、`max_whitelist_entries`、`max_rate_entries`、`max_local_ip_cache`。

`webui` 与 `capacity` 有重叠字段。
`capacity` 是给用户调上限用的那一段，`webui` 里的同名项是面板侧的读数。
`clear_logs_at` 随 `webui` 段落盘，热重载和重启都会保留。

## 七、哪些值会被拒

拒绝分两道。第一道在解析阶段（`src/daemon/internal/config/parser.go`），第二道在校验阶段（`src/daemon/internal/jail/jail.go` 的 `Validate`）。
两道都在启动、热重载和 API 写入时跑，口径同一个。

### 解析阶段

| 情况 | 报错的样子 |
|------|------------|
| 出现结构体里没有的字段名 | 解析 YAML 配置失败（严格模式，默认开） |
| `log_destination` 写成四个取值之外 | `log_destination 取值非法` |
| `log_format` 写成 `plain` / `json` 之外 | `log_format 取值非法` |
| jail 数量超过 32 | `jail 数量 N 超过上限 32` |
| 一个 jail 的 `log_files` 超过 10 条 | `log_files 数量 N 超过上限 10` |
| 一个 jail 的正则超过 10 条 | `正则数量超过上限 10` |
| `server_latitude` 与 `server_longitude` 只写一个 | `必须成对给出` |
| 纬度不在 -90 到 90，经度不在 -180 到 180 | 超出范围 |
| `geoip_egress_probe_url` 不以 `http://` 或 `https://` 开头 | 协议不合法 |
| 同一个 URL 没有主机名、超过 2048 字符、含空白或控制字符 | 对应的那条拒绝 |
| 坐标字段写成既不是数值也不是字符串的东西 | `坐标必须是数值或字符串（可为空）` |

解析失败时配置一点都没被改，整份回滚。
严格模式是默认，加 `--no-strict` 才忽略未知字段名。

### 校验阶段

智能默认跑完之后校验。这些是硬错误：

| 情况 | 说明 |
|------|------|
| jail 数量为 0 或超过 32 | 至少要有一个 jail |
| `interval` 为 0 或大于 60 | 检查间隔限定在 1 到 60 秒 |
| `log_max_files` 为 0 | 0 意味着轮转后一片都不留 |
| `defaults.max_retries` 为 0 | 兜底阈值不能是 0 |
| `defaults.findtime` 为 0 | 兜底窗口不能是 0 |
| 启用的 jail 没有 `log_files` | 没日志源就没法监控 |
| 启用的 jail 最终 `max_retries` 或 `findtime` 为 0 | 智能默认补完仍为 0，判错 |
| 启用的 jail 最终 `ban_time` 为 0 或小于 -1 | 永久用 -1，其余必须是正数 |
| `cluster.window` 或 `cluster.min_ips` 为 0 | 开着检测却永不触发，判错 |
| `cluster.prefix_v4` 不在 16 到 32 | 聚合前缀过短会封掉过大范围 |
| `cluster.prefix_v6` 不在 32 到 128 | 同上 |

正则本身还有一层安全检查（`src/daemon/internal/logparse/rule.go` 的 `ValidateRegexSafety`）：
单条超过 1024 字节、有嵌套量词、有占有量词（`++`、`*+`）、分支数超过 50 的模式被拒。

正则编译失败不拦启动。
它只记一条告警，该 jail 退化成解析层的关键字回退。
结构性错误才拒绝加载。

启动能过的配置，热重载和 API 写入按同一口径判。
三条路共用同一个后处理函数。

## 八、哪些值不会被拒，但会被改

这几条是「悄悄修正」，写的时候要看清：

| 你写的 | 实际生效 |
|--------|----------|
| `max_retries: 0` | 回落成默认档；默认值也小于 1 时用 3 |
| `findtime: 0` | 回落成默认档；默认值小于 60 时用 600 |
| `findtime: 1` 到 `9` | 抬到 10 |
| `ban_time: 0` | 回落成默认档；默认档为 0 时用 600 |
| 新 jail 少写的数值字段 | 按第三节的智能推断补 |

想写永久封禁，用 `ban_time: -1`。
`ban_time: 0` 不是永久，是走回落。

`metrics_port` 写 0 是关闭 HTTP 面：面板、API、指标都不监听。
口径见 `src/daemon/internal/jail/jail.go` 里 `Validate` 上方那行注释。

## 九、改完怎么生效

改 `/etc/firewall/*.yaml` 之后：

```bash
sudo systemctl reload firewall-daemon
```

服务单元里 `ExecReload` 给主进程发 `HUP`。
重载失败时守护进程保留上一份配置，并用 `--rollback` 可以退回上一个版本。

## 十、验证配置

```bash
# 语法与字段
yamllint -c .yamllint config/*.yaml

# 集成测试覆盖配置加载与校验
sudo python3 -m pytest tests/test_09_daemon_config.py -v

# 守护进程单元测试
cd src/daemon && go test ./internal/config/...
```

## 相关文档

- [配置示例](examples.md)：`config/` 目录里现成的配置。
- [ProcFS 接口](procfs.md)：绕过守护进程，直接问内核。
- [用户态守护进程](../architecture/daemon.md)：配置怎么下发进内核。
