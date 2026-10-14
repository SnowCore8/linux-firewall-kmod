# 快速上手

一条主路径，五步跑通。
每步都写「预期看到什么」，对不上就别往下走。

前置：仓库已经编出两个产物。没有就先跑 `make build-quick`，见 [安装](installation.md)。
下面的命令都在仓库根目录执行，都需要 root。

## 第 1 步：加载内核模块

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
```

预期：这条命令不打印任何东西，退出码 0。

验证模块在跑：

```bash
lsmod | grep firewall
```

预期：输出第一列是 `firewall`。

看内核侧配置：

```bash
sudo cat /proc/firewall/config
```

预期：四行内容，`ban_time` 是你传进去的 600。

```text
Current Firewall Configuration:
--------------------------------
ban_time: 600 seconds
Ban entries: 0
Whitelist entries: 0
```

## 第 2 步：起守护进程

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml
```

预期：进程不退出，终端（stderr）连续打出日志，其中有两行：

```text
内核 netlink 链路已就绪
HTTP 服务器已启动
```

模块没加载时不会走到这一步。启动检查会直接报错退出，退出码 1：

```text
内核接口不可用: /proc/firewall/... 不存在（内核模块未加载？）
```

想同时看到日志文件，看配置里的 `defaults.log_file`。

## 第 3 步：打开面板

浏览器访问：

```text
http://127.0.0.1:9119/dashboard
```

端口来自 `defaults.metrics_port`，默认 9119。
`config/default.yaml` 把 `metrics_bind_address` 写成 `0.0.0.0`，所以局域网地址也能访问。

配了 `metrics_username` 和 `metrics_password` 时，页面显示登录表单。
填配置文件里的那两个值。
令牌存在浏览器 `sessionStorage`，键名 `firewall.access_token`，关掉标签页就没了。

想跳过登录表单，直接用免登录地址：

```text
http://127.0.0.1:9119/?access_token=<base64(用户名:密码)>
```

令牌会先被写进 `sessionStorage`，然后从地址栏清掉。

预期：登录后面板出数据，不用刷新页面也会自己更新。
更新间隔是 `webui.sse_push_interval`，默认 1 秒。

一个已知限制：Service Worker 只在安全上下文（HTTPS 或 localhost）注册。
通过 `http://<局域网IP>:9119` 访问时界面正常，但无法「添加到主屏幕」。

## 第 4 步：手工封禁一个 IP

```bash
echo "203.0.113.9" | sudo tee /proc/firewall/bans
```

预期：`tee` 把命令原样回显一次，退出码 0。
接口本身不回文本，成功与否只看写入字节数和退出码。

确认它进了封禁表：

```bash
sudo cat /proc/firewall/bans
```

预期：地址列按 40 列左对齐，剩余秒数从 600 往下走。

```text
Banned IP List:
-------------------
203.0.113.9                              (expires in 571 seconds)
-------------------
Total: 1 active bans (0 permanent, 1 temporary)
```

面板的封禁页此时也能看到这个地址。

想指定时长或封成永久：

```bash
echo "203.0.113.10 3600" | sudo tee /proc/firewall/bans   # 一小时
echo "203.0.113.11 0"    | sudo tee /proc/firewall/bans   # 永久
```

预期：`cat /proc/firewall/bans` 里那两条变成三条，`203.0.113.11` 显示 `(permanent)`。

## 第 5 步：解封

```bash
echo "unban 203.0.113.9"  | sudo tee /proc/firewall/bans
echo "unban 203.0.113.10" | sudo tee /proc/firewall/bans
echo "unban 203.0.113.11" | sudo tee /proc/firewall/bans
```

预期：三条命令都只回显输入。

看结果：

```bash
sudo cat /proc/firewall/bans
sudo cat /proc/firewall/stats | grep -E "^(total_bans|total_unbans|current_bans) "
```

预期：列表只剩表头和计数行，`Total: 0 active bans (0 permanent, 0 temporary)`。
`stats` 是每行「键 空格 值」的机器可读格式，这三行对应刚才的三次封、三次解：

```text
total_bans 3
total_unbans 3
current_bans 0
```

字段清单和其余条目见 [ProcFS 接口](../configuration/procfs.md)。

## 顺手试两件事

```bash
# 白名单：这个网段之后封不进去
echo "203.0.113.0/24" | sudo tee /proc/firewall/whitelist

# 改内核默认封禁时长
echo "ban_time 300" | sudo tee /proc/firewall/config
```

预期：写白名单后 `sudo cat /proc/firewall/whitelist` 多一行 `203.0.113.0/24  on manual`。
手工添加的条目，设备列固定写 `manual`。
写 `ban_time` 后 `sudo cat /proc/firewall/config` 的第一行变成 `ban_time: 300 seconds`。

## 收尾

守护进程那个终端按 Ctrl-C。它会按登记的逆序关停各执行体。

```bash
sudo rmmod firewall
```

预期：`lsmod | grep firewall` 没有输出。
`/proc/firewall/` 这个目录也随之消失。

## 接下来

- 让它开机自启：[安装](installation.md) 的第四节和第五节。
- 加自己的 Jail：[YAML 配置](../configuration/yaml-config.md)。
- 抄现成配置：[配置示例](../configuration/examples.md)。
