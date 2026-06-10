# 配置指南

本章节介绍 Linux Firewall 内核模块的配置方法和选项。

## 配置文件位置

| 文件 | 路径 | 用途 |
|------|------|------|
| 主配置文件 | `/etc/firewall/default.yaml` | 全局配置和 jail 定义 |
| 数据库 | `/var/lib/firewall/bans.db` | SQLite 持久化封禁记录 |
| 日志文件 | `/var/log/firewall.log` | 守护进程日志 |

## 配置层次结构

```
default.yaml
├── global          # 全局设置
│   ├── log_level
│   ├── log_file
│   └── db_path
├── whitelist       # IP 白名单列表
│   └[]- <IP/CIDR>
└── jails           # Jail 定义
    └[]- name
        ├── enabled
        ├── log_path
        ├── filter
        │   └── regex
        ├── action
        │   ├── ban_time
        │   ├── find_time
        │   └── max_retries
        ├── port
        └── protocol
```

## 配置加载顺序

1. 系统启动时读取 `/etc/firewall/default.yaml`
2. 解析全局配置
3. 加载白名单到内核（最多 64 条）
4. 初始化每个启用的 jail
5. 注册 inotify 监听日志文件
6. 恢复 SQLite 中未过期的封禁记录

## 运行时修改

配置可通过以下方式在运行时修改：

| 方式 | 说明 | 重启后保留 |
|------|------|------------|
| ProcFS 接口 | 直接写入 `/proc/firewall/` | 否 |
| 编辑 YAML + 重启 | `systemctl restart firewall` | 是 |
| fwctl 命令 | 动态管理 | 部分（取决于操作） |

## 配置验证

修改配置后，验证配置是否正确：

```bash
# 检查 YAML 语法
cat /etc/firewall/default.yaml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)"

# 重新加载并检查状态
sudo systemctl restart firewall
sudo systemctl status firewall
```