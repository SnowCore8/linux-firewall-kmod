"""13 - FRP Jail 配置测试"""

import time
from pathlib import Path

import pytest
import yaml

from .config import CONFIG_DIR, DAEMON_PATH, PROC_BANS
from .conftest import (
    count_bans,
    free_tcp_port,
    generate_test_yaml,
    run_daemon_captured,
    run_daemon_then_append_log,
    wait_procfs,
)


class TestFrpJail:
    """FRP Jail 配置测试"""

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

    def test_frp_jail_exists(self):
        """13.1 FRP Jail 定义存在"""
        frp_yaml = CONFIG_DIR / "frp.yaml"
        default_yaml = CONFIG_DIR / "default.yaml"

        has_frp = frp_yaml.exists()
        if not has_frp and default_yaml.exists():
            content = default_yaml.read_text()
            has_frp = "frp:" in content

        assert has_frp, "FRP Jail 定义不存在"

    def test_frp_log_config(self):
        """13.2 FRP 日志文件配置"""
        frp_yaml = CONFIG_DIR / "frp.yaml"
        default_yaml = CONFIG_DIR / "default.yaml"

        found = False
        for cfg in [frp_yaml, default_yaml]:
            if cfg.exists():
                content = cfg.read_text()
                if "/var/log/frp" in content:
                    found = True
                    break

        assert found, "frp.log 路径未配置"

    def test_frp_log_parse(self, tmp_path):
        """13.3 FRP 日志解析"""
        frp_log = tmp_path / "frp_test.log"
        frp_log.write_text("")

        frp_yaml = tmp_path / "frp.yaml"
        config = {
            "defaults": {
                "max_retries": 1, "findtime": 1, "ban_time": 5,
                "interval": 1, "metrics_port": free_tcp_port(),
            },
            "jails": {
                "frp": {
                    "enabled": True,
                    "log_files": [str(frp_log)],
                    "max_retries": 1, "findtime": 1, "ban_time": 5,
                    # 与 config/frp.yaml 的用户连接日志格式一致：必须从方括号里
                    # 提取 IP，空 pattern 在 FRP 行上取不到地址。
                    "regexes": {
                        "user_connection": {
                            "pattern": r".*get a user connection \[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):\d+\]"
                        }
                    },
                }
            },
        }
        frp_yaml.write_text(yaml.dump(config))

        ban_count = run_daemon_then_append_log(
            [str(DAEMON_PATH), "-c", str(frp_yaml)],
            str(frp_log),
            "2026/04/22 10:30:01 [W] [proxy/proxy.go:100] get a user connection [203.0.113.50:12345]\n"
            "2026/04/22 10:30:02 [E] [server/control.go:200] invalid token from 198.51.100.100\n"
            "2026/04/22 10:30:03 [W] [server/control.go:300] connection timeout from 192.0.2.200\n",
        )
        if PROC_BANS.exists():
            assert ban_count >= 1, "FRP 日志解析处理成功，有 IP 被封禁"
