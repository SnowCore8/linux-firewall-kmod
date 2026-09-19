"""13 - FRP Jail 配置测试"""

import time
from pathlib import Path

import pytest
import yaml

from .config import CONFIG_DIR, DAEMON_PATH, PROC_BANS
from .conftest import count_bans, generate_test_yaml, run_daemon_captured, wait_procfs


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
        frp_log.write_text(
            "2026/04/22 10:30:01 [W] [proxy/proxy.go:100] get a user connection [203.0.113.50:12345]\n"
            "2026/04/22 10:30:02 [E] [server/control.go:200] invalid token from 198.51.100.100\n"
            "2026/04/22 10:30:03 [W] [server/control.go:300] connection timeout from 192.0.2.200\n"
        )

        frp_yaml = tmp_path / "frp.yaml"
        config = {
            "defaults": {
                "max_retries": 1, "findtime": 1, "ban_time": 5,
                "interval": 1, "metrics_port": 9119,
            },
            "jails": {
                "frp": {
                    "enabled": True,
                    "log_files": [str(frp_log)],
                    "max_retries": 1, "findtime": 1, "ban_time": 5,
                    "regexes": {"default": {"pattern": ""}},
                }
            },
        }
        frp_yaml.write_text(yaml.dump(config))

        run_daemon_captured([str(DAEMON_PATH), "-c", str(frp_yaml)], timeout=5)
        time.sleep(1)

        if PROC_BANS.exists():
            ban_count = count_bans()
            assert ban_count >= 1, "FRP 日志解析处理成功，有 IP 被封禁"
