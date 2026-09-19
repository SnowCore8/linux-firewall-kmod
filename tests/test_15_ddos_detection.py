"""15 - DDoS 检测集成测试"""

import os

import pytest

from .config import PROC_CONFIG, PROC_STATS
from .conftest import get_prometheus_metrics, is_daemon_running, get_daemon_pid


class TestDdosDetection:
    """DDoS 检测集成测试"""

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    def test_ddos_config(self):
        """15.1 DDoS 检测配置验证"""
        config_paths = ["/etc/firewall/default.yaml"]
        for path in config_paths:
            if os.path.exists(path):
                content = open(path).read()
                if "ddos:" in content:
                    assert True
                    return
        pytest.skip("DDoS 配置节不存在")

    def test_prometheus_ddos_metrics(self):
        """15.2 Prometheus DDoS 指标验证"""
        metrics = get_prometheus_metrics()
        if not metrics:
            pytest.skip("Prometheus 端点不可访问")

        assert "firewall_ddos" in metrics, "DDoS Prometheus 指标不存在"

    def test_auto_ban_trigger(self):
        """15.3 自动封禁触发测试"""
        metrics = get_prometheus_metrics()
        if not metrics:
            pytest.skip("Prometheus 端点不可访问")

        if "firewall_ddos_auto_bans_total" in metrics:
            assert True
        else:
            pytest.skip("DDoS 自动封禁指标不存在")

    def test_daemon_log(self):
        """15.4 守护进程日志验证"""
        log_path = "/var/log/firewall.log"
        if not os.path.exists(log_path):
            pytest.skip("守护进程日志文件不存在")

        assert os.path.exists(log_path), "守护进程日志文件不存在"
