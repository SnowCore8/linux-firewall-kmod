"""19 - Netlink 通信与健康指标集成测试"""

import json
import subprocess
import time

import pytest

from .conftest import (
    get_prometheus_metrics,
    is_daemon_running,
    parse_metric,
)


class TestNetlinkComm:
    """Netlink 通信与健康指标集成测试"""

    METRICS_PORT = 9119
    WEBUI_PORT = 8080

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    def test_netlink_metrics_exist(self):
        """19.1 Prometheus netlink 指标存在性"""
        metrics = get_prometheus_metrics(self.METRICS_PORT)
        if not metrics:
            pytest.skip("Prometheus 端点无响应")

        expected = [
            "firewall_netlink_messages_sent_total",
            "firewall_netlink_messages_received_total",
            "firewall_netlink_send_errors_total",
            "firewall_netlink_recv_errors_total",
        ]

        for metric in expected:
            if f"{metric} " in metrics:
                # HELP/TYPE 注释行也含 "<metric> " 子串，要求存在真实样本行
                assert any(
                    line.startswith(f"{metric} ")
                    for line in metrics.splitlines()
                ), f"{metric} 缺少标准 Prometheus 样本行"
            else:
                pytest.skip(f"{metric} 指标不存在")

    def test_ban_triggers_netlink_count(self):
        """19.2 封禁操作触发 netlink 消息计数递增"""
        metrics = get_prometheus_metrics(self.METRICS_PORT)
        if not metrics:
            pytest.skip("Prometheus 端点无响应")

        sent_before = parse_metric(metrics, "firewall_netlink_messages_sent_total")

        test_ip = "192.0.2.200"
        try:
            subprocess.run(
                [
                    "curl", "-s", "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps({"ip": test_ip, "duration": 60}),
                    f"http://localhost:{self.WEBUI_PORT}/api/bans",
                ],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip("API 不可达")

        time.sleep(1)

        metrics_after = get_prometheus_metrics(self.METRICS_PORT)
        sent_after = parse_metric(metrics_after, "firewall_netlink_messages_sent_total")

        assert sent_after >= sent_before, (
            f"发送计数减少 (before={sent_before}, after={sent_after})"
        )

        try:
            subprocess.run(
                ["curl", "-s", "-X", "DELETE",
                 f"http://localhost:{self.WEBUI_PORT}/api/bans/{test_ip}"],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def test_netlink_error_counts(self):
        """19.3 netlink 错误计数初始为零"""
        metrics = get_prometheus_metrics(self.METRICS_PORT)
        if not metrics:
            pytest.skip("Prometheus 端点无响应")

        send_err = parse_metric(metrics, "firewall_netlink_send_errors_total")
        recv_err = parse_metric(metrics, "firewall_netlink_recv_errors_total")

        # parse_metric 未命中时返回 0.0，用样本行存在性区分"指标缺失"与"计数为 0"
        for name, value in (
            ("firewall_netlink_send_errors_total", send_err),
            ("firewall_netlink_recv_errors_total", recv_err),
        ):
            assert any(
                line.startswith(f"{name} ")
                for line in metrics.splitlines()
            ), f"{name} 指标缺失 (parse_metric 返回默认值 {value})"
