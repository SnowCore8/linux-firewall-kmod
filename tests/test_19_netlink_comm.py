"""19 - Netlink 通信与健康指标集成测试（版本化 API + 真实计数器增量）

与 test_16 同口径：Web UI / JSON API / SSE / metrics 共用**同一监听端口**
（`daemon_http_port()` 读自仓库默认配置），路径带 `/api/v1` 前缀，响应为
`{"code","data","message"}` 信封。旧用例的独立 `WEBUI_PORT = 8080` 与
非版本化路径（`POST /api/bans`）已不存在。

关键差异：19.2 不再满足于「计数未减少」这种恒真断言，而是经真实 HTTP 封禁操作
后断言内核 netlink 发送计数**确实自增**。
"""

import json
import subprocess
import time

import pytest

from .config import TEST_IP
from .conftest import (
    daemon_http_port,
    get_prometheus_metrics,
    is_daemon_running,
    parse_metric,
)

_NETLINK_SENT = "firewall_netlink_messages_sent_total"
# 期望存在的 netlink 健康指标（daemon 侧 DAEMON_STATS，见 kernel/transport.rs）。
_NETLINK_METRICS = [
    "firewall_netlink_messages_sent_total",
    "firewall_netlink_messages_received_total",
    "firewall_netlink_send_errors_total",
    "firewall_netlink_recv_errors_total",
]


def _has_sample(metrics: str, name: str) -> bool:
    """判断指标是否有真实样本行（HELP/TYPE 注释行不算）。"""
    return any(line.startswith(f"{name} ") for line in metrics.splitlines())


def _curl(method: str, url: str, data: dict | None = None, timeout: int = 5) -> tuple[int, str]:
    """发一次 HTTP 请求，返回 (状态码, 响应体)；不可达时状态码为 0。"""
    cmd = ["curl", "-s", "-w", "%{http_code}", "-o", "/dev/stdout", "-X", method]
    if data is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
    cmd.append(url)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 0, ""
    out = result.stdout
    body = out[:-3] if len(out) > 3 else ""
    code = int(out[-3:]) if len(out) >= 3 else 0
    return code, body


class TestNetlinkComm:
    """Netlink 通信与健康指标集成测试。

    需要外部已起的 daemon（daemon-up 形态）；daemon 未运行时整体跳过。
    """

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    @staticmethod
    def _metrics() -> str:
        return get_prometheus_metrics(daemon_http_port())

    def test_netlink_metrics_exist(self):
        """19.1 Prometheus netlink 指标存在且各有真实样本行"""
        metrics = self._metrics()
        assert metrics, "Prometheus 端点不可访问"

        for metric in _NETLINK_METRICS:
            assert _has_sample(metrics, metric), f"{metric} 缺少 Prometheus 样本行"

    def test_ban_triggers_netlink_count(self):
        """19.2 真实封禁操作使 netlink 发送计数自增（不满足于「未减少」）

        经 `POST /api/v1/bans` 下发一次临时封禁，内核确认后 daemon 的 netlink
        发送计数必然 +1；据此轮询断言，而不是断言一个恒真的 `>=`。
        """
        port = daemon_http_port()
        metrics_before = self._metrics()
        assert metrics_before, "Prometheus 端点不可访问"
        before = parse_metric(metrics_before, _NETLINK_SENT)

        code, body = _curl(
            "POST",
            f"http://localhost:{port}/api/v1/bans",
            {"ip": TEST_IP, "duration": 60},
        )
        assert code == 201, (
            f"封禁请求未返回 201（HTTP {code}）: {body[:200]}；"
            "daemon 是否以回环免鉴权配置运行？"
        )

        try:
            # 事件驱动轮询：封禁要等内核确认，计数落定时刻不确定，固定 sleep 易偶发。
            deadline = time.monotonic() + 6
            after = before
            while after <= before and time.monotonic() < deadline:
                time.sleep(0.3)
                after = parse_metric(self._metrics(), _NETLINK_SENT)

            assert after > before, (
                f"封禁后 netlink 发送计数未自增（{before} -> {after}）"
            )
        finally:
            # 清理：解封测试 IP，避免污染后续用例
            _curl("DELETE", f"http://localhost:{port}/api/v1/bans/{TEST_IP}")

    def test_netlink_error_counts(self):
        """19.3 netlink 错误计数存在（错误计数本身可非零，不作等值断言）"""
        metrics = self._metrics()
        assert metrics, "Prometheus 端点不可访问"

        for name in (
            "firewall_netlink_send_errors_total",
            "firewall_netlink_recv_errors_total",
        ):
            assert _has_sample(metrics, name), (
                f"{name} 指标缺失（parse_metric 返回默认值 "
                f"{parse_metric(metrics, name)}）"
            )
