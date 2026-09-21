"""15 - DDoS 检测集成测试"""

import os

import pytest
import yaml

from .config import CONFIG_DIR, PROC_CONFIG, PROC_STATS
from .conftest import get_prometheus_metrics, is_daemon_running, get_daemon_pid


class TestDdosDetection:
    """DDoS 检测集成测试"""

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    def test_ddos_config(self):
        """15.1 DDoS 检测配置验证"""
        # 配置取仓库内 config/（而非硬编码 /etc/firewall/default.yaml）
        config_paths = [str(CONFIG_DIR / "default.yaml")]
        for path in config_paths:
            if os.path.exists(path):
                content = open(path).read()
                if "ddos:" in content:
                    # 仅出现 "ddos:" 子串不能证明配置有效（可能来自注释或空段），
                    # 故解析 YAML，要求 ddos 段存在且为非空映射
                    data = yaml.safe_load(content)
                    assert isinstance(data, dict) and isinstance(
                        data.get("ddos"), dict
                    ), "ddos 配置段缺失或格式非法"
                    assert len(data["ddos"]) > 0, "ddos 配置段为空"
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
            # 子串命中也可能来自 HELP/TYPE 注释行，要求存在真实样本行
            assert any(
                line.startswith("firewall_ddos_auto_bans_total ")
                for line in metrics.splitlines()
            ), "firewall_ddos_auto_bans_total 缺少标准 Prometheus 样本行"
        else:
            pytest.skip("DDoS 自动封禁指标不存在")

    def test_daemon_log(self):
        """15.4 守护进程日志验证"""
        log_path = "/var/log/firewall.log"
        if not os.path.exists(log_path):
            pytest.skip("守护进程日志文件不存在")

        with open(log_path) as f:
            lines = [line for line in f if line.strip()]
        assert lines, "守护进程日志文件为空"
        # 日志为 JSON Lines 格式，至少应含一条守护进程写入的 JSON 记录
        assert any(line.lstrip().startswith("{") for line in lines), (
            "日志中无守护进程写入的 JSON 记录"
        )
