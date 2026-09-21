"""21 - 多 Jail 并发集成测试"""

import os
import signal
import subprocess
import time

import pytest
import yaml

from .config import DAEMON_PATH
from .conftest import get_prometheus_metrics, mark_daemon_launched, parse_metric


class TestMultiJail:
    """多 Jail 并发集成测试"""

    @pytest.fixture(autouse=True)
    def check_daemon_binary(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程二进制不存在: {DAEMON_PATH}")

    @pytest.fixture
    def multi_jail_setup(self, tmp_path):
        """创建多 Jail 测试环境"""
        log1 = tmp_path / "jail1.log"
        log2 = tmp_path / "jail2.log"
        log3 = tmp_path / "jail3.log"
        log1.write_text("")
        log2.write_text("")
        log3.write_text("")

        config = {
            "defaults": {
                "max_retries": 3, "findtime": 600, "ban_time": 300,
                "interval": 1, "metrics_port": 9122,
            },
            "jails": {
                "jail-alpha": {
                    "enabled": True,
                    "log_files": [str(log1)],
                    "max_retries": 3, "findtime": 600, "ban_time": 300,
                    "regexes": {"default": {"pattern": r"Failed login from (?P<ip>\d+\.\d+\.\d+\.\d+)"}},
                },
                "jail-beta": {
                    "enabled": True,
                    "log_files": [str(log2)],
                    "max_retries": 5, "findtime": 300, "ban_time": 600,
                    "regexes": {"default": {"pattern": r"unauthorized access from (?P<ip>\d+\.\d+\.\d+\.\d+)"}},
                },
                "jail-gamma": {
                    "enabled": True,
                    "log_files": [str(log3)],
                    "max_retries": 2, "findtime": 120, "ban_time": 900,
                    "regexes": {"default": {"pattern": r"blocked (?P<ip>\d+\.\d+\.\d+\.\d+)"}},
                },
            },
        }
        config_file = tmp_path / "multi_jail.yaml"
        config_file.write_text(yaml.dump(config))

        # 起过 daemon 必须让 teardown 重载模块清租约，否则后续用例的新 daemon 会被内核拒绝。
        mark_daemon_launched()
        proc = subprocess.Popen(
            [str(DAEMON_PATH), "-c", str(config_file)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        yield {
            "proc": proc,
            "log1": log1,
            "log2": log2,
            "log3": log3,
            "metrics_port": 9122,
        }

        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    def test_multi_jail_config_load(self, multi_jail_setup):
        """21.1 多 Jail 配置加载"""
        proc = multi_jail_setup["proc"]
        assert proc.poll() is None, "多 Jail 配置加载失败，守护进程未启动"

    def test_concurrent_log_write(self, multi_jail_setup):
        """21.2 多 Jail 日志并发写入"""
        log1 = multi_jail_setup["log1"]
        log2 = multi_jail_setup["log2"]
        log3 = multi_jail_setup["log3"]

        for i in range(1, 11):
            with open(log1, "a") as f:
                f.write(f"Failed login from 10.0.{i}.1\n")
            with open(log2, "a") as f:
                f.write(f"unauthorized access from 10.0.{i}.2\n")
            with open(log3, "a") as f:
                f.write(f"blocked 10.0.{i}.3\n")

        time.sleep(3)

        # 本次共写入 30 行（3 个 Jail × 10 行），守护进程解析计数应至少增加 30
        metrics = get_prometheus_metrics(multi_jail_setup["metrics_port"])
        if not metrics:
            pytest.skip("Prometheus 端点不可达")
        parsed = parse_metric(metrics, "firewall_daemon_lines_parsed_total")
        assert parsed >= 30, (
            f"并发写入 30 行后守护进程解析计数不足 (parsed={parsed})"
        )

    def test_jail_independence(self, multi_jail_setup):
        """21.3 Jail 独立性验证"""
        log3 = multi_jail_setup["log3"]
        metrics_port = multi_jail_setup["metrics_port"]

        for i in range(1, 4):
            with open(log3, "a") as f:
                f.write(f"blocked 10.0.50.{i}\n")

        time.sleep(2)

        try:
            result = subprocess.run(
                ["curl", "-s", f"http://localhost:{metrics_port}/metrics"],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout:
                # "or True" 使断言恒真；改为要求指标以真实样本行出现
                assert any(
                    line.startswith("firewall_daemon_lines_parsed_total ")
                    for line in result.stdout.splitlines()
                ), "指标端点未暴露 firewall_daemon_lines_parsed_total 样本行"
            else:
                pytest.skip(f"Prometheus 端点不可达 (端口 {metrics_port})")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pytest.skip(f"Prometheus 端点不可达 (端口 {metrics_port})")

    def test_cleanup(self, multi_jail_setup):
        """21.4 清理"""
        proc = multi_jail_setup["proc"]
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

        assert proc.poll() is not None, "守护进程未停止"
