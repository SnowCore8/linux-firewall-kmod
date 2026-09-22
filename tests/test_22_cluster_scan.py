"""集群扫描检测（按 /24）集成测试。

判定语义见 ``src/daemon/decision/cluster.rs``：同一网段内出现足够多的不同源
IP、且每个 IP 的失败数都很低时，判为集群扫描并封禁该网段。

本用例覆盖的是「点得着」的部分——配置能被接受、日志写入后确实产生封禁记录；
逐条边界（恰好 N、恰好 K、跨窗口、/24 边界）由 ``cluster.rs`` 的内嵌单测与
``tests/`` 里的纯逻辑用例负责，集成层不做阈值细节断言。
"""

import re
import signal
import subprocess
import time

import pytest
import yaml

from .config import DAEMON_PATH
from .conftest import mark_daemon_launched

# 触发封禁的失败行：单个 IP 只出现一次，故单 IP 阈值不可能被触及。
CLUSTER_PATTERN = r"probe from (?P<ip>\d+\.\d+\.\d+\.\d+)"

# 集群检测周期（daemon 侧 `CLUSTER_SCAN_INTERVAL`）为 10 秒，且首个到期点是
# 「启动 + 一个周期」，故判定从启动后约 10 秒才开始。等到 25 秒留足余量。
DETECT_WAIT_SECONDS = 25


def _banned_ips() -> set[str]:
    """读取内核封禁表里的 IP 集合（模块未加载时返回空集）。"""
    try:
        with open("/proc/firewall/bans", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return set()
    return set(re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", text))


def _banned_cidrs() -> set[str]:
    """读取封禁表里的网段条目（形如 ``203.0.113.0/24``）。"""
    try:
        with open("/proc/firewall/bans", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return set()
    return set(re.findall(r"\b\d+\.\d+\.\d+\.\d+/\d{1,2}\b", text))


class TestClusterScan:
    """网段内多源 IP 的集群扫描判定"""

    @pytest.fixture(autouse=True)
    def check_daemon_binary(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程二进制不存在: {DAEMON_PATH}")

    @pytest.fixture
    def cluster_setup(self, tmp_path):
        """一个开了 cluster 检测的 jail，参数收窄到便于触发。"""
        log = tmp_path / "cluster.log"
        log.write_text("")

        config = {
            "defaults": {
                "max_retries": 100,  # 单 IP 阈值刻意抬高：只有集群判定能触发
                "findtime": 600,
                "ban_time": 300,
                "interval": 1,
                "metrics_port": 9123,
            },
            "jails": {
                "probe": {
                    "enabled": True,
                    "log_files": [str(log)],
                    "max_retries": 100,
                    "findtime": 600,
                    "ban_time": 300,
                    "regexes": {"default": {"pattern": CLUSTER_PATTERN}},
                    "cluster": {
                        "enabled": True,
                        "audit_only": False,
                        "window": 600,
                        "min_ips": 3,
                        "max_per_ip": 1,
                        "ban_time": 300,
                    },
                },
            },
        }
        config_file = tmp_path / "cluster.yaml"
        config_file.write_text(yaml.dump(config))

        mark_daemon_launched()
        proc = subprocess.Popen(
            [str(DAEMON_PATH), "-c", str(config_file)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        yield {"proc": proc, "log": log}

        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    def test_cluster_config_is_accepted(self, cluster_setup):
        """22.1 带 cluster 段的配置能被接受（字段名与类型正确）。"""
        assert cluster_setup["proc"].poll() is None, (
            "带 cluster 配置的守护进程启动失败——检查 YAML 字段名是否与 "
            "YamlCluster 一致"
        )

    def test_single_heavy_ip_does_not_trigger(self, cluster_setup):
        """22.2 单 IP 高频失败不触发集群判定。

        这是判据不误伤的核心：``max_per_ip`` 把「一个 /24 一个 IP、但是很活跃」
        排除在外（正常访客与 CGNAT 都是这个形状）。

        等待时长必须盖过一整轮检测周期——否则用例会在检测真正跑起来之前就断言
        「没有封禁」，那是空断言。与 22.3 配对：两者等同样久，一个证有命中、
        一个证无命中，才说明判据在跑且分得开。
        """
        log = cluster_setup["log"]
        before = _banned_ips()
        with open(log, "a") as f:
            for _ in range(20):
                f.write("probe from 198.51.100.7\n")
        time.sleep(DETECT_WAIT_SECONDS)
        after = _banned_ips()
        assert after == before, (
            f"单个高频 IP 不应因集群判定被封禁，但封禁表出现了 {after - before}"
        )

    def test_distinct_ips_in_one_subnet_trigger(self, cluster_setup):
        """22.3 同一 /24 内多个不同源 IP 触发集群判定。

        每个 IP 只失败一次（远低于 ``max_retries``），单 IP 计数永不达标；
        命中只能来自集群判定。
        """
        log = cluster_setup["log"]
        before = _banned_ips()
        with open(log, "a") as f:
            for host in (11, 12, 13, 14):
                f.write(f"probe from 203.0.113.{host}\n")
        time.sleep(DETECT_WAIT_SECONDS)
        after = _banned_ips()

        # 命中后可由两种形态落地：整段条目（203.0.113.0/24）或展开为逐 IP。
        # 两者都算通过——处置粒度是实现细节，用例只断言「该网段被处置」。
        hit_cidrs = _banned_cidrs()
        hit_ips = after - before
        subnet = {"203.0.113.%d" % h for h in (11, 12, 13, 14)}
        assert "203.0.113.0/24" in hit_cidrs or hit_ips & subnet, (
            f"同一 /24 内 4 个不同 IP 各失败一次，应触发集群封禁；"
            f"实际新增封禁 {hit_ips}，网段条目 {hit_cidrs}"
        )
