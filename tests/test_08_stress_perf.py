"""08 - 压力/性能测试"""

import os
import time

import pytest

from .config import (
    BAN_PERF_THRESHOLD_MS,
    PERF_TEST_COUNT,
    STRESS_IP_COUNT,
    STRESS_THRESHOLD_MS,
    UNBAN_PERF_THRESHOLD_MS,
)
from .conftest import count_bans, wait_procfs


@pytest.mark.slow
@pytest.mark.stress
class TestStressPerf:
    """压力/性能测试"""

    @pytest.mark.perf
    def test_ban_performance(self, clean_bans):
        """8.1 封禁性能"""
        from .config import PROC_BANS

        # 预热 5 次，让内核哈希表进入稳态
        for i in range(5):
            try:
                PROC_BANS.write_text(f"10.99.{i // 256}.{i % 256}")
            except (PermissionError, OSError):
                pass
        time.sleep(0.5)

        failures = 0

        # 记录系统负载，便于事后排查异常值
        load_avg = os.getloadavg()
        print(f"System load: {load_avg}")

        start = time.time()

        for i in range(1, PERF_TEST_COUNT + 1):
            try:
                PROC_BANS.write_text(f"203.0.114.{i}")
            except (PermissionError, OSError):
                failures += 1

        duration_ms = (time.time() - start) * 1000
        avg_ms = duration_ms / PERF_TEST_COUNT

        assert failures == 0, f"{failures}/{PERF_TEST_COUNT} 次封禁写入失败，耗时数据无效"
        wait_procfs()
        assert count_bans() >= PERF_TEST_COUNT, (
            f"封禁写入后仅 {count_bans()} 条，期望至少 {PERF_TEST_COUNT} 条"
        )

        assert duration_ms <= BAN_PERF_THRESHOLD_MS, (
            f"封禁 {PERF_TEST_COUNT} IP 超时: {duration_ms:.0f}ms "
            f"(阈值 {BAN_PERF_THRESHOLD_MS}ms, 平均 {avg_ms:.1f}ms/IP)"
        )

    def test_unban_performance(self, clean_bans):
        """8.2 解封性能"""
        from .config import PROC_BANS

        failures = 0
        for i in range(1, PERF_TEST_COUNT + 1):
            try:
                PROC_BANS.write_text(f"203.0.114.{i}")
            except (PermissionError, OSError):
                failures += 1
        assert failures == 0, f"预热封禁失败 {failures}/{PERF_TEST_COUNT} 次"
        wait_procfs()

        start = time.time()

        failures = 0
        for i in range(1, PERF_TEST_COUNT + 1):
            try:
                PROC_BANS.write_text(f"unban 203.0.114.{i}")
            except (PermissionError, OSError):
                failures += 1

        duration_ms = (time.time() - start) * 1000
        avg_ms = duration_ms / PERF_TEST_COUNT

        assert failures == 0, f"{failures}/{PERF_TEST_COUNT} 次解封写入失败，耗时数据无效"
        wait_procfs()
        assert count_bans() == 0, f"解封后仍残留 {count_bans()} 条封禁"

        assert duration_ms <= UNBAN_PERF_THRESHOLD_MS, (
            f"解封 {PERF_TEST_COUNT} IP 超时: {duration_ms:.0f}ms "
            f"(阈值 {UNBAN_PERF_THRESHOLD_MS}ms, 平均 {avg_ms:.1f}ms/IP)"
        )

    def test_stress_rapid_ban(self, clean_bans):
        """8.3 压力测试 (快速大量封禁)"""
        from .config import PROC_BANS

        start = time.time()

        failures = 0
        for i in range(1, STRESS_IP_COUNT + 1):
            try:
                PROC_BANS.write_text(f"172.16.{i // 255}.{i % 255}")
            except (PermissionError, OSError):
                failures += 1

        duration_ms = (time.time() - start) * 1000

        assert failures == 0, f"压力写入失败 {failures}/{STRESS_IP_COUNT} 次"
        wait_procfs()
        assert count_bans() >= STRESS_IP_COUNT, (
            f"压力写入后仅 {count_bans()} 条，期望至少 {STRESS_IP_COUNT} 条"
        )

        assert duration_ms <= STRESS_THRESHOLD_MS, (
            f"压力测试超时: {duration_ms:.0f}ms (阈值 {STRESS_THRESHOLD_MS}ms)"
        )

        for i in range(1, STRESS_IP_COUNT + 1):
            try:
                PROC_BANS.write_text(f"unban 172.16.{i // 255}.{i % 255}")
            except (PermissionError, OSError):
                pass
