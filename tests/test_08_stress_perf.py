"""08 - 压力/性能测试"""

import time

import pytest

from .config import (
    BAN_PERF_THRESHOLD_MS,
    PERF_TEST_COUNT,
    STRESS_IP_COUNT,
    STRESS_THRESHOLD_MS,
    UNBAN_PERF_THRESHOLD_MS,
)
from .conftest import wait_procfs


class TestStressPerf:
    """压力/性能测试"""

    def test_ban_performance(self, clean_bans):
        """8.1 封禁性能"""
        from .config import PROC_BANS

        start = time.time()

        for i in range(1, PERF_TEST_COUNT + 1):
            try:
                PROC_BANS.write_text(f"203.0.114.{i}")
            except (PermissionError, OSError):
                pass

        duration_ms = (time.time() - start) * 1000
        avg_ms = duration_ms / PERF_TEST_COUNT

        assert duration_ms <= BAN_PERF_THRESHOLD_MS, (
            f"封禁 {PERF_TEST_COUNT} IP 超时: {duration_ms:.0f}ms "
            f"(阈值 {BAN_PERF_THRESHOLD_MS}ms, 平均 {avg_ms:.1f}ms/IP)"
        )

    def test_unban_performance(self, clean_bans):
        """8.2 解封性能"""
        from .config import PROC_BANS

        for i in range(1, PERF_TEST_COUNT + 1):
            try:
                PROC_BANS.write_text(f"203.0.114.{i}")
            except (PermissionError, OSError):
                pass
        wait_procfs()

        start = time.time()

        for i in range(1, PERF_TEST_COUNT + 1):
            try:
                PROC_BANS.write_text(f"unban 203.0.114.{i}")
            except (PermissionError, OSError):
                pass

        duration_ms = (time.time() - start) * 1000
        avg_ms = duration_ms / PERF_TEST_COUNT

        assert duration_ms <= UNBAN_PERF_THRESHOLD_MS, (
            f"解封 {PERF_TEST_COUNT} IP 超时: {duration_ms:.0f}ms "
            f"(阈值 {UNBAN_PERF_THRESHOLD_MS}ms, 平均 {avg_ms:.1f}ms/IP)"
        )

    def test_stress_rapid_ban(self, clean_bans):
        """8.3 压力测试 (快速大量封禁)"""
        from .config import PROC_BANS

        start = time.time()

        for i in range(1, STRESS_IP_COUNT + 1):
            try:
                PROC_BANS.write_text(f"172.16.{i // 255}.{i % 255}")
            except (PermissionError, OSError):
                pass

        duration_ms = (time.time() - start) * 1000

        assert duration_ms <= STRESS_THRESHOLD_MS, (
            f"压力测试超时: {duration_ms:.0f}ms (阈值 {STRESS_THRESHOLD_MS}ms)"
        )

        for i in range(1, STRESS_IP_COUNT + 1):
            try:
                PROC_BANS.write_text(f"unban 172.16.{i // 255}.{i % 255}")
            except (PermissionError, OSError):
                pass
