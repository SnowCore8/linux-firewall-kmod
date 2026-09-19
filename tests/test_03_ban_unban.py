"""03 - 封禁/解封测试"""

import pytest

from .config import TEST_IP, TEST_IP2
from .conftest import (
    ban_ip,
    ban_multiple,
    count_bans,
    get_stat,
    ip_is_banned,
    unban_ip,
    unban_multiple,
    wait_procfs,
)
from .config import PROC_BANS


class TestBanUnban:
    """封禁/解封测试"""

    def test_basic_ban_unban(self, clean_bans):
        """3.1 基本封禁/解封"""
        ban_ip(TEST_IP)
        assert ip_is_banned(TEST_IP), f"IP {TEST_IP} 封禁失败"

        unban_ip(TEST_IP)
        assert not ip_is_banned(TEST_IP), f"IP {TEST_IP} 解封失败"

    def test_batch_ban(self, clean_bans):
        """3.2 批量封禁"""
        ips = [f"203.0.113.{i}" for i in range(1, 11)]
        ban_multiple(*ips)

        count = count_bans()
        assert count >= 10, f"批量封禁 10 个 IP，实际 {count} 个"

        unban_multiple(*ips)

    def test_duplicate_ban(self, clean_bans):
        """3.3 重复封禁处理"""
        ban_ip(TEST_IP2)
        ban_ip(TEST_IP2)

        content = PROC_BANS.read_text()
        dup_count = content.count(TEST_IP2)
        assert dup_count == 1, f"重复封禁产生 {dup_count} 个条目，预期 1 个"

        unban_ip(TEST_IP2)

    def test_ban_unban_cycle(self, clean_bans):
        """3.4 封禁/解封循环稳定性"""
        for cycle in range(1, 6):
            ip = f"198.51.100.{cycle}"
            ban_ip(ip)
            unban_ip(ip)

        for cycle in range(1, 6):
            ip = f"198.51.100.{cycle}"
            assert not ip_is_banned(ip), f"IP {ip} 未解封"

    def test_duplicate_ban_stats(self, clean_bans):
        """3.5 重复封禁不污染统计计数器"""
        test_ip = "203.0.113.250"

        total_before = get_stat("total_bans")
        current_before = get_stat("current_bans")

        ban_ip(test_ip)
        ban_ip(test_ip)
        ban_ip(test_ip)

        total_after = get_stat("total_bans")
        current_after = get_stat("current_bans")

        total_delta = total_after - total_before
        current_delta = current_after - current_before

        assert total_delta == 1, f"重复 ban 3 次后 total_bans 应 +1，实际 +{total_delta}"
        assert current_delta == 1, f"重复 ban 3 次后 current_bans 应 +1，实际 +{current_delta}"

        unban_ip(test_ip)

    def test_ipv6_duplicate_ban_stats(self, clean_bans):
        """3.6 IPv6 重复封禁不污染统计"""
        v6_ip = "2001:db8::1"

        if ip_is_banned(v6_ip):
            unban_ip(v6_ip)

        total_before = get_stat("total_bans")
        current_before = get_stat("current_bans")

        PROC_BANS.write_text(v6_ip)
        PROC_BANS.write_text(v6_ip)
        PROC_BANS.write_text(v6_ip)
        wait_procfs()

        total_after = get_stat("total_bans")
        current_after = get_stat("current_bans")

        total_delta = total_after - total_before
        current_delta = current_after - current_before

        assert total_delta == 1, f"IPv6 重复 ban 3 次后 total_bans 应 +1，实际 +{total_delta}"
        assert current_delta == 1, f"IPv6 重复 ban 3 次后 current_bans 应 +1，实际 +{current_delta}"

        unban_ip(v6_ip)
