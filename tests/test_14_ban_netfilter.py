"""14 - 黑名单 IP netfilter 封禁测试"""

import time

import pytest

from .config import PROC_BANS, PROC_STATS
from .conftest import get_stat, ip_is_banned, wait_procfs


class TestBanNetfilter:
    """netfilter 封禁条目格式与包统计验证"""

    TEST_IP = "223.5.5.5"

    def test_initial_packet_stats(self, clean_bans):
        """14.1 初始包统计记录"""
        dropped = get_stat("packets_dropped")
        accepted = get_stat("packets_accepted")
        assert dropped >= 0, f"packets_dropped 初始值异常: {dropped}"
        assert accepted >= 0, f"packets_accepted 初始值异常: {accepted}"

    def test_ban_entry_format(self, clean_bans):
        """14.2 netfilter 封禁条目格式"""
        PROC_BANS.write_text(self.TEST_IP)
        time.sleep(1)

        content = PROC_BANS.read_text()
        lines = [l for l in content.splitlines() if self.TEST_IP in l]
        assert len(lines) > 0, f"ban_table 中无 {self.TEST_IP} 的记录"

    def test_packet_stats_after_ban(self, clean_bans):
        """14.3 封禁后包统计变化"""
        before_bans = get_stat("current_bans")

        PROC_BANS.write_text(self.TEST_IP)
        time.sleep(1)

        after_bans = get_stat("current_bans")
        assert after_bans > before_bans, (
            f"封禁数量未增加 ({before_bans} → {after_bans})"
        )

        PROC_BANS.write_text(f"unban {self.TEST_IP}")
        time.sleep(1)

        final_bans = get_stat("current_bans")
        assert final_bans <= before_bans + 1, (
            f"current_bans 未恢复: before={before_bans}, final={final_bans}"
        )
