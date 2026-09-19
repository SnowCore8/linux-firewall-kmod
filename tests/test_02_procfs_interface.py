"""02 - Procfs 接口测试"""

import pytest

from .config import PROC_BANS, PROC_CONFIG, PROC_DIR, PROC_STATS, PROC_WHITELIST
from .conftest import get_stat


class TestProcfsInterface:
    """Procfs 接口测试"""

    def test_proc_dir_exists(self):
        """2.1 proc 目录存在"""
        assert PROC_DIR.is_dir(), f"proc 目录不存在: {PROC_DIR}"

    def test_bans_file_exists(self):
        """2.1 bans 接口文件存在"""
        assert PROC_BANS.exists(), f"bans 文件不存在: {PROC_BANS}"

    def test_whitelist_file_exists(self):
        """2.1 whitelist 接口文件存在"""
        assert PROC_WHITELIST.exists(), f"whitelist 文件不存在: {PROC_WHITELIST}"

    def test_stats_file_exists(self):
        """2.1 stats 接口文件存在"""
        assert PROC_STATS.exists(), f"stats 文件不存在: {PROC_STATS}"

    def test_config_file_exists(self):
        """2.1 config 接口文件存在"""
        assert PROC_CONFIG.exists(), f"config 文件不存在: {PROC_CONFIG}"

    def test_bans_writable(self):
        """2.2 bans 接口可写"""
        import os
        assert os.access(str(PROC_BANS), os.W_OK), "bans 接口不可写"

    def test_whitelist_writable(self):
        """2.2 whitelist 接口可写"""
        import os
        assert os.access(str(PROC_WHITELIST), os.W_OK), "whitelist 接口不可写"

    def test_stats_readable(self):
        """2.3 stats 接口可读"""
        content = PROC_STATS.read_text()
        assert len(content) > 0, "stats 内容为空"

    def test_stats_has_expected_fields(self):
        """2.3 stats 包含预期字段"""
        content = PROC_STATS.read_text()
        expected_fields = ["current_bans", "total_bans", "total_unbans"]
        for field in expected_fields:
            assert field in content, f"stats 缺少字段: {field}"

    def test_config_readable(self):
        """2.4 config 接口可读"""
        content = PROC_CONFIG.read_text()
        assert len(content) > 0, "config 内容为空"

    def test_stats_values_are_numbers(self):
        """2.5 stats 值为数字"""
        content = PROC_STATS.read_text()
        for line in content.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    int(parts[1])
                except ValueError:
                    pytest.fail(f"stats 值非数字: {line}")
