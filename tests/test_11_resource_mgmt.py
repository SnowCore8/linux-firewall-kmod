"""11 - 资源管理测试"""

import time

import pytest

from .config import KERNEL_MODULE_PATH, PROC_BANS, PROC_DIR
from .conftest import (
    count_bans,
    get_stat,
    load_module,
    unload_module,
    wait_procfs,
)


class TestResourceMgmt:
    """资源管理测试"""

    def test_module_load_unload_cycle(self):
        """11.1 模块加载/卸载循环"""
        for _ in range(3):
            unload_module()
            load_module()

        assert PROC_BANS.exists(), "3 次加载/卸载循环后模块不可访问"

    def test_stability_after_many_ops(self, clean_bans):
        """11.2 大量操作后模块稳定性"""
        for i in range(1, 51):
            try:
                PROC_BANS.write_text(f"203.0.113.{i % 256}")
            except (PermissionError, OSError):
                pass

        wait_procfs()
        assert PROC_BANS.exists(), "大量操作后模块无响应"

        for i in range(1, 51):
            try:
                PROC_BANS.write_text(f"unban 203.0.113.{i % 256}")
            except (PermissionError, OSError):
                pass

    def test_ban_capacity_boundary(self, clean_bans):
        """11.3 封禁容量边界测试"""
        for i in range(1, 201):
            try:
                PROC_BANS.write_text(f"10.0.{i // 256}.{i % 256}")
            except (PermissionError, OSError):
                pass

        time.sleep(0.5)
        final_count = count_bans()
        stat_bans = get_stat("current_bans")
        # 内核有泛洪闸门（fw_max_bans_per_second，默认 200/秒），实际条目可能少于
        # 注入的 200；故断言内核计数为正、未超过注入量，且列表行数不少于该计数
        # （列表另含头/尾固定文本行），而非仅校验 4096 容量上限
        assert 0 < stat_bans <= 200, (
            f"写入 200 个 IP 后内核 current_bans 异常: {stat_bans}"
        )
        assert final_count >= stat_bans, (
            f"封禁列表行数({final_count})少于内核计数({stat_bans})"
        )

        for i in range(1, 201):
            try:
                PROC_BANS.write_text(f"unban 10.0.{i // 256}.{i % 256}")
            except (PermissionError, OSError):
                pass
            if i % 50 == 0:
                time.sleep(0.05)

    def test_procfs_cleanup_after_unload(self):
        """11.4 模块卸载后 procfs 清理"""
        unload_module()
        time.sleep(2)

        if not PROC_DIR.is_dir():
            pass  # 预期行为
        else:
            pytest.fail("模块卸载后 proc 目录仍存在")

        load_module()
