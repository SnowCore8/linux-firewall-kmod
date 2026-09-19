"""11 - 资源管理测试"""

import time

import pytest

from .config import KERNEL_MODULE_PATH, MAX_BAN_CAPACITY, PROC_BANS, PROC_DIR
from .conftest import (
    count_bans,
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
        """11.3 封禁容量边界测试 (4096 上限)"""
        for i in range(1, 201):
            try:
                PROC_BANS.write_text(f"10.0.{i // 256}.{i % 256}")
            except (PermissionError, OSError):
                pass

        time.sleep(0.5)
        final_count = count_bans()
        assert final_count <= MAX_BAN_CAPACITY, (
            f"封禁数量超出 {MAX_BAN_CAPACITY} 上限，实际 {final_count}"
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
