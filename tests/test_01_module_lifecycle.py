"""01 - 模块装卸测试"""

import subprocess
from pathlib import Path

import pytest

from .config import KERNEL_MODULE_PATH, PROC_DIR
from .conftest import is_module_loaded, load_module


class TestModuleLifecycle:
    """模块装卸测试"""

    def test_module_file_exists(self):
        """1.1 内核模块文件存在"""
        assert KERNEL_MODULE_PATH.exists(), f"内核模块文件不存在: {KERNEL_MODULE_PATH}"

    def test_module_load(self):
        """1.2 模块加载成功"""
        assert is_module_loaded() or PROC_DIR.is_dir(), "模块未加载"

    def test_sysfs_parameter_readable(self):
        """1.3 sysfs 参数文件可读"""
        param_path = Path("/sys/module/firewall/parameters/fw_ban_time")
        if not param_path.exists():
            pytest.skip("sysfs 参数文件不存在")
        value = param_path.read_text().strip()
        assert value != "unknown", "sysfs 参数值不可读"

    def test_duplicate_load_rejected(self):
        """1.4 重复加载被拒绝"""
        result = subprocess.run(
            ["insmod", str(KERNEL_MODULE_PATH)],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0, "重复加载应被拒绝"
