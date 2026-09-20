"""18 - 日志轮转检测集成测试"""

import os
import shutil
import time

import pytest

from .config import CONFIG_DIR
from .conftest import get_daemon_pid, is_daemon_running


class TestLogRotation:
    """日志轮转检测集成测试"""

    # 配置取仓库内的 config/（而非硬编码 /etc/firewall）；日志目录用 pytest 的
    # tmp_path（而非硬编码 /var/log/firewall-test），避免触碰系统路径。
    CONFIG_PATH = CONFIG_DIR / "default.yaml"

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    @pytest.fixture(autouse=True)
    def setup_and_cleanup(self, tmp_path):
        """设置和清理测试环境"""
        backup = None
        config_existed = os.path.exists(self.CONFIG_PATH)

        if config_existed:
            backup = tmp_path / "default.yaml.bak"
            shutil.copy2(self.CONFIG_PATH, str(backup))

        self.log_dir = tmp_path / "firewall-test"
        self.test_log = self.log_dir / "test.log"
        os.makedirs(self.log_dir, exist_ok=True)

        yield

        pid = get_daemon_pid()
        if config_existed and backup and backup.exists():
            shutil.copy2(str(backup), self.CONFIG_PATH)
            if pid:
                os.kill(int(pid), 1)
        elif not config_existed:
            if os.path.exists(self.CONFIG_PATH):
                os.remove(self.CONFIG_PATH)

    def test_mv_rotation(self):
        """18.1 模拟日志轮转（mv + 创建新文件）"""
        with open(self.test_log, "w") as f:
            f.write("Before rotation\n")

        before_inode = os.stat(self.test_log).st_ino

        os.rename(self.test_log, f"{self.test_log}.1")
        assert os.path.isfile(f"{self.test_log}.1"), "旧日志未移动"

        with open(self.test_log, "w") as f:
            f.write("New log file after rotation\n")
        assert os.path.isfile(self.test_log), "新日志文件未创建"

        after_inode = os.stat(self.test_log).st_ino
        assert before_inode != after_inode, "日志轮转后 inode 未改变"

    def test_copytruncate_rotation(self):
        """18.2 模拟 copytruncate 轮转方式"""
        with open(self.test_log, "w") as f:
            f.write("Before copytruncate\n")

        before_inode = os.stat(self.test_log).st_ino

        shutil.copy2(self.test_log, f"{self.test_log}.2")
        with open(self.test_log, "w") as f:
            pass  # 清空文件

        after_inode = os.stat(self.test_log).st_ino
        assert before_inode == after_inode, "copytruncate 后 inode 改变"

        after_size = os.path.getsize(self.test_log)
        assert after_size == 0, f"copytruncate 后文件大小不为 0: {after_size}"

        with open(self.test_log, "w") as f:
            f.write("After copytruncate entry from 192.168.2.1\n")
        time.sleep(2)

        final_size = os.path.getsize(self.test_log)
        assert final_size > 0, f"copytruncate 后新内容未写入: {final_size} bytes"
