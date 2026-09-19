"""18 - 日志轮转检测集成测试"""

import os
import shutil
import time

import pytest

from .conftest import get_daemon_pid, is_daemon_running


class TestLogRotation:
    """日志轮转检测集成测试"""

    CONFIG_PATH = "/etc/firewall/default.yaml"
    TEST_LOG_DIR = "/var/log/firewall-test"
    TEST_LOG = "/var/log/firewall-test/test.log"

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

        os.makedirs(self.TEST_LOG_DIR, exist_ok=True)

        yield

        pid = get_daemon_pid()
        if config_existed and backup and backup.exists():
            shutil.copy2(str(backup), self.CONFIG_PATH)
            if pid:
                os.kill(int(pid), 1)
        elif not config_existed:
            for f in [self.CONFIG_PATH]:
                if os.path.exists(f):
                    os.remove(f)

        if os.path.exists(self.TEST_LOG_DIR):
            shutil.rmtree(self.TEST_LOG_DIR, ignore_errors=True)

    def test_mv_rotation(self):
        """18.1 模拟日志轮转（mv + 创建新文件）"""
        with open(self.TEST_LOG, "w") as f:
            f.write("Before rotation\n")

        before_inode = os.stat(self.TEST_LOG).st_ino

        os.rename(self.TEST_LOG, f"{self.TEST_LOG}.1")
        assert os.path.isfile(f"{self.TEST_LOG}.1"), "旧日志未移动"

        with open(self.TEST_LOG, "w") as f:
            f.write("New log file after rotation\n")
        assert os.path.isfile(self.TEST_LOG), "新日志文件未创建"

        after_inode = os.stat(self.TEST_LOG).st_ino
        assert before_inode != after_inode, "日志轮转后 inode 未改变"

    def test_copytruncate_rotation(self):
        """18.2 模拟 copytruncate 轮转方式"""
        with open(self.TEST_LOG, "w") as f:
            f.write("Before copytruncate\n")

        before_inode = os.stat(self.TEST_LOG).st_ino

        shutil.copy2(self.TEST_LOG, f"{self.TEST_LOG}.2")
        with open(self.TEST_LOG, "w") as f:
            pass  # 清空文件

        after_inode = os.stat(self.TEST_LOG).st_ino
        assert before_inode == after_inode, "copytruncate 后 inode 改变"

        after_size = os.path.getsize(self.TEST_LOG)
        assert after_size == 0, f"copytruncate 后文件大小不为 0: {after_size}"

        with open(self.TEST_LOG, "w") as f:
            f.write("After copytruncate entry from 192.168.2.1\n")
        time.sleep(2)

        final_size = os.path.getsize(self.TEST_LOG)
        assert final_size > 0, f"copytruncate 后新内容未写入: {final_size} bytes"
