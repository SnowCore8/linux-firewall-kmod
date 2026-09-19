"""17 - 配置热重载（SIGHUP）集成测试"""

import os
import shutil
import time

import pytest

from .conftest import get_daemon_pid, is_daemon_running


class TestConfigReload:
    """配置热重载（SIGHUP）集成测试"""

    CONFIG_PATH = "/etc/firewall/default.yaml"

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    @pytest.fixture(autouse=True)
    def backup_config(self, tmp_path):
        """备份并恢复配置"""
        backup = None
        config_existed = os.path.exists(self.CONFIG_PATH)

        if config_existed:
            backup = tmp_path / "default.yaml.bak"
            shutil.copy2(self.CONFIG_PATH, str(backup))

        yield

        if config_existed and backup and backup.exists():
            shutil.copy2(str(backup), self.CONFIG_PATH)
            pid = get_daemon_pid()
            if pid:
                os.kill(int(pid), 1)  # SIGHUP
        elif not config_existed and os.path.exists(self.CONFIG_PATH):
            os.remove(self.CONFIG_PATH)

    def test_daemon_pid(self):
        """17.1 守护进程 PID 获取"""
        pid = get_daemon_pid()
        assert pid, "无法获取守护进程 PID"

    def test_sighup_reload(self):
        """17.2 发送 SIGHUP 并验证进程存活"""
        pid = get_daemon_pid()
        if not pid:
            pytest.skip("守护进程未运行")

        os.kill(int(pid), 1)  # SIGHUP
        time.sleep(2)

        assert is_daemon_running(), "SIGHUP 后守护进程退出"

        after_pid = get_daemon_pid()
        assert pid == after_pid, f"守护进程 PID 变化: {pid} -> {after_pid}"

    def test_sighup_log_record(self):
        """17.3 验证日志中记录了重载事件"""
        log_path = "/var/log/firewall.log"
        if not os.path.exists(log_path):
            pytest.skip("日志文件不存在")

        before_lines = len(open(log_path).readlines())

        pid = get_daemon_pid()
        if pid:
            os.kill(int(pid), 1)
        time.sleep(2)

        after_lines = len(open(log_path).readlines())
        assert after_lines > before_lines, "SIGHUP 后日志无新内容"

    def test_modify_config_reload(self):
        """17.4 修改配置文件并重新加载"""
        if not os.path.exists(self.CONFIG_PATH):
            pytest.skip("配置文件不存在")

        content = open(self.CONFIG_PATH).read()
        modified = content.replace("max_retries: 3", "max_retries: 10")
        if modified == content:
            modified = content.replace("max_retries: 5", "max_retries: 10")

        with open(self.CONFIG_PATH, "w") as f:
            f.write(modified)

        pid = get_daemon_pid()
        if pid:
            os.kill(int(pid), 1)
        time.sleep(2)

        assert is_daemon_running(), "修改配置后 SIGHUP 守护进程退出"

    def test_invalid_config_tolerance(self):
        """17.5 无效配置测试"""
        if not os.path.exists(self.CONFIG_PATH):
            pytest.skip("配置文件不存在")

        backup_content = open(self.CONFIG_PATH).read()

        with open(self.CONFIG_PATH, "w") as f:
            f.write("invalid_yaml: [")

        pid = get_daemon_pid()
        if pid:
            os.kill(int(pid), 1)
        time.sleep(2)

        assert is_daemon_running(), "无效配置导致守护进程退出"

        with open(self.CONFIG_PATH, "w") as f:
            f.write(backup_content)

        if pid:
            os.kill(int(pid), 1)
        time.sleep(1)

    def test_multiple_sighup(self):
        """17.6 多次连续 SIGHUP 测试"""
        pid = get_daemon_pid()
        if not pid:
            pytest.skip("守护进程未运行")

        for _ in range(5):
            os.kill(int(pid), 1)
            time.sleep(0.5)

        time.sleep(2)
        assert is_daemon_running(), "连续 5 次 SIGHUP 后守护进程退出"
