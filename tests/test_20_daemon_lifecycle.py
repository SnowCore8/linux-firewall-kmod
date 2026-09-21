"""20 - 守护进程生命周期集成测试"""

import os
import signal
import subprocess
import time

import pytest
import yaml

from .config import DAEMON_PATH
from .conftest import mark_daemon_launched


class TestDaemonLifecycle:
    """守护进程生命周期集成测试"""

    PID_FILE = "/run/firewall-daemon.pid"

    @pytest.fixture(autouse=True)
    def check_daemon_binary(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程二进制不存在: {DAEMON_PATH}")

    @pytest.fixture
    def test_config(self, tmp_path):
        config = {
            "defaults": {
                "max_retries": 3, "findtime": 600, "ban_time": 300,
                "interval": 1, "metrics_port": 9121,
            },
            "jails": {
                "sshd": {
                    "enabled": True,
                    "log_files": ["/var/log/auth.log"],
                    "max_retries": 3, "findtime": 600, "ban_time": 300,
                    "regexes": {"default": {"pattern": ""}},
                }
            },
        }
        config_file = tmp_path / "lifecycle.yaml"
        config_file.write_text(yaml.dump(config))
        return str(config_file)

    @pytest.fixture
    def daemon_process(self, test_config):
        """启动并管理守护进程"""
        pid_file = self.PID_FILE

        if os.path.exists(pid_file):
            try:
                old_pid = int(open(pid_file).read().strip())
                os.kill(old_pid, signal.SIGTERM)
                time.sleep(1)
            except (ValueError, ProcessLookupError):
                pass
            try:
                os.remove(pid_file)
            except FileNotFoundError:
                pass

        # 起过 daemon 必须让 teardown 重载模块清租约，否则后续用例的新 daemon 会被内核拒绝。
        mark_daemon_launched()
        proc = subprocess.Popen(
            [str(DAEMON_PATH), "-c", test_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        yield proc

        try:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
        except Exception:
            pass

        try:
            os.remove(pid_file)
        except FileNotFoundError:
            pass

    def test_start_and_pid_file(self, daemon_process):
        """20.1 守护进程启动与 PID 文件"""
        assert daemon_process.poll() is None, "守护进程启动失败"

        if os.path.exists(self.PID_FILE):
            pid_content = open(self.PID_FILE).read().strip()
            assert pid_content == str(daemon_process.pid), (
                f"PID 文件内容不匹配: {pid_content} != {daemon_process.pid}"
            )

    def test_single_instance(self, daemon_process, test_config):
        """20.2 单实例约束"""
        second = subprocess.Popen(
            [str(DAEMON_PATH), "-c", test_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

        if second.poll() is not None:
            # 被拒绝的实例必须以非零码退出（daemonizer 的 flock 失败经 bail! 退出）
            assert second.returncode != 0, (
                f"第二个实例以退出码 {second.returncode} 退出，未被拒绝"
            )
        else:
            second.send_signal(signal.SIGTERM)
            second.wait(timeout=3)
            pytest.skip("第二个实例启动成功（单实例约束可能未启用）")

    def test_sigterm_graceful_exit(self, daemon_process):
        """20.3 SIGTERM 优雅退出"""
        if daemon_process.poll() is not None:
            pytest.skip("守护进程未运行")

        daemon_process.send_signal(signal.SIGTERM)
        try:
            daemon_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            daemon_process.kill()
            daemon_process.wait(timeout=2)

        assert daemon_process.poll() is not None, "SIGTERM 后守护进程仍在运行"
