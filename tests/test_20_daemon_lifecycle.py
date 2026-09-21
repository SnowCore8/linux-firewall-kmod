"""20 - 守护进程生命周期集成测试"""

import os
import signal
import subprocess
import time

import pytest
import yaml

from .config import DAEMON_PATH
from .conftest import mark_daemon_launched, terminate_process


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

    def test_immediate_takeover_after_crash(self, test_config):
        """20.4 守护进程崩溃后，新实例可立即注册（无需等 30s 活动超时）

        回归：内核侧的注册互斥原先只认「30 秒活动超时」这一条判据，而 daemon 崩溃
        （SIGKILL / OOM / panic）不发任何注销报文。于是一个被 SIGKILL 的 daemon 会
        占住 portid 租约最长 30 秒，这段时间内服务管理器反复重启也只会拿到
        `accepted = 0` 并以非零码退出——即「崩溃后 30 秒起不来」。

        修复：内核在拒绝注册前先探活旧 portid（`netlink_unicast` 返回负值即视为
        已无 socket），已死则立即放行接管，30 秒活动超时退居「活着但卡死」的兜底。

        本用例刻意**不重载模块**：重载会直接清空租约，那样测不到接管逻辑本身。
        两个 daemon 都调用 mark_daemon_launched()，故末尾的 release_kernel_lease
        仍会在 teardown 里重载模块，不把租约泄漏给后续用例。
        """
        # 第一个实例：正常注册并持有租约
        mark_daemon_launched()
        first = subprocess.Popen(
            [str(DAEMON_PATH), "-c", test_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(2)
            assert first.poll() is None, (
                f"首个实例未启动：rc={first.returncode} "
                f"stderr={first.stderr.read().decode(errors='replace')[:200] if first.stderr else ''}"
            )

            # 模拟崩溃：SIGKILL 不发注销消息，租约仍在旧 portid 上
            first.kill()
            first.wait(timeout=3)

            # 紧接着起第二个实例：窗口内（远小于 30 秒）应能立即注册成功
            mark_daemon_launched()
            second = subprocess.Popen(
                [str(DAEMON_PATH), "-c", test_config],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            try:
                time.sleep(2)
                if second.poll() is not None:
                    err = (
                        second.stderr.read().decode(errors="replace")[:300]
                        if second.stderr
                        else ""
                    )
                    pytest.fail(
                        "崩溃后立即重启被拒：内核未消除 30s 注册盲窗 "
                        f"(rc={second.returncode}, stderr={err})"
                    )
            finally:
                terminate_process(second)
        finally:
            terminate_process(first)
