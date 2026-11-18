"""20 - 守护进程生命周期集成测试"""

import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from .config import DAEMON_PATH
from .conftest import (
    free_tcp_port,
    generate_test_yaml,
    mark_daemon_launched,
    terminate_process,
    wait_until,
)

# `-d/--daemon` 模式写下的 PID 文件路径（src/daemon/cmd/firewall-daemon/main.go 的
# daemonPIDFile）。该模式要写 /run，属于 root 用例；test_isolation 已保证本类只在 root
# 且内核模块就绪时执行。
PID_FILE = "/run/firewall-daemon.pid"
DAEMONIZED_ENV = "FIREWALL_DAEMONIZED=1"


def _read_pid_file() -> int | None:
    """读 PID 文件里的 pid；文件不存在或内容非法时返回 None。"""
    try:
        return int(Path(PID_FILE).read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _proc_cmdline(pid: int) -> str:
    """读 /proc/<pid>/cmdline，把 NUL 分隔符换成空格；进程不存在时返回空串。"""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b" ").decode(errors="replace")


def _proc_environ(pid: int) -> str:
    """读 /proc/<pid>/environ（NUL 分隔，转成换行分隔）；进程不存在时返回空串。"""
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\0", b"\n").decode(errors="replace")


def _find_test_daemons(test_config: str) -> list[int]:
    """扫描 /proc，返回命令行同时含 daemon 二进制与本用例配置路径的进程。"""
    binary = str(DAEMON_PATH).encode()
    config = test_config.encode()
    matches: list[int] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            continue
        if binary in raw and config in raw:
            matches.append(pid)
    return sorted(matches)


def _clear_stale_pid_file(test_config: str) -> None:
    """清掉上一轮遗留的测试 PID 文件。

    存活进程的 cmdline 必须含本用例配置才允许终止；否则拒绝碰它，让启动失败原样暴露。
    """
    pid = _read_pid_file()
    # cmdline 为空既可能是进程已消失，也可能是僵尸；两种都按陈旧记录处理。
    cmdline = _proc_cmdline(pid) if pid is not None else ""
    if cmdline:
        if test_config not in cmdline:
            pytest.fail(
                f"PID 文件 {PID_FILE} 被进程 {pid} 占用，其 cmdline 不含本用例配置 "
                f"{test_config}；拒绝终止非测试进程"
            )
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        wait_until(lambda: not Path(f"/proc/{pid}").exists(), timeout=3)
    try:
        os.remove(PID_FILE)
    except FileNotFoundError:
        pass


def _terminate_test_daemons(test_config: str) -> None:
    """终止本用例配置启动的所有 daemon（含 --daemon 子进程），并清掉其 PID 文件。"""
    pids = _find_test_daemons(test_config)
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    wait_until(lambda: not _find_test_daemons(test_config), timeout=5)
    for pid in _find_test_daemons(test_config):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
    wait_until(lambda: not _find_test_daemons(test_config), timeout=3)
    # 优雅退出的 daemon 会自己删 PID 文件；被 SIGKILL 时按内容归属补删。
    if _read_pid_file() in pids:
        try:
            os.remove(PID_FILE)
        except FileNotFoundError:
            pass


class TestDaemonLifecycle:
    """守护进程生命周期集成测试"""

    @pytest.fixture(autouse=True)
    def check_daemon_binary(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程二进制不存在: {DAEMON_PATH}")

    @pytest.fixture
    def test_config(self, tmp_path):
        config = {
            "defaults": {
                "max_retries": 3, "findtime": 600, "ban_time": 300,
                "interval": 1, "metrics_port": free_tcp_port(),
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
        """前台启动并管理守护进程（不带 --daemon，不写 PID 文件）。"""
        _clear_stale_pid_file(test_config)

        # 起过 daemon 必须让 teardown 重载模块清租约，否则后续用例的新 daemon 会被内核拒绝。
        mark_daemon_launched()
        proc = subprocess.Popen(
            [str(DAEMON_PATH), "-c", test_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # 慢环境（TCG/QEMU）里 9p 上的二进制装载可能超过 2s；等它真正登记租约。
        deadline = time.monotonic() + 6.0
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.2)
            if proc.poll() is not None:
                break
        time.sleep(1.0)

        yield proc

        terminate_process(proc)

    @pytest.fixture
    def daemonized_process(self, test_config):
        """用 `--daemon` 启动 daemon；父进程写完 PID 文件后立即退出。

        `-d` 模式由父进程重新执行出子进程并写下子进程 PID（daemonize.Spawn），
        因此 Popen 句柄对应的是父进程，返回后其 returncode 应为 0。
        """
        _clear_stale_pid_file(test_config)
        mark_daemon_launched()
        parent = subprocess.Popen(
            [str(DAEMON_PATH), "--daemon", "-c", test_config],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            _out, err = parent.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            terminate_process(parent)
            _terminate_test_daemons(test_config)
            pytest.fail("--daemon 父进程未退出（守护化后应立刻返回）")

        if parent.returncode != 0:
            stderr = err.decode(errors="replace")[:300]
            _terminate_test_daemons(test_config)
            pytest.fail(
                f"--daemon 父进程退出码 {parent.returncode}，stderr={stderr!r}"
            )

        try:
            yield parent
        finally:
            _terminate_test_daemons(test_config)

    def test_start_and_pid_file(self, daemon_process):
        """20.1 前台启动：进程存活，且不写 PID 文件

        PID 文件只由 `--daemon` 模式的父进程写入；前台模式（Popen 不带 --daemon）
        没有守护化步骤，因此不能拿 Popen.pid 去比对 /run/firewall-daemon.pid。
        """
        assert daemon_process.poll() is None, "守护进程启动失败"
        assert not os.path.exists(PID_FILE), (
            f"前台模式不应写 PID 文件 {PID_FILE}；该文件存在说明有其它 daemon 实例"
        )

    def test_daemon_mode_writes_pid_file(self, daemonized_process, test_config):
        """20.2 --daemon 模式写 PID 文件，内容等于真实 daemon 子进程 PID"""
        assert wait_until(lambda: _read_pid_file() is not None, timeout=5), (
            "--daemon 模式未写出 PID 文件"
        )
        pid = _read_pid_file()
        assert pid is not None, "PID 文件内容不可解析"

        # 父进程写完 PID 文件即退出，子进程可能尚未 exec 完成（cmdline/environ 还是
        # 父进程的副本）。轮询到出现 FIREWALL_DAEMONIZED 标记，确保读到的是子进程本身。
        def child_ready() -> bool:
            return (
                _find_test_daemons(test_config) == [pid]
                and DAEMONIZED_ENV in _proc_environ(pid)
            )

        assert wait_until(child_ready, timeout=5), (
            f"PID {pid} 未成为唯一的守护化子进程；"
            f"/proc 中匹配进程={_find_test_daemons(test_config)}, "
            f"environ 含标记={DAEMONIZED_ENV in _proc_environ(pid)}"
        )

        cmdline = _proc_cmdline(pid)
        assert str(DAEMON_PATH) in cmdline, (
            f"进程 {pid} 的 cmdline 不含 daemon 二进制: {cmdline!r}"
        )
        assert test_config in cmdline, (
            f"进程 {pid} 不是本用例配置启动的实例: {cmdline!r}"
        )
        assert "--daemon" in cmdline.split(), (
            f"进程 {pid} 的 cmdline 不含 --daemon: {cmdline!r}"
        )
        assert DAEMONIZED_ENV in _proc_environ(pid), (
            f"进程 {pid} 缺少 {DAEMONIZED_ENV}，不是守护化后的子进程"
        )
        assert daemonized_process.returncode == 0

    def test_single_instance(self, daemon_process, test_config, tmp_path):
        """20.3 单实例约束：第二实例在独立空闲端口上被内核明确拒绝"""
        assert daemon_process.poll() is None, "首个实例未运行，无法验证单实例约束"

        second_config = tmp_path / "second_instance.yaml"
        generate_test_yaml(
            str(second_config),
            str(tmp_path / "second_instance.log"),
            metrics_port=free_tcp_port(),
        )

        mark_daemon_launched()
        second = subprocess.Popen(
            [str(DAEMON_PATH), "-c", str(second_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            try:
                _out, err = second.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                terminate_process(second)
                pytest.fail(
                    "第二个实例未被单实例约束拒绝：它在独立空闲端口上持续存活"
                )
        finally:
            terminate_process(second)

        assert second.returncode != 0, (
            f"第二个实例以退出码 {second.returncode} 退出，未被拒绝"
        )
        stderr = err.decode(errors="replace")
        reasons = ("拒绝", "refused", "Refused", "已有活跃的守护进程", "单实例")
        assert any(reason in stderr for reason in reasons), (
            f"第二实例非零退出（rc={second.returncode}）但缺少明确拒绝原因："
            f"stderr={stderr[:300]!r}"
        )
        assert daemon_process.poll() is None, "第二实例退出时首个实例也已退出"

    def test_sigterm_graceful_exit(self, daemon_process):
        """20.4 SIGTERM 优雅退出"""
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
        """20.5 守护进程崩溃后，新实例可立即注册（无需等 30s 活动超时）

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
