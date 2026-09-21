"""18 - 日志轮转检测集成测试（自起 daemon，断言 log_rotations 指标）

本套件不再依赖外部已起的 daemon：自行用一份指向 tmp 目录 jail 的配置起进程，
以 `-c` 顶掉硬编码的 /etc 路径，端口取空闲端口避免与真实 daemon 抢 9119。
判定依据是 daemon 自身的 Prometheus 计数 `firewall_daemon_log_rotations_total`
（`log_rotation.rs` 在识别到轮转时自增），而不是「文件确实被改名了」这类只验证
测试脚手架的断言。

形态要求：本套件自起 daemon，需在 **daemon-down** 形态下运行——内核单守护进程
租约使得有外部 daemon 时自起会被拒（此时跳过）。
"""

import os
import shutil
import subprocess
import time

import pytest

from .config import DAEMON_PATH
from .conftest import (
    free_tcp_port,
    generate_test_yaml,
    get_prometheus_metrics,
    is_daemon_running,
    mark_daemon_launched,
    parse_metric,
    terminate_process,
    wait_for_metric,
)

# 轮转计数由 `log_rotation.rs::handle_log_rotation` 自增；行解析数由
# `line_processor.rs` 自增，用来确认「daemon 确实读到了新内容」。
_LOG_ROTATIONS = "firewall_daemon_log_rotations_total"
_LINES_PARSED = "firewall_daemon_lines_parsed_total"


def _log_lines(count: int, marker: str) -> str:
    """生成 `count` 行日志；每行首带 `marker` 便于人工排查是哪一轮写入的。"""
    return "".join(
        f"{marker} sshd[{1000 + i}]: Failed password for root from 198.51.100.77 "
        f"port {20000 + i} ssh2\n"
        for i in range(count)
    )


def _wait_until_http_ready(proc: subprocess.Popen, port: int, timeout: float = 8.0) -> None:
    """事件驱动等待 daemon 的 HTTP 端点就绪；进程提前退出直接判失败。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _out, err = proc.communicate()
            pytest.fail(
                "daemon 启动即退出（检查内核模块与配置）: "
                f"rc={proc.returncode} stderr={err.decode(errors='replace')[:200]}"
            )
        if get_prometheus_metrics(port):
            return
        time.sleep(0.2)
    pytest.fail(f"daemon HTTP 端口 {port} 未在 {timeout}s 内就绪")


class TestLogRotation:
    """日志轮转检测（inotify + inode 重连）。"""

    @pytest.fixture(autouse=True)
    def check_daemon_binary(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

    @pytest.fixture
    def running_daemon(self, tmp_path):
        """起一个只监控 tmp jail 的 daemon，yield `(proc, port, log_file)`。

        日志文件在启动前先建好（否则 inotify 无处可挂），断言走 daemon 的指标端点。
        """
        # 内核用「单守护进程租约」限制同一时刻只有一个 daemon（fw_netlink.c 的
        # portid 独占）：外部已有 daemon 在跑时，本用例自起的进程会被内核 Refused
        # 而立即退出。此时不是缺陷而是形态不匹配——跳过，并在 daemon-down 形态下运行。
        if is_daemon_running():
            pytest.skip(
                "已有守护进程持有内核租约，无法自起测试用 daemon；"
                "请在 daemon-down 形态下运行本套件"
            )

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "auth.log"
        log_file.write_text("")

        port = free_tcp_port()
        cfg_path = tmp_path / "rot.yaml"
        # max_retries 抬高：本套件只关心「轮转是否被识别 / 新内容是否被读」，不需要
        # 触发封禁；metrics_port 用空闲端口，缺省的 metrics_bind_address 是回环。
        generate_test_yaml(
            str(cfg_path),
            str(log_file),
            max_retries=100,
            findtime=600,
            ban_time=60,
            metrics_port=port,
        )

        # 声明本轮起过 daemon：`test_isolation` 收尾会重载模块以释放内核租约
        # （内核无注销消息，租约靠 30s 超时兜底，重载是唯一的立即释放手段）。
        mark_daemon_launched()
        proc = subprocess.Popen(
            [str(DAEMON_PATH), "-c", str(cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            _wait_until_http_ready(proc, port)
            yield proc, port, log_file
        finally:
            terminate_process(proc)

    def test_mv_rotation_triggers_detection(self, running_daemon):
        """18.1 `mv` 轮转（改名 + 新建同名文件）：inode 变化必须识别为一次轮转

        先写入并确认已被解析，再改名走 `MOVE_SELF` 分支，断言轮转计数自增。
        """
        _proc, port, log_file = running_daemon

        log_file.write_text(_log_lines(2, "before"))
        parsed = wait_for_metric(port, _LINES_PARSED, lambda v: v >= 2, timeout=6)
        assert parsed >= 2, f"初始日志未被解析（lines_parsed={parsed}）"

        base = parse_metric(get_prometheus_metrics(port), _LOG_ROTATIONS)

        # logrotate 风格：先改名（MOVE_SELF），再新建同名文件（新 inode）
        os.rename(log_file, f"{log_file}.1")
        log_file.write_text(_log_lines(2, "after"))

        after = wait_for_metric(
            port, _LOG_ROTATIONS, lambda v: v > base, timeout=8
        )
        assert after > base, (
            f"mv 轮转未被识别（log_rotations {base} -> {after}）"
        )

    def test_copytruncate_keeps_parsing(self, running_daemon):
        """18.2 copytruncate（原地清空后写新内容）：新内容必须仍被读到

        关键在偏移重置：若 daemon 未在文件缩小时把 offset 归零，会停在旧长度上，
        新写入的内容永远读不到。故先写大文件（offset 高），再 truncate 成更小的
        新文件——最终 size 小于旧 offset，收缩必然可被观测到。
        """
        _proc, port, log_file = running_daemon

        log_file.write_text(_log_lines(10, "old"))
        parsed0 = wait_for_metric(port, _LINES_PARSED, lambda v: v >= 10, timeout=6)
        assert parsed0 >= 10, f"初始日志未被解析（lines_parsed={parsed0}）"

        # copytruncate：备份后把原文件截断并写入更短的新内容（inode 不变）
        shutil.copy2(log_file, f"{log_file}.2")
        log_file.write_text(_log_lines(2, "new"))

        parsed1 = wait_for_metric(
            port, _LINES_PARSED, lambda v: v >= parsed0 + 2, timeout=8
        )
        assert parsed1 >= parsed0 + 2, (
            f"copytruncate 后新内容未被解析（lines_parsed {parsed0} -> {parsed1}）："
            "偏移未在文件缩小时重置"
        )
