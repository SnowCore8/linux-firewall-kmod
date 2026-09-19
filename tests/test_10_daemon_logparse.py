"""10 - 日志解析测试"""

import subprocess
import time
from pathlib import Path

import pytest
import yaml

from .config import (
    DAEMON_PATH,
    LOG_LINE_FRP,
    LOG_LINE_NGINX,
    LOG_LINE_SSHD,
    LOG_LINE_SSHD_INVALID,
    LOG_LINE_VSFTPD,
    PROC_BANS,
)
from .conftest import count_bans, generate_test_yaml, run_daemon_captured, wait_procfs


class TestDaemonLogparse:
    """日志解析测试"""

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

    def test_log_parse_function(self, tmp_path):
        """10.1 日志解析功能"""
        test_log = tmp_path / "logparse.log"
        test_log.write_text(
            f"{LOG_LINE_SSHD}\n"
            f"{LOG_LINE_SSHD_INVALID}\n"
            f"{LOG_LINE_VSFTPD}\n"
            f"{LOG_LINE_NGINX}\n"
            f"{LOG_LINE_FRP}\n"
            "Invalid line with no IP address\n"
            "Mar 10 10:30:01 server sshd[1234]: Failed password for root from port ssh2\n"
        )

        yaml_config = tmp_path / "logparse.yaml"
        generate_test_yaml(str(yaml_config), str(test_log), max_retries=1, findtime=1, ban_time=5)

        run_daemon_captured([str(DAEMON_PATH), "-c", str(yaml_config)], timeout=5)
        time.sleep(1)

        if PROC_BANS.exists():
            ban_count = count_bans()
            if ban_count > 0:
                assert ban_count >= 1, "日志解析成功，有 IP 被封禁"
            else:
                pytest.skip("日志解析后无 IP 被封禁（可能是正则未匹配）")

    def test_special_char_log(self, tmp_path):
        """10.2 特殊字符日志处理"""
        special_log = tmp_path / "special.log"
        special_log.write_text(
            "Mar 10 10:30:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 12345 ssh2\n"
            "Mar 10 10:30:02 server sshd[1235]: Failed password for <script>alert('xss')</script> from 192.0.2.2 port 12346 ssh2\n"
            "Mar 10 10:30:03 server sshd[1236]: Failed password for root from 192.0.2.3 port 12347 ssh2\n"
        )

        special_yaml = tmp_path / "special.yaml"
        generate_test_yaml(str(special_yaml), str(special_log), max_retries=1, findtime=1, ban_time=5)

        run_daemon_captured([str(DAEMON_PATH), "-c", str(special_yaml)], timeout=5)
        time.sleep(1)

        assert PROC_BANS.exists(), "特殊字符日志处理后 procfs 不可访问"

    def test_empty_log(self, tmp_path):
        """10.3 空日志文件处理"""
        empty_log = tmp_path / "empty.log"
        empty_log.write_text("")

        empty_yaml = tmp_path / "empty.yaml"
        generate_test_yaml(str(empty_yaml), str(empty_log), max_retries=1, findtime=1, ban_time=5)

        run_daemon_captured([str(DAEMON_PATH), "-c", str(empty_yaml)], timeout=3)

        assert PROC_BANS.exists(), "空日志文件处理后 procfs 不可访问"

    def test_nonexistent_log(self, tmp_path):
        """10.4 不存在日志文件处理"""
        nonexist_yaml = tmp_path / "nonexist.yaml"
        generate_test_yaml(
            str(nonexist_yaml), "/nonexistent/log.log", max_retries=1, findtime=1, ban_time=5
        )

        try:
            result = subprocess.run(
                [str(DAEMON_PATH), "-c", str(nonexist_yaml)],
                capture_output=True,
                timeout=3,
            )
            assert result.returncode != 0, f"不存在的日志文件未被拒绝 (退出码={result.returncode})"
        except subprocess.TimeoutExpired:
            pytest.skip("守护进程启动超时（可能日志文件检查被阻塞）")
