"""17 - 配置热重载（SIGHUP）集成测试"""

import os
import shutil
import time

import pytest

from .config import CONFIG_DIR
from .conftest import (
    daemon_http_port,
    get_daemon_pid,
    get_prometheus_metrics,
    is_daemon_running,
    parse_metric,
)

# 配置重载次数以 daemon 的 Prometheus 指标 `firewall_daemon_config_reloads_total`
# 为权威读数（`src/daemon/config_reloader.rs` 在每次成功重载时自增）。日志行数不是
# 可靠信号：租约/轮询告警按秒混入，会掩盖真实的重载。
_RELOAD_METRIC = "firewall_daemon_config_reloads_total"


def _reloads() -> float:
    """读取 daemon 的配置重载计数；指标端点不可达时直接断言失败（不静默返回 0）。"""
    metrics = get_prometheus_metrics(daemon_http_port())
    assert metrics, "Prometheus 端点不可访问，无法读取重载计数"
    return parse_metric(metrics, _RELOAD_METRIC)


class TestConfigReload:
    """配置热重载（SIGHUP）集成测试。

    配置文件取仓库内 `config/`（而非硬编码 `/etc/firewall/default.yaml`，该路径
    在开发机上并不存在），与 `test_18` 的做法一致。
    """

    CONFIG_PATH = CONFIG_DIR / "default.yaml"

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

    def test_no_spontaneous_reload(self):
        """17.3 静置期不得自触发重载（回归：回写 ↔ inotify 自持环）

        先静置 2 秒，让上一用例 teardown 发出的 SIGHUP 落地（重载在主循环 poll
        超时分支处理，最多延迟 `interval` 秒）；随后取基线，2 秒内计数必须完全
        不变。自持重载风暴以每秒数十次的速度持续自增，故该等式断言可失败。
        """
        time.sleep(2)  # 排空上一用例遗留的延迟重载
        first = _reloads()
        time.sleep(2)
        second = _reloads()
        assert second == first, (
            f"静置期间配置重载自增 {first} -> {second}："
            "疑似回写触发自身 inotify 监视，形成自持重载风暴"
        )

    def test_sighup_triggers_reload(self):
        """17.4 SIGHUP 必须触发一次配置重载（以指标轮询为准，不依赖日志行数）"""
        pid = get_daemon_pid()
        if not pid:
            pytest.skip("守护进程未运行")

        before = _reloads()
        os.kill(int(pid), 1)  # SIGHUP

        # daemon 的 SIGHUP 在主循环 poll 超时分支被处理，延迟最长为配置的
        # `interval` 秒；此处轮询至多 6 秒，超时即判失败。
        deadline = time.time() + 6
        after = before
        while time.time() < deadline:
            after = _reloads()
            if after > before:
                break
            time.sleep(0.3)

        assert after > before, f"SIGHUP 未触发配置重载（计数仍为 {before}）"
        assert is_daemon_running(), "SIGHUP 后守护进程退出"

    def test_modify_config_reload(self):
        """17.5 修改配置文件并重新加载"""
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
        """17.6 无效配置测试"""
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
        """17.7 多次连续 SIGHUP 测试"""
        pid = get_daemon_pid()
        if not pid:
            pytest.skip("守护进程未运行")

        for _ in range(5):
            os.kill(int(pid), 1)
            time.sleep(0.5)

        time.sleep(2)
        assert is_daemon_running(), "连续 5 次 SIGHUP 后守护进程退出"
