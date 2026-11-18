"""09 - 守护进程配置测试"""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from .config import CONFIG_DIR, DAEMON_PATH
from .conftest import daemon_starts_ok, free_tcp_port, generate_test_yaml


def _config_with_free_port(source: Path, dest: Path) -> Path:
    """复制默认配置到 dest，只把 metrics_port 换成空闲端口。

    自起 daemon 的用例必须独占端口（见 tests/README.md「两种测试形态」）。本用例要
    验证仓库默认配置能加载，故保留文件其余内容，仅替换监听端口，避免与 daemon-up
    形态的外部 daemon 抢 9119。
    """
    port = free_tcp_port()
    text = source.read_text()
    text, count = re.subn(
        r"(?m)^(\s*)metrics_port:\s*\d+",
        rf"\g<1>metrics_port: {port}",
        text,
    )
    if count != 1:
        pytest.fail(f"默认配置 {source} 应恰有一行 metrics_port，实际 {count} 行")
    dest.write_text(text)
    return dest


class TestDaemonConfig:
    """守护进程配置测试"""

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        """检查守护进程是否存在"""
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

    @pytest.mark.no_module
    def test_daemon_help(self):
        """9.1 --help 正常"""
        result = subprocess.run(
            [str(DAEMON_PATH), "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, f"--help 失败: {result.stderr}"

    @pytest.mark.no_module
    def test_config_dir_exists(self):
        """9.2 config/ 目录存在"""
        assert CONFIG_DIR.is_dir(), f"config 目录不存在: {CONFIG_DIR}"

    @pytest.mark.no_module
    def test_default_yaml_exists(self):
        """9.2 default.yaml 存在"""
        default_yaml = CONFIG_DIR / "default.yaml"
        assert default_yaml.exists(), f"default.yaml 不存在: {default_yaml}"

    def test_default_config_dir_load(self, tmp_path):
        """9.3 默认配置目录加载（复制默认配置，仅替换监听端口）"""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        for source in CONFIG_DIR.glob("*.yaml"):
            dest = config_dir / source.name
            if source.name == "default.yaml":
                _config_with_free_port(source, dest)
            else:
                shutil.copyfile(source, dest)

        ok, rc = daemon_starts_ok([str(DAEMON_PATH), "-C", str(config_dir)])
        assert ok, f"默认配置目录加载失败 (退出码={rc})"

    def test_custom_config_dir(self, tmp_path):
        """9.4 指定配置目录 (-C)"""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        test_log = tmp_path / "auth.log"
        test_log.write_text("")
        generate_test_yaml(
            str(config_dir / "test1.yaml"),
            str(test_log),
            max_retries=7,
            findtime=120,
            ban_time=300,
            metrics_port=free_tcp_port(),
        )

        ok, rc = daemon_starts_ok([str(DAEMON_PATH), "-C", str(config_dir)])
        assert ok, f"指定配置目录加载失败 (退出码={rc})"

    def test_single_config_file(self, tmp_path):
        """9.5 单个配置文件加载 (-c)（复制默认配置，仅替换监听端口）"""
        default_yaml = _config_with_free_port(
            CONFIG_DIR / "default.yaml", tmp_path / "default.yaml"
        )
        ok, rc = daemon_starts_ok([str(DAEMON_PATH), "-c", str(default_yaml)])
        assert ok, f"单配置文件加载失败 (退出码={rc})"

    @pytest.mark.no_module
    def test_invalid_config(self, tmp_path):
        """9.6 无效配置处理"""
        invalid_config = tmp_path / "invalid.yaml"
        invalid_config.write_text("invalid: [yaml: broken")

        result = subprocess.run(
            [str(DAEMON_PATH), "-c", str(invalid_config)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        rc = result.returncode
        assert rc < 128 or rc == 137, f"无效 YAML 处理异常 (退出码={rc})"

    @pytest.mark.no_module
    def test_nonexistent_config(self):
        """9.7 不存在的配置文件"""
        result = subprocess.run(
            [str(DAEMON_PATH), "-c", "/nonexistent/config.yaml"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        rc = result.returncode
        assert rc != 0 and rc not in (124, 137), (
            f"不存在配置文件未被拒绝 (退出码={rc})"
        )
