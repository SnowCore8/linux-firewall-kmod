"""09 - 守护进程配置测试"""

import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from .config import CONFIG_DIR, DAEMON_PATH
from .conftest import daemon_starts_ok, generate_test_yaml


class TestDaemonConfig:
    """守护进程配置测试"""

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        """检查守护进程是否存在"""
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

    def test_daemon_help(self):
        """9.1 --help 正常"""
        result = subprocess.run(
            [str(DAEMON_PATH), "--help"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        assert result.returncode == 0, f"--help 失败: {result.stderr}"

    def test_config_dir_exists(self):
        """9.2 config/ 目录存在"""
        assert CONFIG_DIR.is_dir(), f"config 目录不存在: {CONFIG_DIR}"

    def test_default_yaml_exists(self):
        """9.2 default.yaml 存在"""
        default_yaml = CONFIG_DIR / "default.yaml"
        assert default_yaml.exists(), f"default.yaml 不存在: {default_yaml}"

    def test_default_config_dir_load(self):
        """9.3 默认配置目录加载"""
        ok, rc = daemon_starts_ok([str(DAEMON_PATH), "-C", str(CONFIG_DIR)])
        assert ok, f"默认配置目录加载失败 (退出码={rc})"

    def test_custom_config_dir(self, tmp_path):
        """9.4 指定配置目录 (-C)"""
        config_dir = tmp_path / "config"
        config_dir.mkdir()

        generate_test_yaml(
            str(config_dir / "test1.yaml"),
            "/var/log/auth.log",
            max_retries=7,
            findtime=120,
            ban_time=300,
            metrics_port=9130,
        )

        ok, rc = daemon_starts_ok([str(DAEMON_PATH), "-C", str(config_dir)])
        assert ok, f"指定配置目录加载失败 (退出码={rc})"

    def test_single_config_file(self):
        """9.5 单个配置文件加载 (-c)"""
        default_yaml = CONFIG_DIR / "default.yaml"
        ok, rc = daemon_starts_ok([str(DAEMON_PATH), "-c", str(default_yaml)])
        assert ok, f"单配置文件加载失败 (退出码={rc})"

    def test_invalid_config(self, tmp_path):
        """9.6 无效配置处理"""
        invalid_config = tmp_path / "invalid.yaml"
        invalid_config.write_text("invalid: [yaml: broken")

        result = subprocess.run(
            [str(DAEMON_PATH), "-c", str(invalid_config)],
            capture_output=True,
            text=True,
            timeout=2,
        )
        rc = result.returncode
        assert rc < 128 or rc == 137, f"无效 YAML 处理异常 (退出码={rc})"

    def test_nonexistent_config(self):
        """9.7 不存在的配置文件"""
        result = subprocess.run(
            [str(DAEMON_PATH), "-c", "/nonexistent/config.yaml"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        rc = result.returncode
        assert rc != 0 and rc not in (124, 137), (
            f"不存在配置文件未被拒绝 (退出码={rc})"
        )
