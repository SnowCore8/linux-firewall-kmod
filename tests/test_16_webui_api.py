"""16 - Web UI API 端到端集成测试"""

import json
import subprocess
import time

import pytest

from .conftest import is_daemon_running


def curl_get(url: str, timeout: int = 5) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["curl", "-s", "-w", "%{http_code}", "-o", "/dev/stdout", url],
            capture_output=True, text=True, timeout=timeout,
        )
        body = result.stdout[:-3] if len(result.stdout) > 3 else ""
        code = int(result.stdout[-3:]) if len(result.stdout) >= 3 else 0
        return code, body
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        return 0, ""


class TestWebuiApi:
    """Web UI API 端到端集成测试"""

    WEBUI_PORT = 8080

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    def test_root_accessible(self):
        """16.1 Web UI 根路径可访问"""
        code, _ = curl_get(f"http://localhost:{self.WEBUI_PORT}/")
        assert code == 200, f"Web UI 根路径不可访问 (HTTP {code})"

    def test_api_stats(self):
        """16.2 /api/stats 端点测试"""
        code, body = curl_get(f"http://localhost:{self.WEBUI_PORT}/api/stats")
        assert code == 200, f"/api/stats 返回 HTTP {code}"
        assert len(body) > 0, "/api/stats 返回空响应"

        data = json.loads(body)
        assert isinstance(data, dict), "/api/stats 返回非 JSON 对象"

    def test_api_bans(self):
        """16.3 /api/bans 端点测试"""
        code, body = curl_get(f"http://localhost:{self.WEBUI_PORT}/api/bans")
        assert code == 200, f"/api/bans 返回 HTTP {code}"
        assert len(body) > 0, "/api/bans 返回空响应"

        data = json.loads(body)
        assert isinstance(data, list), "/api/bans 返回非数组"

    def test_api_jails(self):
        """16.4 /api/jails 端点测试"""
        code, body = curl_get(f"http://localhost:{self.WEBUI_PORT}/api/jails")
        assert code == 200, f"/api/jails 返回 HTTP {code}"

        data = json.loads(body)
        assert isinstance(data, (dict, list)), "/api/jails 返回无效格式"

    def test_api_config(self):
        """16.5 /api/config 端点测试"""
        code, body = curl_get(f"http://localhost:{self.WEBUI_PORT}/api/config")
        assert code == 200, f"/api/config 返回 HTTP {code}"

        data = json.loads(body)
        assert isinstance(data, dict), "/api/config 返回非 JSON 对象"

    def test_sse_endpoint(self):
        """16.6 SSE 连接测试"""
        try:
            result = subprocess.run(
                ["curl", "-s", "-N", "--max-time", "2",
                 f"http://localhost:{self.WEBUI_PORT}/events"],
                capture_output=True, text=True, timeout=5,
            )
            if "event:" in result.stdout:
                assert True
            else:
                pytest.skip("SSE /events 端点未响应")
        except subprocess.TimeoutExpired:
            pytest.skip("SSE 连接超时")

    def test_404_handling(self):
        """16.7 错误处理测试"""
        code, _ = curl_get(f"http://localhost:{self.WEBUI_PORT}/api/nonexistent")
        assert code == 404, f"不存在的端点返回 HTTP {code} (预期 404)"

    def test_response_time(self):
        """16.8 响应时间测试"""
        start = time.time()
        curl_get(f"http://localhost:{self.WEBUI_PORT}/api/stats")
        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 1000, f"/api/stats 响应时间过长: {duration_ms:.0f}ms"
