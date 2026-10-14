"""16 - Web UI API 端到端集成测试（版本化 /api/v1/*）"""

import json
import time

import pytest

from .conftest import daemon_http_port, http_request, is_daemon_running, run_curl


def curl_get(url: str, timeout: int = 5) -> tuple[int, str]:
    """GET 一次，返回 (HTTP 状态码, 响应体)；不跟随重定向以便断言 3xx。

    实现收敛到 `conftest.http_request`：部署配置带凭据时自动补 Basic 认证，凭据经
    stdin 注入，不进 argv（否则 pytest 打印命令行时会漏密码）。
    """
    return http_request("GET", url, None, timeout)


class TestWebuiApi:
    """Web UI API 端到端集成测试。

    重写后的 daemon 把 Web UI / JSON API / SSE / metrics 放在**同一监听端口**
    （`defaults.metrics_port`，默认 9119），路径一律带 `/api/v1` 前缀，响应统一为
    `{"code","data","message"}` 信封。旧用例使用的独立 `WEBUI_PORT = 8080` 与
    非版本化路径（`/api/stats`、`/api/bans`、`/events`）已不存在。
    """

    @pytest.fixture(autouse=True)
    def check_daemon(self):
        if not is_daemon_running():
            pytest.skip("守护进程未运行")

    @staticmethod
    def _base() -> str:
        """监听地址基址（端口从仓库默认配置读取）。"""
        return f"http://localhost:{daemon_http_port()}"

    def test_root_redirects_to_dashboard(self):
        """16.1 根路径重定向到 /dashboard（SPA 入口），/dashboard 可访问"""
        code, _ = curl_get(f"{self._base()}/")
        assert code in (301, 302, 303, 307, 308), f"根路径未重定向 (HTTP {code})"

        code, _ = curl_get(f"{self._base()}/dashboard")
        assert code == 200, f"/dashboard 不可访问 (HTTP {code})"

    def test_api_stats(self):
        """16.2 /api/v1/stats 返回统一信封，data 为对象"""
        code, body = curl_get(f"{self._base()}/api/v1/stats")
        assert code == 200, f"/api/v1/stats 返回 HTTP {code}"
        data = json.loads(body)
        assert isinstance(data, dict), "/api/v1/stats 返回非 JSON 对象"
        assert "code" in data and "data" in data, "/api/v1/stats 缺少统一信封字段"
        assert isinstance(data["data"], dict), "/api/v1/stats 的 data 非对象"

    def test_api_bans(self):
        """16.3 /api/v1/bans 返回分页信封，data.items 为数组"""
        code, body = curl_get(f"{self._base()}/api/v1/bans")
        assert code == 200, f"/api/v1/bans 返回 HTTP {code}"
        data = json.loads(body)
        assert isinstance(data.get("data"), dict), "/api/v1/bans 的 data 非对象"
        assert isinstance(data["data"].get("items"), list), "data.items 非数组"

    def test_api_jails(self):
        """16.4 /api/v1/jails 可访问且 data 形状合法"""
        code, body = curl_get(f"{self._base()}/api/v1/jails")
        assert code == 200, f"/api/v1/jails 返回 HTTP {code}"
        data = json.loads(body)
        assert isinstance(data.get("data"), (dict, list)), "/api/v1/jails 的 data 形状非法"

    def test_api_config(self):
        """16.5 /api/v1/config 返回统一信封，data 为对象"""
        code, body = curl_get(f"{self._base()}/api/v1/config")
        assert code == 200, f"/api/v1/config 返回 HTTP {code}"
        data = json.loads(body)
        assert isinstance(data.get("data"), dict), "/api/v1/config 的 data 非对象"

    def test_sse_endpoint(self):
        """16.6 SSE 连接（/api/v1/events）返回行首 event: 字段

        `/api/v1/events` 是 `auth = required`。curl 设得了请求头，所以走契约的
        `Authorization: Basic` 首选通道（`run_curl` 经 stdin 注入），不用只给
        `EventSource` 兜底的 `?access_token=`：那种写法会把凭据拼进 URL，而 URL
        出现在 argv 里、也会出现在失败输出里。
        """
        result = run_curl(
            ["-s", "-N", "--max-time", "2"],
            f"{self._base()}/api/v1/events",
        )
        stdout = result.stdout if result is not None else ""
        assert "event:" in stdout, "SSE 未返回任何事件字段"
        fields = [
            line.split(":", 1)[0]
            for line in stdout.splitlines()
            if ":" in line
        ]
        assert "event" in fields, "SSE 响应缺少行首 event: 字段"

    def test_404_handling(self):
        """16.7 不存在的端点返回 404"""
        code, _ = curl_get(f"{self._base()}/api/v1/nonexistent")
        assert code == 404, f"不存在的端点返回 HTTP {code} (预期 404)"

    def test_response_time(self):
        """16.8 /api/v1/stats 响应时间"""
        start = time.time()
        curl_get(f"{self._base()}/api/v1/stats")
        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 1000, f"/api/v1/stats 响应时间过长: {duration_ms:.0f}ms"
