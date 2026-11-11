"""24 - 并发配置重载 + 封禁/解封集成测试（M-21 / L-26）

自起 daemon（空闲端口、临时配置、凭据经环境变量注入），三件事同时进行：

1. 手工封禁 / 解封（`POST` / `DELETE /api/v2/bans`）；
2. SIGHUP 触发的配置热重载（`internal/runtime/file_reloader.go` 的 Reload）；
3. `PUT /api/v2/config` 写 webui 段（`internal/http/config_api.go` 的 persistWebui）。

断言的是「丢失更新」这类缺陷：重载不得把已成功写入的封禁或配置回退。重载把整份
`cfg` 换掉（`fileReloader.applyConfig`），若它在 PUT 写盘之后又用旧内容覆盖内存，
或把封禁镜像清空，终态就会与文件/响应不一致。

重载计数以 daemon 的 Prometheus 指标 `firewall_daemon_config_reloads_total` 为准
（`cmd/firewall-daemon/main.go:1005`，每次成功重载自增），等待一律轮询，不靠固定
sleep 猜落地时刻；并发结束后再补一次重载，让内存收敛到文件，终态断言才有确定答案。
"""

import json
import os
import signal
import threading

import pytest
import yaml

from .config import DAEMON_PATH
from .conftest import (
    free_tcp_port,
    generate_test_yaml,
    http_basic_request,
    is_daemon_running,
    parse_metric,
    start_daemon,
    terminate_process,
    wait_http_ready,
    wait_until,
)

_CREDS = ("fixture-user", "fixture-pass")
_RELOAD_METRIC = "firewall_daemon_config_reloads_total"

# TEST-NET-3：稳定封禁集只封不解，churn 集反复「封 → 解」。
_STABLE_IPS = [f"203.0.113.{octet}" for octet in range(10, 22)]
_CHURN_IPS = [f"203.0.113.{octet}" for octet in range(30, 33)]

# 两个合法取值（rate_warning_pps 必须小于 rate_critical_pps 的默认 200000），
# 交替写入以制造「PUT 与重载竞争同一份 webui 段」的窗口。
_PUT_VALUES = [70000, 90000, 70000]
_RELOAD_ROUNDS = 4


def _api(port: int, method: str, path: str, body: dict | None = None, timeout: float = 8.0):
    return http_basic_request(port, method, path, _CREDS, body, timeout)


def _reloads(port: int) -> float:
    """读取重载计数；端点不可达时直接判失败（不静默返回 0）。"""
    code, body = _api(port, "GET", "/metrics")
    assert code == 200, f"/metrics 返回 HTTP {code}，无法读取重载计数"
    return parse_metric(body, _RELOAD_METRIC)


class TestConcurrentReloadBans:
    """并发重载与封禁写入的一致性。"""

    @pytest.fixture(autouse=True)
    def check_daemon_binary(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

    @pytest.fixture
    def daemon(self, tmp_path):
        # 内核单守护进程租约：外部已有 daemon 时自起会被拒，属形态不匹配。
        if is_daemon_running():
            pytest.skip(
                "已有守护进程持有内核租约，无法自起测试用 daemon；"
                "请在 daemon-down 形态下运行本套件"
            )

        log_file = tmp_path / "auth.log"
        log_file.write_text("")
        port = free_tcp_port()
        cfg_path = tmp_path / "concurrent.yaml"
        generate_test_yaml(
            str(cfg_path),
            str(log_file),
            max_retries=100,
            findtime=600,
            ban_time=60,
            metrics_port=port,
        )

        env = os.environ.copy()
        env["FIREWALL_METRICS_USERNAME"] = _CREDS[0]
        env["FIREWALL_METRICS_PASSWORD"] = _CREDS[1]
        proc = start_daemon(str(cfg_path), env=env)
        try:
            wait_http_ready(proc, port)
            yield proc, port, cfg_path
        finally:
            terminate_process(proc)

    def test_reload_during_ban_churn_keeps_state(self, daemon):
        """24.1 重载与封禁/解封/配置写入并发：不得 5xx，也不得回退已写入的状态"""
        proc, port, cfg_path = daemon

        results: list[tuple[str, int, str]] = []
        churn_final: dict[str, bool] = {}
        churn_lock = threading.Lock()
        worker_errors: list[BaseException] = []
        failed_reloads: list[int] = []
        barrier = threading.Barrier(4)

        def reload_worker() -> None:
            for round_no in range(_RELOAD_ROUNDS):
                before = _reloads(port)
                os.kill(proc.pid, signal.SIGHUP)
                # 重载在 daemon 主循环 poll 超时分支处理，最多延迟 interval(1s)；
                # 计数不自增就是「这次重载没落地」，按失败记录，不猜。
                if not wait_until(lambda: _reloads(port) > before, timeout=6.0, interval=0.1):
                    failed_reloads.append(round_no)
                    return

        def stable_ban_worker() -> None:
            for ip in _STABLE_IPS:
                code, _ = _api(port, "POST", "/api/v2/bans", {"ip": ip, "duration": 300})
                results.append(("ban", code, ip))

        def churn_worker() -> None:
            for _ in range(3):
                for ip in _CHURN_IPS:
                    code, _ = _api(port, "POST", "/api/v2/bans", {"ip": ip, "duration": 300})
                    results.append(("churn-ban", code, ip))
                    if code == 201:
                        with churn_lock:
                            churn_final[ip] = True
                    code, _ = _api(port, "DELETE", f"/api/v2/bans/{ip}")
                    results.append(("churn-unban", code, ip))
                    if code == 200:
                        with churn_lock:
                            churn_final[ip] = False

        def config_worker() -> None:
            for value in _PUT_VALUES:
                code, _ = _api(port, "PUT", "/api/v2/config", {"rate_warning_pps": value})
                results.append(("config", code, str(value)))

        def guarded(worker) -> None:
            try:
                barrier.wait(timeout=10)
                worker()
            except BaseException as exc:  # noqa: BLE001 - 收进断言里统一报告
                worker_errors.append(exc)

        threads = [
            threading.Thread(target=guarded, args=(worker,))
            for worker in (reload_worker, stable_ban_worker, churn_worker, config_worker)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        assert not any(thread.is_alive() for thread in threads), "并发 worker 未在 60s 内结束"

        assert not worker_errors, f"并发 worker 抛出异常: {worker_errors}"
        assert not failed_reloads, (
            f"封禁/解封与配置写入并发期间第 {failed_reloads} 次重载未落地"
        )

        server_errors = [item for item in results if 500 <= item[1] < 600]
        assert not server_errors, f"并发期间出现 5xx: {server_errors[:5]}"

        bad_bans = [item for item in results if item[0] == "ban" and item[1] != 201]
        assert not bad_bans, f"稳定封禁未全部成功: {bad_bans[:5]}"
        bad_churn = [
            item for item in results if item[0] == "churn-ban" and item[1] != 201
        ] + [item for item in results if item[0] == "churn-unban" and item[1] != 200]
        assert not bad_churn, f"churn 封禁/解封出现非预期状态码: {bad_churn[:5]}"
        bad_config = [item for item in results if item[0] == "config" and item[1] != 200]
        assert not bad_config, f"PUT /config 未全部成功: {bad_config[:5]}"

        # 补一次重载让内存收敛到文件，再断言终态：这是「最终一致」的判据。
        before = _reloads(port)
        os.kill(proc.pid, signal.SIGHUP)
        assert wait_until(lambda: _reloads(port) > before, timeout=6.0, interval=0.1), (
            "并发结束后的收尾重载未落地"
        )

        last_value = _PUT_VALUES[-1]
        code, body = _api(port, "GET", "/api/v2/config")
        assert code == 200, f"GET /api/v2/config 返回 HTTP {code}"
        current = json.loads(body)["data"]["rate_warning_pps"]
        assert current == last_value, (
            f"重载把刚写入的配置回退：rate_warning_pps={current}，期望 {last_value}"
        )
        on_disk = yaml.safe_load(cfg_path.read_text()).get("webui", {})
        assert on_disk.get("rate_warning_pps") == last_value, (
            f"配置文件里的值与 API 返回不一致: {on_disk.get('rate_warning_pps')}"
        )

        code, body = _api(port, "GET", "/api/v2/bans?page=1&page_size=100")
        assert code == 200, f"GET /api/v2/bans 返回 HTTP {code}"
        listed = {item["ip"] for item in json.loads(body)["data"]["items"]}
        missing = [ip for ip in _STABLE_IPS if ip not in listed]
        assert not missing, f"重载把已写入的封禁回退（列表中缺失）: {missing}"
        drifted = [ip for ip, banned in churn_final.items() if (ip in listed) != banned]
        assert not drifted, (
            f"churn IP 终态与最后一次成功操作不一致: {drifted}"
        )

        assert proc.poll() is None, "并发重载后守护进程退出"
        assert _api(port, "GET", "/api/v2/health")[0] == 200
