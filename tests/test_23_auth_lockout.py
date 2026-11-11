"""23 - 认证失败锁定（契约 auth 段）集成测试

锁定账本是**进程级**的（`src/daemon/internal/http/auth_lockout.go:22-29`：一份账本，
不按路由、不按来源 IP 切分），所以本套件自起 daemon：若对外部 daemon 触发锁定，后续
所有带凭据的用例会连续 401 最长 `lockout_seconds` 秒。

阈值与窗口取自 `contract/http.fwidl` 的 auth 段（契约是线格式的单一真相源），不在用例
里第二次写死 10 / 60。响应形状同样照契约 errmodel AUTH_UNAUTHORIZED：401 纯文本
`"401 Unauthorized\n"`——契约没有为锁定单独编一个状态码（例如 429）。

锁定窗口长 60 秒，本套件不真等它过期：窗口的「不会过早结束」用 2 秒观察证明，
重置路径用「重启进程清空账本」证明（账本是内存态，重启后的新进程必然未锁定）。
窗口到点自动解锁本身未在此验证（见 test_lockout_holds_then_clears_with_process_restart）。
"""

import os
import re
import time

import pytest

from .config import DAEMON_PATH, PROJECT_ROOT
from .conftest import (
    free_tcp_port,
    generate_test_yaml,
    http_basic_request,
    is_daemon_running,
    start_daemon,
    terminate_process,
    wait_http_ready,
)

# 用例自带的凭据：经环境变量注入，不写进临时配置文件，也不进入命令行参数
# （`internal/config/credentials_env.go` 的 applyEnvCredentials）。
_CREDS = ("fixture-user", "fixture-pass")
_WRONG = ("fixture-user", "fixture-pass-wrong")

# 契约 errmodel AUTH_UNAUTHORIZED 声明的响应体原文（auth.go 的 authUnauthorizedBody）。
_UNAUTHORIZED_BODY = "401 Unauthorized\n"


def _contract_auth() -> tuple[int, int]:
    """从契约读出 (failure_threshold, lockout_seconds)；缺项直接判失败。"""
    text = (PROJECT_ROOT / "contract" / "http.fwidl").read_text()
    values = {}
    for key in ("failure_threshold", "lockout_seconds"):
        match = re.search(rf"^\s*{key}\s*=\s*(\d+)", text, re.MULTILINE)
        assert match, f"contract/http.fwidl 的 auth 段缺少 {key}"
        values[key] = int(match.group(1))
    return values["failure_threshold"], values["lockout_seconds"]


class _Daemon:
    """自起 daemon 的管理器：可重启（验证锁定账本随进程消失）。"""

    def __init__(self, cfg_path: str, port: int):
        self.cfg_path = cfg_path
        self.port = port
        self.proc = None

    def start(self) -> "_Daemon":
        env = os.environ.copy()
        env["FIREWALL_METRICS_USERNAME"] = _CREDS[0]
        env["FIREWALL_METRICS_PASSWORD"] = _CREDS[1]
        self.proc = start_daemon(self.cfg_path, env=env)
        wait_http_ready(self.proc, self.port)
        return self

    def stop(self) -> None:
        if self.proc is not None:
            terminate_process(self.proc)
            self.proc = None

    def probe(self, credentials: tuple[str, str] | None) -> tuple[int, str]:
        """向一个 auth = required 的端点发一次请求（这里取封禁列表）。"""
        return http_basic_request(
            self.port, "GET", "/api/v2/bans", credentials, timeout=5.0
        )

    def expect(self, credentials: tuple[str, str] | None, want: int, note: str) -> str:
        code, body = self.probe(credentials)
        assert code == want, f"{note}: HTTP {code}（期望 {want}）"
        return body


class TestAuthLockout:
    """认证失败计数与锁定窗口的线上行为。"""

    @pytest.fixture(autouse=True)
    def check_daemon_binary(self):
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

    @pytest.fixture
    def daemon(self, tmp_path):
        # 单守护进程约束由内核租约保证：外部已有 daemon 时自起会被拒，属形态不匹配。
        if is_daemon_running():
            pytest.skip(
                "已有守护进程持有内核租约，无法自起测试用 daemon；"
                "请在 daemon-down 形态下运行本套件"
            )

        log_file = tmp_path / "auth.log"
        log_file.write_text("")
        port = free_tcp_port()
        cfg_path = tmp_path / "lockout.yaml"
        # max_retries 抬高：本套件不关心封禁判定，只要 daemon 起得来。
        generate_test_yaml(
            str(cfg_path),
            str(log_file),
            max_retries=100,
            findtime=600,
            ban_time=60,
            metrics_port=port,
        )

        daemon = _Daemon(str(cfg_path), port).start()
        try:
            yield daemon
        finally:
            daemon.stop()

    def test_consecutive_failures_lock_out_correct_credentials(self, daemon):
        """23.1 连续失败达阈值后锁定，正确凭据在锁定期内同样被拒

        含两条容易被合并掉的分支：成功请求清零连续计数（阈值下 1 次成功后再错 1 次
        不得锁定），以及锁定响应仍按契约是 401 纯文本而不是 429。
        """
        threshold, _ = _contract_auth()
        assert threshold >= 2, f"契约 failure_threshold={threshold} 太小，无法区分计数边界"

        daemon.expect(_CREDS, 200, "初始正确凭据")

        # 阈值下 1 次连续失败：尚未锁定
        for _ in range(threshold - 1):
            code, body = daemon.probe(_WRONG)
            assert code == 401, f"第 {threshold - 1} 次内的错误凭据返回 HTTP {code}"
            assert body == _UNAUTHORIZED_BODY, f"401 响应体与契约不符: {body!r}"

        # 成功请求必须清零连续计数：若未清零，下面的 1 次失败会凑满阈值并锁定。
        daemon.expect(_CREDS, 200, "阈值下 1 次成功")
        assert daemon.probe(_WRONG)[0] == 401
        daemon.expect(_CREDS, 200, "成功后连续计数已清零（未清零则此处已被锁定）")

        # 连续 threshold 次错误凭据：达到阈值
        for _ in range(threshold):
            code, _ = daemon.probe(_WRONG)
            assert code == 401, f"锁定前的错误凭据返回 HTTP {code}"

        body = daemon.expect(_CREDS, 401, "锁定期间的正确凭据")
        assert body == _UNAUTHORIZED_BODY, f"锁定响应体与契约不符: {body!r}"
        daemon.expect(_WRONG, 401, "锁定期间的错误凭据")
        # 账本是整进程一份（auth_lockout.go:15-20）：换一条 auth = required 的路由
        # 不能绕过锁定，否则按路由各计一份就把预算摊成了 28×threshold。
        code, _ = http_basic_request(daemon.port, "GET", "/metrics", _CREDS)
        assert code == 401, f"锁定期间 /metrics 放行了正确凭据（HTTP {code}）"

    def test_anonymous_requests_do_not_consume_budget(self, daemon):
        """23.2 未携带凭据的请求不计入失败次数

        面板加载时第一批请求本来就匿名（`internal/http/auth.go:56-60`）；若把它们算成
        失败，正常打开页面的人会把 API 锁死。
        """
        threshold, _ = _contract_auth()

        for _ in range(threshold * 2):
            code, _ = http_basic_request(daemon.port, "GET", "/api/v2/bans", None)
            assert code == 401

        daemon.expect(_CREDS, 200, "匿名请求不应消耗失败预算")

    def test_lockout_holds_then_clears_with_process_restart(self, daemon):
        """23.3 锁定期内不会过早解除；账本随进程重启清空

        窗口 60 秒不适合作用例时长，故「窗口到点自动解锁」不在本用例范围内（见模块
        文档）。这里证明两件事：锁定后 2 秒内正确凭据持续被拒（不是一次性抖动），
        以及新进程从「未锁定」起步（账本是内存态，无持久化）。
        """
        threshold, lockout_seconds = _contract_auth()
        assert lockout_seconds > 2, (
            f"契约 lockout_seconds={lockout_seconds}，本用例的 2 秒观察窗口不成立"
        )

        for _ in range(threshold):
            assert daemon.probe(_WRONG)[0] == 401
        daemon.expect(_CREDS, 401, "达到阈值后立即锁定")

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            daemon.expect(_CREDS, 401, "锁定窗口内正确凭据不得通过")
            time.sleep(0.25)

        daemon.stop()
        daemon.start()
        daemon.expect(_CREDS, 200, "重启后正确凭据应恢复可用")
