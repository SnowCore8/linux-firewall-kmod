"""pytest 测试框架 - fixtures 和辅助函数"""

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from .config import (
    BUILD_DIR,
    CONFIG_DIR,
    DAEMON_PATH,
    KERNEL_MODULE_PATH,
    PROC_BANS,
    PROC_CONFIG,
    PROC_DIR,
    PROC_STATS,
    PROC_WHITELIST,
    PROCFS_SYNC_DELAY,
)

# ============================================================================
# 内核模块管理
# ============================================================================


def is_module_loaded() -> bool:
    """检查内核模块是否已加载"""
    result = subprocess.run(["lsmod"], capture_output=True, text=True)
    return any(line.startswith("firewall") for line in result.stdout.splitlines())


def load_module(params: str = "") -> bool:
    """加载内核模块"""
    unload_module()
    time.sleep(0.3)

    cmd = ["insmod", str(KERNEL_MODULE_PATH)]
    if params:
        cmd.extend(params.split())

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False

    # 验证模块加载成功
    for _ in range(10):
        if is_module_loaded():
            return True
        time.sleep(0.2)
    return False


def unload_module() -> bool:
    """卸载内核模块"""
    if not is_module_loaded():
        return True

    result = subprocess.run(["rmmod", "firewall"], capture_output=True, text=True)
    if result.returncode != 0:
        return False

    time.sleep(0.3)
    return not is_module_loaded()


def check_module_ready() -> bool:
    """检查模块是否完全就绪"""
    if not is_module_loaded():
        return False
    if not PROC_DIR.is_dir():
        return False
    if not os.access(str(PROC_BANS), os.W_OK):
        return False
    return True


# ============================================================================
# 内核租约卫生
# ============================================================================

# 本轮用例是否起过 daemon。内核把「单守护进程」实现为 `portid + 30 秒活动超时`
# （src/kernel-module/fw_netlink.c 的 FW_NL_DAEMON_TIMEOUT），daemon 侧与内核侧都
# 没有注销消息，因此 daemon 退出（含被 SIGKILL）后租约仍被占住最多 30 秒：这期间
# 任何新 daemon 都会收到 `Refused`，并按既有裁定以非零码退出。唯一可靠的立即释放
# 手段是重载模块，故只在确实起过 daemon 的轮次付这次代价。
_daemon_launched = False


def mark_daemon_launched() -> None:
    """标记本轮已起过 daemon。

    任何新增的 daemon 启动点都必须调用它，否则该轮次结束后租约会残留，污染下一个
    用例（表现为新 daemon 以非零码退出、用例断言失败）。
    """
    global _daemon_launched
    _daemon_launched = True


def release_kernel_lease() -> None:
    """重载模块以清空内核侧的守护进程租约；本轮未起过 daemon 时是空操作。

    必须在用例**之后**调用：重载会一并清掉封禁/白名单/速率等模块内状态。卸载或
    加载失败时不抛错，后续用例的 `check_module_ready` 会照常跳过。
    """
    global _daemon_launched
    if not _daemon_launched:
        return
    _daemon_launched = False
    load_module()
    time.sleep(0.3)


def terminate_process(proc: subprocess.Popen, timeout: float = 3.0) -> None:
    """先 SIGTERM 再兜底 SIGKILL，并等到进程真正退出。

    SIGTERM 让 daemon 走完自己的清理路径（状态回写、关库、删 PID 文件）；直接
    SIGKILL 会留下半写状态。等待退出还保证后续步骤看到的进程表是稳定的。
    """
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    proc.kill()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


# ============================================================================
# Procfs 辅助函数
# ============================================================================


def wait_procfs():
    """等待 procfs 处理完成"""
    time.sleep(PROCFS_SYNC_DELAY)


def get_stat(name: str) -> int:
    """获取 procfs 统计值"""
    try:
        content = PROC_STATS.read_text()
        for line in content.splitlines():
            if name in line:
                parts = line.split()
                if len(parts) >= 2:
                    return int(parts[1])
    except (FileNotFoundError, ValueError, PermissionError):
        pass
    return 0


def count_bans() -> int:
    """获取封禁列表行数"""
    try:
        lines = PROC_BANS.read_text().strip().splitlines()
        return len([l for l in lines if l.strip()])
    except (FileNotFoundError, PermissionError):
        return 0


def count_whitelist() -> int:
    """获取白名单行数"""
    try:
        lines = PROC_WHITELIST.read_text().strip().splitlines()
        return len([l for l in lines if l.strip()])
    except (FileNotFoundError, PermissionError):
        return 0


def ban_ip(ip: str):
    """封禁 IP"""
    PROC_BANS.write_text(ip)
    wait_procfs()


def ban_ip_with_time(ip: str, seconds: int):
    """封禁 IP 带时长"""
    PROC_BANS.write_text(f"{ip} {seconds}")
    wait_procfs()


def ban_ip_permanent(ip: str):
    """永久封禁 IP"""
    PROC_BANS.write_text(f"{ip} 0")
    wait_procfs()


def unban_ip(ip: str):
    """解封 IP"""
    PROC_BANS.write_text(f"unban {ip}")
    wait_procfs()


def ban_multiple(*ips: str):
    """批量封禁"""
    for ip in ips:
        try:
            PROC_BANS.write_text(ip)
        except PermissionError:
            pass
    wait_procfs()


def unban_multiple(*ips: str):
    """批量解封"""
    for ip in ips:
        try:
            PROC_BANS.write_text(f"unban {ip}")
        except PermissionError:
            pass
    wait_procfs()


def ip_is_banned(ip: str) -> bool:
    """检查 IP 是否在封禁列表中"""
    try:
        content = PROC_BANS.read_text()
        return ip in content
    except (FileNotFoundError, PermissionError):
        return False


def whitelist_add(subnet: str):
    """添加白名单"""
    PROC_WHITELIST.write_text(f"add {subnet}")
    wait_procfs()


def whitelist_remove(subnet: str):
    """移除白名单"""
    PROC_WHITELIST.write_text(f"remove {subnet}")
    wait_procfs()


# ============================================================================
# 数据重置
# ============================================================================


def reset_all_data():
    """重置所有测试数据"""
    # 清空封禁列表
    try:
        content = PROC_BANS.read_text()
        ips = re.findall(r"^\d+\.\d+\.\d+\.\d+", content, re.MULTILINE)
        # 也匹配 IPv6
        ipv6s = re.findall(r"^[0-9a-fA-F:]+(?::[0-9a-fA-F]+)+", content, re.MULTILINE)
        for ip in ips + ipv6s:
            try:
                PROC_BANS.write_text(f"unban {ip}")
            except PermissionError:
                pass
        if ips or ipv6s:
            wait_procfs()
    except (FileNotFoundError, PermissionError):
        pass

    # 清空手动白名单
    try:
        content = PROC_WHITELIST.read_text()
        manual_entries = re.findall(
            r"^(\S+)\s+.*\b(manual|restored)\s*$", content, re.MULTILINE
        )
        for entry in manual_entries:
            subnet = entry[0] if isinstance(entry, tuple) else entry
            try:
                PROC_WHITELIST.write_text(f"remove {subnet}")
            except PermissionError:
                pass
        if manual_entries:
            wait_procfs()
    except (FileNotFoundError, PermissionError):
        pass

    # 清理临时文件
    for pattern in ["/tmp/fw_test_*.log", "/tmp/fw_test_*.yaml",
                    "/tmp/fw_test_*.conf", "/tmp/fw_test_*.tmp",
                    "/tmp/fw_test_*.db", "/tmp/test_bans.db"]:
        import glob
        for f in glob.glob(pattern):
            try:
                os.remove(f)
            except OSError:
                pass


def cleanup_state():
    """清理模块状态文件与残留的 daemon 进程"""
    try:
        os.remove("/var/lib/firewall/state")
    except FileNotFoundError:
        pass
    # 只按「测试专用配置路径」定位进程，避免误伤真实 daemon；先 SIGTERM 让其优雅
    # 退出，短暂等待后再对仍存活的补 SIGKILL。
    pattern = "firewall-daemon -c /var/log/firewall_test_"
    pids = subprocess.run(
        ["pgrep", "-f", pattern], capture_output=True, text=True
    ).stdout.split()
    for pid in pids:
        subprocess.run(["kill", "-TERM", pid], capture_output=True)
    if pids:
        time.sleep(0.5)
        for pid in pids:
            subprocess.run(["kill", "-KILL", pid], capture_output=True)


# ============================================================================
# 守护进程辅助函数
# ============================================================================


def daemon_starts_ok(cmd: list[str]) -> tuple[bool, int]:
    """运行守护进程，接受 0/124/137/超时 为正常退出码。

    用 Popen + communicate 而不是 `subprocess.run(timeout=...)`：后者超时会直接
    SIGKILL 掉守护进程，留下最多 30 秒不释放的内核租约（见 release_kernel_lease）。
    """
    mark_daemon_launched()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.communicate(timeout=2)
        rc = proc.returncode
        return rc in (0, 124, 137, -9), rc
    except subprocess.TimeoutExpired:
        terminate_process(proc)
        return True, 124


def is_daemon_running() -> bool:
    """检查守护进程是否运行"""
    result = subprocess.run(["pgrep", "-f", "firewall-daemon"], capture_output=True)
    return result.returncode == 0


def get_daemon_pid() -> str:
    """获取守护进程 PID"""
    result = subprocess.run(
        ["pgrep", "-f", "firewall-daemon"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip().splitlines()[0]
    return ""


def get_prometheus_metrics(port: int = 9119) -> str:
    """获取 Prometheus 指标"""
    try:
        result = subprocess.run(
            ["curl", "-s", f"http://localhost:{port}/metrics"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def parse_metric(metrics: str, name: str) -> float:
    """解析 Prometheus 指标值"""
    for line in metrics.splitlines():
        if line.startswith(f"{name} "):
            return float(line.split()[1])
    return 0.0


def run_daemon_captured(cmd: list[str], timeout: int = 5):
    """运行守护进程，超时视为正常（长运行服务）。

    超时后用 SIGTERM 停掉并等其退出，不用 `subprocess.run(timeout=...)` 的 SIGKILL：
    后者会留下未释放的内核租约，见 release_kernel_lease。
    """
    mark_daemon_launched()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate_process(proc)


def daemon_run_probe(cmd: list[str], timeout: int = 3) -> tuple[int | None, bytes]:
    """起 daemon 观察 `timeout` 秒：仍在运行返回 `(None, b"")`，提前退出返回 `(退出码, stderr)`。

    供「守护进程不应因某个配置而退出」这类用例使用。与 `subprocess.run(timeout=...)`
    的区别同 run_daemon_captured：超时走 SIGTERM 并等待退出，不残留内核租约。
    """
    mark_daemon_launched()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _out, err = proc.communicate(timeout=timeout)
        return proc.returncode, err
    except subprocess.TimeoutExpired:
        terminate_process(proc)
        return None, b""


def generate_test_yaml(
    file_path: str,
    log_file: str,
    max_retries: int = 1,
    findtime: int = 1,
    ban_time: int = 5,
    metrics_port: int = 9119,
    jail_name: str = "sshd",
):
    """生成测试用 YAML 配置"""
    config = {
        "defaults": {
            "max_retries": max_retries,
            "findtime": findtime,
            "ban_time": ban_time,
            "interval": 1,
            "metrics_port": metrics_port,
        },
        "jails": {
            jail_name: {
                "enabled": True,
                "log_files": [log_file],
                "max_retries": max_retries,
                "findtime": findtime,
                "ban_time": ban_time,
                "regexes": {"default": {"pattern": ""}},
            }
        },
    }
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


# ============================================================================
# Pytest Fixtures
# ============================================================================


@pytest.fixture(scope="session", autouse=True)
def session_setup():
    """会话级设置：确保模块加载"""
    if os.geteuid() != 0:
        pytest.skip("需要 root 权限运行测试")

    if not KERNEL_MODULE_PATH.exists():
        pytest.skip(f"内核模块不存在: {KERNEL_MODULE_PATH}")

    if not check_module_ready():
        if not load_module():
            pytest.skip("内核模块加载失败")
        time.sleep(1)

    yield

    # 会话结束清理
    reset_all_data()
    unload_module()


@pytest.fixture(autouse=True)
def test_isolation():
    """每个测试前后的数据隔离"""
    reset_all_data()
    time.sleep(0.3)

    if not check_module_ready():
        if not load_module():
            pytest.skip("模块未就绪且重新加载失败")
        time.sleep(0.5)

    yield

    cleanup_state()
    # 起过 daemon 的轮次必须重载模块：内核租约没有注销消息，30 秒内新 daemon 会被拒。
    release_kernel_lease()

    if not check_module_ready():
        load_module()
        time.sleep(0.5)


@pytest.fixture
def clean_bans():
    """确保封禁列表为空的 fixture"""
    reset_all_data()
    wait_procfs()
    yield
    reset_all_data()


@pytest.fixture
def daemon_binary():
    """确保守护进程二进制存在"""
    if not DAEMON_PATH.exists():
        pytest.skip(f"守护进程不存在: {DAEMON_PATH}")
    return DAEMON_PATH


@pytest.fixture
def tmp_config(tmp_path):
    """创建临时配置目录的 fixture"""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    return config_dir
