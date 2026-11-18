"""07 - 并发/竞态条件测试"""

import subprocess
import threading
import time

import pytest

from .config import PROC_BANS, PROC_STATS, PROC_WHITELIST
from .conftest import count_bans, get_stat, unban_multiple, wait_procfs, whitelist_remove


def _safe_write_bans(data: str):
    try:
        PROC_BANS.write_text(data)
    except (PermissionError, FileNotFoundError, OSError):
        pass


def _safe_write_whitelist(data: str):
    try:
        PROC_WHITELIST.write_text(data)
    except (PermissionError, FileNotFoundError, OSError):
        pass


def _safe_unban_multiple(*ips: str):
    for ip in ips:
        _safe_write_bans(f"unban {ip}")


class TestConcurrency:
    """并发/竞态条件测试"""

    def test_concurrent_ban(self, clean_bans):
        """7.1 并发封禁"""
        start = time.time()

        test_ips = [f"192.168.100.{i}" for i in range(1, 21)]
        errors = []

        def safe_ban(ip):
            try:
                PROC_BANS.write_text(ip)
            except Exception as e:
                errors.append(e)

        threads = []
        for ip in test_ips:
            t = threading.Thread(target=safe_ban, args=(ip,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        duration_ms = (time.time() - start) * 1000
        assert duration_ms <= 5000, f"并发封禁 20 IP 超时: {duration_ms:.0f}ms"
        assert not errors, f"子线程封禁异常: {errors}"

        time.sleep(0.5)

        # 验证所有 IP 被封禁
        bans_content = PROC_BANS.read_text()
        banned_ips = bans_content.split()
        for ip in test_ips:
            assert ip in banned_ips, f"IP {ip} not found in bans"

    def test_concurrent_ban_unban(self, clean_bans):
        """7.2 同时封禁和解封：用不相交的 IP 集合，终态可判定"""
        ban_ips = [f"10.10.10.{i}" for i in range(1, 11)]
        unban_ips = [f"10.10.20.{i}" for i in range(1, 11)]

        # 先串行建立「已封禁」基数，避免把封禁/解封的竞争结果当成断言依据
        for ip in unban_ips:
            PROC_BANS.write_text(ip)
        wait_procfs()
        assert count_bans() >= len(unban_ips), "建立解封基数失败"

        errors = []

        def worker(data: str):
            try:
                PROC_BANS.write_text(data)
            except Exception as exc:  # noqa: BLE001 - 子线程异常必须带回主线程
                errors.append(exc)

        threads = []
        for ip in ban_ips:
            threads.append(threading.Thread(target=worker, args=(ip,)))
        for ip in unban_ips:
            threads.append(threading.Thread(target=worker, args=(f"unban {ip}",)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"并发 ban/unban 子线程异常: {errors}"
        wait_procfs()

        bans = PROC_BANS.read_text().split()
        missing = [ip for ip in ban_ips if ip not in bans]
        still_banned = [ip for ip in unban_ips if ip in bans]
        assert not missing, f"并发封禁丢失: {missing}"
        assert not still_banned, f"并发解封未生效: {still_banned}"

        _safe_unban_multiple(*ban_ips)

    def test_concurrent_whitelist_ban(self, clean_bans):
        """7.3 白名单和封禁列表并发操作"""
        threads = []
        for i in range(1, 6):
            threads.append(threading.Thread(
                target=lambda subnet=f"172.20.{i}.0/24": _safe_write_whitelist(
                    f"add {subnet}"
                )
            ))
            threads.append(threading.Thread(
                target=lambda ip=f"172.20.{i}.{i}": _safe_write_bans(ip)
            ))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        time.sleep(0.5)

        if PROC_WHITELIST.exists() and PROC_BANS.exists():
            wl_content = PROC_WHITELIST.read_text()
            bans_content = PROC_BANS.read_text()
            assert len(wl_content) > 0 and len(bans_content) > 0, "并发操作后接口异常"

        for i in range(1, 6):
            _safe_write_whitelist(f"remove 172.20.{i}.0/24")
            _safe_write_bans(f"unban 172.20.{i}.{i}")

    def test_read_during_write(self, clean_bans):
        """7.4 读取时修改：读不能抛错，写要全部落地"""
        errors = []

        def reader():
            try:
                PROC_BANS.read_text()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def writer(ip: str):
            try:
                PROC_BANS.write_text(ip)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = []
        for i in range(1, 11):
            threads.append(threading.Thread(target=reader))
            threads.append(threading.Thread(target=writer, args=(f"192.168.200.{i}",)))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"读写并发异常: {errors}"
        wait_procfs()

        ban_count = get_stat("current_bans")
        expected = [f"192.168.200.{i}" for i in range(1, 11)]
        bans = PROC_BANS.read_text().split()
        missing = [ip for ip in expected if ip not in bans]
        assert not missing, f"并发写入丢失: {missing}"
        assert ban_count == len(expected), (
            f"统计与封禁表不一致: current_bans={ban_count}, 期望 {len(expected)}"
        )

        unban_multiple(*expected)
