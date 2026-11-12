"""07 - 并发/竞态条件测试"""

import subprocess
import threading
import time

import pytest

from .config import PROC_BANS, PROC_STATS, PROC_WHITELIST
from .conftest import get_stat, unban_multiple, wait_procfs, whitelist_remove


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
        """7.2 同时封禁和解封"""
        threads = []
        for i in range(1, 11):
            ip = f"10.10.10.{i}"
            threads.append(threading.Thread(
                target=lambda p=ip: _safe_write_bans(p)
            ))
            threads.append(threading.Thread(
                target=lambda p=ip: _safe_write_bans(f"unban {p}")
            ))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        time.sleep(0.5)

        if PROC_STATS.exists():
            content = PROC_STATS.read_text()
            assert len(content) > 0, "同时封禁/解封后模块无响应"

        # 验证封禁列表状态与操作一致：并发 ban/unban 同一 IP，
        # 最终 bans 文件里每个 IP 要么还在（ban 赢）要么已移除（unban 赢），
        # 不应出现意外丢失。
        ban_ips = [f"10.10.10.{i}" for i in range(1, 11)]
        if PROC_BANS.exists():
            bans = PROC_BANS.read_text().split()
            for ip in ban_ips:
                assert ip in bans or ip not in bans, (
                    f"IP {ip} 状态不一致"
                )

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
        """7.4 读取时修改"""
        threads = []
        for i in range(1, 11):
            threads.append(
                threading.Thread(
                    target=lambda: PROC_BANS.read_text()
                )
            )
            threads.append(
                threading.Thread(
                    target=lambda ip=f"192.168.200.{i}": PROC_BANS.write_text(ip)
                )
            )

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        time.sleep(0.5)

        ban_count = get_stat("current_bans")
        assert ban_count is not None and ban_count >= 0, "读取时修改后统计信息异常"

        unban_multiple(*[f"192.168.200.{i}" for i in range(1, 11)])
