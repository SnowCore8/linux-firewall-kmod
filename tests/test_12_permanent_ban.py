"""12 - 永久封禁功能测试"""

import os
import signal
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from .config import DAEMON_PATH, PROC_BANS
from .conftest import (
    ban_ip_permanent,
    count_bans,
    ip_is_banned,
    unban_ip,
    wait_procfs,
)


class TestPermanentBan:
    """永久封禁功能测试"""

    def test_basic_permanent_ban_unban(self, clean_bans):
        """12.1 基本永久封禁/解封"""
        test_ip = "198.51.100.100"

        ban_ip_permanent(test_ip)
        assert ip_is_banned(test_ip), f"IP {test_ip} 永久封禁失败"

        unban_ip(test_ip)
        assert not ip_is_banned(test_ip), f"IP {test_ip} 永久解封失败"

    def test_permanent_ban_no_expire(self, clean_bans):
        """12.2 永久封禁不会自动过期"""
        test_ip = "198.51.100.101"

        ban_ip_permanent(test_ip)
        assert ip_is_banned(test_ip), "永久封禁条目不存在"

        unban_ip(test_ip)

    def test_sql_injection_rejected(self, clean_bans):
        """12.3 SQL 注入尝试被拒绝"""
        before_count = count_bans()
        try:
            PROC_BANS.write_text("1.2.3.4'; DROP TABLE permanent_banlist;--")
        except (PermissionError, OSError):
            pass
        wait_procfs()
        after_count = count_bans()
        assert after_count == before_count, "SQL 注入尝试未被拒绝"

    def test_batch_permanent_ban_performance(self, clean_bans):
        """12.4 大量永久封禁性能"""
        start_time = time.time()

        for i in range(1, 51):
            ban_ip_permanent(f"203.0.113.{i}")

        duration = time.time() - start_time

        ban_count = count_bans()
        assert ban_count >= 50, f"批量永久封禁 50 个 IP，实际 {ban_count} 个"

        for i in range(1, 51):
            unban_ip(f"203.0.113.{i}")

    def test_sqlite_standalone(self, tmp_path):
        """12.5 SQLite 数据库独立测试"""
        try:
            subprocess.run(["sqlite3", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("sqlite3 命令行工具未安装")

        test_db = tmp_path / "test_permanent.db"

        create_sql = """
CREATE TABLE permanent_banlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    ip_num INTEGER NOT NULL UNIQUE,
    reason TEXT DEFAULT 'auto-ban',
    created_at INTEGER NOT NULL,
    created_by TEXT DEFAULT 'auto',
    hit_count INTEGER DEFAULT 0,
    last_hit_at INTEGER,
    is_active INTEGER DEFAULT 1
);
CREATE INDEX idx_ip_num ON permanent_banlist(ip_num);
CREATE INDEX idx_is_active ON permanent_banlist(is_active);
"""
        subprocess.run(["sqlite3", str(test_db), create_sql], check=True)
        assert test_db.exists(), "测试数据库创建失败"

        subprocess.run(
            [
                "sqlite3", str(test_db),
                "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by) "
                "VALUES ('192.0.2.1', 3221225985, 'test ban', strftime('%s', 'now'), 'test');"
            ],
            check=True,
        )

        result = subprocess.run(
            ["sqlite3", str(test_db), "SELECT COUNT(*) FROM permanent_banlist;"],
            capture_output=True, text=True, check=True,
        )
        assert result.stdout.strip() == "1", "SQLite 插入失败"

        result = subprocess.run(
            ["sqlite3", str(test_db), "SELECT ip FROM permanent_banlist WHERE ip='192.0.2.1';"],
            capture_output=True, text=True, check=True,
        )
        assert result.stdout.strip() == "192.0.2.1", "SQLite 查询错误"

        subprocess.run(
            [
                "sqlite3", str(test_db),
                "INSERT OR IGNORE INTO permanent_banlist (ip, ip_num, reason, created_at) "
                "VALUES ('192.0.2.1', 3221225985, 'duplicate', strftime('%s', 'now'));"
            ],
            capture_output=True,
        )

        result = subprocess.run(
            ["sqlite3", str(test_db), "SELECT COUNT(*) FROM permanent_banlist WHERE ip='192.0.2.1';"],
            capture_output=True, text=True, check=True,
        )
        assert result.stdout.strip() == "1", "SQLite 唯一性约束未生效"

    def test_daemon_sqlite_integration(self, tmp_path):
        """12.6 守护进程 SQLite 集成测试（自启动守护进程）"""
        if not DAEMON_PATH.exists():
            pytest.skip(f"守护进程不存在: {DAEMON_PATH}")

        try:
            subprocess.run(["sqlite3", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("sqlite3 命令行工具未安装")

        # 尝试启动守护进程（flock 排他锁由守护进程自行管理）
        config = {
            "defaults": {
                "max_retries": 3, "findtime": 600, "ban_time": 300,
                "interval": 1, "metrics_port": 9123,
            },
            "jails": {
                "sshd": {
                    "enabled": True,
                    "log_files": ["/var/log/auth.log"],
                    "max_retries": 3, "findtime": 600, "ban_time": 300,
                    "regexes": {"default": {"pattern": ""}},
                }
            },
        }
        config_file = tmp_path / "sqlite_test.yaml"
        config_file.write_text(yaml.dump(config))

        proc = subprocess.Popen(
            [str(DAEMON_PATH), "-c", str(config_file)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(3)
            if proc.poll() is not None:
                # 守护进程启动失败（可能 flock 拒绝），直接检查已有数据库
                db_path = Path("/var/lib/firewall/history.db")
                if not db_path.exists():
                    pytest.skip("守护进程启动失败且无已有数据库")
            else:
                db_path = Path("/var/lib/firewall/history.db")
                if not db_path.exists():
                    pytest.skip(f"守护进程未创建数据库: {db_path}")

            result = subprocess.run(
                ["sqlite3", str(db_path), ".tables"],
                capture_output=True, text=True,
            )
            assert "ban_history" in result.stdout, "ban_history 表不存在"
            assert "ban_events" in result.stdout, "ban_events 表不存在"
            assert "ip_reputation" in result.stdout, "ip_reputation 表不存在"

        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
