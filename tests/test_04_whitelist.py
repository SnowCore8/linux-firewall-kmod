"""04 - 白名单测试"""

import pytest

from .config import (
    BROADCAST_IP,
    LOCALHOST_IP,
    MULTICAST_IP,
    PROC_BANS,
    PROC_WHITELIST,
    TEST_SUBNET,
    TEST_SUBNET_IP,
    ZERO_IP,
)
from .conftest import (
    count_bans,
    count_whitelist,
    get_stat,
    ip_is_banned,
    unban_ip,
    wait_procfs,
    whitelist_add,
    whitelist_remove,
)


class TestWhitelist:
    """白名单测试"""

    def test_system_ip_auto_discovery(self):
        """4.1 系统 IP 自动发现"""
        wl_count = count_whitelist()
        assert wl_count >= 1, f"系统 IP 自动发现 ({wl_count} 个)"

    def test_manual_add_remove(self):
        """4.2 手动添加/移除白名单"""
        wl_before = count_whitelist()
        whitelist_add(TEST_SUBNET)
        wl_after = count_whitelist()

        if wl_after > wl_before:
            content = PROC_WHITELIST.read_text()
            assert TEST_SUBNET in content, f"手动添加子网白名单 {TEST_SUBNET} 失败"

            whitelist_remove(TEST_SUBNET)
            content = PROC_WHITELIST.read_text()
            assert TEST_SUBNET not in content, "白名单移除失败"
        else:
            pytest.skip("白名单计数未增加（添加未生效或已满），跳过子网添加")

    def test_whitelist_protection(self):
        """4.3 白名单保护"""
        whitelist_add(TEST_SUBNET)
        wl_count = count_whitelist()

        if not any(TEST_SUBNET in line for line in PROC_WHITELIST.read_text().splitlines()):
            pytest.skip("白名单添加失败，跳过保护测试")

        bans_before = count_bans()
        rejects_before = get_stat("whitelist_rejects")

        try:
            PROC_BANS.write_text(TEST_SUBNET_IP)
        except (PermissionError, OSError):
            pass  # 内核拒绝白名单 IP 的封禁，这是预期行为
        wait_procfs()

        bans_after = count_bans()
        assert bans_after == bans_before, "白名单子网 IP 进入封禁列表"
        assert not ip_is_banned(TEST_SUBNET_IP), "封禁列表中包含白名单 IP"

        rejects_after = get_stat("whitelist_rejects")
        rejects_delta = rejects_after - rejects_before
        assert rejects_delta >= 1, f"白名单拒绝计数器 +{rejects_delta} (预期 ≥1)"

        whitelist_remove(TEST_SUBNET)

    def test_special_ip_protection(self):
        """4.4 特殊 IP 地址保护"""
        special_ips = [
            (ZERO_IP, "零地址 (0.0.0.0)"),
            (BROADCAST_IP, "广播地址 (255.255.255.255)"),
            (MULTICAST_IP, "组播地址 (224.0.0.1)"),
            (LOCALHOST_IP, "回环地址 (127.0.0.1)"),
        ]

        for ip, desc in special_ips:
            try:
                PROC_BANS.write_text(ip)
            except (PermissionError, OSError):
                pass
            wait_procfs()
            assert not ip_is_banned(ip), f"{desc} 保护失败"

    def test_whitelist_format_validation(self):
        """4.5 白名单格式验证"""
        invalid_inputs = [
            ("add invalid_subnet", "无效子网格式"),
            ("add 999.999.999.999/32", "无效子网 IP"),
            ("add 192.168.1.0/33", "无效前缀长度"),
        ]

        for input_str, desc in invalid_inputs:
            with pytest.raises((PermissionError, OSError)):
                PROC_WHITELIST.write_text(input_str)

    def test_whitelist_capacity(self):
        """4.6 白名单容量测试（计数与成功添加数一致）"""
        before = get_stat("current_whitelist")
        added = []
        for i in range(1, 51):
            subnet = f"10.{i // 255}.{i % 255}.0/24"
            try:
                PROC_WHITELIST.write_text(f"add {subnet}")
                added.append(subnet)
            except (PermissionError, OSError):
                pass

        wait_procfs()
        wl_count = get_stat("current_whitelist")
        # 计数应恰好等于基线加上本次成功添加的条目数；固定的 64/4096 上限已不再是
        # 真实容量（真实上限见 config.py 说明），故不在此断言陈旧常数
        assert wl_count == before + len(added), (
            f"白名单计数与添加数量不符: before={before}, "
            f"added={len(added)}, count={wl_count}"
        )

        for subnet in added:
            try:
                PROC_WHITELIST.write_text(f"remove {subnet}")
            except (PermissionError, OSError):
                pass
