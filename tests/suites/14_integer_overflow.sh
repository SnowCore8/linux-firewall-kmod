#!/bin/bash
# Test Suite 14: Integer Overflow Protection
# Tests for ban time overflow protection in kernel module

source "$(dirname "$0")/../test_framework.sh"
source "$(dirname "$0")/../test_config.sh"

test_suite_name="integer_overflow"

# Test 1: Normal ban time (should succeed)
test_normal_ban_time() {
    local ip="192.168.1.100"
    echo "$ip 3600" | sudo tee /proc/firewall/bans >/dev/null 2>&1
    assert_success "echo '$ip 3600' | sudo tee /proc/firewall/bans"
    assert_contains "cat /proc/firewall/bans" "$ip" "Normal ban time (3600s) should succeed"
    echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null 2>&1
}

# Test 2: Maximum allowed ban time (should succeed)
test_max_ban_time() {
    local ip="192.168.1.101"
    local max_time=31536000  # 365 days
    echo "$ip $max_time" | sudo tee /proc/firewall/bans >/dev/null 2>&1
    assert_success "echo '$ip $max_time' | sudo tee /proc/firewall/bans"
    assert_contains "cat /proc/firewall/bans" "$ip" "Max ban time (365 days) should succeed"
    echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null 2>&1
}

# Test 3: Ban time exceeding maximum (should fail)
test_excessive_ban_time() {
    local ip="192.168.1.102"
    local excessive_time=999999999  # Way too large
    local result
    result=$(echo "$ip $excessive_time" | sudo tee /proc/firewall/bans 2>&1)
    # Should either reject or the kernel log should show overflow warning
    assert_true "dmesg | tail -20 | grep -q 'overflow\\|exceeds maximum\\|Invalid ban duration'" "Excessive ban time should be rejected or logged"
    echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null 2>&1
}

# Test 4: Permanent ban (0 seconds) should still work
test_permanent_ban() {
    local ip="192.168.1.103"
    echo "$ip 0" | sudo tee /proc/firewall/bans >/dev/null 2>&1
    assert_success "echo '$ip 0' | sudo tee /proc/firewall/bans"
    assert_contains "cat /proc/firewall/bans" "$ip" "Permanent ban (0s) should succeed"
    echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null 2>&1
}

# Test 5: Minimum ban time (should succeed)
test_min_ban_time() {
    local ip="192.168.1.104"
    echo "$ip 30" | sudo tee /proc/firewall/bans >/dev/null 2>&1
    assert_success "echo '$ip 30' | sudo tee /proc/firewall/bans"
    assert_contains "cat /proc/firewall/bans" "$ip" "Minimum ban time (30s) should succeed"
    echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null 2>&1
}

# Test 6: Very small ban time (should succeed but log warning)
test_small_ban_time() {
    local ip="192.168.1.105"
    echo "$ip 1" | sudo tee /proc/firewall/bans >/dev/null 2>&1
    assert_success "echo '$ip 1' | sudo tee /proc/firewall/bans"
    # Note: 1 second ban is allowed but may expire quickly
    echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null 2>&1
}

# Register all tests
register_test "test_normal_ban_time" "Normal ban time (3600s)"
register_test "test_max_ban_time" "Maximum ban time (365 days)"
register_test "test_excessive_ban_time" "Excessive ban time rejection"
register_test "test_permanent_ban" "Permanent ban (0s)"
register_test "test_min_ban_time" "Minimum ban time (30s)"
register_test "test_small_ban_time" "Small ban time (1s)"
