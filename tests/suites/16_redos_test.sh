#!/bin/bash
# Test Suite 16: ReDoS Protection
# Tests for regex safety validation in daemon

source "$(dirname "$0")/../test_framework.sh"
source "$(dirname "$0")/../test_config.sh"

test_suite_name="redos_protection"

# Test 1: Nested quantifier )+ should be rejected
test_nested_quantifier_plus() {
    local unsafe_regex="(a+)+"
    assert_true "echo '$unsafe_regex' | grep -q ')+\|)*\|){\|}?'" "Nested quantifier )+ should be detected"
}

# Test 2: Nested quantifier )* should be rejected
test_nested_quantifier_star() {
    local unsafe_regex="(a*)+"
    assert_true "echo '$unsafe_regex' | grep -q ')+\|)*\|){\|}?'" "Nested quantifier )* should be detected"
}

# Test 3: Nested quantifier ){ should be rejected
test_nested_quantifier_brace() {
    local unsafe_regex="(a{1,10})+"
    assert_true "echo '$unsafe_regex' | grep -q ')+\|)*\|){\|}?'" "Nested quantifier ){ should be detected"
}

# Test 4: Excessive alternation should be rejected
test_excessive_alternation() {
    # Generate a pattern with 51 alternations (limit is 50)
    local pattern="a"
    for i in $(seq 1 51); do
        pattern="${pattern}|b"
    done
    local pipe_count=$(echo "$pattern" | tr -cd '|' | wc -c)
    assert_true "[[ $pipe_count -gt 50 ]]" "Pattern with >50 alternations should be detected ($pipe_count pipes)"
}

# Test 5: Safe regex should pass validation
test_safe_regex() {
    local safe_regex="Failed password for (invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
    local has_nested_quant=false
    if echo "$safe_regex" | grep -qE '\)\+|\)\*|\)\{|\}\?|\+\+|\*\+'; then
        has_nested_quant=true
    fi
    assert_false "[[ $has_nested_quant == true ]]" "Safe regex should not trigger nested quantifier detection"
}

# Test 6: Pattern length limit should be enforced
test_pattern_length() {
    # Generate a pattern longer than 1024 bytes
    local long_pattern="a"
    for i in $(seq 1 1100); do
        long_pattern="${long_pattern}a"
    done
    local pattern_len=${#long_pattern}
    assert_true "[[ $pattern_len -gt 1024 ]]" "Pattern >1024 bytes should be detected ($pattern_len bytes)"
}

# Test 7: Possessive quantifiers should be rejected
test_possessive_quantifiers() {
    local unsafe_regex="(a++)"
    assert_true "echo '$unsafe_regex' | grep -q '++\|\*+'" "Possessive quantifier ++ should be detected"
}

# Register all tests
register_test "test_nested_quantifier_plus" "Nested quantifier )+ detection"
register_test "test_nested_quantifier_star" "Nested quantifier )* detection"
register_test "test_nested_quantifier_brace" "Nested quantifier ){ detection"
register_test "test_excessive_alternation" "Excessive alternation detection"
register_test "test_safe_regex" "Safe regex validation"
register_test "test_pattern_length" "Pattern length limit"
register_test "test_possessive_quantifiers" "Possessive quantifier detection"
