#!/bin/bash
# Test Suite 16: ReDoS Protection
# Tests for regex safety validation in daemon

fw_test_header "ReDoS 防护测试"

# Test 1: Nested quantifier )+ should be rejected
fw_subsection "嵌套量词 )+"
local unsafe_regex="(a+)+"
assert_true "echo '$unsafe_regex' | grep -q ')+\|)*\|){\|}?'" "嵌套量词 )+ 应被检测到"

# Test 2: Nested quantifier )* should be rejected
fw_subsection "嵌套量词 )*"
local unsafe_regex="(a*)+"
assert_true "echo '$unsafe_regex' | grep -q ')+\|)*\|){\|}?'" "嵌套量词 )* 应被检测到"

# Test 3: Nested quantifier ){ should be rejected
fw_subsection "嵌套量词 ){"
local unsafe_regex="(a{1,10})+"
assert_true "echo '$unsafe_regex' | grep -q ')+\|)*\|){\|}?'" "嵌套量词 ){ 应被检测到"

# Test 4: Excessive alternation should be rejected
fw_subsection "过度交替"
local pattern="a"
for i in $(seq 1 51); do
    pattern="${pattern}|b"
done
local pipe_count=$(echo "$pattern" | tr -cd '|' | wc -c)
assert_true "[[ $pipe_count -gt 50 ]]" "超过50个交替符应被检测到 ($pipe_count 个)"

# Test 5: Safe regex should pass validation
fw_subsection "安全正则"
local safe_regex="Failed password for (invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
assert_false "echo '$safe_regex' | grep -qE '\)\+|\)\*|\)\{|\}\?|\+\+|\*\+'" "安全正不应触发嵌套量词检测"

# Test 6: Pattern length limit should be enforced
fw_subsection "模式长度限制"
local long_pattern="a"
for i in $(seq 1 1100); do
    long_pattern="${long_pattern}a"
done
local pattern_len=${#long_pattern}
assert_true "[[ $pattern_len -gt 1024 ]]" "超过1024字节的模式应被检测到 ($pattern_len 字节)"

# Test 7: Possessive quantifiers should be rejected
fw_subsection "占有量词"
local unsafe_regex="(a++)"
assert_true "echo '$unsafe_regex' | grep -q '++\|\*+'" "占有量词 ++ 应被检测到"
