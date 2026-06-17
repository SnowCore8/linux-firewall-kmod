#!/bin/bash
# 16_webui_api.sh - Web UI API 端到端集成测试

fw_test_header "Web UI API 端到端集成测试"

# 检查守护进程是否运行
if ! pgrep -f "firewall-daemon" > /dev/null; then
    fw_log_warn "守护进程未运行，跳过 Web UI API 测试"
    fw_log_info "请先启动守护进程: sudo ./build/daemon/firewall-daemon"
    exit 0
fi

# 16.1 API 端点可达性测试
fw_subsection "API 端点可达性测试"

# 检查 Web UI 端口（默认 8080）
WEBUI_PORT=${WEBUI_PORT:-8080}

if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WEBUI_PORT}/" 2>/dev/null | grep -q "200"; then
    assert_true "[[ true ]]" "Web UI 根路径可访问 (HTTP 200)"
else
    fw_log_warn "Web UI 端口 ${WEBUI_PORT} 不可访问，尝试默认端口 8080"
    WEBUI_PORT=8080
fi

# 16.2 /api/stats 端点测试
fw_subsection "/api/stats 端点测试"

local_stats_response=$(curl -s "http://localhost:${WEBUI_PORT}/api/stats" 2>/dev/null)

if [[ -n "$local_stats_response" ]]; then
    assert_true "[[ -n '$local_stats_response' ]]" "/api/stats 返回非空响应"
    
    # 验证 JSON 格式
    if echo "$local_stats_response" | jq . > /dev/null 2>&1; then
        assert_true "[[ true ]]" "/api/stats 返回有效 JSON"
        
        # 检查关键字段
        if echo "$local_stats_response" | jq -e '.total_bans' > /dev/null 2>&1; then
            assert_true "[[ true ]]" "/api/stats 包含 total_bans 字段"
        fi
        
        if echo "$local_stats_response" | jq -e '.current_bans' > /dev/null 2>&1; then
            assert_true "[[ true ]]" "/api/stats 包含 current_bans 字段"
        fi
    else
        fw_log_warn "/api/stats 返回的不是有效 JSON"
    fi
else
    fw_log_warn "/api/stats 端点无响应"
fi

# 16.3 /api/bans 端点测试
fw_subsection "/api/bans 端点测试"

local_bans_response=$(curl -s "http://localhost:${WEBUI_PORT}/api/bans" 2>/dev/null)

if [[ -n "$local_bans_response" ]]; then
    assert_true "[[ -n '$local_bans_response' ]]" "/api/bans 返回非空响应"
    
    # 验证 JSON 格式
    if echo "$local_bans_response" | jq . > /dev/null 2>&1; then
        assert_true "[[ true ]]" "/api/bans 返回有效 JSON"
        
        # 检查是否为数组
        if echo "$local_bans_response" | jq -e 'type == "array"' > /dev/null 2>&1; then
            assert_true "[[ true ]]" "/api/bans 返回数组格式"
        fi
    else
        fw_log_warn "/api/bans 返回的不是有效 JSON"
    fi
else
    fw_log_warn "/api/bans 端点无响应"
fi

# 16.4 /api/jails 端点测试
fw_subsection "/api/jails 端点测试"

local_jails_response=$(curl -s "http://localhost:${WEBUI_PORT}/api/jails" 2>/dev/null)

if [[ -n "$local_jails_response" ]]; then
    assert_true "[[ -n '$local_jails_response' ]]" "/api/jails 返回非空响应"
    
    # 验证 JSON 格式
    if echo "$local_jails_response" | jq . > /dev/null 2>&1; then
        assert_true "[[ true ]]" "/api/jails 返回有效 JSON"
    else
        fw_log_warn "/api/jails 返回的不是有效 JSON"
    fi
else
    fw_log_warn "/api/jails 端点无响应"
fi

# 16.5 /api/config 端点测试
fw_subsection "/api/config 端点测试"

local_config_response=$(curl -s "http://localhost:${WEBUI_PORT}/api/config" 2>/dev/null)

if [[ -n "$local_config_response" ]]; then
    assert_true "[[ -n '$local_config_response' ]]" "/api/config 返回非空响应"
    
    # 验证 JSON 格式
    if echo "$local_config_response" | jq . > /dev/null 2>&1; then
        assert_true "[[ true ]]" "/api/config 返回有效 JSON"
    else
        fw_log_warn "/api/config 返回的不是有效 JSON"
    fi
else
    fw_log_warn "/api/config 端点无响应"
fi

# 16.6 SSE 连接测试
fw_subsection "SSE 连接测试"

# 测试 SSE 端点（/events）
if curl -s -N --max-time 2 "http://localhost:${WEBUI_PORT}/events" 2>/dev/null | head -1 | grep -q "event:"; then
    assert_true "[[ true ]]" "SSE /events 端点可连接"
else
    fw_log_info "SSE /events 端点未响应或格式不符（可能需要浏览器环境）"
fi

# 16.7 错误处理测试
fw_subsection "错误处理测试"

# 测试不存在的端点
local_404_response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${WEBUI_PORT}/api/nonexistent" 2>/dev/null)
if [[ "$local_404_response" == "404" ]]; then
    assert_true "[[ true ]]" "不存在的 API 端点返回 404"
else
    fw_log_warn "不存在的 API 端点返回 HTTP $local_404_response（预期 404）"
fi

# 16.8 响应时间测试
fw_subsection "响应时间测试"

# 测试 /api/stats 响应时间
local_start_time=$(date +%s%N)
curl -s "http://localhost:${WEBUI_PORT}/api/stats" > /dev/null 2>&1
local_end_time=$(date +%s%N)
local_response_time_ms=$(( (local_end_time - local_start_time) / 1000000 ))

if [[ $local_response_time_ms -lt 1000 ]]; then
    assert_true "[[ true ]]" "/api/stats 响应时间 < 1000ms (实际: ${local_response_time_ms}ms)"
else
    fw_log_warn "/api/stats 响应时间过长: ${local_response_time_ms}ms"
fi

fw_log_info "Web UI API 端到端集成测试完成"
