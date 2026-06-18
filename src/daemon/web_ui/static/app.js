// Firewall Daemon Dashboard - JavaScript
'use strict';

// Global state
let charts = {};
let eventSource = null;

// Web UI 配置（从 API 加载）
let webuiConfig = {
    rate_warning_pps: 1000,
    rate_critical_pps: 10000,
    rate_warning_syn: 100,
    rate_critical_syn: 1000
};
// SSE endpoint
const SSE_ENDPOINT = '/api/events';

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    loadWebuiConfig();
    initializeCharts();
    setupEventListeners();
    connectSSE();
});

// Setup event listeners
function setupEventListeners() {
    // Manual refresh button (fallback for SSE)
    document.getElementById('refresh-btn').addEventListener('click', () => {
        if (!eventSource || eventSource.readyState === EventSource.CLOSED) {
            connectSSE();
        }
    });

    // Search input
    document.getElementById('search-input').addEventListener('input', filterTable);

    // Jail filter
    document.getElementById('jail-filter').addEventListener('change', filterTable);
}

// Connect to SSE endpoint

// 加载 Web UI 配置
async function loadWebuiConfig() {
    try {
        const response = await fetch('/api/config');
        if (response.ok) {
            const config = await response.json();
            webuiConfig = { ...webuiConfig, ...config };
            console.log('Web UI config loaded:', webuiConfig);
        }
    } catch (error) {
        console.warn('Failed to load Web UI config, using defaults:', error);
    }
}
function connectSSE() {
    if (eventSource) {
        eventSource.close();
    }

    updateStatus('loading');
    eventSource = new EventSource(SSE_ENDPOINT);

    // Listen for stats events
    eventSource.addEventListener('stats', (event) => {
        try {
            const stats = JSON.parse(event.data);
            updateStats(stats);
            updateCharts(stats);
            updateStatus('online');
        } catch (error) {
            console.error('Failed to parse stats event:', error);
        }
    });

    // Listen for bans events
    eventSource.addEventListener('bans', (event) => {
        try {
            const bans = JSON.parse(event.data);
            updateBansTable(bans);
        } catch (error) {
            console.error('Failed to parse bans event:', error);
        }
    });

    // Listen for jails events
    eventSource.addEventListener('jails', (event) => {
        try {
            const jails = JSON.parse(event.data);
            updateJailFilter(jails);
        } catch (error) {
            console.error('Failed to parse jails event:', error);
        }
    });

    // Listen for rates events
    eventSource.addEventListener('rates', (event) => {
        try {
            const rates = JSON.parse(event.data);
            updateRatesPanel(rates);
        } catch (error) {
            console.error('Failed to parse rates event:', error);
        }
    });

    // Handle connection errors
    eventSource.onerror = () => {
        console.error('SSE connection error');
        updateStatus('offline');
        // EventSource will auto-reconnect
    };

    // Handle connection open
    eventSource.onopen = () => {
        console.log('SSE connection established');
        updateStatus('online');
    };
}

// Update status badge
function updateStatus(status) {
    const badge = document.getElementById('status');
    const text = badge.querySelector('.status-text');
    badge.className = 'status-badge';

    switch (status) {
        case 'online':
            text.textContent = '实时连接';
            badge.classList.add('online');
            break;
        case 'loading':
            text.textContent = '连接中...';
            break;
        case 'offline':
            text.textContent = '连接断开';
            break;
    }
}

// Update statistics cards
function updateStats(stats) {
    document.getElementById('active-bans').textContent = formatNumber(stats.active_bans);
    document.getElementById('today-bans').textContent = formatNumber(stats.today_bans);
    document.getElementById('failed-attempts').textContent = formatNumber(stats.failed_attempts);
    document.getElementById('ddos-events').textContent = formatNumber(stats.ddos_events);
    document.getElementById('uptime').textContent = formatUptime(stats.uptime_seconds);

    // 更新内核统计数据（使用单位换算）
    if (stats.kernel_current_bans !== undefined) {
        document.getElementById('kernel-current-bans').textContent = formatNumber(stats.kernel_current_bans);
        document.getElementById('kernel-total-bans').textContent = formatNumber(stats.kernel_total_bans);
        document.getElementById('kernel-total-unbans').textContent = formatNumber(stats.kernel_total_unbans);
        document.getElementById('kernel-whitelist-count').textContent = formatNumber(stats.kernel_whitelist_count);
        document.getElementById('kernel-packets-dropped').textContent = formatNumber(stats.kernel_packets_dropped, true);
        document.getElementById('kernel-packets-accepted').textContent = formatNumber(stats.kernel_packets_accepted, true);
    }
}

// Format number with commas and optional unit conversion for large numbers
function formatNumber(num, convertUnits = false) {
    if (convertUnits && num >= 1000) {
        const units = ['', 'K', 'M', 'G', 'T', 'P'];
        let unitIndex = 0;
        let value = num;
        
        while (value >= 1000 && unitIndex < units.length - 1) {
            value /= 1000;
            unitIndex++;
        }
        
        return value.toFixed(value >= 100 ? 0 : value >= 10 ? 1 : 2) + units[unitIndex];
    }
    
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

// Format uptime
function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);

    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
}

// Initialize charts
function initializeCharts() {
    // Chart.js global defaults
    Chart.defaults.color = '#cbd5e1';
    Chart.defaults.borderColor = '#475569';
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';

    // Ban trend chart (line)
    const banTrendCtx = document.getElementById('ban-trend-chart').getContext('2d');
    charts.banTrend = new Chart(banTrendCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: '封禁数',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(71, 85, 105, 0.3)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    // Jail distribution chart (doughnut)
    const jailDistCtx = document.getElementById('jail-distribution-chart').getContext('2d');
    charts.jailDistribution = new Chart(jailDistCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#3b82f6',
                    '#10b981',
                    '#f59e0b',
                    '#ef4444',
                    '#8b5cf6'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // Failure reasons chart (bar)
    const failureCtx = document.getElementById('failure-reasons-chart').getContext('2d');
    charts.failureReasons = new Chart(failureCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '次数',
                data: [],
                backgroundColor: '#ef4444'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(71, 85, 105, 0.3)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    // Traffic chart (area)
    const trafficCtx = document.getElementById('traffic-chart').getContext('2d');
    charts.traffic = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: '请求/秒',
                data: [],
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(71, 85, 105, 0.3)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    // Rate timeline chart (real-time, 5 minutes)
    const rateTimelineCtx = document.getElementById('rate-timeline-chart').getContext('2d');
    charts.rateTimeline = new Chart(rateTimelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: '总速率 (pps)',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                },
                {
                    label: 'SYN',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.05)',
                    tension: 0.4,
                    fill: false,
                    borderWidth: 1
                },
                {
                    label: 'UDP',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.05)',
                    tension: 0.4,
                    fill: false,
                    borderWidth: 1
                },
                {
                    label: 'ICMP',
                    data: [],
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.05)',
                    tension: 0.4,
                    fill: false,
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            animation: {
                duration: 300
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        padding: 15
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(71, 85, 105, 0.3)' },
                    ticks: {
                        callback: function(value) {
                            if (value >= 1000000) return (value / 1000000).toFixed(1) + 'M';
                            if (value >= 1000) return (value / 1000).toFixed(1) + 'K';
                            return value;
                        }
                    }
                },
                x: {
                    grid: { display: false },
                    ticks: {
                        maxTicksLimit: 10,
                        maxRotation: 0
                    }
                }
            }
        }
    });

    // Initialize rate timeline with empty data (5 minutes = 300 seconds)
    const maxTimelinePoints = 300;
    charts.rateTimeline.data.labels = Array(maxTimelinePoints).fill('');
    charts.rateTimeline.data.datasets.forEach(dataset => {
        dataset.data = Array(maxTimelinePoints).fill(0);
    });
}

// Update charts with new data
function updateCharts(stats) {
    // Update ban trend chart
    if (stats.ban_trend) {
        charts.banTrend.data.labels = stats.ban_trend.labels;
        charts.banTrend.data.datasets[0].data = stats.ban_trend.values;
        charts.banTrend.update('none');
    }

    // Update jail distribution chart
    if (stats.jail_distribution) {
        charts.jailDistribution.data.labels = stats.jail_distribution.labels;
        charts.jailDistribution.data.datasets[0].data = stats.jail_distribution.values;
        charts.jailDistribution.update('none');
    }

    // Update failure reasons chart
    if (stats.failure_reasons) {
        charts.failureReasons.data.labels = stats.failure_reasons.labels;
        charts.failureReasons.data.datasets[0].data = stats.failure_reasons.values;
        charts.failureReasons.update('none');
    }

    // Update traffic chart
    if (stats.traffic) {
        charts.traffic.data.labels = stats.traffic.labels;
        charts.traffic.data.datasets[0].data = stats.traffic.values;
        charts.traffic.update('none');
    }
}

// Update bans table
function updateBansTable(bans) {
    const tbody = document.getElementById('bans-table-body');

    if (!bans || bans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading">暂无活跃封禁</td></tr>';
        return;
    }

    tbody.innerHTML = bans.map(ban => `
        <tr>
            <td>${ban.ip}</td>
            <td>${ban.jail}</td>
            <td>${formatDateTime(ban.banned_at)}</td>
            <td>${formatDuration(ban.remaining_seconds)}</td>
            <td>${ban.reason}</td>
        </tr>
    `).join('');
}

// Update jail filter dropdown
function updateJailFilter(jails) {
    const select = document.getElementById('jail-filter');
    const currentValue = select.value;

    // Keep the "All" option
    select.innerHTML = '<option value="">所有 Jail</option>';

    if (jails && jails.length > 0) {
        jails.forEach(jail => {
            const option = document.createElement('option');
            option.value = jail.name;
            option.textContent = jail.name;
            select.appendChild(option);
        });
    }

    // Restore previous selection
    select.value = currentValue;
}

// Update DDoS rates panel
function updateRatesPanel(rates) {
    const grid = document.getElementById('rates-grid');

    if (!rates || rates.length === 0) {
        grid.innerHTML = '<div class="rates-empty">暂无活跃速率数据</div>';
        return;
    }

    // Update rate cards
    grid.innerHTML = rates.map(rate => {
        const totalPps = rate.packets_per_sec;
        const totalBps = rate.bytes_per_sec;
        const synPps = rate.syn_packets_per_sec;
        const udpPps = rate.udp_packets_per_sec;
        const icmpPps = rate.icmp_packets_per_sec;

        // 根据速率确定告警级别
        let alertLevel = 'normal';
        if (totalPps > webuiConfig.rate_critical_pps || synPps > webuiConfig.rate_critical_syn) {
            alertLevel = 'critical';
        } else if (totalPps > webuiConfig.rate_warning_pps || synPps > webuiConfig.rate_warning_syn) {
            alertLevel = 'warning';
        }

        return `
            <div class="rate-card rate-${alertLevel}">
                <div class="rate-header">
                    <span class="rate-ip">${rate.ip}</span>
                    <span class="rate-alert rate-${alertLevel}">${alertLevel === 'critical' ? '🚨 严重' : alertLevel === 'warning' ? '⚠️ 警告' : '✓ 正常'}</span>
                </div>
                <div class="rate-stats">
                    <div class="rate-stat">
                        <div class="rate-label">总速率</div>
                        <div class="rate-value">${formatRate(totalPps, 'pps')}</div>
                    </div>
                    <div class="rate-stat">
                        <div class="rate-label">带宽</div>
                        <div class="rate-value">${formatRate(totalBps, 'bps')}</div>
                    </div>
                    <div class="rate-stat">
                        <div class="rate-label">SYN</div>
                        <div class="rate-value">${formatRate(synPps, 'pps')}</div>
                    </div>
                    <div class="rate-stat">
                        <div class="rate-label">UDP</div>
                        <div class="rate-value">${formatRate(udpPps, 'pps')}</div>
                    </div>
                    <div class="rate-stat">
                        <div class="rate-label">ICMP</div>
                        <div class="rate-value">${formatRate(icmpPps, 'pps')}</div>
                    </div>
                </div>
            </div>
        `;
    }).join('');

    // Update rate timeline chart
    updateRateTimeline(rates);
}

// Update rate timeline chart (real-time rolling window)
function updateRateTimeline(rates) {
    if (!charts.rateTimeline) return;

    const maxTimelinePoints = 300; // 5 minutes

    // Calculate total rates across all IPs
    let totalPps = 0;
    let totalSyn = 0;
    let totalUdp = 0;
    let totalIcmp = 0;

    rates.forEach(rate => {
        totalPps += rate.packets_per_sec;
        totalSyn += rate.syn_packets_per_sec;
        totalUdp += rate.udp_packets_per_sec;
        totalIcmp += rate.icmp_packets_per_sec;
    });

    // Get current time label
    const now = new Date();
    const timeLabel = now.toLocaleTimeString('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });

    // Add new data point
    charts.rateTimeline.data.labels.push(timeLabel);
    charts.rateTimeline.data.datasets[0].data.push(totalPps);
    charts.rateTimeline.data.datasets[1].data.push(totalSyn);
    charts.rateTimeline.data.datasets[2].data.push(totalUdp);
    charts.rateTimeline.data.datasets[3].data.push(totalIcmp);

    // Remove oldest data point if exceeding max
    if (charts.rateTimeline.data.labels.length > maxTimelinePoints) {
        charts.rateTimeline.data.labels.shift();
        charts.rateTimeline.data.datasets.forEach(dataset => {
            dataset.data.shift();
        });
    }

    // Update chart with animation
    charts.rateTimeline.update('default');
}

// Format rate with appropriate unit
function formatRate(value, type) {
    if (value === 0) return '0';

    const units = type === 'bps'
        ? ['bps', 'Kbps', 'Mbps', 'Gbps']
        : ['pps', 'Kpps', 'Mpps', 'Gpps'];

    let unitIndex = 0;
    let formattedValue = value;

    while (formattedValue >= 1000 && unitIndex < units.length - 1) {
        formattedValue /= 1000;
        unitIndex++;
    }

    return `${formattedValue.toFixed(unitIndex === 0 ? 0 : 2)} ${units[unitIndex]}`;
}

// Filter table based on search and jail filter
function filterTable() {
    const searchValue = document.getElementById('search-input').value.toLowerCase();
    const jailValue = document.getElementById('jail-filter').value;
    const rows = document.querySelectorAll('#bans-table-body tr');

    rows.forEach(row => {
        const ip = row.cells[0]?.textContent.toLowerCase() || '';
        const jail = row.cells[1]?.textContent || '';

        const matchesSearch = ip.includes(searchValue);
        const matchesJail = !jailValue || jail === jailValue;

        row.style.display = matchesSearch && matchesJail ? '' : 'none';
    });
}

// Format date and time
function formatDateTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Format duration
function formatDuration(seconds) {
    if (seconds < 0) return '永久';

    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    if (hours > 0) return `${hours}h ${mins}m`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
}
