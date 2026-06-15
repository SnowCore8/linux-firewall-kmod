// Firewall Daemon Dashboard - JavaScript
'use strict';

// Global state
let refreshInterval = 10000; // 10 seconds
let refreshTimer = null;
let charts = {};

// API endpoints
const API_ENDPOINTS = {
    stats: '/api/stats',
    bans: '/api/bans',
    jails: '/api/jails'
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    setupEventListeners();
    loadData();
    startAutoRefresh();
});

// Setup event listeners
function setupEventListeners() {
    // Manual refresh button
    document.getElementById('refresh-btn').addEventListener('click', loadData);

    // Refresh interval selector
    document.getElementById('refresh-interval').addEventListener('change', (e) => {
        refreshInterval = parseInt(e.target.value) * 1000;
        startAutoRefresh();
    });

    // Search input
    document.getElementById('search-input').addEventListener('input', filterTable);

    // Jail filter
    document.getElementById('jail-filter').addEventListener('change', filterTable);
}

// Start auto-refresh
function startAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
    }

    if (refreshInterval > 0) {
        refreshTimer = setInterval(loadData, refreshInterval);
    }
}

// Load all data
async function loadData() {
    try {
        updateStatus('loading');

        const [stats, bans, jails] = await Promise.all([
            fetchJSON(API_ENDPOINTS.stats),
            fetchJSON(API_ENDPOINTS.bans),
            fetchJSON(API_ENDPOINTS.jails)
        ]);

        updateStats(stats);
        updateCharts(stats);
        updateBansTable(bans);
        updateJailFilter(jails);

        updateStatus('online');
    } catch (error) {
        console.error('Failed to load data:', error);
        updateStatus('offline');
    }
}

// Fetch JSON from API
async function fetchJSON(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return response.json();
}

// Update status badge
function updateStatus(status) {
    const badge = document.getElementById('status');
    badge.className = 'status-badge';

    switch (status) {
        case 'online':
            badge.textContent = '在线';
            badge.classList.add('online');
            break;
        case 'loading':
            badge.textContent = '加载中...';
            break;
        case 'offline':
            badge.textContent = '离线';
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
}

// Format number with commas
function formatNumber(num) {
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
