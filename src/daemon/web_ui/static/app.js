// Firewall Daemon Dashboard — Dark Theme
'use strict';

// ── 全局状态 ──
let charts = {};
let eventSource = null;
let webuiConfig = {
    rate_warning_pps: 1000,
    rate_critical_pps: 10000,
    rate_warning_syn: 100,
    rate_critical_syn: 1000
};

// 迷你图历史数据（保留最近 20 个数据点）
const SPARKLINE_MAX = 20;
let sparkData = {
    activeBans: [],
    todayBans: [],
    failed: [],
    ddos: []
};

const SSE_ENDPOINT = '/api/events';

// ── 初始化 ──
document.addEventListener('DOMContentLoaded', () => {
    loadWebuiConfig();
    initializeCharts();
    setupEventListeners();
    setupScrollSpy();
    setupMobileMenu();
    connectSSE();
});

// ── 事件监听 ──
function setupEventListeners() {
    document.getElementById('refresh-btn').addEventListener('click', () => {
        const svg = document.querySelector('#refresh-btn svg');
        svg.style.animation = 'none';
        void svg.offsetWidth;
        svg.style.animation = 'spin-once 0.5s var(--ease-out)';
        if (!eventSource || eventSource.readyState === EventSource.CLOSED) {
            connectSSE();
        }
    });

    document.getElementById('search-input').addEventListener('input', filterTable);
    document.getElementById('jail-filter').addEventListener('change', filterTable);
}

// ── 加载配置 ──
async function loadWebuiConfig() {
    try {
        const response = await fetch('/api/config');
        if (response.ok) {
            const config = await response.json();
            webuiConfig = { ...webuiConfig, ...config };
        }
    } catch (e) {
        // 使用默认配置
    }
}

// ─ SSE 连接（长连接模式） ──
let reconnectTimer = null;

function connectSSE() {
    if (eventSource) {
        eventSource.close();
    }
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }

    updateStatus('loading');
    eventSource = new EventSource(SSE_ENDPOINT);

    const handleData = (parser, updater) => (event) => {
        try {
            const data = parser(event.data);
            updater(data);
        } catch (e) {
            console.error('Failed to parse event:', e);
        }
    };

    eventSource.addEventListener('connected', (event) => {
        updateStatus('online');
    });

    eventSource.addEventListener('stats', handleData(
        JSON.parse,
        (stats) => { updateStats(stats); updateCharts(stats); }
    ));
    eventSource.addEventListener('bans', handleData(JSON.parse, updateBansTable));
    eventSource.addEventListener('jails', handleData(JSON.parse, updateJailFilter));
    eventSource.addEventListener('rates', handleData(JSON.parse, updateRatesPanel));

    eventSource.onopen = () => {
        updateStatus('online');
    };

    eventSource.onerror = () => {
        // 短连接模式下，onerror 仅表示本次连接关闭
        // 不修改状态——状态由 connected / 数据事件控制
    };
}

// ── 状态指示器 ──
function updateStatus(status) {
    const el = document.getElementById('status');
    const label = el.querySelector('.status-label');
    el.className = 'connection-status';

    switch (status) {
        case 'online':
            label.textContent = '实时连接';
            el.classList.add('online');
            break;
        case 'loading':
            label.textContent = '连接中...';
            break;
        case 'offline':
            label.textContent = '连接断开';
            el.classList.add('offline');
            break;
    }
}

// ── 统计数据更新 ──
function updateStats(stats) {
    // 统一使用 current_bans（合并了原来的 active_bans 和 kernel_current_bans）
    updateStatValue('active-bans', formatNumber(stats.current_bans));
    updateStatValue('today-bans', formatNumber(stats.today_bans));
    updateStatValue('failed-attempts', formatNumber(stats.failed_attempts));
    updateStatValue('ddos-events', formatNumber(stats.ddos_events));
    updateStatValue('uptime', formatUptime(stats.uptime_seconds));

    // 顶栏快捷统计
    updateStatValue('header-active-bans', formatNumber(stats.current_bans));
    updateStatValue('header-today-bans', formatNumber(stats.today_bans));

    // 内核统计
    updateStatValue('kernel-current-bans', formatNumber(stats.current_bans));
    updateStatValue('kernel-total-bans', formatNumber(stats.total_bans));
    updateStatValue('kernel-total-unbans', formatNumber(stats.total_unbans));
    updateStatValue('kernel-whitelist-count', formatNumber(stats.whitelist_count));
    updateStatValue('kernel-packets-dropped', formatNumber(stats.packets_dropped, true));
    updateStatValue('kernel-packets-accepted', formatNumber(stats.packets_accepted, true));

    // 封禁计数徽章
    const badge = document.getElementById('ban-count-badge');
    if (badge) {
        badge.textContent = formatNumber(stats.current_bans);
    }

    // 更新迷你图数据
    pushSparkData('activeBans', stats.current_bans);
    pushSparkData('todayBans', stats.today_bans);
    pushSparkData('failed', stats.failed_attempts);
    pushSparkData('ddos', stats.ddos_events);

    renderSparkline('spark-active-bans', sparkData.activeBans, '#ef4444');
    renderSparkline('spark-today-bans', sparkData.todayBans, '#3b82f6');
    renderSparkline('spark-failed', sparkData.failed, '#f59e0b');
    renderSparkline('spark-ddos', sparkData.ddos, '#a855f7');
}

function updateStatValue(id, newValue) {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.textContent !== newValue) {
        el.textContent = newValue;
        el.classList.remove('flash');
        void el.offsetWidth;
        el.classList.add('flash');
    }
}

// ── 迷你图 ──
function pushSparkData(key, value) {
    sparkData[key].push(value);
    if (sparkData[key].length > SPARKLINE_MAX) {
        sparkData[key].shift();
    }
}

function renderSparkline(containerId, data, color) {
    const container = document.getElementById(containerId);
    if (!container || data.length < 2) return;

    const w = 120;
    const h = 32;
    const max = Math.max(...data, 1);
    const min = Math.min(...data, 0);
    const range = max - min || 1;
    const step = w / (data.length - 1);

    const points = data.map((v, i) => {
        const x = i * step;
        const y = h - ((v - min) / range) * (h - 4) - 2;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    // 渐变填充路径
    const fillPoints = `0,${h} ${points.join(' ')} ${w},${h}`;

    const uid = containerId + '-grad';
    container.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
        <defs>
            <linearGradient id="${uid}" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stop-color="${color}" stop-opacity="0.4"/>
                <stop offset="100%" stop-color="${color}" stop-opacity="0.05"/>
            </linearGradient>
        </defs>
        <polygon points="${fillPoints}" fill="url(#${uid})"/>
        <polyline points="${points.join(' ')}" fill="none" stroke="${color}"
            stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>`;
}

// ── 格式化 ──
function formatNumber(num, convertUnits) {
    if (convertUnits && num >= 1000) {
        const units = ['', 'K', 'M', 'G', 'T', 'P'];
        let idx = 0;
        let val = num;
        while (val >= 1000 && idx < units.length - 1) {
            val /= 1000;
            idx++;
        }
        return val.toFixed(val >= 100 ? 0 : val >= 10 ? 1 : 2) + units[idx];
    }
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
}

function formatDateTime(timestamp) {
    return new Date(timestamp * 1000).toLocaleString('zh-CN', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit'
    });
}

function formatDuration(seconds) {
    if (seconds < 0) return '永久';
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (hours > 0) return `${hours}h ${mins}m`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
}

function formatRate(value, type) {
    if (value === 0) return '0';
    const units = type === 'bps'
        ? ['bps', 'Kbps', 'Mbps', 'Gbps']
        : ['pps', 'Kpps', 'Mpps', 'Gpps'];
    let idx = 0;
    let val = value;
    while (val >= 1000 && idx < units.length - 1) {
        val /= 1000;
        idx++;
    }
    return `${val.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

// ── 图表初始化 ──
function initializeCharts() {
    // Chart.js 全局暗色主题
    Chart.defaults.color = '#64748b';
    Chart.defaults.borderColor = 'rgba(148, 163, 184, 0.08)';
    Chart.defaults.font.family = "'Inter', 'SF Pro Display', -apple-system, sans-serif";

    const tooltipStyle = {
        backgroundColor: '#1e293b',
        titleColor: '#f1f5f9',
        bodyColor: '#94a3b8',
        borderColor: 'rgba(148, 163, 184, 0.15)',
        borderWidth: 1,
        padding: 10,
        cornerRadius: 8,
        displayColors: true,
        boxPadding: 4
    };

    const scaleDefaults = {
        grid: { color: 'rgba(148, 163, 184, 0.06)' },
        border: { display: false }
    };

    // 封禁趋势（折线图）
    charts.banTrend = new Chart(
        document.getElementById('ban-trend-chart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: '封禁数',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: createGradient('ban-trend-chart', '#3b82f6'),
                tension: 0.4,
                fill: true,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: '#3b82f6'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: tooltipStyle
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ...scaleDefaults,
                    ticks: {
                        stepSize: 1,
                        callback: (v) => Number.isInteger(v) ? v : null
                    }
                },
                x: { grid: { display: false }, border: { display: false } }
            }
        }
    });

    // Jail 分布（环形图）
    charts.jailDistribution = new Chart(
        document.getElementById('jail-distribution-chart').getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#3b82f6', '#22c55e', '#f59e0b',
                    '#ef4444', '#a855f7', '#06b6d4'
                ],
                borderWidth: 0,
                hoverOffset: 6,
                spacing: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 16,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        font: { size: 11 }
                    }
                },
                tooltip: tooltipStyle
            },
            cutout: '68%'
        }
    });

    // 失败原因（柱状图）
    charts.failureReasons = new Chart(
        document.getElementById('failure-reasons-chart').getContext('2d'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '次数',
                data: [],
                backgroundColor: 'rgba(239, 68, 68, 0.7)',
                hoverBackgroundColor: 'rgba(239, 68, 68, 0.9)',
                borderRadius: 6,
                borderSkipped: false,
                barThickness: 32
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: tooltipStyle
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ...scaleDefaults,
                    ticks: {
                        stepSize: 1,
                        callback: (v) => Number.isInteger(v) ? v : null
                    }
                },
                x: { grid: { display: false }, border: { display: false } }
            }
        }
    });

    // 实时流量（面积图）
    charts.traffic = new Chart(
        document.getElementById('traffic-chart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: '请求/秒',
                data: [],
                borderColor: '#22c55e',
                backgroundColor: createGradient('traffic-chart', '#22c55e'),
                tension: 0.4,
                fill: true,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4,
                pointHoverBackgroundColor: '#22c55e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: tooltipStyle
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ...scaleDefaults,
                    ticks: {
                        stepSize: 1,
                        callback: (v) => Number.isInteger(v) ? v : null
                    }
                },
                x: { grid: { display: false }, border: { display: false } }
            }
        }
    });

    // 实时速率时间轴
    charts.rateTimeline = new Chart(
        document.getElementById('rate-timeline-chart').getContext('2d'), {
        type: 'line',
        data: {
            labels: Array(300).fill(''),
            datasets: [
                {
                    label: '总速率',
                    data: Array(300).fill(0),
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.06)',
                    tension: 0.4, fill: true, borderWidth: 2,
                    pointRadius: 0, pointHoverRadius: 3
                },
                {
                    label: 'SYN',
                    data: Array(300).fill(0),
                    borderColor: '#ef4444',
                    backgroundColor: 'transparent',
                    tension: 0.4, fill: false, borderWidth: 1.5,
                    pointRadius: 0, pointHoverRadius: 3
                },
                {
                    label: 'UDP',
                    data: Array(300).fill(0),
                    borderColor: '#f59e0b',
                    backgroundColor: 'transparent',
                    tension: 0.4, fill: false, borderWidth: 1.5,
                    pointRadius: 0, pointHoverRadius: 3
                },
                {
                    label: 'ICMP',
                    data: Array(300).fill(0),
                    borderColor: '#a855f7',
                    backgroundColor: 'transparent',
                    tension: 0.4, fill: false, borderWidth: 1.5,
                    pointRadius: 0, pointHoverRadius: 3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            animation: { duration: 300 },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 12,
                        font: { size: 11 }
                    }
                },
                tooltip: {
                    ...tooltipStyle,
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ...scaleDefaults,
                    ticks: {
                        callback: (v) => {
                            if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M';
                            if (v >= 1e3) return (v / 1e3).toFixed(1) + 'K';
                            return Number.isInteger(v) ? v : null;
                        },
                        font: { size: 10 }
                    }
                },
                x: {
                    grid: { display: false },
                    border: { display: false },
                    ticks: {
                        maxTicksLimit: 10,
                        maxRotation: 0,
                        font: { size: 10 }
                    }
                }
            }
        }
    });
}

// 创建渐变填充
function createGradient(canvasId, color) {
    const canvas = document.getElementById(canvasId);
    const ctx = canvas.getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 200);
    gradient.addColorStop(0, color + '20');
    gradient.addColorStop(1, color + '00');
    return gradient;
}

// ── 图表更新 ──
function updateCharts(stats) {
    if (stats.ban_trend) {
        charts.banTrend.data.labels = stats.ban_trend.labels;
        charts.banTrend.data.datasets[0].data = stats.ban_trend.values;
        charts.banTrend.update('none');
    }
    if (stats.jail_distribution) {
        charts.jailDistribution.data.labels = stats.jail_distribution.labels;
        charts.jailDistribution.data.datasets[0].data = stats.jail_distribution.values;
        charts.jailDistribution.update('none');
    }
    if (stats.failure_reasons) {
        charts.failureReasons.data.labels = stats.failure_reasons.labels;
        charts.failureReasons.data.datasets[0].data = stats.failure_reasons.values;
        charts.failureReasons.update('none');
    }
    if (stats.failed_attempts_trend) {
        charts.traffic.data.labels = stats.failed_attempts_trend.labels;
        charts.traffic.data.datasets[0].data = stats.failed_attempts_trend.values;
        charts.traffic.update('none');
    }
}

// ── 封禁表格 ──
function updateBansTable(bans) {
    const tbody = document.getElementById('bans-table-body');

    if (!bans || bans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="table-empty">
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <span>暂无活跃封禁</span>
            </div></td></tr>`;
        return;
    }

    tbody.innerHTML = bans.map(ban => `
        <tr>
            <td><span class="table-ip">${ban.ip}</span></td>
            <td><span class="table-jail">${ban.jail}</span></td>
            <td><span class="table-time">${formatDateTime(ban.banned_at)}</span></td>
            <td><span class="table-time">${formatDuration(ban.remaining_seconds)}</span></td>
            <td>${ban.reason}</td>
        </tr>
    `).join('');
}

function updateJailFilter(jails) {
    const select = document.getElementById('jail-filter');
    const current = select.value;
    select.innerHTML = '<option value="">所有 Jail</option>';

    if (jails && jails.length > 0) {
        jails.forEach(jail => {
            const opt = document.createElement('option');
            opt.value = jail.name;
            opt.textContent = jail.name;
            select.appendChild(opt);
        });
    }
    select.value = current;
}

function filterTable() {
    const search = document.getElementById('search-input').value.toLowerCase();
    const jail = document.getElementById('jail-filter').value;
    const rows = document.querySelectorAll('#bans-table-body tr');

    rows.forEach(row => {
        const ip = row.cells[0]?.textContent.toLowerCase() || '';
        const j = row.cells[1]?.textContent || '';
        const match = ip.includes(search) && (!jail || j === jail);
        row.style.display = match ? '' : 'none';
    });
}

// ── DDoS 速率面板 ──
function updateRatesPanel(rates) {
    const grid = document.getElementById('rates-grid');

    if (!rates || rates.length === 0) {
        grid.innerHTML = `<div class="rates-empty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
            <span>暂无活跃速率数据</span>
        </div>`;
        return;
    }

    grid.innerHTML = rates.map(rate => {
        const pps = rate.packets_per_sec;
        const syn = rate.syn_packets_per_sec;
        let level = 'normal';
        let text = '正常';

        if (pps > webuiConfig.rate_critical_pps || syn > webuiConfig.rate_critical_syn) {
            level = 'critical';
            text = '严重';
        } else if (pps > webuiConfig.rate_warning_pps || syn > webuiConfig.rate_warning_syn) {
            level = 'warning';
            text = '警告';
        }

        return `<div class="rate-card rate-${level}">
            <div class="rate-header">
                <span class="rate-ip">${rate.ip}</span>
                <span class="rate-badge rate-${level}">${text}</span>
            </div>
            <div class="rate-stats">
                <div class="rate-stat">
                    <div class="rate-stat-label">总速率</div>
                    <div class="rate-stat-value">${formatRate(pps, 'pps')}</div>
                </div>
                <div class="rate-stat">
                    <div class="rate-stat-label">带宽</div>
                    <div class="rate-stat-value">${formatRate(rate.bytes_per_sec, 'bps')}</div>
                </div>
                <div class="rate-stat">
                    <div class="rate-stat-label">SYN</div>
                    <div class="rate-stat-value">${formatRate(syn, 'pps')}</div>
                </div>
                <div class="rate-stat">
                    <div class="rate-stat-label">UDP</div>
                    <div class="rate-stat-value">${formatRate(rate.udp_packets_per_sec, 'pps')}</div>
                </div>
                <div class="rate-stat">
                    <div class="rate-stat-label">ICMP</div>
                    <div class="rate-stat-value">${formatRate(rate.icmp_packets_per_sec, 'pps')}</div>
                </div>
            </div>
        </div>`;
    }).join('');

    updateRateTimeline(rates);
}

function updateRateTimeline(rates) {
    if (!charts.rateTimeline) return;

    let totalPps = 0, totalSyn = 0, totalUdp = 0, totalIcmp = 0;
    rates.forEach(r => {
        totalPps += r.packets_per_sec;
        totalSyn += r.syn_packets_per_sec;
        totalUdp += r.udp_packets_per_sec;
        totalIcmp += r.icmp_packets_per_sec;
    });

    const label = new Date().toLocaleTimeString('zh-CN', {
        hour: '2-digit', minute: '2-digit', second: '2-digit'
    });

    const ds = charts.rateTimeline.data;
    ds.labels.push(label);
    ds.datasets[0].data.push(totalPps);
    ds.datasets[1].data.push(totalSyn);
    ds.datasets[2].data.push(totalUdp);
    ds.datasets[3].data.push(totalIcmp);

    if (ds.labels.length > 300) {
        ds.labels.shift();
        ds.datasets.forEach(d => d.data.shift());
    }

    charts.rateTimeline.update('default');
}

// ── 滚动监听（Scroll Spy） ──
function setupScrollSpy() {
    const navItems = document.querySelectorAll('.nav-item[data-section]');
    const sections = document.querySelectorAll('.content-section[id]');

    // 点击导航项平滑滚动
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = item.getAttribute('data-section');
            const target = document.getElementById(targetId);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }

            // 更新激活状态
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            // 移动端关闭侧边栏
            closeMobileMenu();
        });
    });

    // Intersection Observer 自动更新激活状态
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const id = entry.target.id;
                navItems.forEach(n => {
                    n.classList.toggle('active',
                        n.getAttribute('data-section') === id);
                });
            }
        });
    }, {
        rootMargin: '-20% 0px -70% 0px',
        threshold: 0
    });

    sections.forEach(section => observer.observe(section));
}

// ── 移动端菜单 ──
function setupMobileMenu() {
    const btn = document.getElementById('mobile-menu-btn');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.getElementById('sidebar-overlay');

    btn.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('visible');
    });

    overlay.addEventListener('click', closeMobileMenu);
}

function closeMobileMenu() {
    document.querySelector('.sidebar').classList.remove('open');
    document.getElementById('sidebar-overlay').classList.remove('visible');
}
