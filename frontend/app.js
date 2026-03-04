/**
 * WAF Shield — Dashboard Application JavaScript v2
 *
 * Handles real-time polling, Chart.js visualizations, attack testing,
 * log management, and domain threat intelligence scanning.
 */

// ── Configuration ──
const API_BASE = window.location.origin;
const POLL_INTERVAL = 2000;

// ── State ──
let isSimulating = false;
let pollTimer = null;
let currentFilter = "all";
let trafficChart = null;
let threatChart = null;
let lastScanResult = null;

// ── Chart Colors ──
const COLORS = {
    Normal: "#10b981",
    SQL_Injection: "#f59e0b",
    DDoS: "#ef4444",
    MITM: "#8b5cf6",
};

const COLORS_ALPHA = {
    Normal: "rgba(16, 185, 129, 0.2)",
    SQL_Injection: "rgba(245, 158, 11, 0.2)",
    DDoS: "rgba(239, 68, 68, 0.2)",
    MITM: "rgba(139, 92, 246, 0.2)",
};

// ═══════════════════════════════════════════
// ── Initialization ──
// ═══════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    fetchModelInfo();
    checkApiStatus();
    pollData();

    // Enter key in domain input
    const domainInput = document.getElementById("domainInput");
    if (domainInput) {
        domainInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") scanDomain();
        });
    }
});

// ═══════════════════════════════════════════
// ── Domain Scanner ──
// ═══════════════════════════════════════════

async function checkApiStatus() {
    try {
        const res = await fetch(`${API_BASE}/api/domain-scan/status`);
        const status = await res.json();
        const container = document.getElementById("apiStatusBadges");
        if (!container) return;

        container.innerHTML = `
            <span class="api-badge ${status.virustotal ? "connected" : "demo"}">
                ${status.virustotal ? "●" : "○"} VT
            </span>
            <span class="api-badge ${status.securitytrails ? "connected" : "demo"}">
                ${status.securitytrails ? "●" : "○"} ST
            </span>
        `;
    } catch (err) {
        console.debug("API status check failed:", err.message);
    }
}

async function scanDomain() {
    const input = document.getElementById("domainInput");
    const btn = document.getElementById("btnScan");
    const resultsSection = document.getElementById("domainResults");
    const domain = input.value.trim();

    if (!domain) {
        input.focus();
        input.style.borderColor = "var(--red)";
        setTimeout(() => input.style.borderColor = "", 1500);
        return;
    }

    // Show loading
    btn.classList.add("scanning");
    btn.disabled = true;
    btn.innerHTML = `
        <div class="scan-spinner" style="width:16px;height:16px;border-width:2px;"></div>
        Scanning...
    `;
    resultsSection.style.display = "grid";
    resultsSection.innerHTML = `
        <div class="card" style="grid-column:1/-1;">
            <div class="scan-loading">
                <div class="scan-spinner"></div>
                <p class="scan-loading-text">Querying threat intelligence for <strong>${escapeHtml(domain)}</strong>...</p>
            </div>
        </div>
    `;

    try {
        const res = await fetch(`${API_BASE}/api/domain-scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain }),
        });
        const data = await res.json();

        if (data.error) {
            resultsSection.innerHTML = `
                <div class="card" style="grid-column:1/-1;">
                    <div class="scan-loading">
                        <p class="scan-loading-text" style="color:var(--red);">⚠ ${escapeHtml(data.error)}</p>
                    </div>
                </div>
            `;
            return;
        }

        lastScanResult = data;
        renderDomainResults(data);
    } catch (err) {
        resultsSection.innerHTML = `
            <div class="card" style="grid-column:1/-1;">
                <div class="scan-loading">
                    <p class="scan-loading-text" style="color:var(--red);">⚠ Connection error: ${err.message}. Is the server running?</p>
                </div>
            </div>
        `;
    } finally {
        btn.classList.remove("scanning");
        btn.disabled = false;
        btn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Scan
        `;
    }
}

function renderDomainResults(data) {
    const resultsSection = document.getElementById("domainResults");
    resultsSection.style.display = "grid";

    // Rebuild the original structure
    resultsSection.innerHTML = `
        <div class="card card-risk" id="riskCard">
            <div class="card-header">
                <h2>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Risk Assessment
                </h2>
                <span class="badge badge-${data.risk_level}" id="riskBadge">${data.risk_level.toUpperCase()}</span>
            </div>
            <div class="risk-body">
                <div class="risk-gauge-wrap">
                    <svg class="risk-gauge" viewBox="0 0 120 120" id="riskGauge">
                        <circle class="gauge-bg" cx="60" cy="60" r="52" />
                        <circle class="gauge-fill" cx="60" cy="60" r="52" id="gaugeFill" />
                        <text class="gauge-text" x="60" y="55" id="gaugeText">0</text>
                        <text class="gauge-label" x="60" y="72">RISK SCORE</text>
                    </svg>
                </div>
                <div class="risk-details" id="riskDetails"></div>
            </div>
        </div>
        <div class="card card-detections">
            <div class="card-header">
                <h2>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    Detection Results
                </h2>
            </div>
            <div class="detection-grid" id="detectionGrid"></div>
        </div>
        <div class="card card-threat-feed">
            <div class="card-header">
                <h2>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
                    Real-Time Threat Feed
                </h2>
                <span class="badge badge-live"><span class="pulse-dot pulse-dot-sm"></span> LIVE</span>
            </div>
            <div class="threat-feed-list" id="threatFeedList"></div>
        </div>
        <div class="card card-dns">
            <div class="card-header">
                <h2>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    DNS & Infrastructure
                </h2>
            </div>
            <div class="dns-body" id="dnsBody"></div>
        </div>
    `;

    // Render each sub-section
    renderRiskGauge(data.risk_score, data.risk_level);
    renderRiskDetails(data);
    renderDetections(data.detection_stats);
    renderThreatFeed(data.threat_feed);
    renderDnsInfo(data);
}

function renderRiskGauge(score, level) {
    const fill = document.getElementById("gaugeFill");
    const text = document.getElementById("gaugeText");
    if (!fill || !text) return;

    const circumference = 2 * Math.PI * 52;
    const offset = circumference - (score / 100) * circumference;

    const colorMap = {
        safe: "#10b981",
        low: "#06b6d4",
        medium: "#f59e0b",
        high: "#f97316",
        critical: "#ef4444",
    };
    const color = colorMap[level] || "#10b981";

    // Animate
    setTimeout(() => {
        fill.style.strokeDashoffset = offset;
        fill.style.stroke = color;
        text.textContent = score;
    }, 100);
}

function renderRiskDetails(data) {
    const container = document.getElementById("riskDetails");
    if (!container) return;

    const apiVt = data.api_status?.virustotal || "unknown";
    const apiSt = data.api_status?.securitytrails || "unknown";

    container.innerHTML = `
        <div class="risk-info-row">
            <span class="risk-info-label">Domain</span>
            <span class="risk-info-value">${escapeHtml(data.domain)}</span>
        </div>
        <div class="risk-info-row">
            <span class="risk-info-label">Scan Time</span>
            <span class="risk-info-value">${data.scan_time || "N/A"}</span>
        </div>
        <div class="risk-info-row">
            <span class="risk-info-label">Reputation</span>
            <span class="risk-info-value" style="color:${data.reputation >= 0 ? 'var(--green)' : 'var(--red)'}">${data.reputation}</span>
        </div>
        <div class="risk-info-row">
            <span class="risk-info-label">VT Status</span>
            <span class="risk-info-value" style="color:${apiVt === 'live' ? 'var(--green)' : 'var(--yellow)'}">${apiVt.toUpperCase()}</span>
        </div>
        <div class="risk-info-row">
            <span class="risk-info-label">ST Status</span>
            <span class="risk-info-value" style="color:${apiSt === 'live' ? 'var(--green)' : 'var(--yellow)'}">${apiSt.toUpperCase()}</span>
        </div>
        ${data.cached ? '<div class="risk-info-row"><span class="risk-info-label">Cache</span><span class="risk-info-value" style="color:var(--cyan)">CACHED</span></div>' : ''}
    `;
}

function renderDetections(stats) {
    const grid = document.getElementById("detectionGrid");
    if (!grid || !stats) return;

    grid.innerHTML = `
        <div class="detection-card malicious">
            <div class="detection-count">${stats.malicious || 0}</div>
            <div class="detection-label">Malicious</div>
        </div>
        <div class="detection-card suspicious">
            <div class="detection-count">${stats.suspicious || 0}</div>
            <div class="detection-label">Suspicious</div>
        </div>
        <div class="detection-card harmless">
            <div class="detection-count">${stats.harmless || 0}</div>
            <div class="detection-label">Harmless</div>
        </div>
        <div class="detection-card undetected">
            <div class="detection-count">${stats.undetected || 0}</div>
            <div class="detection-label">Undetected</div>
        </div>
    `;
}

function renderThreatFeed(threats) {
    const list = document.getElementById("threatFeedList");
    if (!list || !threats) return;

    if (threats.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No active threats detected</p></div>';
        return;
    }

    list.innerHTML = threats.map((t, i) => `
        <div class="threat-item" style="animation-delay:${i * 0.08}s">
            <div class="threat-severity ${t.severity}"></div>
            <div class="threat-info">
                <div class="threat-name">${escapeHtml(t.threat)}</div>
                <div class="threat-meta">
                    <span>⏱ ${t.time}</span>
                    <span>📡 ${escapeHtml(t.source)}</span>
                    ${t.count > 0 ? `<span>×${t.count} detections</span>` : ''}
                </div>
            </div>
            <span class="threat-status ${t.status}">${t.status}</span>
        </div>
    `).join("");
}

function renderDnsInfo(data) {
    const body = document.getElementById("dnsBody");
    if (!body) return;

    const dns = data.dns_records || {};
    const subs = data.subdomains || [];
    const whois = data.whois || {};

    body.innerHTML = `
        <div class="dns-section">
            <div class="dns-section-title">A Records / IPs</div>
            <div class="dns-record-list">
                ${(dns.a || []).length > 0
            ? (dns.a || []).map(r => `<div class="dns-record">${escapeHtml(r)}</div>`).join("")
            : '<div class="dns-record" style="color:var(--text-muted)">No records</div>'
        }
            </div>
        </div>
        <div class="dns-section">
            <div class="dns-section-title">Subdomains (${subs.length})</div>
            <div class="dns-record-list" style="max-height:180px;overflow-y:auto;">
                ${subs.length > 0
            ? subs.map(s => `<div class="dns-record">${escapeHtml(s)}</div>`).join("")
            : '<div class="dns-record" style="color:var(--text-muted)">No subdomains found</div>'
        }
            </div>
        </div>
        <div class="dns-section">
            <div class="dns-section-title">WHOIS & DNS Details</div>
            <div class="dns-record-list">
                <div class="dns-record"><strong>Registrar:</strong> ${escapeHtml(whois.registrar || "N/A")}</div>
                <div class="dns-record"><strong>Created:</strong> ${escapeHtml(whois.created_date || "N/A")}</div>
                <div class="dns-record"><strong>Expires:</strong> ${escapeHtml(whois.expires_date || "N/A")}</div>
                ${(dns.mx || []).length > 0
            ? `<div class="dns-record"><strong>MX:</strong> ${(dns.mx || []).map(r => escapeHtml(r)).join(", ")}</div>`
            : ''
        }
                ${(dns.ns || []).length > 0
            ? `<div class="dns-record"><strong>NS:</strong> ${(dns.ns || []).map(r => escapeHtml(r)).join(", ")}</div>`
            : ''
        }
            </div>
        </div>
    `;
}

// ═══════════════════════════════════════════
// ── Simulation Control ──
// ═══════════════════════════════════════════

async function toggleSimulation() {
    const btn = document.getElementById("btnSimulate");
    const pill = document.getElementById("statusPill");
    const statusText = document.getElementById("statusText");

    if (!isSimulating) {
        try {
            await fetch(`${API_BASE}/api/simulate/start`, { method: "POST" });
            isSimulating = true;
            btn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
                </svg>
                Stop Simulation`;
            btn.classList.add("running");
            pill.classList.add("active");
            statusText.textContent = "Monitoring Active";
            startPolling();
        } catch (err) {
            console.error("Failed to start simulation:", err);
        }
    } else {
        try {
            await fetch(`${API_BASE}/api/simulate/stop`, { method: "POST" });
            isSimulating = false;
            btn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <polygon points="5 3 19 12 5 21 5 3"/>
                </svg>
                Start Simulation`;
            btn.classList.remove("running");
            pill.classList.remove("active");
            statusText.textContent = "Inactive";
            stopPolling();
        } catch (err) {
            console.error("Failed to stop simulation:", err);
        }
    }
}

function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollData, POLL_INTERVAL);
}

function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

async function pollData() {
    try {
        const [statsRes, logsRes, historyRes] = await Promise.all([
            fetch(`${API_BASE}/api/stats`),
            fetch(`${API_BASE}/api/logs?limit=100`),
            fetch(`${API_BASE}/api/traffic-history?seconds=120`),
        ]);

        const stats = await statsRes.json();
        const logs = await logsRes.json();
        const history = await historyRes.json();

        updateStats(stats);
        updateLogs(logs);
        updateTrafficChart(history);
        updateThreatChart(stats);

        // Auto-detect if simulation is running
        if (stats.running && !isSimulating) {
            isSimulating = true;
            document.getElementById("statusPill").classList.add("active");
            document.getElementById("statusText").textContent = "Monitoring Active";
            const btn = document.getElementById("btnSimulate");
            btn.classList.add("running");
            btn.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                    <rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>
                </svg>
                Stop Simulation`;
            startPolling();
        }
    } catch (err) {
        console.debug("Polling error (server may be starting):", err.message);
    }
}

// ═══════════════════════════════════════════
// ── Stats Update ──
// ═══════════════════════════════════════════

function updateStats(stats) {
    animateValue("statTotal", stats.total_requests || 0);
    animateValue("statAllowed", stats.allowed || 0);
    animateValue("statBlocked", stats.blocked || 0);
    animateValue("statSql", stats.sql_injection || 0);
    animateValue("statDdos", stats.ddos || 0);
    animateValue("statMitm", stats.mitm || 0);
}

function animateValue(elementId, newValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const current = parseInt(el.textContent) || 0;
    if (current === newValue) return;

    const diff = newValue - current;
    const steps = Math.min(Math.abs(diff), 15);
    const stepValue = diff / steps;
    let step = 0;

    const timer = setInterval(() => {
        step++;
        if (step >= steps) {
            el.textContent = newValue.toLocaleString();
            clearInterval(timer);
        } else {
            el.textContent = Math.round(current + stepValue * step).toLocaleString();
        }
    }, 30);
}

// ═══════════════════════════════════════════
// ── Charts ──
// ═══════════════════════════════════════════

function initCharts() {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 11;

    const trafficCtx = document.getElementById("trafficChart").getContext("2d");
    trafficChart = new Chart(trafficCtx, {
        type: "line",
        data: {
            labels: [],
            datasets: [
                { label: "Normal", data: [], borderColor: COLORS.Normal, backgroundColor: COLORS_ALPHA.Normal, fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0, pointHoverRadius: 4 },
                { label: "SQL Injection", data: [], borderColor: COLORS.SQL_Injection, backgroundColor: COLORS_ALPHA.SQL_Injection, fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0, pointHoverRadius: 4 },
                { label: "DDoS", data: [], borderColor: COLORS.DDoS, backgroundColor: COLORS_ALPHA.DDoS, fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0, pointHoverRadius: 4 },
                { label: "MITM", data: [], borderColor: COLORS.MITM, backgroundColor: COLORS_ALPHA.MITM, fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0, pointHoverRadius: 4 },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: "index", intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "rgba(13, 19, 33, 0.95)",
                    borderColor: "rgba(255,255,255,0.08)",
                    borderWidth: 1,
                    cornerRadius: 10,
                    padding: 10,
                },
            },
            scales: {
                x: { grid: { color: "rgba(255,255,255,0.03)", drawBorder: false }, ticks: { maxTicksLimit: 10 } },
                y: { grid: { color: "rgba(255,255,255,0.03)", drawBorder: false }, beginAtZero: true, ticks: { stepSize: 1 } },
            },
        },
    });

    const threatCtx = document.getElementById("threatChart").getContext("2d");
    threatChart = new Chart(threatCtx, {
        type: "doughnut",
        data: {
            labels: ["Normal", "SQL Injection", "DDoS", "MITM"],
            datasets: [{
                data: [1, 0, 0, 0],
                backgroundColor: [COLORS.Normal, COLORS.SQL_Injection, COLORS.DDoS, COLORS.MITM],
                borderColor: "rgba(6, 10, 20, 0.9)",
                borderWidth: 3,
                hoverOffset: 8,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "rgba(13, 19, 33, 0.95)",
                    borderColor: "rgba(255,255,255,0.08)",
                    borderWidth: 1,
                    cornerRadius: 10,
                    callbacks: {
                        label: function (context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const value = context.parsed;
                            const pct = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return ` ${context.label}: ${value} (${pct}%)`;
                        },
                    },
                },
            },
        },
    });
}

function updateTrafficChart(history) {
    if (!history || history.length === 0) return;

    trafficChart.data.labels = history.map((h) => h.time);
    trafficChart.data.datasets[0].data = history.map((h) => h.Normal || 0);
    trafficChart.data.datasets[1].data = history.map((h) => h.SQL_Injection || 0);
    trafficChart.data.datasets[2].data = history.map((h) => h.DDoS || 0);
    trafficChart.data.datasets[3].data = history.map((h) => h.MITM || 0);
    trafficChart.update("none");
}

function updateThreatChart(stats) {
    const data = [stats.normal || 0, stats.sql_injection || 0, stats.ddos || 0, stats.mitm || 0];
    if (data.every((d) => d === 0)) return;
    threatChart.data.datasets[0].data = data;
    threatChart.update("none");
}

// ═══════════════════════════════════════════
// ── Logs ──
// ═══════════════════════════════════════════

let displayedLogIds = new Set();

function updateLogs(logs) {
    const tbody = document.getElementById("logsBody");
    if (!logs || logs.length === 0) return;

    const filtered = currentFilter === "all" ? logs : logs.filter((l) => l.classification === currentFilter);

    const rows = filtered.slice(0, 50).map((log) => {
        const isNew = !displayedLogIds.has(log.id);
        displayedLogIds.add(log.id);

        const classLower = log.classification.toLowerCase();
        const confColor =
            classLower === "normal" ? COLORS.Normal
                : classLower === "sql_injection" ? COLORS.SQL_Injection
                    : classLower === "ddos" ? COLORS.DDoS
                        : COLORS.MITM;

        return `
        <tr class="${isNew ? "log-row-new" : ""}">
            <td style="color:var(--text-muted); font-family:var(--font-mono); font-size:0.7rem;">${log.id}</td>
            <td style="font-family:var(--font-mono); font-size:0.75rem;">${log.timestamp}</td>
            <td style="font-family:var(--font-mono); font-size:0.75rem;">${log.ip}</td>
            <td><span style="color:var(--cyan); font-weight:500;">${log.method}</span></td>
            <td class="url-cell" title="${escapeHtml(log.url)}">${escapeHtml(truncate(log.url, 40))}</td>
            <td><span class="class-badge ${classLower}">${log.classification.replace("_", " ")}</span></td>
            <td>
                <div class="confidence-bar">
                    <div class="conf-bar-wrap">
                        <div class="conf-bar" style="width:${log.confidence}%; background:${confColor}"></div>
                    </div>
                    <span style="font-family:var(--font-mono); font-size:0.7rem; color:var(--text-muted);">${log.confidence}%</span>
                </div>
            </td>
            <td><span class="action-badge ${log.action.toLowerCase()}">${log.action}</span></td>
        </tr>`;
    }).join("");

    tbody.innerHTML = rows || '<tr class="empty-row"><td colspan="8"><div class="empty-state">No matching logs</div></td></tr>';
}

function filterLogs(filter, btnEl) {
    currentFilter = filter;
    document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
    if (btnEl) btnEl.classList.add("active");
    pollData();
}

// ═══════════════════════════════════════════
// ── Attack Testing ──
// ═══════════════════════════════════════════

async function testAttack(type) {
    const resultDiv = document.getElementById("testResult");
    resultDiv.innerHTML = '<div class="result-placeholder"><p>Analyzing...</p></div>';

    try {
        const res = await fetch(`${API_BASE}/api/test-attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type }),
        });
        const data = await res.json();
        displayTestResult(data);
    } catch (err) {
        resultDiv.innerHTML = `<div class="result-placeholder"><p style="color:var(--red);">Error: ${err.message}. Is the server running?</p></div>`;
    }
}

async function testCustomPayload() {
    const payload = document.getElementById("customPayload").value.trim();
    if (!payload) return;

    const resultDiv = document.getElementById("testResult");
    resultDiv.innerHTML = '<div class="result-placeholder"><p>Analyzing payload...</p></div>';

    try {
        const res = await fetch(`${API_BASE}/api/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url: `/api/input?q=${encodeURIComponent(payload)}`,
                method: "POST",
                headers: { "User-Agent": "Custom-Test" },
                body: payload,
                ip: "127.0.0.1",
                params: { input: payload },
            }),
        });
        const data = await res.json();
        displayTestResult(data);
    } catch (err) {
        resultDiv.innerHTML = `<div class="result-placeholder"><p style="color:var(--red);">Error: ${err.message}</p></div>`;
    }
}

function displayTestResult(data) {
    const resultDiv = document.getElementById("testResult");
    const classLower = data.classification.toLowerCase();
    const classColor = COLORS[data.classification] || "#94a3b8";

    const probs = data.probabilities || {};
    const probBars = Object.entries(probs).map(
        ([cls, val]) => `
        <div class="prob-row">
            <span class="prob-label">${cls.replace("_", " ")}</span>
            <div class="prob-bar-wrap">
                <div class="prob-bar" style="width:${val}%; background:${COLORS[cls] || "#666"}"></div>
            </div>
            <span class="prob-value">${val}%</span>
        </div>`
    ).join("");

    resultDiv.innerHTML = `
        <div class="result-content">
            <div class="result-header">
                <span class="result-class" style="color:${classColor}">${data.classification.replace("_", " ")}</span>
                <span class="result-action ${data.is_attack ? "blocked" : "allowed"}">${data.action}</span>
            </div>
            <div style="font-size:0.8rem; color:var(--text-secondary); margin-bottom:0.5rem;">
                Confidence: <strong style="color:${classColor}">${data.confidence}%</strong>
                ${data.severity ? `&nbsp;·&nbsp;Severity: <strong>${data.severity.toUpperCase()}</strong>` : ""}
            </div>
            <div class="result-probs">${probBars}</div>
        </div>`;
}

// ═══════════════════════════════════════════
// ── Model Info ──
// ═══════════════════════════════════════════

async function fetchModelInfo() {
    const badge = document.getElementById("modelBadge");
    if (badge) badge.addEventListener("click", showModelModal);
}

async function showModelModal() {
    const modal = document.getElementById("modelModal");
    const body = document.getElementById("modelDetails");
    modal.style.display = "flex";

    try {
        const res = await fetch(`${API_BASE}/api/model-info`);
        const info = await res.json();
        body.innerHTML = `
            <div style="display:grid; gap:0.75rem;">
                <div><strong>Model Type:</strong> ${info.model_type}</div>
                <div><strong>Parameters:</strong> ${info.total_parameters?.toLocaleString()}</div>
                <div><strong>Device:</strong> ${info.device}</div>
                <div><strong>Input Features:</strong> ${info.input_features} dimensions</div>
                <div><strong>Output Classes:</strong> ${info.output_classes?.join(", ")}</div>
                <hr style="border-color:rgba(255,255,255,0.06);">
                <div style="font-size:0.8rem; font-weight:600; margin-bottom:0.25rem;">Architecture Details:</div>
                <div style="font-family:var(--font-mono); font-size:0.75rem; line-height:1.8; background:rgba(0,0,0,0.3); padding:0.75rem; border-radius:10px;">
                    d_model: ${info.architecture?.d_model}<br>
                    attention_heads: ${info.architecture?.num_heads}<br>
                    encoder_layers: ${info.architecture?.num_layers}<br>
                    feedforward_dim: ${info.architecture?.feedforward_dim}<br>
                    sequence: ${info.architecture?.sequence_length}<br>
                    cls_token: ${info.architecture?.cls_token}
                </div>
            </div>`;
    } catch (err) {
        body.innerHTML = `<p style="color:var(--red);">Could not load model info. Is the server running?</p>`;
    }
}

function closeModal() {
    document.getElementById("modelModal").style.display = "none";
}

document.addEventListener("click", (e) => {
    if (e.target.id === "modelModal") closeModal();
});

// ═══════════════════════════════════════════
// ── Utilities ──
// ═══════════════════════════════════════════

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

function truncate(str, max) {
    return str && str.length > max ? str.substring(0, max) + "…" : str || "";
}
