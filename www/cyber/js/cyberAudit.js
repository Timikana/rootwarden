/**
 * cyber/js/cyberAudit.js — Logique JS du module Cyber Audit.
 */

const API = window.API_URL || '/api_proxy.php';

async function apiPost(endpoint, body) {
    const r = await fetch(`${API}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
}

async function apiGet(endpoint) {
    const r = await fetch(`${API}${endpoint}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
}

function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

/* ── Grade colors ──────────────────────────────────────────────────────── */
const GRADE_COLORS = { A: '#22c55e', B: '#3b82f6', C: '#eab308', D: '#f97316', F: '#ef4444' };
const SEV_STYLES = {
    critical: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-700 dark:text-red-300' },
    high:     { bg: 'bg-orange-100 dark:bg-orange-900/30', text: 'text-orange-700 dark:text-orange-300' },
    medium:   { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-700 dark:text-yellow-300' },
    low:      { bg: 'bg-blue-100 dark:bg-blue-900/30', text: 'text-blue-700 dark:text-blue-300' },
    info:     { bg: 'bg-gray-100 dark:bg-gray-700', text: 'text-gray-500 dark:text-gray-400' },
};

const CHECK_ICONS = {
    account: '\u{1F464}',
    sudoers: '\u{1F512}',
    port:    '\u{1F310}',
    suid:    '\u{26A0}',
    security: '\u{1F4E6}',
    file:    '\u{1F4C4}',
};

/* ── Score circle SVG ──────────────────────────────────────────────────── */
function renderScore(score, grade) {
    const color = GRADE_COLORS[grade] || GRADE_COLORS.F;
    const pct = score / 100;
    const r = 54, circ = 2 * Math.PI * r;
    const offset = circ * (1 - pct);
    return `<svg width="128" height="128" viewBox="0 0 128 128">
        <circle cx="64" cy="64" r="${r}" fill="none" stroke="#374151" stroke-width="8"/>
        <circle cx="64" cy="64" r="${r}" fill="none" stroke="${color}" stroke-width="8"
                stroke-dasharray="${circ}" stroke-dashoffset="${offset}"
                transform="rotate(-90 64 64)" stroke-linecap="round"/>
        <text x="64" y="64" text-anchor="middle" dominant-baseline="central"
              fill="${color}" font-size="28" font-weight="bold">${score}</text>
    </svg>`;
}

/* ── Scan single server ────────────────────────────────────────────────── */
async function scanServer() {
    const serverId = document.getElementById('cyber-server').value;
    if (!serverId) { toast(__('select_server') || 'Selectionnez un serveur', 'warning'); return; }

    toast(__('scanning') || 'Scan en cours...', 'info');

    try {
        const d = await apiPost('/cyber-audit/scan', { machine_id: parseInt(serverId) });
        if (!d.success) { toast(d.message || 'Erreur', 'error'); return; }

        showScoreCard(d);
        showFindings(d.findings);
        toast(__('scan_success') || 'Scan termine', 'success');
        loadFleet();
    } catch (e) {
        toast(e.message, 'error');
    }
}

/* ── Scan all servers ──────────────────────────────────────────────────── */
async function scanAll() {
    toast(__('scanning') || 'Scan en cours...', 'info');
    try {
        const d = await apiPost('/cyber-audit/scan-all', {});
        if (!d.success) { toast(d.message || 'Erreur', 'error'); return; }

        const ok = d.results.filter(r => r.success).length;
        const fail = d.results.filter(r => !r.success).length;
        toast(`Scan termine : ${ok} OK, ${fail} echoues`, ok > 0 ? 'success' : 'warning');
        loadFleet();
    } catch (e) {
        toast(e.message, 'error');
    }
}

/* ── Display score card ────────────────────────────────────────────────── */
function showScoreCard(d) {
    const card = document.getElementById('score-card');
    card.classList.remove('hidden');

    document.getElementById('score-circle').innerHTML = renderScore(d.score, d.grade);
    document.getElementById('score-grade').textContent = d.grade;
    document.getElementById('score-grade').style.color = GRADE_COLORS[d.grade] || '';
    document.getElementById('score-number').textContent = d.score + ' / 100';

    const badges = document.getElementById('severity-badges');
    badges.innerHTML = '';
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    (d.findings || []).forEach(function(f) { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    ['critical', 'high', 'medium', 'low'].forEach(function(sev) {
        if (counts[sev] === 0) return;
        var s = SEV_STYLES[sev];
        var badge = document.createElement('span');
        badge.className = 'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-bold ' + s.bg + ' ' + s.text;
        badge.textContent = sev.charAt(0).toUpperCase() + sev.slice(1) + ' : ' + counts[sev];
        badges.appendChild(badge);
    });
}

/* ── Display findings ──────────────────────────────────────────────────── */
function showFindings(findings) {
    var card = document.getElementById('findings-card');
    var list = document.getElementById('findings-list');
    card.classList.remove('hidden');
    list.innerHTML = '';

    if (!findings || findings.length === 0) {
        list.innerHTML = '<p class="text-sm text-green-500 font-medium">Aucun probleme detecte</p>';
        return;
    }

    findings.forEach(function(f) {
        var s = SEV_STYLES[f.severity] || SEV_STYLES.info;
        var checkType = (f.check || '').split('_')[0];
        var icon = CHECK_ICONS[checkType] || '\u{2139}';

        var row = document.createElement('div');
        row.className = 'flex items-start gap-3 p-3 rounded-lg ' + s.bg;

        var iconSpan = document.createElement('span');
        iconSpan.className = 'text-lg flex-shrink-0';
        iconSpan.textContent = icon;

        var content = document.createElement('div');
        content.className = 'flex-1 min-w-0';

        var sevBadge = document.createElement('span');
        sevBadge.className = 'text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ' + s.text;
        sevBadge.textContent = f.severity;

        var detail = document.createElement('span');
        detail.className = 'text-sm ml-2 ' + s.text;
        detail.textContent = f.detail;

        content.appendChild(sevBadge);
        content.appendChild(detail);
        row.appendChild(iconSpan);
        row.appendChild(content);
        list.appendChild(row);
    });
}

/* ── Fleet overview ────────────────────────────────────────────────────── */
async function loadFleet() {
    try {
        var d = await apiGet('/cyber-audit/fleet');
        if (!d.success) return;

        var table = document.getElementById('fleet-table');
        var empty = document.getElementById('fleet-empty');
        var summary = document.getElementById('fleet-summary');

        if (!d.machines || d.machines.length === 0) {
            table.innerHTML = '';
            empty.style.display = '';
            summary.innerHTML = '';
            return;
        }

        empty.style.display = 'none';
        summary.innerHTML = '';
        var avgBadge = document.createElement('span');
        avgBadge.className = 'text-sm font-bold';
        avgBadge.textContent = __('fleet_avg') + ' : ' + d.summary.avg_score + '/100';
        summary.appendChild(avgBadge);

        table.innerHTML = '';
        d.machines.forEach(function(m) {
            var tr = document.createElement('tr');
            tr.className = 'border-b border-gray-200 dark:border-gray-700';

            var gradeColor = GRADE_COLORS[m.grade] || '';

            tr.innerHTML =
                '<td class="p-2 font-semibold">' + escHtml(m.name) + '</td>' +
                '<td class="p-2 text-center text-xs">' + escHtml(m.environment || '') + '</td>' +
                '<td class="p-2 text-center font-bold">' + m.score + '</td>' +
                '<td class="p-2 text-center"><span class="text-lg font-extrabold" style="color:' + gradeColor + '">' + escHtml(m.grade) + '</span></td>' +
                '<td class="p-2 text-center">' + _countBadge(m.accounts_critical, m.accounts_high) + '</td>' +
                '<td class="p-2 text-center">' + _countBadge(m.sudoers_critical, m.sudoers_high) + '</td>' +
                '<td class="p-2 text-center">' + _countBadge(m.ports_critical, m.ports_high) + '</td>' +
                '<td class="p-2 text-center">' + (m.suid_high > 0 ? '<span class="text-orange-500 font-bold">' + m.suid_high + '</span>' : '<span class="text-green-500">0</span>') + '</td>' +
                '<td class="p-2 text-center">' + (m.updates_pending > 0 ? '<span class="text-red-500 font-bold">' + m.updates_pending + '</span>' : '<span class="text-green-500">0</span>') + '</td>' +
                '<td class="p-2 text-center text-xs text-gray-400">' + escHtml((m.audited_at || '').slice(0, 16)) + '</td>';

            table.appendChild(tr);
        });
    } catch (e) {
        console.error('Fleet load failed:', e);
    }
}

function _countBadge(critical, high) {
    if (critical > 0) return '<span class="text-red-500 font-bold">' + critical + 'C</span>';
    if (high > 0) return '<span class="text-orange-500 font-bold">' + high + 'H</span>';
    return '<span class="text-green-500">OK</span>';
}

/* ── Init : charger la fleet au chargement ─────────────────────────────── */
document.addEventListener('DOMContentLoaded', loadFleet);
