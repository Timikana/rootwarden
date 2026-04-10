// sshAudit.js — Interactions JS pour la page SSH Audit
const API = window.API_URL || '/api_proxy.php';
let _currentServer = null;
let _lastFindings = [];
let _lastScore = null;

// ── Helpers ──────────────────────────────────────────────────────────────────

function getServer() {
    const sel = document.getElementById('server');
    if (!sel || !sel.value) {
        toast(__('audit_select_server'), 'warning');
        return null;
    }
    try { return JSON.parse(sel.value); }
    catch { toast(__('audit_invalid_server'), 'error'); return null; }
}

function serverPayload(extra = {}) {
    return {
        machine_id: _currentServer.id,
        ...extra
    };
}

function appendLog(msg) {
    const c = document.getElementById('logs-container');
    if (!c) return;
    const p = document.createElement('p');
    p.textContent = msg;
    c.appendChild(p);
    c.scrollTop = c.scrollHeight;
}

function clearLogs() {
    const c = document.getElementById('logs-container');
    if (c) c.innerHTML = '';
}

async function apiPost(endpoint, body) {
    const r = await fetch(`${API}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return r.json();
}

async function apiGet(endpoint) {
    const r = await fetch(`${API}${endpoint}`);
    return r.json();
}

// ── Scan single server ──────────────────────────────────────────────────────

async function scanServer() {
    const srv = getServer();
    if (!srv) return;
    _currentServer = srv;

    clearLogs();
    appendLog(__('audit_scanning', { server: srv.name }));

    try {
        const d = await apiPost('/ssh-audit/scan', serverPayload());
        if (!d.success) {
            appendLog(__('error_with_msg', { msg: d.message }));
            toast(__('error_with_msg', { msg: d.message }), 'error');
            return;
        }

        _lastScore = d.score;
        _lastFindings = d.findings || [];

        // Show score card
        const scoreCard = document.getElementById('score-card');
        scoreCard.classList.remove('hidden');
        document.getElementById('score-circle').innerHTML = renderScore(d.score, d.grade);
        document.getElementById('score-grade').textContent = d.grade;
        document.getElementById('score-grade').style.color = gradeColor(d.grade);
        document.getElementById('score-number').textContent = d.score + ' / 100';

        // Update severity counters
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        // Normalize findings from backend format to UI format
        _lastFindings = _lastFindings.map(f => ({
            severity: f.severity,
            directive: f.key || f.directive || '',
            current: f.current_value || f.current || '',
            recommended: f.fix || f.recommended || '',
            description: f.msg_key ? __('audit_rule_' + f.msg_key) : (f.description || ''),
            fixable: !!(f.fix),
            policy: f.policy || 'audit',
            msg_key: f.msg_key || '',
        }));
        _lastFindings.forEach(f => {
            const sev = (f.severity || '').toLowerCase();
            if (counts[sev] !== undefined) counts[sev]++;
        });
        document.getElementById('count-critical').textContent = counts.critical;
        document.getElementById('count-high').textContent = counts.high;
        document.getElementById('count-medium').textContent = counts.medium;
        document.getElementById('count-low').textContent = counts.low;

        // Render findings table
        document.getElementById('findings-container').classList.remove('hidden');
        renderFindings(_lastFindings);

        // Load history for this server
        loadHistory(srv.id);

        // Load policies if admin
        if (window.IS_ADMIN) {
            loadPolicies(srv.id);
        }

        appendLog(__('audit_scan_complete', { server: srv.name, score: d.score, grade: d.grade }));
        toast(__('audit_scan_complete', { server: srv.name, score: d.score, grade: d.grade }), 'success');

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
        toast(__('exception_with_msg', { msg: e }), 'error');
    }
}

// ── Scan all servers (admin) ────────────────────────────────────────────────

async function scanAll() {
    if (!window.IS_ADMIN) return;

    clearLogs();
    appendLog(__('audit_scanning_all'));

    try {
        const d = await apiPost('/ssh-audit/scan-all', {});
        if (!d.success) {
            appendLog(__('error_with_msg', { msg: d.message }));
            toast(__('error_with_msg', { msg: d.message }), 'error');
            return;
        }

        const results = d.results || [];
        const fleetContainer = document.getElementById('fleet-container');
        if (fleetContainer) {
            fleetContainer.classList.remove('hidden');
            renderFleetView(results);
        }

        appendLog(__('audit_scan_all_complete', { count: results.length }));
        toast(__('audit_scan_all_complete', { count: results.length }), 'success');

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
        toast(__('exception_with_msg', { msg: e }), 'error');
    }
}

// ── View raw config ─────────────────────────────────────────────────────────

async function viewConfig() {
    if (!_currentServer) return;

    appendLog(__('audit_loading_config', { server: _currentServer.name }));

    try {
        const d = await apiPost('/ssh-audit/config', serverPayload());
        if (!d.success) {
            appendLog(__('error_with_msg', { msg: d.message }));
            toast(d.message, 'error');
            return;
        }

        document.getElementById('config-content').textContent = d.config || '';
        document.getElementById('config-modal').classList.remove('hidden');
        appendLog(__('audit_config_loaded', { server: _currentServer.name }));

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

function closeConfigModal() {
    document.getElementById('config-modal').classList.add('hidden');
}

// ── Fix directive (admin) ───────────────────────────────────────────────────

async function fixDirective(key, value) {
    if (!_currentServer || !window.IS_ADMIN) return;
    if (!confirm(__('audit_fix_confirm', { key: key, value: value, server: _currentServer.name }))) return;

    appendLog(__('audit_fixing', { key: key, server: _currentServer.name }));

    try {
        const d = await apiPost('/ssh-audit/fix', serverPayload({ directive: key, value: value }));
        appendLog(d.success ? __('audit_fixed', { key: key }) : __('error_with_msg', { msg: d.message }));
        toast(d.success ? __('audit_fixed', { key: key }) : d.message, d.success ? 'success' : 'error');

        // Auto-rescan to update score
        if (d.success) {
            appendLog(__('audit_rescanning', { server: _currentServer.name }));
            scanServer();
        }

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
        toast(__('exception_with_msg', { msg: e }), 'error');
    }
}

// ── Load history ────────────────────────────────────────────────────────────

async function loadHistory(machineId) {
    try {
        const d = await apiGet(`/ssh-audit/results?machine_id=${encodeURIComponent(machineId)}`);
        const container = document.getElementById('history-container');
        const list = document.getElementById('history-list');
        const noMsg = document.getElementById('no-history-msg');

        if (!d.success || !d.results || d.results.length === 0) {
            container.classList.remove('hidden');
            list.innerHTML = '';
            noMsg.classList.remove('hidden');
            return;
        }

        noMsg.classList.add('hidden');
        container.classList.remove('hidden');

        // Show last 5 scans
        const scans = d.results.slice(0, 5);
        list.innerHTML = scans.map(s => `
            <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <div class="flex items-center gap-3">
                    <span class="text-lg font-extrabold" style="color:${gradeColor(s.grade)}">${escHtml(s.grade)}</span>
                    <span class="text-sm font-medium text-gray-800 dark:text-gray-200">${escHtml(String(s.score))} / 100</span>
                </div>
                <div class="flex items-center gap-3">
                    <span class="text-xs text-gray-500 dark:text-gray-400">${escHtml(s.scanned_at || s.date || '')}</span>
                    <span class="text-xs px-2 py-0.5 rounded-full font-bold bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">${escHtml(String(s.critical_count || 0))} ${escHtml(__('audit_critical_short'))}</span>
                </div>
            </div>
        `).join('');

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

// ── Policies (admin) ────────────────────────────────────────────────────────

async function loadPolicies(machineId) {
    if (!window.IS_ADMIN) return;

    try {
        const d = await apiGet(`/ssh-audit/policies?machine_id=${encodeURIComponent(machineId)}`);
        const list = document.getElementById('policies-list');
        if (!list) return;

        if (!d.success || !d.policies || d.policies.length === 0) {
            list.innerHTML = `<p class="text-sm text-gray-400 dark:text-gray-500 italic">${escHtml(__('audit_no_policies'))}</p>`;
            return;
        }

        list.innerHTML = d.policies.map(p => {
            const isIgnored = p.policy === 'ignore';
            const toggleLabel = isIgnored ? __('audit_policy_audit') : __('audit_policy_ignore');
            const toggleTarget = isIgnored ? 'audit' : 'ignore';
            const badgeCls = isIgnored
                ? 'bg-gray-100 dark:bg-gray-600 text-gray-600 dark:text-gray-300'
                : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300';
            const statusLabel = isIgnored ? __('audit_status_ignored') : __('audit_status_audited');

            return `
                <div class="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div class="flex items-center gap-3">
                        <span class="font-mono text-sm font-medium text-gray-800 dark:text-gray-200">${escHtml(p.directive)}</span>
                        <span class="px-2 py-0.5 rounded-full text-xs font-bold ${badgeCls}">${escHtml(statusLabel)}</span>
                        ${p.reason ? `<span class="text-xs text-gray-400 dark:text-gray-500 italic">${escHtml(p.reason)}</span>` : ''}
                    </div>
                    <button onclick="togglePolicy('${escAttr(p.directive)}', '${escAttr(toggleTarget)}')" class="text-xs px-3 py-1 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors">
                        ${escHtml(toggleLabel)}
                    </button>
                </div>`;
        }).join('');

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

async function togglePolicy(directive, policy) {
    if (!_currentServer || !window.IS_ADMIN) return;

    let reason = '';
    if (policy === 'ignore') {
        reason = prompt(__('audit_ignore_reason'));
        if (reason === null) return; // Cancelled
    }

    appendLog(__('audit_updating_policy', { directive: directive }));

    try {
        const d = await apiPost('/ssh-audit/policies', serverPayload({
            directive: directive,
            policy: policy,
            reason: reason
        }));

        if (d.success) {
            toast(__('audit_policy_updated', { directive: directive }), 'success');
            appendLog(__('audit_policy_updated', { directive: directive }));
            loadPolicies(_currentServer.id);
        } else {
            toast(d.message, 'error');
            appendLog(__('error_with_msg', { msg: d.message }));
        }

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
        toast(__('exception_with_msg', { msg: e }), 'error');
    }
}

// ── Render: score circle (SVG) ──────────────────────────────────────────────

function renderScore(score, grade) {
    const colors = { A: '#22c55e', B: '#3b82f6', C: '#eab308', D: '#f97316', F: '#ef4444' };
    const color = colors[grade] || colors.F;
    const radius = 54;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (score / 100) * circumference;

    return `
        <svg width="128" height="128" viewBox="0 0 128 128">
            <circle cx="64" cy="64" r="${radius}" fill="none" stroke="currentColor" stroke-width="8" class="text-gray-200 dark:text-gray-700"/>
            <circle cx="64" cy="64" r="${radius}" fill="none" stroke="${escAttr(color)}" stroke-width="8"
                stroke-dasharray="${circumference}" stroke-dashoffset="${circumference}"
                stroke-linecap="round" transform="rotate(-90 64 64)"
                style="transition: stroke-dashoffset 1s ease-out;">
                <animate attributeName="stroke-dashoffset" from="${circumference}" to="${offset}" dur="1s" fill="freeze"/>
            </circle>
            <text x="64" y="68" text-anchor="middle" class="fill-current text-gray-800 dark:text-gray-100" font-size="28" font-weight="bold">${escHtml(String(score))}</text>
        </svg>`;
}

// ── Render: findings table ──────────────────────────────────────────────────

function renderFindings(findings) {
    const tbody = document.getElementById('findings-tbody');
    const noMsg = document.getElementById('no-findings-msg');

    if (!findings || findings.length === 0) {
        tbody.innerHTML = '';
        noMsg.classList.remove('hidden');
        return;
    }

    noMsg.classList.add('hidden');
    tbody.innerHTML = findings.map(f => {
        const policyLabel = f.policy === 'ignore' ? __('audit_status_ignored') : __('audit_status_audited');
        const policyCls = f.policy === 'ignore'
            ? 'bg-gray-100 dark:bg-gray-600 text-gray-500 dark:text-gray-400'
            : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300';

        let actionHtml = '';
        if (window.IS_ADMIN && f.fixable) {
            actionHtml = `<button onclick="fixDirective('${escAttr(f.directive)}', '${escAttr(f.recommended)}')" class="text-xs px-2 py-1 rounded bg-amber-500 hover:bg-amber-600 text-white transition-colors font-medium">${escHtml(__('audit_btn_fix'))}</button>`;
        }

        return `
            <tr class="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                <td class="py-2 px-3">${severityBadge(f.severity)}</td>
                <td class="py-2 px-3 font-mono text-sm font-medium">${escHtml(f.directive || '')}</td>
                <td class="py-2 px-3 text-xs font-mono text-red-600 dark:text-red-400">${escHtml(f.current || '')}</td>
                <td class="py-2 px-3 text-xs font-mono text-green-600 dark:text-green-400">${escHtml(f.recommended || '')}</td>
                <td class="py-2 px-3 text-xs text-gray-500 dark:text-gray-400 max-w-xs">${escHtml(f.description || '')}</td>
                <td class="py-2 px-3">
                    ${window.IS_ADMIN
                        ? `<button onclick="toggleDirective('${escAttr(f.directive)}', ${f.current !== '(absent)'})"
                             class="text-xs px-2 py-1 rounded ${f.current !== '(absent)' ? 'bg-green-100 dark:bg-green-900/30 text-green-700' : 'bg-gray-100 dark:bg-gray-600 text-gray-500'} transition-colors"
                             title="${f.current !== '(absent)' ? escAttr(__('audit_toggle_disable', {key: f.directive})) : escAttr(__('audit_toggle_enable', {key: f.directive}))}"
                            >${f.current !== '(absent)' ? escHtml(__('audit_directive_enabled')) : escHtml(__('audit_directive_disabled'))}</button>`
                        : `<span class="px-2 py-0.5 rounded-full text-xs font-bold ${policyCls}">${escHtml(policyLabel)}</span>`}
                </td>
                ${window.IS_ADMIN ? `<td class="py-2 px-3 text-right">${actionHtml}</td>` : ''}
            </tr>`;
    }).join('');
}

// ── Render: fleet view (admin) ──────────────────────────────────────────────

function renderFleetView(results) {
    const tbody = document.getElementById('fleet-tbody');
    if (!tbody) return;

    tbody.innerHTML = results.map(r => {
        const color = gradeColor(r.grade);
        const barWidth = Math.max(0, Math.min(100, r.score || 0));

        return `
            <tr class="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
                <td class="py-2 px-3 font-medium text-sm">${escHtml(r.server || r.name || '')}</td>
                <td class="py-2 px-3 text-xs font-mono text-gray-500 dark:text-gray-400">${escHtml(r.ip || '')}</td>
                <td class="py-2 px-3 text-sm font-bold">${escHtml(String(r.score || 0))}</td>
                <td class="py-2 px-3">
                    <div class="flex items-center gap-2">
                        <div class="w-24 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                            <div class="h-full rounded-full transition-all duration-500" style="width:${barWidth}%;background:${escAttr(color)}"></div>
                        </div>
                        <span class="text-sm font-extrabold" style="color:${escAttr(color)}">${escHtml(r.grade || '?')}</span>
                    </div>
                </td>
                <td class="py-2 px-3">
                    <span class="px-2 py-0.5 rounded-full text-xs font-bold bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">${escHtml(String(r.critical_count || 0))}</span>
                </td>
                <td class="py-2 px-3 text-xs text-gray-500 dark:text-gray-400">${escHtml(r.last_scan || r.scanned_at || '')}</td>
            </tr>`;
    }).join('');
}

// ── Utilities ───────────────────────────────────────────────────────────────

function severityBadge(severity) {
    const sev = (severity || '').toLowerCase();
    const badges = {
        critical: { cls: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300', key: 'audit_severity_critical' },
        high:     { cls: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300', key: 'audit_severity_high' },
        medium:   { cls: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300', key: 'audit_severity_medium' },
        low:      { cls: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300', key: 'audit_severity_low' },
        info:     { cls: 'bg-gray-100 dark:bg-gray-600 text-gray-600 dark:text-gray-300', key: 'audit_severity_info' },
    };
    const b = badges[sev] || badges.info;
    return `<span class="px-2 py-0.5 rounded-full text-xs font-bold ${b.cls}">${escHtml(__(b.key))}</span>`;
}

function gradeColor(grade) {
    const colors = { A: '#22c55e', B: '#3b82f6', C: '#eab308', D: '#f97316', F: '#ef4444' };
    return colors[grade] || colors.F;
}

function escAttr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/'/g, '&#39;')
                     .replace(/"/g, '&quot;').replace(/</g, '&lt;')
                     .replace(/>/g, '&gt;').replace(/\\/g, '\\\\');
}

// ── Editor ──────────────────────────────────────────────────────────────────

async function openEditor() {
    if (!_currentServer) { toast(__('audit_select_server'), 'warning'); return; }
    appendLog(__('audit_editor_loading', { server: _currentServer.name }));
    try {
        const d = await apiPost('/ssh-audit/config', serverPayload());
        if (!d.success) { toast(d.message, 'error'); return; }
        document.getElementById('editor-content').value = d.config || '';
        document.getElementById('editor-modal').classList.remove('hidden');
    } catch (e) { toast(__('exception_with_msg', { msg: e }), 'error'); }
}

function closeEditor() {
    document.getElementById('editor-modal').classList.add('hidden');
}

async function saveConfig() {
    if (!_currentServer) return;
    if (!confirm(__('audit_save_confirm', { server: _currentServer.name }))) return;
    const config = document.getElementById('editor-content').value;
    appendLog(__('audit_saving_config', { server: _currentServer.name }));
    try {
        const d = await apiPost('/ssh-audit/save-config', { ...serverPayload(), config });
        if (d.success) {
            toast(__('audit_saved'), 'success');
            appendLog(__('audit_saved'));
            closeEditor();
        } else {
            toast(__('audit_save_error', { msg: d.message }), 'error');
            appendLog(__('audit_save_error', { msg: d.message }));
        }
    } catch (e) { toast(__('exception_with_msg', { msg: e }), 'error'); }
}

// ── Toggle directive ON/OFF ─────────────────────────────────────────────────

async function toggleDirective(key, currentlyEnabled) {
    if (!_currentServer) return;
    const action = currentlyEnabled ? 'disable' : 'enable';
    const confirmKey = currentlyEnabled ? 'audit_toggle_disable' : 'audit_toggle_enable';
    if (!confirm(__(confirmKey, { key }))) return;

    appendLog(__('audit_toggling', { key, action }));
    try {
        const d = await apiPost('/ssh-audit/toggle', { ...serverPayload(), directive: key, enable: !currentlyEnabled });
        if (d.success) {
            toast(__('audit_toggled', { key, action }), 'success');
            appendLog(__('audit_toggled', { key, action }));
            scanServer(); // Refresh findings
        } else {
            toast(d.message, 'error');
        }
    } catch (e) { toast(__('exception_with_msg', { msg: e }), 'error'); }
}

// ── Backups ─────────────────────────────────────────────────────────────────

async function loadBackups() {
    if (!_currentServer) { toast(__('audit_select_server'), 'warning'); return; }
    document.getElementById('backups-modal').classList.remove('hidden');
    const list = document.getElementById('backups-list');
    list.innerHTML = `<p class="text-sm text-gray-400">${escHtml(__('audit_loading_backups'))}</p>`;

    try {
        const d = await apiPost('/ssh-audit/backups', serverPayload());
        if (!d.success || !d.backups || d.backups.length === 0) {
            list.innerHTML = `<p class="text-sm text-gray-400">${escHtml(__('audit_no_backups'))}</p>`;
            return;
        }
        list.innerHTML = d.backups.map(b => `
            <div class="flex items-center justify-between px-3 py-2 rounded-lg bg-gray-50 dark:bg-gray-700/50 mb-2">
                <div>
                    <span class="text-sm font-mono text-gray-700 dark:text-gray-300">${escHtml(b.filename)}</span>
                    <span class="text-xs text-gray-400 ml-2">${escHtml(b.date)}</span>
                    <span class="text-xs text-gray-400 ml-2">${Math.round(b.size / 1024)} KB</span>
                </div>
                <button onclick="restoreBackup('${escAttr(b.filename)}')" class="text-xs px-2 py-1 rounded bg-amber-500 hover:bg-amber-600 text-white">${escHtml(__('audit_btn_restore'))}</button>
            </div>
        `).join('');
    } catch (e) { list.innerHTML = `<p class="text-sm text-red-400">Error</p>`; }
}

async function restoreBackup(backupName) {
    if (!_currentServer) return;
    if (!confirm(__('audit_restore_confirm', { name: backupName, server: _currentServer.name }))) return;

    try {
        const d = await apiPost('/ssh-audit/restore', { ...serverPayload(), backup_name: backupName });
        toast(d.success ? __('audit_restored') : d.message, d.success ? 'success' : 'error');
        appendLog(d.success ? __('audit_restored') : d.message);
        if (d.success) document.getElementById('backups-modal').classList.add('hidden');
    } catch (e) { toast(__('exception_with_msg', { msg: e }), 'error'); }
}

// ── Reload sshd ─────────────────────────────────────────────────────────────

async function reloadSshd() {
    if (!_currentServer) { toast(__('audit_select_server'), 'warning'); return; }
    if (!confirm(__('audit_reload_confirm', { server: _currentServer.name }))) return;

    appendLog(__('audit_reloading', { server: _currentServer.name }));
    try {
        const d = await apiPost('/ssh-audit/reload', serverPayload());
        if (d.success) {
            toast(__('audit_reloaded'), 'success');
            appendLog(__('audit_reloaded'));
            // Auto rescan after reload
            appendLog(__('audit_rescanning_after_reload'));
            scanServer();
        } else {
            toast(__('audit_reload_error', { msg: d.message }), 'error');
            appendLog(__('audit_reload_error', { msg: d.message }));
        }
    } catch (e) { toast(__('exception_with_msg', { msg: e }), 'error'); }
}
