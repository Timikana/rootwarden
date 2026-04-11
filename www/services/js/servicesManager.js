// servicesManager.js — Interactions JS pour la page Services systemd
const API = window.API_URL || '/api_proxy.php';
const PROTECTED_SERVICES = ['sshd', 'ssh', 'systemd-journald', 'systemd-logind', 'dbus', 'dbus-broker'];
let _currentServer = null;
let _allServices = [];
let _currentLogService = null;

// ── Helpers ──────────────────────────────────────────────────────────────────

function getServer() {
    const sel = document.getElementById('server');
    if (!sel || !sel.value) {
        toast(__('select_server'), 'warning');
        return null;
    }
    try { return JSON.parse(sel.value); }
    catch { toast(__('invalid_server'), 'error'); return null; }
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
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
}

// ── Charger les services ────────────────────────────────────────────────────

async function loadServices() {
    const srv = getServer();
    if (!srv) return;
    _currentServer = srv;

    clearLogs();
    appendLog(__('svc_loading', { server: srv.name }));

    try {
        const d = await apiPost('/services/list', serverPayload());
        if (!d.success) {
            appendLog(__('error_with_msg', { msg: d.message }));
            toast(__('error_with_msg', { msg: d.message }), 'error');
            return;
        }

        _allServices = (d.services || []).map(s => ({
            ...s,
            name: s.name.replace(/\.service$/, ''),
            enabled: s.unit_file_state || s.enabled || 'unknown',
        }));
        updateStats(_allServices);

        document.getElementById('stats-bar').classList.remove('hidden');
        document.getElementById('filters-row').classList.remove('hidden');
        document.getElementById('services-table-container').classList.remove('hidden');

        renderTable(_allServices);
        appendLog(__('svc_loaded', { count: _allServices.length, server: srv.name }));

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
        toast(__('exception_with_msg', { msg: e }), 'error');
    }
}

// ── Stats ───────────────────────────────────────────────────────────────────

function updateStats(services) {
    const total = services.length;
    const running = services.filter(s => s.active === 'active').length;
    const stopped = services.filter(s => s.active === 'inactive').length;
    const failed = services.filter(s => s.active === 'failed').length;

    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-running').textContent = running;
    document.getElementById('stat-stopped').textContent = stopped;
    document.getElementById('stat-failed').textContent = failed;
}

// ── Filtrage client ─────────────────────────────────────────────────────────

function filterServices() {
    const status = document.getElementById('filter-status').value;
    const category = document.getElementById('filter-category').value;
    const search = document.getElementById('filter-search').value.toLowerCase().trim();

    let filtered = _allServices;

    if (status) {
        filtered = filtered.filter(s => {
            if (status === 'running') return s.active === 'active';
            if (status === 'stopped') return s.active === 'inactive';
            if (status === 'failed') return s.active === 'failed';
            return true;
        });
    }

    if (category) {
        filtered = filtered.filter(s => s.category === category);
    }

    if (search) {
        filtered = filtered.filter(s =>
            (s.name || '').toLowerCase().includes(search) ||
            (s.description || '').toLowerCase().includes(search)
        );
    }

    renderTable(filtered);
}

// ── Rendu tableau ───────────────────────────────────────────────────────────

function renderTable(services) {
    const tbody = document.getElementById('services-tbody');
    const noMsg = document.getElementById('no-services-msg');

    if (!services || services.length === 0) {
        tbody.innerHTML = '';
        noMsg.classList.remove('hidden');
        return;
    }

    noMsg.classList.add('hidden');
    tbody.innerHTML = services.map(svc => `
        <tr class="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors">
            <td class="py-2 px-3 font-mono text-sm font-medium">${escHtml(svc.name)}</td>
            <td class="py-2 px-3">${statusBadge(svc.active, svc.sub)}</td>
            <td class="py-2 px-3">${enabledBadge(svc.enabled)}</td>
            <td class="py-2 px-3">${categoryBadge(svc.category)}</td>
            <td class="py-2 px-3 text-xs text-gray-500 dark:text-gray-400 max-w-xs truncate">${escHtml(svc.description || '-')}</td>
            <td class="py-2 px-3 text-right">${actionButtons(svc)}</td>
        </tr>
    `).join('');
}

// ── Badges ──────────────────────────────────────────────────────────────────

function statusBadge(active, sub) {
    const labels = {
        active:   { cls: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300', key: 'svc_status_running' },
        inactive: { cls: 'bg-gray-100 dark:bg-gray-600 text-gray-600 dark:text-gray-300', key: 'svc_status_stopped' },
        failed:   { cls: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300', key: 'svc_status_failed' },
        activating: { cls: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300', key: 'svc_status_activating' },
    };
    const l = labels[active] || labels.inactive;
    return `<span class="px-2 py-0.5 rounded-full text-xs font-bold ${l.cls}">${escHtml(__(l.key))}</span>`;
}

function enabledBadge(enabled) {
    if (enabled === 'enabled') {
        return `<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300">${__('svc_enabled_yes')}</span>`;
    }
    return `<span class="px-2 py-0.5 rounded-full text-xs font-bold bg-gray-100 dark:bg-gray-600 text-gray-500 dark:text-gray-400">${__('svc_enabled_no')}</span>`;
}

function categoryBadge(category) {
    const colors = {
        web:        'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300',
        database:   'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300',
        mail:       'bg-pink-100 dark:bg-pink-900/30 text-pink-700 dark:text-pink-300',
        security:   'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
        network:    'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300',
        system:     'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300',
        monitoring: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300',
        ssh:        'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300',
        containers: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300',
        ftp:        'bg-teal-100 dark:bg-teal-900/30 text-teal-700 dark:text-teal-300',
        other:      'bg-gray-100 dark:bg-gray-600 text-gray-600 dark:text-gray-300',
    };
    const cls = colors[category] || colors.other;
    const catKey = 'svc_cat_' + (category || 'other');
    const label = __(catKey);
    return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${escHtml(label)}</span>`;
}

function actionButtons(svc) {
    const name = escAttr(svc.name);
    const disabled = svc.protected ? 'disabled title="' + escAttr(__('svc_protected')) + '"' : '';
    const disabledCls = svc.protected ? 'opacity-50 cursor-not-allowed' : '';

    let html = `<div class="flex items-center justify-end gap-1 flex-wrap">`;

    // Detail button (always available)
    html += `<button onclick="viewDetail('${name}')" class="text-xs px-2 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white transition-colors">${__('svc_btn_detail')}</button>`;

    // Logs button (always available)
    html += `<button onclick="viewLogs('${name}')" class="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">${__('svc_btn_logs')}</button>`;

    // Start/Stop/Restart
    if (svc.active === 'active') {
        html += `<button onclick="stopService('${name}')" ${disabled} class="text-xs px-2 py-1 rounded bg-red-600 hover:bg-red-700 text-white transition-colors ${disabledCls}">${__('svc_btn_stop')}</button>`;
        html += `<button onclick="restartService('${name}')" ${disabled} class="text-xs px-2 py-1 rounded bg-amber-500 hover:bg-amber-600 text-white transition-colors ${disabledCls}">${__('svc_btn_restart')}</button>`;
    } else {
        html += `<button onclick="startService('${name}')" ${disabled} class="text-xs px-2 py-1 rounded bg-green-600 hover:bg-green-700 text-white transition-colors ${disabledCls}">${__('svc_btn_start')}</button>`;
    }

    // Enable/Disable boot
    if (svc.enabled === 'enabled') {
        html += `<button onclick="disableService('${name}')" ${disabled} class="text-xs px-2 py-1 rounded border border-orange-400 text-orange-600 dark:text-orange-400 hover:bg-orange-50 dark:hover:bg-orange-900/20 transition-colors ${disabledCls}" title="${escAttr(__('svc_btn_disable'))}">${__('svc_btn_disable')}</button>`;
    } else if (svc.enabled !== 'static' && svc.enabled !== 'masked') {
        html += `<button onclick="enableService('${name}')" ${disabled} class="text-xs px-2 py-1 rounded border border-green-400 text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900/20 transition-colors ${disabledCls}" title="${escAttr(__('svc_btn_enable'))}">${__('svc_btn_enable')}</button>`;
    }

    html += `</div>`;
    return html;
}

// ── Actions : Start / Stop / Restart ────────────────────────────────────────

async function startService(name) {
    if (!_currentServer) return;
    if (!confirm(__('svc_confirm_start', { name: name, server: _currentServer.name }))) return;

    appendLog(__('svc_starting', { name }));
    try {
        const d = await apiPost('/services/start', serverPayload({ service: name }));
        appendLog(d.success ? __('svc_started', { name }) : __('error_with_msg', { msg: d.message }));
        toast(d.success ? __('svc_started', { name }) : d.message, d.success ? 'success' : 'error');
        if (d.success) loadServices();
    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

async function stopService(name) {
    if (!_currentServer) return;
    if (!confirm(__('svc_confirm_stop', { name: name, server: _currentServer.name }))) return;

    appendLog(__('svc_stopping', { name }));
    try {
        const d = await apiPost('/services/stop', serverPayload({ service: name }));
        appendLog(d.success ? __('svc_stopped', { name }) : __('error_with_msg', { msg: d.message }));
        toast(d.success ? __('svc_stopped', { name }) : d.message, d.success ? 'success' : 'error');
        if (d.success) loadServices();
    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

async function restartService(name) {
    if (!_currentServer) return;
    if (!confirm(__('svc_confirm_restart', { name: name, server: _currentServer.name }))) return;

    appendLog(__('svc_restarting', { name }));
    try {
        const d = await apiPost('/services/restart', serverPayload({ service: name }));
        appendLog(d.success ? __('svc_restarted', { name }) : __('error_with_msg', { msg: d.message }));
        toast(d.success ? __('svc_restarted', { name }) : d.message, d.success ? 'success' : 'error');
        if (d.success) loadServices();
    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

// ── Actions : Enable / Disable ──────────────────────────────────────────────

async function enableService(name) {
    if (!_currentServer) return;
    if (!confirm(__('svc_confirm_enable', { name: name, server: _currentServer.name }))) return;

    appendLog(__('svc_enabling', { name }));
    try {
        const d = await apiPost('/services/enable', serverPayload({ service: name }));
        appendLog(d.success ? __('svc_enabled_msg', { name }) : __('error_with_msg', { msg: d.message }));
        toast(d.success ? __('svc_enabled_msg', { name }) : d.message, d.success ? 'success' : 'error');
        if (d.success) loadServices();
    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

async function disableService(name) {
    if (!_currentServer) return;
    if (!confirm(__('svc_confirm_disable', { name: name, server: _currentServer.name }))) return;

    appendLog(__('svc_disabling', { name }));
    try {
        const d = await apiPost('/services/disable', serverPayload({ service: name }));
        appendLog(d.success ? __('svc_disabled_msg', { name }) : __('error_with_msg', { msg: d.message }));
        toast(d.success ? __('svc_disabled_msg', { name }) : d.message, d.success ? 'success' : 'error');
        if (d.success) loadServices();
    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

// ── Detail modal ────────────────────────────────────────────────────────────

async function viewDetail(name) {
    if (!_currentServer) return;

    appendLog(__('svc_loading_detail', { name }));
    try {
        const d = await apiPost('/services/status', serverPayload({ service: name }));
        if (!d.success) {
            appendLog(__('error_with_msg', { msg: d.message }));
            toast(d.message, 'error');
            return;
        }

        // Backend returns properties at root level (ActiveState, MainPID, etc.)
        const pid = d.MainPID || d.pid || '-';
        const mem = d.MemoryCurrent ? (parseInt(d.MemoryCurrent) / 1024 / 1024).toFixed(1) + ' MB' : '-';
        const uptime = d.ExecMainStartTimestamp || d.uptime || '-';
        const desc = d.Description || d.description || '-';
        const activeState = d.ActiveState || d.active || 'unknown';
        const subState = d.SubState || d.sub || '';

        document.getElementById('detail-name').textContent = name;
        document.getElementById('detail-pid').textContent = pid;
        document.getElementById('detail-memory').textContent = mem;
        document.getElementById('detail-uptime').textContent = uptime;
        document.getElementById('detail-description').textContent = desc;

        const statusEl = document.getElementById('detail-status');
        statusEl.innerHTML = statusBadge(activeState, subState);

        // Action buttons in detail modal
        const actionsEl = document.getElementById('detail-actions');
        const isProtected = PROTECTED_SERVICES && PROTECTED_SERVICES.includes(name);
        const disabled = isProtected ? 'disabled' : '';
        const disabledCls = isProtected ? 'opacity-50 cursor-not-allowed' : '';
        const eName = escAttr(name);

        let actHtml = '';
        if (activeState === 'active') {
            actHtml += `<button onclick="stopService('${eName}');closeDetailModal()" ${disabled} class="px-4 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors ${disabledCls}">${__('svc_btn_stop')}</button>`;
            actHtml += `<button onclick="restartService('${eName}');closeDetailModal()" ${disabled} class="px-4 py-2 text-sm bg-amber-500 hover:bg-amber-600 text-white rounded-lg font-medium transition-colors ${disabledCls}">${__('svc_btn_restart')}</button>`;
        } else {
            actHtml += `<button onclick="startService('${eName}');closeDetailModal()" ${disabled} class="px-4 py-2 text-sm bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition-colors ${disabledCls}">${__('svc_btn_start')}</button>`;
        }
        actHtml += `<button onclick="viewLogs('${eName}');closeDetailModal()" class="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-colors">${__('svc_btn_logs')}</button>`;
        actionsEl.innerHTML = actHtml;

        document.getElementById('detail-modal').classList.remove('hidden');
        appendLog(__('svc_detail_loaded', { name }));

    } catch (e) {
        appendLog(__('exception_with_msg', { msg: e }));
    }
}

function closeDetailModal() {
    document.getElementById('detail-modal').classList.add('hidden');
}

// ── Logs modal ──────────────────────────────────────────────────────────────

async function viewLogs(name) {
    if (!_currentServer) return;
    _currentLogService = name;

    document.getElementById('logs-service-name').textContent = name;
    document.getElementById('logs-content').textContent = __('svc_loading_logs');
    document.getElementById('logs-modal').classList.remove('hidden');

    await fetchLogs(name);
}

async function fetchLogs(name) {
    const lines = parseInt(document.getElementById('logs-lines').value) || 100;

    appendLog(__('svc_fetching_logs', { name, lines }));
    try {
        const d = await apiPost('/services/logs', serverPayload({ service: name, lines }));
        if (!d.success) {
            document.getElementById('logs-content').textContent = __('error_with_msg', { msg: d.message });
            return;
        }
        document.getElementById('logs-content').textContent = d.logs || __('svc_no_logs');
        appendLog(__('svc_logs_loaded', { name }));
    } catch (e) {
        document.getElementById('logs-content').textContent = __('exception_with_msg', { msg: e });
    }
}

function refreshLogs() {
    if (_currentLogService) {
        fetchLogs(_currentLogService);
    }
}

function closeLogsModal() {
    document.getElementById('logs-modal').classList.add('hidden');
    _currentLogService = null;
}

// ── Utilitaires XSS-safe ────────────────────────────────────────────────────

function escAttr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/'/g, '&#39;')
                     .replace(/"/g, '&quot;').replace(/</g, '&lt;')
                     .replace(/>/g, '&gt;').replace(/\\/g, '\\\\');
}
