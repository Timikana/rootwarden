/**
 * graylog.js — Frontend module Graylog.
 * Maintenu : Equipe Admin.Sys RootWarden — v1.15.0
 */
const API = window.API_URL || '/api_proxy.php';

function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
function escAttr(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\\/g, '&#92;'); }
function __(k) { return (window._i18n && window._i18n[k]) || k; }

function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

async function apiFetch(path, opts = {}) {
    const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-TOKEN'] = csrf;
    const res = await fetch(`${API}${path}`, Object.assign({ headers }, opts));
    const text = await res.text();
    try { return JSON.parse(text); }
    catch { return { success: false, message: text || `HTTP ${res.status}` }; }
}

// ── Config ────────────────────────────────────────────────────

async function glLoadConfig() {
    const r = await apiFetch('/graylog/config');
    if (!r.success || !r.config) return;
    const c = r.config;
    document.getElementById('gl-server-url').value = c.server_url || '';
    document.getElementById('gl-sidecar-version').value = c.sidecar_version || 'latest';
    document.getElementById('gl-tls-verify').checked = c.tls_verify !== false;
    const ts = document.getElementById('gl-token-status');
    if (ts) ts.textContent = c.api_token_set ? ('(' + __('graylog.token_set') + ')') : ('(' + __('graylog.token_not_set') + ')');
}

async function glSaveConfig() {
    const body = {
        server_url: document.getElementById('gl-server-url').value.trim(),
        sidecar_version: document.getElementById('gl-sidecar-version').value.trim(),
        tls_verify: document.getElementById('gl-tls-verify').checked,
        api_token: document.getElementById('gl-api-token').value,
    };
    const status = document.getElementById('gl-config-status');
    status.textContent = __('graylog.saving');
    const r = await apiFetch('/graylog/config', { method: 'POST', body: JSON.stringify(body) });
    status.textContent = r.success ? ('✓ ' + __('graylog.saved')) : ('✗ ' + escHtml(r.message || 'Erreur'));
    if (r.success) {
        document.getElementById('gl-api-token').value = '';
        glLoadConfig();
    }
}

// ── Servers / sidecar ────────────────────────────────────────

async function glLoadServers() {
    const c = document.getElementById('gl-servers-container');
    c.innerHTML = `<div class="text-sm text-gray-500 text-center py-6">${escHtml(__('graylog.loading'))}</div>`;
    const r = await apiFetch('/graylog/servers');
    if (!r.success) { c.innerHTML = `<div class="text-sm text-red-500 py-6">${escHtml(r.message || 'Erreur')}</div>`; return; }
    if (!r.servers.length) { c.innerHTML = `<div class="text-sm text-gray-500 py-6">${escHtml(__('graylog.no_servers'))}</div>`; return; }
    let html = '<table class="w-full text-sm"><thead class="bg-gray-50 dark:bg-gray-700/50"><tr>' +
        '<th class="text-left px-3 py-2">Name</th><th class="text-left px-3 py-2">IP</th>' +
        `<th class="text-left px-3 py-2">${escHtml(__('graylog.col_status'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('graylog.col_version'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('graylog.col_actions'))}</th></tr></thead><tbody class="divide-y divide-gray-100 dark:divide-gray-700">`;
    for (const s of r.servers) {
        const badge = ({
            running: `<span class="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">${escHtml(__('graylog.status_running'))}</span>`,
            stopped: `<span class="text-[10px] px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40">${escHtml(__('graylog.status_stopped'))}</span>`,
            never_registered: `<span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-700">${escHtml(__('graylog.status_never'))}</span>`,
        })[s.status] || `<span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">${escHtml(s.status || '—')}</span>`;
        html += `<tr>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.name)}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.ip)}</td>
            <td class="px-3 py-2">${badge}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.version || '—')}</td>
            <td class="px-3 py-2 whitespace-nowrap">
                <button onclick="glInstall(${s.id})" class="text-xs text-blue-500 hover:text-blue-700">${escHtml(__('graylog.btn_install'))}</button>
                <button onclick="glRegister(${s.id})" class="text-xs text-green-500 hover:text-green-700 ml-2">${escHtml(__('graylog.btn_register'))}</button>
                <button onclick="glUninstall(${s.id})" class="text-xs text-red-500 hover:text-red-700 ml-2">${escHtml(__('graylog.btn_uninstall'))}</button>
            </td>
        </tr>`;
    }
    html += '</tbody></table>';
    c.innerHTML = html;
}

async function glInstall(machineId) {
    if (!confirm(__('graylog.confirm_install'))) return;
    const r = await apiFetch('/graylog/install', { method: 'POST', body: JSON.stringify({ machine_id: machineId, collector: 'filebeat' }) });
    alert((r.message || (r.success ? 'OK' : 'Echec')) + (r.version ? ' — v' + r.version : ''));
    glLoadServers();
}

async function glUninstall(machineId) {
    if (!confirm(__('graylog.confirm_uninstall'))) return;
    const r = await apiFetch('/graylog/uninstall', { method: 'POST', body: JSON.stringify({ machine_id: machineId }) });
    alert(r.message || (r.success ? 'OK' : 'Echec'));
    glLoadServers();
}

async function glRegister(machineId) {
    const r = await apiFetch('/graylog/register', { method: 'POST', body: JSON.stringify({ machine_id: machineId }) });
    alert('status=' + (r.status || '—'));
    glLoadServers();
}

// ── Collectors ────────────────────────────────────────────────

let _glCurrentCollector = null;

async function glLoadCollectors() {
    const list = document.getElementById('gl-collectors-list');
    if (!list) return;
    const r = await apiFetch('/graylog/collectors');
    if (!r.success) { list.innerHTML = `<div class="text-xs text-red-500 p-2">${escHtml(r.message || 'Erreur')}</div>`; return; }
    if (!r.collectors.length) { list.innerHTML = `<div class="text-xs text-gray-400 text-center py-3">—</div>`; return; }
    list.innerHTML = r.collectors.map(c => `
        <div class="flex items-center justify-between px-2 py-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700/40 cursor-pointer text-xs"
             onclick="glSelectCollector('${escAttr(c.name)}')">
            <div class="flex items-center gap-2 min-w-0">
                <span class="font-medium truncate">${escHtml(c.name)}</span>
                <span class="text-[10px] px-1 py-0.5 rounded bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">${escHtml(c.collector_type)}</span>
            </div>
            <span class="text-[10px] text-gray-400 mono">${c.bytes}o</span>
        </div>`).join('');
}

async function glSelectCollector(name) {
    const r = await apiFetch('/graylog/collectors/' + encodeURIComponent(name));
    if (!r.success) { alert(r.message); return; }
    _glCurrentCollector = name;
    document.getElementById('gl-col-name').value = r.collector.name;
    document.getElementById('gl-col-type').value = r.collector.collector_type;
    document.getElementById('gl-col-tags').value = r.collector.tags || '';
    document.getElementById('gl-col-editor').value = r.collector.content || '';
    document.getElementById('gl-col-status').textContent = `sha=${r.collector ? '' : ''} bytes=${(r.collector.content || '').length}`;
}

function glNewCollector() {
    _glCurrentCollector = null;
    document.getElementById('gl-col-name').value = '';
    document.getElementById('gl-col-type').value = 'filebeat';
    document.getElementById('gl-col-tags').value = '';
    document.getElementById('gl-col-editor').value = '';
    document.getElementById('gl-col-status').textContent = '';
}

async function glSaveCollector() {
    const body = {
        name: document.getElementById('gl-col-name').value.trim(),
        collector_type: document.getElementById('gl-col-type').value,
        content: document.getElementById('gl-col-editor').value,
        tags: document.getElementById('gl-col-tags').value.trim(),
    };
    const status = document.getElementById('gl-col-status');
    status.textContent = __('graylog.saving');
    const r = await apiFetch('/graylog/collectors', { method: 'POST', body: JSON.stringify(body) });
    if (!r.success) { status.textContent = '✗ ' + escHtml(r.message || 'Erreur'); return; }
    status.textContent = `✓ ${__('graylog.saved')} — sha=${r.sha8} ${r.bytes}o`;
    _glCurrentCollector = body.name;
    glLoadCollectors();
}

async function glDeleteCollector() {
    const name = document.getElementById('gl-col-name').value.trim();
    if (!name) return;
    if (!confirm(__('graylog.confirm_delete_collector') + '\n\n' + name)) return;
    const r = await apiFetch('/graylog/collectors/' + encodeURIComponent(name), { method: 'DELETE' });
    alert(r.success ? 'OK' : (r.message || 'Echec'));
    if (r.success) { glNewCollector(); glLoadCollectors(); }
}

// Auto-init onglets
document.addEventListener('DOMContentLoaded', () => {
    glLoadConfig();
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (!btn) return;
        if (btn.dataset.tab === 'deploy') glLoadServers();
        if (btn.dataset.tab === 'collectors') glLoadCollectors();
    });
});
