/**
 * graylog.js — Frontend module Graylog (rsyslog forwarding).
 * Maintenu : Equipe Admin.Sys RootWarden — v1.15.0
 */
const API = window.API_URL || '/api_proxy.php';

function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
function escAttr(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\\/g, '&#92;'); }
function __(k) { return (window._i18n && window._i18n[k]) || k; }

function getCsrfToken() { const m = document.querySelector('meta[name="csrf-token"]'); return m ? m.getAttribute('content') : ''; }

async function apiFetch(path, opts = {}) {
    const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    const csrf = getCsrfToken();
    if (csrf) headers['X-CSRF-TOKEN'] = csrf;
    const res = await fetch(`${API}${path}`, Object.assign({ headers }, opts));
    const text = await res.text();
    try { return JSON.parse(text); } catch { return { success: false, message: text || `HTTP ${res.status}` }; }
}

// ── Config ─────────────────────────────────────

async function glLoadConfig() {
    const r = await apiFetch('/graylog/config');
    if (!r.success || !r.config) return;
    const c = r.config;
    document.getElementById('gl-host').value = c.server_host || '';
    document.getElementById('gl-port').value = c.server_port || 514;
    document.getElementById('gl-proto').value = c.protocol || 'udp';
    document.getElementById('gl-tls-ca').value = c.tls_ca_path || '';
    document.getElementById('gl-rl-burst').value = c.ratelimit_burst || 0;
    document.getElementById('gl-rl-interval').value = c.ratelimit_interval || 0;
}

async function glSaveConfig() {
    const body = {
        server_host: document.getElementById('gl-host').value.trim(),
        server_port: parseInt(document.getElementById('gl-port').value, 10) || 514,
        protocol: document.getElementById('gl-proto').value,
        tls_ca_path: document.getElementById('gl-tls-ca').value.trim(),
        ratelimit_burst: parseInt(document.getElementById('gl-rl-burst').value, 10) || 0,
        ratelimit_interval: parseInt(document.getElementById('gl-rl-interval').value, 10) || 0,
    };
    const status = document.getElementById('gl-config-status');
    status.textContent = __('graylog.saving');
    const r = await apiFetch('/graylog/config', { method: 'POST', body: JSON.stringify(body) });
    status.textContent = r.success ? ('✓ ' + __('graylog.saved')) : ('✗ ' + escHtml(r.message || 'Erreur'));
    if (r.success) glLoadConfig();
}

// ── Servers ────────────────────────────────────

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
        `<th class="text-left px-3 py-2">${escHtml(__('graylog.col_last_deploy'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('graylog.col_actions'))}</th></tr></thead><tbody class="divide-y divide-gray-100 dark:divide-gray-700">`;
    for (const s of r.servers) {
        const badge = s.forward_deployed
            ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/40">${escHtml(__('graylog.status_forwarding'))}</span>`
            : `<span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-700">${escHtml(__('graylog.status_not_deployed'))}</span>`;
        html += `<tr>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.name)}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.ip)}</td>
            <td class="px-3 py-2">${badge}</td>
            <td class="px-3 py-2 mono text-[11px]">${escHtml(s.rsyslog_version || '—')}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.last_deploy_at || '—')}</td>
            <td class="px-3 py-2 whitespace-nowrap">
                <button onclick="glDeploy(${s.id})" class="text-xs text-blue-500 hover:text-blue-700">${escHtml(__('graylog.btn_deploy'))}</button>
                <button onclick="glTest(${s.id})" class="text-xs text-green-500 hover:text-green-700 ml-2">${escHtml(__('graylog.btn_test'))}</button>
                <button onclick="glUninstall(${s.id})" class="text-xs text-red-500 hover:text-red-700 ml-2">${escHtml(__('graylog.btn_uninstall'))}</button>
            </td>
        </tr>`;
    }
    html += '</tbody></table>';
    c.innerHTML = html;
}

async function glDeploy(mid) {
    if (!confirm(__('graylog.confirm_deploy'))) return;
    const r = await apiFetch('/graylog/deploy', { method: 'POST', body: JSON.stringify({ machine_id: mid }) });
    const parts = [];
    if (r.rsyslog_version) parts.push('rsyslog=' + r.rsyslog_version);
    if (r.templates_pushed) parts.push('templates=' + r.templates_pushed.length);
    if (r.syntax_ok !== undefined) parts.push('syntax=' + (r.syntax_ok ? 'OK' : 'KO'));
    if (r.restart_ok !== undefined) parts.push('restart=' + (r.restart_ok ? 'OK' : 'KO'));
    alert((r.success ? '✓ OK' : '✗ Echec') + '\n\n' + parts.join('  ') + (r.stderr ? '\n\n' + r.stderr : ''));
    glLoadServers();
}

async function glTest(mid) {
    const r = await apiFetch('/graylog/test', { method: 'POST', body: JSON.stringify({ machine_id: mid }) });
    alert((r.success ? '✓ ' : '✗ ') + __('graylog.test_sent') + '\n\ntag=' + (r.tag || '—') + '\n\n' + (r.hint || r.message || ''));
}

async function glUninstall(mid) {
    if (!confirm(__('graylog.confirm_uninstall'))) return;
    const r = await apiFetch('/graylog/uninstall', { method: 'POST', body: JSON.stringify({ machine_id: mid }) });
    alert(r.success ? 'OK' : (r.message || 'Echec'));
    glLoadServers();
}

// ── Templates ──────────────────────────────────

async function glLoadTemplates() {
    const list = document.getElementById('gl-templates-list');
    const r = await apiFetch('/graylog/templates');
    if (!r.success) { list.innerHTML = `<div class="text-xs text-red-500 p-2">${escHtml(r.message || 'Erreur')}</div>`; return; }
    if (!r.templates.length) { list.innerHTML = `<div class="text-xs text-gray-400 text-center py-3">—</div>`; return; }
    list.innerHTML = r.templates.map(t => `
        <div class="flex items-center justify-between px-2 py-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700/40 cursor-pointer text-xs"
             onclick="glSelectTemplate('${escAttr(t.name)}')">
            <div class="flex items-center gap-2 min-w-0">
                <span class="font-medium truncate">${escHtml(t.name)}</span>
                ${t.enabled
                    ? `<span class="text-[10px] px-1 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/40">${escHtml(__('graylog.enabled'))}</span>`
                    : `<span class="text-[10px] px-1 py-0.5 rounded bg-gray-100 text-gray-500 dark:bg-gray-700">${escHtml(__('graylog.disabled'))}</span>`}
            </div>
            <span class="text-[10px] text-gray-400 mono">${t.bytes}o</span>
        </div>`).join('');
}

async function glSelectTemplate(name) {
    const r = await apiFetch('/graylog/templates/' + encodeURIComponent(name));
    if (!r.success) { alert(r.message); return; }
    document.getElementById('gl-tpl-name').value = r.template.name;
    document.getElementById('gl-tpl-description').value = r.template.description || '';
    document.getElementById('gl-tpl-enabled').checked = !!r.template.enabled;
    document.getElementById('gl-tpl-editor').value = r.template.content || '';
    document.getElementById('gl-tpl-status').textContent = `bytes=${(r.template.content || '').length}`;
}

function glNewTemplate() {
    document.getElementById('gl-tpl-name').value = '';
    document.getElementById('gl-tpl-description').value = '';
    document.getElementById('gl-tpl-enabled').checked = false;
    document.getElementById('gl-tpl-editor').value = '';
    document.getElementById('gl-tpl-status').textContent = '';
}

async function glSaveTemplate() {
    const body = {
        name: document.getElementById('gl-tpl-name').value.trim(),
        description: document.getElementById('gl-tpl-description').value.trim(),
        content: document.getElementById('gl-tpl-editor').value,
        enabled: document.getElementById('gl-tpl-enabled').checked,
    };
    const status = document.getElementById('gl-tpl-status');
    status.textContent = __('graylog.saving');
    const r = await apiFetch('/graylog/templates', { method: 'POST', body: JSON.stringify(body) });
    if (!r.success) { status.textContent = '✗ ' + escHtml(r.message || 'Erreur'); return; }
    status.textContent = `✓ ${__('graylog.saved')} — sha=${r.sha8} ${r.bytes}o`;
    glLoadTemplates();
}

async function glDeleteTemplate() {
    const name = document.getElementById('gl-tpl-name').value.trim();
    if (!name) return;
    if (!confirm(__('graylog.confirm_delete_template') + '\n\n' + name)) return;
    const r = await apiFetch('/graylog/templates/' + encodeURIComponent(name), { method: 'DELETE' });
    alert(r.success ? 'OK' : (r.message || 'Echec'));
    if (r.success) { glNewTemplate(); glLoadTemplates(); }
}

document.addEventListener('DOMContentLoaded', () => {
    glLoadConfig();
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (!btn) return;
        if (btn.dataset.tab === 'deploy') glLoadServers();
        if (btn.dataset.tab === 'templates') glLoadTemplates();
    });
});
