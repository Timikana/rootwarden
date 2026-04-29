/**
 * wazuh.js - Frontend module Wazuh.
 * Maintenu : Equipe Admin.Sys RootWarden - v1.15.0
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
    const t = await res.text();
    try { return JSON.parse(t); } catch { return { success: false, message: t || `HTTP ${res.status}` }; }
}

// ── Config ──────────────────────────────────────────

async function wzLoadConfig() {
    const r = await apiFetch('/wazuh/config');
    if (!r.success || !r.config) return;
    const c = r.config;
    document.getElementById('wz-manager-ip').value = c.manager_ip || '';
    document.getElementById('wz-manager-port').value = c.manager_port || 1514;
    document.getElementById('wz-registration-port').value = c.registration_port || 1515;
    document.getElementById('wz-default-group').value = c.default_group || 'default';
    document.getElementById('wz-agent-version').value = c.agent_version || 'latest';
    document.getElementById('wz-enable-ar').checked = !!c.enable_active_response;
    document.getElementById('wz-api-url').value = c.api_url || '';
    document.getElementById('wz-api-user').value = c.api_user || '';
    const sRp = document.getElementById('wz-reg-pwd-status');
    if (sRp) sRp.textContent = c.registration_password_set ? ('(' + __('wazuh.pwd_set') + ')') : ('(' + __('wazuh.pwd_not_set') + ')');
    const sAp = document.getElementById('wz-api-pwd-status');
    if (sAp) sAp.textContent = c.api_password_set ? ('(' + __('wazuh.pwd_set') + ')') : ('(' + __('wazuh.pwd_not_set') + ')');
}

async function wzSaveConfig() {
    const body = {
        manager_ip: document.getElementById('wz-manager-ip').value.trim(),
        manager_port: parseInt(document.getElementById('wz-manager-port').value, 10),
        registration_port: parseInt(document.getElementById('wz-registration-port').value, 10),
        registration_password: document.getElementById('wz-reg-pwd').value,
        default_group: document.getElementById('wz-default-group').value.trim(),
        agent_version: document.getElementById('wz-agent-version').value.trim(),
        enable_active_response: document.getElementById('wz-enable-ar').checked,
        api_url: document.getElementById('wz-api-url').value.trim(),
        api_user: document.getElementById('wz-api-user').value.trim(),
        api_password: document.getElementById('wz-api-pwd').value,
    };
    const status = document.getElementById('wz-config-status');
    status.textContent = __('wazuh.saving');
    const r = await apiFetch('/wazuh/config', { method: 'POST', body: JSON.stringify(body) });
    status.textContent = r.success ? ('✓ ' + __('wazuh.saved')) : ('✗ ' + escHtml(r.message || 'Erreur'));
    if (r.success) {
        document.getElementById('wz-reg-pwd').value = '';
        document.getElementById('wz-api-pwd').value = '';
        wzLoadConfig();
    }
}

// ── Servers ────────────────────────────────────────

async function wzLoadServers() {
    const c = document.getElementById('wz-servers-container');
    c.innerHTML = `<div class="text-sm text-gray-500 text-center py-6">${escHtml(__('wazuh.loading'))}</div>`;
    const r = await apiFetch('/wazuh/servers');
    if (!r.success) { c.innerHTML = `<div class="text-sm text-red-500 py-6">${escHtml(r.message || 'Erreur')}</div>`; return; }
    if (!r.servers.length) { c.innerHTML = `<div class="text-sm text-gray-500 py-6">${escHtml(__('wazuh.no_servers'))}</div>`; return; }

    // Compteur serveurs sans agent (pour le bouton Installer tout)
    const noAgent = r.servers.filter(s => !s.agent_id).length;
    const installAllBtn = noAgent > 0
        ? `<div class="mb-3 flex items-center justify-end">
             <button onclick="wzInstallAll()" class="text-xs px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium">
               ${escHtml(__('wazuh.btn_install_all'))} (${noAgent})
             </button>
           </div>`
        : '';

    let html = installAllBtn + '<table class="w-full text-sm"><thead class="bg-gray-50 dark:bg-gray-700/50"><tr>' +
        '<th class="text-left px-3 py-2">Name</th><th class="text-left px-3 py-2">IP</th>' +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_network'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_criticality'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_environment'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_agent_id'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_status'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_version'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_group'))}</th>` +
        `<th class="text-left px-3 py-2">${escHtml(__('wazuh.col_actions'))}</th></tr></thead><tbody class="divide-y divide-gray-100 dark:divide-gray-700">`;
    const badges = {
        active:       ['green', 'status_active'],
        disconnected: ['red',   'status_disconnected'],
        never_connected: ['gray','status_never'],
        pending:      ['yellow','status_pending'],
        unknown:      ['gray',  'status_unknown'],
    };
    for (const s of r.servers) {
        const b = badges[s.status] || ['gray', 'status_unknown'];
        const badge = `<span class="text-[10px] px-1.5 py-0.5 rounded bg-${b[0]}-100 text-${b[0]}-700 dark:bg-${b[0]}-900/40">${escHtml(__('wazuh.' + b[1]))}</span>`;
        // Badges réseau, criticité, environment
        const netBadge = s.network_type === 'EXTERNE'
            ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/40">${escHtml(s.network_type)}</span>`
            : `<span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">${escHtml(s.network_type || '-')}</span>`;
        const critBadge = s.criticality === 'CRITIQUE'
            ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/40 font-bold">${escHtml(s.criticality)}</span>`
            : `<span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400">${escHtml(s.criticality || '-')}</span>`;
        const envBadge = s.environment
            ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 dark:bg-blue-900/40">${escHtml(s.environment)}</span>`
            : '<span class="text-[10px] text-gray-400">-</span>';
        html += `<tr>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.name)}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.ip)}</td>
            <td class="px-3 py-2">${netBadge}</td>
            <td class="px-3 py-2">${critBadge}</td>
            <td class="px-3 py-2">${envBadge}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.agent_id || '-')}</td>
            <td class="px-3 py-2">${badge}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.version || '-')}</td>
            <td class="px-3 py-2 mono text-xs">${escHtml(s.group_name || '-')}</td>
            <td class="px-3 py-2 whitespace-nowrap">
                <button onclick="wzInstall(${s.id})" class="text-xs text-blue-500 hover:text-blue-700">${escHtml(__('wazuh.btn_install'))}</button>
                <button onclick="wzDetect(${s.id})" class="text-xs text-cyan-600 hover:text-cyan-800 ml-2" title="${escHtml(__('wazuh.btn_detect_tip'))}">${escHtml(__('wazuh.btn_detect'))}</button>
                <button onclick="wzRestart(${s.id})" class="text-xs text-green-500 hover:text-green-700 ml-2">${escHtml(__('wazuh.btn_restart'))}</button>
                <button onclick="wzSetGroup(${s.id})" class="text-xs text-purple-500 hover:text-purple-700 ml-2">${escHtml(__('wazuh.btn_setgroup'))}</button>
                <button onclick="wzUninstall(${s.id})" class="text-xs text-red-500 hover:text-red-700 ml-2">${escHtml(__('wazuh.btn_uninstall'))}</button>
            </td>
        </tr>`;
    }
    html += '</tbody></table>';
    c.innerHTML = html;
}

async function wzInstall(mid) {
    if (!confirm(__('wazuh.confirm_install'))) return;
    const r = await apiFetch('/wazuh/install', { method: 'POST', body: JSON.stringify({ machine_id: mid }) });
    alert((r.message || (r.success ? 'OK' : 'Echec')) + (r.agent_id ? ` (agent_id=${r.agent_id})` : ''));
    wzLoadServers();
}

async function wzInstallAll() {
    if (!confirm(__('wazuh.confirm_install_all'))) return;
    // Indicateur visuel pendant le run (peut etre long sur N serveurs)
    const c = document.getElementById('wz-servers-container');
    const loadingHtml = `<div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 rounded-lg p-4 my-3 text-sm flex items-center gap-2">
        <svg class="w-4 h-4 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" stroke-width="3" stroke-dasharray="60" stroke-dashoffset="20"/></svg>
        ${escHtml(__('wazuh.installing_all'))}
    </div>` + c.innerHTML;
    c.innerHTML = loadingHtml;

    const r = await apiFetch('/wazuh/install_all', { method: 'POST', body: JSON.stringify({}) });
    let summary = r.message || (r.success ? 'OK' : 'Echec');
    if (r.details && r.details.length) {
        const fails = r.details.filter(d => !d.success);
        if (fails.length) {
            summary += '\n\n' + __('wazuh.install_all_failures') + ':\n' +
                fails.map(f => `- ${f.name}: ${(f.message || '').slice(0, 100)}`).join('\n');
        }
    }
    alert(summary);
    wzLoadServers();
}

async function wzDetect(mid) {
    const r = await apiFetch('/wazuh/detect', { method: 'POST', body: JSON.stringify({ machine_id: mid }) });
    alert(r.message || (r.success ? 'Agent detecte' : 'Aucun agent'));
    wzLoadServers();
}

async function wzUninstall(mid) {
    if (!confirm(__('wazuh.confirm_uninstall'))) return;
    const r = await apiFetch('/wazuh/uninstall', { method: 'POST', body: JSON.stringify({ machine_id: mid }) });
    alert(r.success ? 'OK' : (r.message || 'Echec'));
    wzLoadServers();
}

async function wzRestart(mid) {
    if (!confirm(__('wazuh.confirm_restart'))) return;
    const r = await apiFetch('/wazuh/restart', { method: 'POST', body: JSON.stringify({ machine_id: mid }) });
    alert(r.success ? 'OK' : (r.message || 'Echec'));
}

async function wzSetGroup(mid) {
    const group = prompt(__('wazuh.prompt_group'));
    if (!group) return;
    const r = await apiFetch('/wazuh/group', { method: 'POST', body: JSON.stringify({ machine_id: mid, group }) });
    alert(r.success ? 'OK' : (r.message || 'Echec'));
    wzLoadServers();
}

// ── Options ────────────────────────────────────────

async function wzLoadOptions() {
    const sel = document.getElementById('wz-opts-machine');
    const form = document.getElementById('wz-opts-form');
    const mid = parseInt(sel.value, 10);
    if (!mid) { form.classList.add('hidden'); return; }
    const r = await apiFetch('/wazuh/options?machine_id=' + mid);
    if (!r.success) { alert(r.message); return; }
    const o = r.options;
    document.getElementById('wz-opts-logformat').value = o.log_format || 'syslog';
    document.getElementById('wz-opts-freq').value = o.syscheck_frequency || 43200;
    document.getElementById('wz-opts-ar').checked = !!o.active_response_enabled;
    document.getElementById('wz-opts-sca').checked = !!o.sca_enabled;
    document.getElementById('wz-opts-rk').checked = !!o.rootcheck_enabled;
    document.getElementById('wz-opts-fim').value = (o.fim_paths || []).join('\n');
    form.classList.remove('hidden');
}

async function wzSaveOptions() {
    const mid = parseInt(document.getElementById('wz-opts-machine').value, 10);
    if (!mid) return;
    const fim_paths = document.getElementById('wz-opts-fim').value.split('\n').map(s => s.trim()).filter(Boolean);
    const body = {
        machine_id: mid,
        log_format: document.getElementById('wz-opts-logformat').value,
        syscheck_frequency: parseInt(document.getElementById('wz-opts-freq').value, 10) || 43200,
        active_response_enabled: document.getElementById('wz-opts-ar').checked,
        sca_enabled: document.getElementById('wz-opts-sca').checked,
        rootcheck_enabled: document.getElementById('wz-opts-rk').checked,
        fim_paths,
    };
    const status = document.getElementById('wz-opts-status');
    status.textContent = __('wazuh.saving');
    const r = await apiFetch('/wazuh/options', { method: 'POST', body: JSON.stringify(body) });
    status.textContent = r.success ? ('✓ ' + __('wazuh.saved')) : ('✗ ' + escHtml(r.message || 'Erreur'));
}

// ── Rules ────────────────────────────────────────

async function wzLoadRules() {
    const list = document.getElementById('wz-rules-list');
    const r = await apiFetch('/wazuh/rules');
    if (!r.success) { list.innerHTML = `<div class="text-xs text-red-500 p-2">${escHtml(r.message || 'Erreur')}</div>`; return; }
    if (!r.rules.length) { list.innerHTML = `<div class="text-xs text-gray-400 text-center py-3">-</div>`; return; }
    const colors = { rules: 'red', decoders: 'blue', cdb: 'purple' };
    list.innerHTML = r.rules.map(rl => {
        const col = colors[rl.rule_type] || 'gray';
        return `<div class="flex items-center justify-between px-2 py-1.5 rounded hover:bg-gray-100 dark:hover:bg-gray-700/40 cursor-pointer text-xs"
             onclick="wzSelectRule('${escAttr(rl.name)}')">
            <div class="flex items-center gap-2 min-w-0">
                <span class="font-medium truncate">${escHtml(rl.name)}</span>
                <span class="text-[10px] px-1 py-0.5 rounded bg-${col}-100 text-${col}-700 dark:bg-${col}-900/40">${escHtml(rl.rule_type)}</span>
            </div>
            <span class="text-[10px] text-gray-400 mono">${rl.bytes}o</span>
        </div>`;
    }).join('');
}

async function wzSelectRule(name) {
    const r = await apiFetch('/wazuh/rules/' + encodeURIComponent(name));
    if (!r.success) { alert(r.message); return; }
    document.getElementById('wz-rule-name').value = r.rule.name;
    document.getElementById('wz-rule-type').value = r.rule.rule_type;
    document.getElementById('wz-rule-editor').value = r.rule.content || '';
    document.getElementById('wz-rule-status').textContent = `bytes=${(r.rule.content || '').length}`;
}

function wzNewRule() {
    document.getElementById('wz-rule-name').value = '';
    document.getElementById('wz-rule-type').value = 'rules';
    document.getElementById('wz-rule-editor').value = '';
    document.getElementById('wz-rule-status').textContent = '';
}

async function wzSaveRule() {
    const body = {
        name: document.getElementById('wz-rule-name').value.trim(),
        rule_type: document.getElementById('wz-rule-type').value,
        content: document.getElementById('wz-rule-editor').value,
    };
    const status = document.getElementById('wz-rule-status');
    status.textContent = __('wazuh.saving');
    const r = await apiFetch('/wazuh/rules', { method: 'POST', body: JSON.stringify(body) });
    if (!r.success) { status.textContent = '✗ ' + escHtml(r.message || 'Erreur'); return; }
    status.textContent = `✓ ${__('wazuh.saved')} - sha=${r.sha8} ${r.bytes}o`;
    wzLoadRules();
}

async function wzDeleteRule() {
    const name = document.getElementById('wz-rule-name').value.trim();
    if (!name) return;
    if (!confirm(__('wazuh.confirm_delete_rule') + '\n\n' + name)) return;
    const r = await apiFetch('/wazuh/rules/' + encodeURIComponent(name), { method: 'DELETE' });
    alert(r.success ? 'OK' : (r.message || 'Echec'));
    if (r.success) { wzNewRule(); wzLoadRules(); }
}

document.addEventListener('DOMContentLoaded', () => {
    wzLoadConfig();
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (!btn) return;
        if (btn.dataset.tab === 'deploy') wzLoadServers();
        if (btn.dataset.tab === 'rules') wzLoadRules();
    });
});
