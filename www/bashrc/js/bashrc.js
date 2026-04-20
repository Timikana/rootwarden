/**
 * bashrc.js — Frontend pour le module Bashrc.
 * Maintenu : Equipe Admin.Sys RootWarden
 */

const API = window.API_URL || '/api_proxy.php';

function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
}
function escAttr(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
        .replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\\/g, '&#92;');
}

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

let _currentUsers = [];
let _currentMachineId = null;

function fmtSize(n) {
    n = Number(n) || 0;
    if (n < 1024) return `${n} o`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} Ko`;
    return `${(n / (1024 * 1024)).toFixed(1)} Mo`;
}
function fmtTime(ts) {
    if (!ts) return '—';
    const d = new Date(Number(ts) * 1000);
    return d.toLocaleString();
}

async function bashrcLoadUsers() {
    const sel = document.getElementById('machine-select');
    const mid = parseInt(sel.value || '0', 10);
    const container = document.getElementById('users-table-container');
    const btnInstall = document.getElementById('btn-install-figlet');
    const banner = document.getElementById('prereq-banner');

    if (!mid) {
        container.innerHTML = `<div class="text-sm text-gray-500 text-center py-6">${escHtml(__('bashrc.pick_server_first'))}</div>`;
        ['btn-preview', 'btn-deploy', 'btn-dryrun'].forEach(id => {
            const b = document.getElementById(id); if (b) b.disabled = true;
        });
        banner.classList.add('hidden');
        btnInstall.classList.add('hidden');
        return;
    }

    _currentMachineId = mid;
    container.innerHTML = `<div class="text-sm text-gray-500 text-center py-6">${escHtml(__('bashrc.loading'))}</div>`;

    const data = await apiFetch(`/bashrc/users?machine_id=${mid}`);
    if (!data.success) {
        container.innerHTML = `<div class="text-sm text-red-500 py-6">${escHtml(data.message || 'Erreur')}</div>`;
        return;
    }

    _currentUsers = data.users || [];
    if (!data.figlet_present) {
        banner.classList.remove('hidden');
        btnInstall.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
        btnInstall.classList.add('hidden');
    }

    if (_currentUsers.length === 0) {
        container.innerHTML = `<div class="text-sm text-gray-500 text-center py-6">${escHtml(__('bashrc.no_users'))}</div>`;
        return;
    }

    let html = `
        <table class="w-full text-sm">
            <thead class="bg-gray-50 dark:bg-gray-700/50">
                <tr>
                    <th class="px-2 py-2 w-8"><input type="checkbox" id="chk-all" onchange="bashrcToggleAll(this)"></th>
                    <th class="text-left px-3 py-2">${escHtml(__('bashrc.col_user'))}</th>
                    <th class="text-left px-3 py-2">UID</th>
                    <th class="text-left px-3 py-2">${escHtml(__('bashrc.col_home'))}</th>
                    <th class="text-left px-3 py-2">${escHtml(__('bashrc.col_shell'))}</th>
                    <th class="text-left px-3 py-2">${escHtml(__('bashrc.col_size'))}</th>
                    <th class="text-left px-3 py-2">${escHtml(__('bashrc.col_mtime'))}</th>
                    <th class="text-left px-3 py-2">SHA</th>
                    <th class="text-left px-3 py-2">${escHtml(__('bashrc.col_status'))}</th>
                    <th class="text-left px-3 py-2">${escHtml(__('bashrc.col_actions'))}</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
    `;
    for (const u of _currentUsers) {
        const statusBadge = u.matches_template
            ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">${escHtml(__('bashrc.status_ok'))}</span>`
            : (u.exists
                ? `<span class="text-[10px] px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300">${escHtml(__('bashrc.status_diff'))}</span>`
                : `<span class="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">${escHtml(__('bashrc.status_absent'))}</span>`);
        const customBadge = u.has_custom
            ? `<span class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">${escHtml(__('bashrc.has_custom'))}</span>`
            : '';
        html += `
            <tr data-user="${escAttr(u.name)}">
                <td class="px-2 py-2 text-center"><input type="checkbox" class="user-chk" value="${escAttr(u.name)}" onchange="bashrcUpdateButtons()"></td>
                <td class="px-3 py-2 mono">${escHtml(u.name)}</td>
                <td class="px-3 py-2">${escHtml(u.uid)}</td>
                <td class="px-3 py-2 mono text-xs">${escHtml(u.home)}</td>
                <td class="px-3 py-2 mono text-xs">${escHtml(u.shell)}</td>
                <td class="px-3 py-2">${fmtSize(u.size)}</td>
                <td class="px-3 py-2 text-xs">${fmtTime(u.mtime)}</td>
                <td class="px-3 py-2 mono text-xs">${escHtml(u.sha8 || '')}</td>
                <td class="px-3 py-2">${statusBadge}${customBadge}</td>
                <td class="px-3 py-2">
                    <button onclick="bashrcRestore('${escAttr(u.name)}')" class="text-xs text-blue-500 hover:text-blue-700">${escHtml(__('bashrc.btn_restore'))}</button>
                </td>
            </tr>
        `;
    }
    html += '</tbody></table>';
    container.innerHTML = html;
    bashrcUpdateButtons();
}

function bashrcToggleAll(src) {
    document.querySelectorAll('.user-chk').forEach(c => { c.checked = src.checked; });
    bashrcUpdateButtons();
}

function bashrcUpdateButtons() {
    const any = document.querySelectorAll('.user-chk:checked').length > 0;
    ['btn-preview', 'btn-deploy', 'btn-dryrun'].forEach(id => {
        const b = document.getElementById(id); if (b) b.disabled = !any;
    });
}

function bashrcSelected() {
    return Array.from(document.querySelectorAll('.user-chk:checked')).map(c => c.value);
}

async function bashrcInstallFiglet() {
    const btn = document.getElementById('btn-install-figlet');
    btn.disabled = true; btn.textContent = __('bashrc.installing');
    const res = await apiFetch('/bashrc/prerequisites', {
        method: 'POST',
        body: JSON.stringify({ machine_id: _currentMachineId }),
    });
    alert(res.message || (res.success ? 'OK' : 'Echec'));
    btn.disabled = false; btn.textContent = __('bashrc.install_figlet');
    bashrcLoadUsers();
}

async function bashrcPreview() {
    const users = bashrcSelected();
    const mode = document.getElementById('deploy-mode').value;
    if (!users.length || !_currentMachineId) return;

    const panel = document.getElementById('preview-panel');
    const content = document.getElementById('preview-content');
    panel.classList.remove('hidden');
    content.innerHTML = `<div class="text-gray-500">${escHtml(__('bashrc.loading'))}</div>`;

    const res = await apiFetch('/bashrc/preview', {
        method: 'POST',
        body: JSON.stringify({ machine_id: _currentMachineId, users, mode }),
    });
    if (!res.success) {
        content.innerHTML = `<div class="text-red-500">${escHtml(res.message || 'Erreur')}</div>`;
        return;
    }
    let html = '';
    for (const r of res.results) {
        html += `<div class="mb-4"><div class="font-bold mb-1">${escHtml(r.user)}</div>`;
        if (r.error) {
            html += `<div class="text-red-500 text-xs">${escHtml(r.error)}</div></div>`;
            continue;
        }
        html += `<div class="text-xs text-gray-500 mb-1">${escHtml(r.home)} — ${r.current_bytes} o → ${r.new_bytes} o${r.custom_detected ? ` — ${escHtml(__('bashrc.has_custom'))}` : ''}</div>`;
        html += '<div class="bg-gray-900 text-gray-100 p-2 rounded">';
        for (const line of (r.diff || '').split('\n')) {
            let cls = '';
            if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('@@')) cls = 'diff-hdr';
            else if (line.startsWith('+')) cls = 'diff-add';
            else if (line.startsWith('-')) cls = 'diff-del';
            html += `<div class="${cls}">${escHtml(line) || '&nbsp;'}</div>`;
        }
        html += '</div></div>';
    }
    content.innerHTML = html || `<div class="text-gray-500">${escHtml(__('bashrc.preview_empty'))}</div>`;
}

async function bashrcDeploy(dryRun) {
    const users = bashrcSelected();
    const mode = document.getElementById('deploy-mode').value;
    if (!users.length || !_currentMachineId) return;

    const label = dryRun ? __('bashrc.confirm_dry') : __('bashrc.confirm_deploy');
    if (!confirm(`${label}\n\n${users.join(', ')}`)) return;

    const panel = document.getElementById('deploy-result');
    const content = document.getElementById('deploy-result-content');
    panel.classList.remove('hidden');
    content.innerHTML = `<div class="text-gray-500">${escHtml(__('bashrc.deploying'))}</div>`;

    const res = await apiFetch('/bashrc/deploy', {
        method: 'POST',
        body: JSON.stringify({ machine_id: _currentMachineId, users, mode, dry_run: dryRun }),
    });
    if (!res.success) {
        content.innerHTML = `<div class="text-red-500">${escHtml(res.message || 'Erreur')}</div>`;
        return;
    }
    const s = res.summary || {};
    let html = `<div class="mb-3 flex gap-3 text-sm">
        <span class="px-2 py-1 rounded bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">${escHtml(__('bashrc.ok'))}: ${s.ok || 0}</span>
        <span class="px-2 py-1 rounded bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">${escHtml(__('bashrc.failed'))}: ${s.failed || 0}</span>
        <span class="px-2 py-1 rounded bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">${escHtml(__('bashrc.skipped'))}: ${s.skipped || 0}</span>
        ${res.dry_run ? `<span class="px-2 py-1 rounded bg-yellow-100 text-yellow-700">DRY RUN</span>` : ''}
    </div>`;
    html += '<table class="w-full text-xs"><thead><tr class="bg-gray-50 dark:bg-gray-700/50"><th class="px-2 py-1 text-left">User</th><th class="px-2 py-1 text-left">OK</th><th class="px-2 py-1 text-left">Backup</th><th class="px-2 py-1 text-left">Syntaxe</th><th class="px-2 py-1 text-left">Detail</th></tr></thead><tbody>';
    for (const r of res.results || []) {
        const detail = r.error || r.reason || (r.dry_run ? __('bashrc.dry_would_run') : '');
        html += `<tr>
            <td class="px-2 py-1 mono">${escHtml(r.user)}</td>
            <td class="px-2 py-1">${r.ok ? '✓' : '✗'}</td>
            <td class="px-2 py-1 mono text-[11px]">${escHtml(r.backup || '')}</td>
            <td class="px-2 py-1">${r.syntax_ok ? '✓' : (r.syntax_ok === false ? '✗' : '—')}</td>
            <td class="px-2 py-1 text-gray-500">${escHtml(detail)}</td>
        </tr>`;
    }
    html += '</tbody></table>';
    content.innerHTML = html;
    if (!dryRun) bashrcLoadUsers();
}

async function bashrcRestore(user) {
    if (!confirm(__('bashrc.confirm_restore') + '\n\n' + user)) return;
    const res = await apiFetch('/bashrc/restore', {
        method: 'POST',
        body: JSON.stringify({ machine_id: _currentMachineId, user }),
    });
    alert(res.message || (res.success ? 'OK' : 'Echec'));
    if (res.success) bashrcLoadUsers();
}

// Bridge i18n : __('bashrc.foo') → window._i18n['bashrc.foo']
function __(key) {
    return (window._i18n && window._i18n[key]) || key;
}
