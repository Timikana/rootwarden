/**
 * bashrc.js - Frontend pour le module Bashrc.
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
    if (!ts) return '-';
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
        html += `<div class="text-xs text-gray-500 mb-1">${escHtml(r.home)} - ${r.current_bytes} o → ${r.new_bytes} o${r.custom_detected ? ` - ${escHtml(__('bashrc.has_custom'))}` : ''}</div>`;
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
            <td class="px-2 py-1">${r.syntax_ok ? '✓' : (r.syntax_ok === false ? '✗' : '-')}</td>
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

// ─────────────────────────────────────────────────────────────
// Template editor (onglet Template)
// ─────────────────────────────────────────────────────────────

let _tplLoaded = false;
let _tplOriginal = '';

async function bashrcTemplateLoad(force = false) {
    const ed = document.getElementById('tpl-editor');
    if (!ed) return;
    if (_tplLoaded && !force) return;
    const status = document.getElementById('tpl-status');
    if (status) status.textContent = __('bashrc.loading');
    const res = await apiFetch('/bashrc/template');
    if (!res.success) {
        if (status) status.textContent = res.message || 'Erreur';
        return;
    }
    _tplOriginal = res.content || '';
    ed.value = _tplOriginal;
    _tplLoaded = true;
    bashrcTemplateUpdateMeta(res);
    if (status) status.textContent = '';
    bashrcTemplateSetDirty(false);
    // Scan initial pour badge danger (si le template en DB contient deja des patterns)
    const warnEl = document.getElementById('tpl-danger');
    if (warnEl) {
        const hits = bashrcTemplateScanDanger(ed.value);
        if (hits.length) {
            warnEl.textContent = '⚠ ' + __('bashrc.template_danger') + ' : ' + hits.join(', ');
            warnEl.classList.remove('hidden');
        } else {
            warnEl.classList.add('hidden');
        }
    }
}

function bashrcTemplateUpdateMeta(info) {
    const l = document.getElementById('tpl-lines');
    const s = document.getElementById('tpl-sha');
    const b = document.getElementById('tpl-bytes');
    if (l) l.textContent = info.lines ?? '-';
    if (s) s.textContent = info.sha8 ?? '-';
    if (b) b.textContent = info.bytes ?? '-';
}

// Patterns destructeurs courants - alerte UI (pas un blocage)
const _TPL_DANGER_PATTERNS = [
    { re: /\brm\s+-[rRf]+\s+\/(\s|$)/,          name: 'rm -rf /' },
    { re: /\bdd\s+if=.*of=\/dev\/[sh]d[a-z]/,   name: 'dd vers disque' },
    { re: /:\(\)\s*\{[^}]*\|\s*:\s*&[^}]*\};\s*:/, name: 'fork bomb' },
    { re: /\bmkfs\.\w+\s+\/dev\//,               name: 'mkfs' },
    { re: /\b>\s*\/dev\/[sh]d[a-z]/,             name: 'redirect vers disque' },
    { re: /\bchmod\s+-R\s+0*777\s+\//,           name: 'chmod 777 /' },
    { re: /\bcurl[^|]*\|\s*(sudo\s+)?(ba)?sh\b/, name: 'curl|sh' },
    { re: /\bwget[^|]*\|\s*(sudo\s+)?(ba)?sh\b/, name: 'wget|sh' },
];

function bashrcTemplateScanDanger(content) {
    const hits = [];
    for (const p of _TPL_DANGER_PATTERNS) {
        if (p.re.test(content)) hits.push(p.name);
    }
    return hits;
}

function bashrcTemplateDirty() {
    const ed = document.getElementById('tpl-editor');
    if (!ed) return;
    bashrcTemplateSetDirty(ed.value !== _tplOriginal);
    // Scan live pour alerte visuelle
    const warnEl = document.getElementById('tpl-danger');
    if (!warnEl) return;
    const hits = bashrcTemplateScanDanger(ed.value);
    if (hits.length) {
        warnEl.textContent = '⚠ ' + __('bashrc.template_danger') + ' : ' + hits.join(', ');
        warnEl.classList.remove('hidden');
    } else {
        warnEl.classList.add('hidden');
    }
}

function bashrcTemplateSetDirty(dirty) {
    const btn = document.getElementById('btn-tpl-save');
    const status = document.getElementById('tpl-status');
    if (btn) btn.disabled = !dirty;
    if (status) status.textContent = dirty ? ('● ' + __('bashrc.template_dirty')) : '';
}

async function bashrcTemplateSave() {
    const ed = document.getElementById('tpl-editor');
    if (!ed || !ed.value) return;
    const hits = bashrcTemplateScanDanger(ed.value);
    if (hits.length) {
        if (!confirm(__('bashrc.template_danger_confirm') + '\n\n• ' + hits.join('\n• '))) return;
    } else if (!confirm(__('bashrc.confirm_save_template'))) return;
    const btn = document.getElementById('btn-tpl-save');
    const status = document.getElementById('tpl-status');
    if (btn) btn.disabled = true;
    if (status) status.textContent = __('bashrc.saving');
    const res = await apiFetch('/bashrc/template', {
        method: 'POST',
        body: JSON.stringify({ content: ed.value }),
    });
    if (!res.success) {
        if (status) status.textContent = '✗ ' + escHtml(res.message || 'Erreur');
        if (btn) btn.disabled = false;
        return;
    }
    _tplOriginal = ed.value;
    bashrcTemplateUpdateMeta(res);
    bashrcTemplateSetDirty(false);
    if (status) status.textContent = '✓ ' + __('bashrc.template_saved');
}

function bashrcTemplateReset() {
    if (!confirm(__('bashrc.confirm_reset_template'))) return;
    const ed = document.getElementById('tpl-editor');
    if (!ed) return;
    ed.value = _tplOriginal;
    bashrcTemplateSetDirty(false);
}

// Auto-load quand on clique l'onglet template
document.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab-btn');
    if (btn && btn.dataset.tab === 'template') bashrcTemplateLoad();
});

// Bridge i18n : __('bashrc.foo') → window._i18n['bashrc.foo']
function __(key) {
    return (window._i18n && window._i18n[key]) || key;
}
