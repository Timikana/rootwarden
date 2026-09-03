/**
 * backups/js/main.js - UI sauvegardes BDD (liste, creer, verifier, restaurer).
 * La restauration (destructive) exige une confirmation forte + superadmin.
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    const isSA = !!window._isSuperadmin;
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function notify(m, t) { if (window.toast) window.toast(m, t || 'info'); }

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, status: r.status, body: j };
    }

    function render(rows) {
        const tb = document.getElementById('backup-tbody');
        tb.innerHTML = '';
        if (!rows.length) {
            tb.innerHTML = `<tr><td colspan="4" class="px-4 py-6 text-center text-gray-400">${escHtml(__('backup.empty'))}</td></tr>`;
            return;
        }
        for (const b of rows) {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60';
            const when = b.created_at ? new Date(b.created_at).toLocaleString() : '—';
            tr.innerHTML =
                `<td class="px-4 py-2 font-mono text-xs">${escHtml(b.filename)}</td>` +
                `<td class="px-4 py-2 text-xs">${escHtml(b.size_mb)} MB</td>` +
                `<td class="px-4 py-2 text-xs text-gray-400">${escHtml(when)}</td>` +
                `<td class="px-4 py-2 text-right"></td>`;
            const cell = tr.lastElementChild;
            const vbtn = document.createElement('button');
            vbtn.className = 'text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 mr-2';
            vbtn.textContent = __('backup.verify');
            vbtn.title = __('backup.tip_verify');
            vbtn.addEventListener('click', () => verify(b.filename, vbtn));
            cell.appendChild(vbtn);
            if (isSA) {
                const rbtn = document.createElement('button');
                rbtn.className = 'text-xs px-2 py-1 rounded bg-rose-600 text-white hover:bg-rose-700';
                rbtn.textContent = __('backup.restore');
                rbtn.title = __('backup.tip_restore');
                rbtn.addEventListener('click', () => restore(b.filename, rbtn));
                cell.appendChild(rbtn);
            }
            tb.appendChild(tr);
        }
    }

    async function load() {
        const res = await api('/admin/backups');
        if (!res.ok || !res.body || !res.body.success) { notify(__('backup.err_load'), 'error'); return; }
        render(res.body.backups || []);
    }

    async function create(btn) {
        if (btn) btn.disabled = true;
        notify(__('backup.creating'), 'info');
        const res = await api('/admin/backups', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        if (btn) btn.disabled = false;
        if (res.ok && res.body && res.body.success) { notify(__('backup.created'), 'success'); load(); }
        else notify(__('backup.err_create'), 'error');
    }

    async function verify(filename, btn) {
        if (btn) { btn.disabled = true; }
        const res = await api('/admin/backups/verify', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename }),
        });
        if (btn) { btn.disabled = false; }
        if (res.ok && res.body && res.body.success && res.body.valid) {
            const shaTxt = res.body.sha_ok === true ? '✓ sha256' : (res.body.has_sidecar ? '✗ sha256' : 'sha256 n/a');
            notify(`${__('backup.verify_ok')} — ${res.body.tables} tables, ${res.body.statements} stmts, ${shaTxt}`, 'success');
        } else {
            notify((res.body && res.body.error) || __('backup.verify_fail'), 'error');
        }
    }

    async function restore(filename, btn) {
        // Confirmation forte : retaper le nom du fichier
        const typed = prompt(__('backup.restore_confirm').replace(':file', filename));
        if (typed !== filename) { if (typed !== null) notify(__('backup.restore_mismatch'), 'error'); return; }
        if (btn) { btn.disabled = true; btn.textContent = '…'; }
        const res = await api('/admin/backups/restore', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename }),
        });
        if (btn) { btn.disabled = false; btn.textContent = __('backup.restore'); }
        if (res.ok && res.body && res.body.success) {
            notify(`${__('backup.restore_ok')} (${res.body.statements} stmts)`, 'success');
            load();
        } else {
            notify((res.body && res.body.message) || __('backup.restore_fail'), 'error');
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('create-btn').addEventListener('click', (e) => create(e.currentTarget));
        load();
    });
})();
