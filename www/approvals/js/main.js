/**
 * approvals/js/main.js - UI du workflow d'approbation 4-eyes.
 * Liste les demandes + approve/reject (bouton approuver desactive sur ses
 * propres demandes : regle 4-eyes appliquee aussi cote backend).
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function notify(m, t) { if (window.toast) window.toast(m, t || 'info'); }

    let currentStatus = 'pending';

    const STATUS_PILL = {
        pending:  'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
        approved: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
        rejected: 'bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300',
        executed: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
        expired:  'bg-gray-100 text-gray-500 dark:bg-gray-700',
    };

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, status: r.status, body: j };
    }

    function render(rows) {
        const tb = document.getElementById('appr-tbody');
        tb.innerHTML = '';
        if (!rows.length) {
            tb.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-gray-400">${escHtml(__('appr.empty'))}</td></tr>`;
            return;
        }
        for (const a of rows) {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60';
            const pill = STATUS_PILL[a.status] || STATUS_PILL.expired;
            tr.innerHTML =
                `<td class="px-4 py-3 font-mono text-xs">${escHtml(a.action_type)}</td>` +
                `<td class="px-4 py-3">${escHtml(a.target || '—')}</td>` +
                `<td class="px-4 py-3">${escHtml(a.machine_name || (a.machine_id ? ('#' + a.machine_id) : '—'))}</td>` +
                `<td class="px-4 py-3">${escHtml(a.requester || '—')}</td>` +
                `<td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-xs ${pill}">${escHtml(a.status)}</span></td>` +
                `<td class="px-4 py-3 text-right"></td>`;
            const cell = tr.lastElementChild;
            if (a.status === 'pending') {
                const ap = document.createElement('button');
                ap.className = 'text-xs px-2.5 py-1 rounded-lg bg-green-600 text-white mr-2 disabled:opacity-40 disabled:cursor-not-allowed';
                ap.textContent = __('appr.approve');
                if (a.is_own) { ap.disabled = true; ap.title = __('appr.own_hint'); }
                else ap.addEventListener('click', () => decide(a.id, 'approve'));
                const rj = document.createElement('button');
                rj.className = 'text-xs px-2.5 py-1 rounded-lg bg-rose-600 text-white';
                rj.textContent = __('appr.reject');
                rj.addEventListener('click', () => decide(a.id, 'reject'));
                cell.appendChild(ap); cell.appendChild(rj);
            } else if (a.approver) {
                cell.innerHTML = `<span class="text-xs text-gray-400">${escHtml(__('appr.by'))} ${escHtml(a.approver)}</span>`;
            }
            tb.appendChild(tr);
        }
    }

    async function load() {
        const res = await api('/approvals?status=' + encodeURIComponent(currentStatus));
        if (!res.ok || !res.body || !res.body.success) { notify(__('appr.err_load'), 'error'); return; }
        render(res.body.approvals || []);
    }

    async function decide(id, action) {
        const verb = action === 'approve' ? __('appr.approve') : __('appr.reject');
        let reason = '';
        if (action === 'reject') { reason = prompt(__('appr.reason_prompt')) || ''; }
        if (!confirm(__('appr.confirm').replace(':action', verb))) return;
        const res = await api('/approvals/' + id + '/' + action, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason }),
        });
        if (res.ok && res.body && res.body.success) { notify(__('appr.done'), 'success'); load(); }
        else notify((res.body && res.body.message) || __('appr.err_decide'), 'error');
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.appr-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                currentStatus = btn.dataset.status;
                document.querySelectorAll('.appr-tab').forEach(b => {
                    b.classList.toggle('bg-blue-600', b === btn);
                    b.classList.toggle('text-white', b === btn);
                    b.classList.toggle('bg-gray-200', b !== btn);
                    b.classList.toggle('dark:bg-gray-700', b !== btn);
                });
                load();
            });
        });
        load();
    });
})();
