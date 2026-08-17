/**
 * drift/js/main.js - UI de la detection de derive de configuration.
 * Charge /drift/results, rend le tableau + resume, declenche /drift/scan(_all).
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }

    const STATUS_PILL = {
        ok:      'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
        drift:   'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
        unknown: 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-300',
    };
    const STATUS_LABEL = { ok: 'OK', drift: __('drift.status_drift'), unknown: '?' };

    function pill(cat) {
        if (!cat) return `<span class="px-2 py-0.5 rounded-full text-xs ${STATUS_PILL.unknown}">—</span>`;
        const cls = STATUS_PILL[cat.status] || STATUS_PILL.unknown;
        const lbl = STATUS_LABEL[cat.status] || cat.status;
        return `<span class="px-2 py-0.5 rounded-full text-xs ${cls}" title="${escHtml(cat.detail || '')}">${escHtml(lbl)}</span>`;
    }

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, status: r.status, body: j };
    }

    function renderSummary(machines) {
        const el = document.getElementById('drift-summary');
        const total = machines.length;
        const withDrift = machines.filter(m => m.drift_count > 0).length;
        const driftCats = machines.reduce((n, m) => n + (m.drift_count || 0), 0);
        const clean = total - withDrift;
        const card = (val, label, color) =>
            `<div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center">
               <div class="text-2xl font-bold ${color}">${val}</div>
               <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">${escHtml(label)}</div>
             </div>`;
        el.innerHTML =
            card(total, __('drift.sum_servers'), 'text-blue-600 dark:text-blue-400') +
            card(clean, __('drift.sum_clean'), 'text-green-600 dark:text-green-400') +
            card(withDrift, __('drift.sum_drifted'), withDrift ? 'text-red-600 dark:text-red-400' : 'text-gray-400') +
            card(driftCats, __('drift.sum_findings'), driftCats ? 'text-orange-500' : 'text-gray-400');
    }

    function renderTable(machines) {
        const tb = document.getElementById('drift-tbody');
        tb.innerHTML = '';
        if (!machines.length) {
            tb.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-gray-400">${escHtml(__('drift.empty'))}</td></tr>`;
            return;
        }
        machines.sort((a, b) => (b.drift_count || 0) - (a.drift_count || 0) || String(a.name).localeCompare(b.name));
        for (const m of machines) {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60 hover:bg-gray-50 dark:hover:bg-gray-700/30';
            const checked = m.checked_at ? new Date(m.checked_at).toLocaleString() : '—';
            tr.innerHTML =
                `<td class="px-4 py-3 font-medium">${escHtml(m.name)}</td>` +
                `<td class="px-4 py-3">${pill(m.categories.sudo)}</td>` +
                `<td class="px-4 py-3">${pill(m.categories.sshd)}</td>` +
                `<td class="px-4 py-3">${pill(m.categories.fail2ban)}</td>` +
                `<td class="px-4 py-3 text-xs text-gray-400">${escHtml(checked)}</td>` +
                `<td class="px-4 py-3 text-right"></td>`;
            // Bouton rescan (addEventListener -> closure, pas d'onclick interpole)
            const btn = document.createElement('button');
            btn.className = 'text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-600';
            btn.textContent = __('drift.btn_rescan');
            btn.addEventListener('click', () => rescan(m.machine_id, btn));
            tr.lastElementChild.appendChild(btn);
            tb.appendChild(tr);
        }
    }

    async function loadResults() {
        const res = await api('/drift/results');
        if (!res.ok || !res.body || !res.body.success) {
            if (window.toast) toast(__('drift.err_load'), 'error');
            return;
        }
        renderSummary(res.body.machines || []);
        renderTable(res.body.machines || []);
    }

    async function rescan(machineId, btn) {
        if (btn) { btn.disabled = true; btn.textContent = '…'; }
        const res = await api('/drift/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ machine_id: machineId }),
        });
        if (res.ok && res.body && res.body.success) {
            if (window.toast) toast(__('drift.scanned'), 'success');
        } else if (window.toast) {
            toast(__('drift.err_scan'), 'error');
        }
        await loadResults();
    }

    async function scanAll(btn) {
        if (btn) { btn.disabled = true; }
        if (window.toast) toast(__('drift.scanning'), 'info');
        const res = await api('/drift/scan_all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        if (res.ok && res.body && res.body.success) {
            if (window.toast) toast(__('drift.scan_done') + ' (' + (res.body.scanned || 0) + ')', 'success');
        } else if (window.toast) {
            toast(__('drift.err_scan'), 'error');
        }
        if (btn) { btn.disabled = false; }
        await loadResults();
    }

    document.addEventListener('DOMContentLoaded', () => {
        const b = document.getElementById('scan-all-btn');
        if (b) b.addEventListener('click', () => scanAll(b));
        loadResults();
    });
})();
