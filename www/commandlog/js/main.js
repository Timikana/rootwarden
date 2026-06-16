/**
 * commandlog/js/main.js - UI du journal des commandes (bastion trail), lecture seule.
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function notify(m, t) { if (window.toast) window.toast(m, t || 'info'); }

    async function api(path) {
        const r = await fetch(API + path);
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, body: j };
    }

    function resultPill(s) {
        if (s === null || s === undefined) return `<span class="text-xs text-gray-400">—</span>`;
        return s
            ? `<span class="px-2 py-0.5 rounded-full text-xs bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">OK</span>`
            : `<span class="px-2 py-0.5 rounded-full text-xs bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300">${escHtml(__('cmdlog.failed'))}</span>`;
    }

    function render(rows) {
        const tb = document.getElementById('cmdlog-tbody');
        tb.innerHTML = '';
        if (!rows.length) {
            tb.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-gray-400">${escHtml(__('cmdlog.empty'))}</td></tr>`;
            return;
        }
        for (const c of rows) {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60 align-top';
            const when = c.created_at ? new Date(c.created_at).toLocaleString() : '—';
            tr.innerHTML =
                `<td class="px-4 py-2 text-xs text-gray-400 whitespace-nowrap">${escHtml(when)}</td>` +
                `<td class="px-4 py-2 text-xs">${escHtml(c.machine_name || (c.machine_id ? ('#' + c.machine_id) : '—'))}</td>` +
                `<td class="px-4 py-2 text-xs">${escHtml(c.user_name || (c.user_id ? ('#' + c.user_id) : __('cmdlog.system')))}</td>` +
                `<td class="px-4 py-2"><span class="px-1.5 py-0.5 rounded text-[10px] bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">${escHtml(c.context)}</span></td>` +
                `<td class="px-4 py-2"><code class="text-[11px] break-all">${escHtml(c.command)}</code>${c.detail ? `<div class="text-[10px] text-gray-400">${escHtml(c.detail)}</div>` : ''}</td>` +
                `<td class="px-4 py-2">${resultPill(c.success)}</td>`;
            tb.appendChild(tr);
        }
    }

    async function loadContexts() {
        const res = await api('/command_log/contexts');
        if (!res.ok || !res.body || !res.body.success) return;
        const sel = document.getElementById('f-context');
        for (const ctx of res.body.contexts || []) {
            const o = document.createElement('option'); o.value = ctx; o.textContent = ctx; sel.appendChild(o);
        }
    }

    async function load() {
        const mid = document.getElementById('f-machine').value;
        const ctx = document.getElementById('f-context').value;
        let q = '/command_log?limit=200';
        if (mid) q += '&machine_id=' + encodeURIComponent(mid);
        if (ctx) q += '&context=' + encodeURIComponent(ctx);
        const res = await api(q);
        if (!res.ok || !res.body || !res.body.success) { notify(__('cmdlog.err_load'), 'error'); return; }
        render(res.body.commands || []);
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('refresh-btn').addEventListener('click', load);
        document.getElementById('f-machine').addEventListener('change', load);
        document.getElementById('f-context').addEventListener('change', load);
        loadContexts();
        load();
    });
})();
