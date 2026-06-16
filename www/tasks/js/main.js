/**
 * tasks/js/main.js - Centre de taches (historique + statut live).
 * Rendu sans onclick interpole (textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }

    const PILL = {
        running: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
        success: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
        error:   'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
        pending: 'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-300',
    };
    const LABEL = {
        running: __('tasks.st_running'), success: __('tasks.st_success'),
        error: __('tasks.st_error'), pending: __('tasks.st_pending'),
    };

    let timer = null;

    async function api(path) {
        const r = await fetch(API + path);
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, body: j };
    }

    function fmtDuration(start, end) {
        if (!start) return '—';
        const s = new Date(start).getTime();
        const e = end ? new Date(end).getTime() : Date.now();
        let ms = Math.max(0, e - s);
        const sec = Math.round(ms / 1000);
        if (sec < 60) return sec + 's';
        const m = Math.floor(sec / 60), r = sec % 60;
        return m + 'm' + (r ? r + 's' : '');
    }

    function renderStats(stats) {
        const el = document.getElementById('task-stats');
        const s = (stats && stats.last24h) || {};
        const card = (val, label, color) =>
            `<div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center">
               <div class="text-2xl font-bold ${color}">${val}</div>
               <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">${escHtml(label)}</div>
             </div>`;
        el.innerHTML =
            card(stats ? stats.running : 0, __('tasks.st_running'), (stats && stats.running) ? 'text-blue-600 dark:text-blue-400' : 'text-gray-400') +
            card(s.success || 0, __('tasks.sum_success_24h'), 'text-green-600 dark:text-green-400') +
            card(s.error || 0, __('tasks.sum_error_24h'), (s.error) ? 'text-red-600 dark:text-red-400' : 'text-gray-400') +
            card((s.success || 0) + (s.error || 0) + (s.running || 0) + (s.pending || 0), __('tasks.sum_total_24h'), 'text-blue-600 dark:text-blue-400');
    }

    function renderTable(tasks) {
        const tb = document.getElementById('task-tbody');
        tb.innerHTML = '';
        if (!tasks.length) {
            tb.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-gray-400">${escHtml(__('tasks.empty'))}</td></tr>`;
            return;
        }
        for (const t of tasks) {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60 hover:bg-gray-50 dark:hover:bg-gray-700/30';
            const cls = PILL[t.status] || PILL.pending;
            const lbl = LABEL[t.status] || t.status;
            const machine = t.machine_name ? ` · ${escHtml(t.machine_name)}` : '';
            const detail = t.detail ? `<div class="text-xs text-gray-400">${escHtml(t.detail)}</div>` : '';
            tr.innerHTML =
                `<td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-xs ${cls}">${escHtml(lbl)}</span></td>` +
                `<td class="px-4 py-3 font-mono text-xs">${escHtml(t.task_type)}</td>` +
                `<td class="px-4 py-3">${escHtml(t.label)}${machine}${detail}</td>` +
                `<td class="px-4 py-3 text-xs text-gray-400">${escHtml(t.started_at ? new Date(t.started_at).toLocaleString() : '—')}</td>` +
                `<td class="px-4 py-3 text-xs text-gray-400">${escHtml(fmtDuration(t.started_at, t.finished_at))}</td>`;
            tb.appendChild(tr);
        }
    }

    async function refresh() {
        const status = document.getElementById('task-filter').value;
        const q = status ? ('?status=' + encodeURIComponent(status) + '&limit=100') : '?limit=100';
        const [list, stats] = await Promise.all([api('/tasks/list' + q), api('/tasks/stats')]);
        if (list.ok && list.body && list.body.success) renderTable(list.body.tasks || []);
        if (stats.ok && stats.body && stats.body.success) renderStats(stats.body);
    }

    function scheduleRefresh() {
        if (timer) clearInterval(timer);
        if (document.getElementById('task-autorefresh').checked) {
            timer = setInterval(refresh, 5000);
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('task-filter').addEventListener('change', refresh);
        document.getElementById('task-autorefresh').addEventListener('change', scheduleRefresh);
        refresh();
        scheduleRefresh();
    });
})();
