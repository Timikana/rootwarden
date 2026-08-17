/**
 * docker/js/main.js - UI inventaire & veille Docker.
 * Liste les conteneurs, badge mise a jour image (digest), commits git en retard
 * + changelog repliable. Scan par serveur ou global (streaming).
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function notify(m, t) { if (window.toast) window.toast(m, t || 'info'); }

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, body: j };
    }

    function updateBadge(c) {
        if (c.image_update) {
            return `<span class="px-2 py-0.5 rounded-full text-xs bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300" title="${esc(__('docker.update_hint'))}">${esc(__('docker.update_available'))}</span>`;
        }
        if (c.remote_digest) {
            return `<span class="px-2 py-0.5 rounded-full text-xs bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">${esc(__('docker.up_to_date'))}</span>`;
        }
        return `<span class="px-2 py-0.5 rounded-full text-xs bg-gray-100 text-gray-500 dark:bg-gray-700">${esc(__('docker.unknown'))}</span>`;
    }

    function gitCell(c, rowId) {
        const n = c.git_behind || 0;
        if (!n) return '<span class="text-gray-400 text-xs">—</span>';
        const label = __('docker.commits_behind').replace(':n', n);
        let html = `<button data-git="${rowId}" class="text-xs px-2 py-0.5 rounded-full bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300 hover:underline">${esc(label)} ▾</button>`;
        if (c.git_changelog) {
            html += `<pre id="git-${rowId}" class="hidden mt-2 bg-gray-100 dark:bg-gray-900 p-2 rounded text-[10px] whitespace-pre-wrap max-w-md">${esc(c.git_changelog)}</pre>`;
        }
        return html;
    }

    function renderSummary(rows) {
        const el = document.getElementById('docker-summary');
        const machines = new Set(rows.map(r => r.machine_id)).size;
        const total = rows.length;
        const imgUpd = rows.filter(r => r.image_update).length;
        const gitUpd = rows.filter(r => (r.git_behind || 0) > 0).length;
        const card = (v, l, c) => `<div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 text-center"><div class="text-2xl font-bold ${c}">${v}</div><div class="text-xs text-gray-500 dark:text-gray-400 mt-1">${esc(l)}</div></div>`;
        el.innerHTML =
            card(total, __('docker.sum_containers'), 'text-blue-600 dark:text-blue-400') +
            card(machines, __('docker.sum_machines'), 'text-gray-600 dark:text-gray-300') +
            card(imgUpd, __('docker.sum_img_updates'), imgUpd ? 'text-amber-600' : 'text-gray-400') +
            card(gitUpd, __('docker.sum_git_updates'), gitUpd ? 'text-indigo-600' : 'text-gray-400');
    }

    function render(rows) {
        const tb = document.getElementById('docker-tbody');
        tb.innerHTML = '';
        if (!rows.length) {
            tb.innerHTML = `<tr><td colspan="7" class="px-4 py-6 text-center text-gray-400">${esc(__('docker.empty'))}</td></tr>`;
            return;
        }
        rows.forEach((c, i) => {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60 align-top';
            const when = c.checked_at ? new Date(c.checked_at).toLocaleString() : '—';
            const proj = c.compose_project ? `<div class="text-[10px] text-gray-400">${esc(c.compose_project)}</div>` : '';
            tr.innerHTML =
                `<td class="px-4 py-2 text-xs">${esc(c.machine_name)}</td>` +
                `<td class="px-4 py-2 text-xs font-medium">${esc(c.container_name)}${proj}</td>` +
                `<td class="px-4 py-2 text-xs font-mono">${esc(c.image)}</td>` +
                `<td class="px-4 py-2 text-xs">${esc(c.status || c.state || '')}</td>` +
                `<td class="px-4 py-2">${updateBadge(c)}</td>` +
                `<td class="px-4 py-2">${gitCell(c, i)}</td>` +
                `<td class="px-4 py-2 text-xs text-gray-400">${esc(when)}</td>`;
            tb.appendChild(tr);
        });
        tb.querySelectorAll('[data-git]').forEach(b => b.addEventListener('click', () => {
            const pre = document.getElementById('git-' + b.dataset.git);
            if (pre) pre.classList.toggle('hidden');
        }));
    }

    async function load() {
        const res = await api('/docker/results');
        if (!res.ok || !res.body || !res.body.success) { notify(__('docker.err_load'), 'error'); return; }
        const rows = res.body.containers || [];
        renderSummary(rows);
        render(rows);
    }

    async function scanOne(btn) {
        const id = document.getElementById('scan-machine').value;
        if (!id) return;
        if (btn) btn.disabled = true;
        notify(__('docker.scanning'), 'info');
        const res = await api('/docker/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ machine_id: parseInt(id) }) });
        if (btn) btn.disabled = false;
        if (res.ok && res.body && res.body.success) {
            notify(res.body.docker ? __('docker.scan_done') : __('docker.no_docker'), 'success');
            load();
        } else notify((res.body && res.body.message) || __('docker.err_scan'), 'error');
    }

    async function scanAll(btn) {
        if (btn) btn.disabled = true;
        notify(__('docker.scanning_all'), 'info');
        try {
            const resp = await fetch(API + '/docker/scan_all', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
            const reader = resp.body.getReader(); const dec = new TextDecoder(); let buf = '', done = 0;
            while (true) {
                const { done: d, value } = await reader.read(); if (d) break;
                buf += dec.decode(value, { stream: true });
                const lines = buf.split('\n'); buf = lines.pop();
                for (const ln of lines) { if (ln.trim()) done++; }
            }
            notify(__('docker.scan_all_done').replace(':n', done), 'success');
        } catch (e) { notify(__('docker.err_scan'), 'error'); }
        if (btn) btn.disabled = false;
        load();
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('scan-one-btn').addEventListener('click', (e) => scanOne(e.currentTarget));
        document.getElementById('scan-all-btn').addEventListener('click', (e) => scanAll(e.currentTarget));
        load();
    });
})();
