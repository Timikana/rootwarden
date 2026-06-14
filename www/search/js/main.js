/**
 * search/js/main.js - Recherche globale (debounce + rendu categorise).
 * Rendu sans onclick interpole (liens <a> + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }

    const CATS = [
        { key: 'machines', icon: '🖥️', label: 'search.cat_machines' },
        { key: 'users',    icon: '👤', label: 'search.cat_users' },
        { key: 'cves',     icon: '🛡️', label: 'search.cat_cves' },
        { key: 'tickets',  icon: '🎟️', label: 'search.cat_tickets' },
        { key: 'audit',    icon: '📜', label: 'search.cat_audit' },
    ];

    async function api(path) {
        const r = await fetch(API + path);
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, body: j };
    }

    function card(cat, items) {
        const rows = items.map(it =>
            `<a href="${escHtml(it.link || '#')}" class="block px-3 py-2 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/40">
                <div class="text-sm font-medium">${escHtml(it.label)}</div>
                <div class="text-xs text-gray-400">${escHtml(it.sub || '')}</div>
             </a>`).join('');
        return `<div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4">
            <div class="font-semibold text-sm mb-2">${cat.icon} ${escHtml(__(cat.label))} <span class="text-gray-400">(${items.length})</span></div>
            <div class="divide-y divide-gray-100 dark:divide-gray-700/60">${rows}</div>
        </div>`;
    }

    async function run(q) {
        const meta = document.getElementById('search-meta');
        const wrap = document.getElementById('search-results');
        if (!q || q.trim().length < 2) { wrap.innerHTML = ''; meta.textContent = __('search.hint_min'); return; }
        meta.textContent = '…';
        const res = await api('/search?q=' + encodeURIComponent(q.trim()));
        if (!res.ok || !res.body || !res.body.success) { meta.textContent = __('search.err'); return; }
        const r = res.body.results || {};
        const blocks = CATS.filter(c => (r[c.key] || []).length).map(c => card(c, r[c.key]));
        wrap.innerHTML = blocks.length ? blocks.join('') : `<div class="col-span-full text-center text-gray-400 py-8">${escHtml(__('search.no_results'))}</div>`;
        meta.textContent = (res.body.total || 0) + ' ' + __('search.results_for') + ' "' + q.trim() + '"';
    }

    let timer = null;
    document.addEventListener('DOMContentLoaded', () => {
        const input = document.getElementById('search-input');
        input.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(() => run(input.value), 300); });
        if (input.value.trim().length >= 2) run(input.value);
    });
})();
