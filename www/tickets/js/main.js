/**
 * tickets/js/main.js - UI ticketing (liste + creation manuelle).
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    // escHtml (variante textContent) n'echappe PAS les guillemets -> dangereux en
    // contexte d'attribut. escAttr ajoute l'echappement des " pour les href, etc.
    function escAttr(s) { return escHtml(s).replace(/"/g, '&quot;'); }
    function notify(m, t) { if (window.toast) window.toast(m, t || 'info'); }

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, body: j };
    }

    function renderStatus(enabled) {
        const el = document.getElementById('tickets-status');
        el.innerHTML = enabled
            ? `<span class="px-2 py-1 rounded-full text-xs bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">${escHtml(__('tickets.provider_on'))}</span>`
            : `<span class="px-2 py-1 rounded-full text-xs bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">${escHtml(__('tickets.provider_off'))}</span>`;
    }

    function refCell(t) {
        // external_url vient de la reponse de l'ITSM (donnee externe) : on
        // n'autorise que http(s) (pas de javascript:) et on echappe les " (attribut).
        const url = String(t.external_url || '');
        if (/^https?:\/\//i.test(url)) {
            return `<a href="${escAttr(url)}" target="_blank" rel="noopener noreferrer" class="text-blue-600 dark:text-blue-400 hover:underline">${escHtml(t.external_id || t.ref || '↗')}</a>`;
        }
        return escHtml(t.external_id || t.ref || '—');
    }

    function render(rows) {
        const tb = document.getElementById('tickets-tbody');
        tb.innerHTML = '';
        if (!rows.length) {
            tb.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-gray-400">${escHtml(__('tickets.empty'))}</td></tr>`;
            return;
        }
        for (const t of rows) {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60';
            const when = t.created_at ? new Date(t.created_at).toLocaleString() : '—';
            tr.innerHTML =
                `<td class="px-4 py-2 text-xs text-gray-400 whitespace-nowrap">${escHtml(when)}</td>` +
                `<td class="px-4 py-2"><span class="px-1.5 py-0.5 rounded text-[10px] bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">${escHtml(t.source)}</span></td>` +
                `<td class="px-4 py-2">${escHtml(t.summary)}</td>` +
                `<td class="px-4 py-2 text-xs">${escHtml(t.machine_name || (t.machine_id ? ('#' + t.machine_id) : '—'))}</td>` +
                `<td class="px-4 py-2 text-xs">${escHtml(t.provider)}</td>` +
                `<td class="px-4 py-2 text-xs">${refCell(t)}</td>`;
            tb.appendChild(tr);
        }
    }

    async function load() {
        const res = await api('/tickets');
        if (!res.ok || !res.body || !res.body.success) { notify(__('tickets.err_load'), 'error'); return; }
        renderStatus(!!res.body.provider_enabled);
        render(res.body.tickets || []);
    }

    async function save() {
        const summary = document.getElementById('t-summary').value.trim();
        if (!summary) { notify(__('tickets.err_summary'), 'error'); return; }
        const payload = {
            source: 'manual',
            machine_id: document.getElementById('t-machine').value || null,
            summary,
            description: document.getElementById('t-desc').value.trim(),
        };
        const res = await api('/tickets', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok && res.body && res.body.success) {
            notify(res.body.deduped ? __('tickets.deduped') : __('tickets.created'), 'success');
            document.getElementById('t-summary').value = '';
            document.getElementById('t-desc').value = '';
            document.getElementById('ticket-form').classList.add('hidden');
            load();
        } else notify((res.body && res.body.message) || __('tickets.err_create'), 'error');
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('new-ticket-btn').addEventListener('click', () => document.getElementById('ticket-form').classList.toggle('hidden'));
        document.getElementById('t-cancel').addEventListener('click', () => document.getElementById('ticket-form').classList.add('hidden'));
        document.getElementById('t-save').addEventListener('click', save);
        load();
    });
})();
