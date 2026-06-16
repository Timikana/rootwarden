/**
 * chatops/js/main.js - Configuration ChatOps : mapping chat<->utilisateur.
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function notify(m, t) { if (window.toast) window.toast(m, t || 'info'); }

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, body: j };
    }

    function renderStatus(enabled) {
        const el = document.getElementById('chatops-status');
        if (enabled) {
            el.innerHTML = `<span class="px-2 py-1 rounded-full text-xs bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">${escHtml(__('chatops.enabled'))}</span>`;
        } else {
            el.innerHTML = `<span class="px-2 py-1 rounded-full text-xs bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">${escHtml(__('chatops.disabled'))}</span>`;
        }
    }

    function render(rows) {
        const tb = document.getElementById('chatops-tbody');
        tb.innerHTML = '';
        if (!rows.length) {
            tb.innerHTML = `<tr><td colspan="5" class="py-4 text-center text-gray-400">${escHtml(__('chatops.empty'))}</td></tr>`;
            return;
        }
        for (const m of rows) {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-100 dark:border-gray-700/60';
            tr.innerHTML =
                `<td class="py-2">${escHtml(m.platform)}</td>` +
                `<td class="py-2 font-mono text-xs">${escHtml(m.chat_user_id)}</td>` +
                `<td class="py-2">${escHtml(m.user_name || ('#' + m.user_id))}</td>` +
                `<td class="py-2">${escHtml(m.label || '')}</td>` +
                `<td class="py-2 text-right"></td>`;
            const del = document.createElement('button');
            del.className = 'text-xs px-2 py-1 rounded bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300';
            del.textContent = __('chatops.delete');
            del.addEventListener('click', () => remove(m.platform, m.chat_user_id));
            tr.lastElementChild.appendChild(del);
            tb.appendChild(tr);
        }
    }

    async function load() {
        const res = await api('/chatops/users');
        if (!res.ok || !res.body || !res.body.success) { notify(__('chatops.err_load'), 'error'); return; }
        renderStatus(!!res.body.enabled);
        render(res.body.mappings || []);
    }

    async function add() {
        const payload = {
            platform: document.getElementById('m-platform').value,
            chat_user_id: document.getElementById('m-chatid').value.trim(),
            user_id: parseInt(document.getElementById('m-user').value),
            label: document.getElementById('m-label').value.trim(),
        };
        if (!payload.chat_user_id) { notify(__('chatops.err_chatid'), 'error'); return; }
        const res = await api('/chatops/users', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok && res.body && res.body.success) {
            notify(__('chatops.saved'), 'success');
            document.getElementById('m-chatid').value = '';
            document.getElementById('m-label').value = '';
            load();
        } else notify(__('chatops.err_save'), 'error');
    }

    async function remove(platform, chatId) {
        if (!confirm(__('chatops.confirm_delete'))) return;
        const res = await api('/chatops/users/' + encodeURIComponent(platform) + '/' + encodeURIComponent(chatId), { method: 'DELETE' });
        if (res.ok && res.body && res.body.success) { notify(__('chatops.deleted'), 'success'); load(); }
        else notify(__('chatops.err_save'), 'error');
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('m-add').addEventListener('click', add);
        load();
    });
})();
