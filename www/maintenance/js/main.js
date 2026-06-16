/**
 * maintenance/js/main.js - UI des fenetres de maintenance.
 * CRUD des fenetres + indicateur "active maintenant" (calcul client-side).
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    const DAYS = window._dayLabels || ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'];
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function notify(m, t) { if (window.toast) window.toast(m, t || 'info'); }

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, status: r.status, body: j };
    }

    // weekday courant lundi=0..dimanche=6 (JS getDay() dimanche=0)
    function todayIdx() { return (new Date().getDay() + 6) % 7; }
    function nowHM() { const d = new Date(); return d.getHours() * 60 + d.getMinutes(); }
    function toMin(hhmm) { const p = String(hhmm || '0:0').split(':'); return (+p[0]) * 60 + (+p[1] || 0); }

    function isActiveNow(w) {
        if (!w.enabled) return false;
        const days = String(w.days || '').split(',').map(s => parseInt(s)).filter(n => !isNaN(n));
        const start = toMin(w.start_time), end = toMin(w.end_time), t = nowHM(), wd = todayIdx();
        if (start <= end) return days.includes(wd) && t >= start && t <= end;
        // fenetre nocturne (a cheval sur minuit)
        if (days.includes(wd) && t >= start) return true;
        const prev = (wd + 6) % 7;
        return days.includes(prev) && t <= end;
    }

    function daysBadges(csv) {
        const set = String(csv || '').split(',').map(s => parseInt(s));
        return DAYS.map((d, i) => `<span class="px-1.5 py-0.5 rounded text-[10px] ${set.includes(i) ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300' : 'bg-gray-100 text-gray-400 dark:bg-gray-700'}">${escHtml(d)}</span>`).join(' ');
    }

    function render(windows) {
        const tb = document.getElementById('win-tbody');
        tb.innerHTML = '';
        if (!windows.length) {
            tb.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-gray-400">${escHtml(__('maint.empty'))}</td></tr>`;
            return;
        }
        for (const w of windows) {
            const tr = document.createElement('tr');
            tr.className = 'border-t border-gray-100 dark:border-gray-700/60';
            const scope = w.scope === 'machine' ? (escHtml(w.machine_name || ('#' + w.machine_id))) : __('maint.scope_global');
            const active = isActiveNow(w);
            const statusPill = !w.enabled
                ? `<span class="px-2 py-0.5 rounded-full text-xs bg-gray-100 text-gray-500 dark:bg-gray-700">${escHtml(__('maint.disabled'))}</span>`
                : (active
                    ? `<span class="px-2 py-0.5 rounded-full text-xs bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">${escHtml(__('maint.active_now'))}</span>`
                    : `<span class="px-2 py-0.5 rounded-full text-xs bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">${escHtml(__('maint.closed_now'))}</span>`);
            tr.innerHTML =
                `<td class="px-4 py-3 font-medium">${escHtml(w.name)}</td>` +
                `<td class="px-4 py-3 text-xs">${scope}</td>` +
                `<td class="px-4 py-3">${daysBadges(w.days)}</td>` +
                `<td class="px-4 py-3 font-mono text-xs">${escHtml(w.start_time)} → ${escHtml(w.end_time)}</td>` +
                `<td class="px-4 py-3">${statusPill}</td>` +
                `<td class="px-4 py-3 text-right"></td>`;
            const cell = tr.lastElementChild;
            const tg = document.createElement('button');
            tg.className = 'text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 mr-2';
            tg.textContent = w.enabled ? __('maint.disable') : __('maint.enable');
            tg.addEventListener('click', () => toggle(w.id, !w.enabled));
            const del = document.createElement('button');
            del.className = 'text-xs px-2 py-1 rounded bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300';
            del.textContent = __('maint.delete');
            del.addEventListener('click', () => remove(w.id, w.name));
            cell.appendChild(tg); cell.appendChild(del);
            tb.appendChild(tr);
        }
    }

    async function load() {
        const res = await api('/maintenance/windows');
        if (!res.ok || !res.body || !res.body.success) { notify(__('maint.err_load'), 'error'); return; }
        render(res.body.windows || []);
    }

    async function toggle(id, enabled) {
        const res = await api('/maintenance/windows/' + id, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled }),
        });
        if (res.ok && res.body && res.body.success) load(); else notify(__('maint.err_save'), 'error');
    }

    async function remove(id, name) {
        if (!confirm(__('maint.confirm_delete').replace(':name', name))) return;
        const res = await api('/maintenance/windows/' + id, { method: 'DELETE' });
        if (res.ok && res.body && res.body.success) { notify(__('maint.deleted'), 'success'); load(); }
        else notify(__('maint.err_save'), 'error');
    }

    async function save() {
        const name = (document.getElementById('w-name').value || '').trim();
        if (!name) { notify(__('maint.err_name'), 'error'); return; }
        const scope = document.getElementById('w-scope').value;
        const days = Array.from(document.querySelectorAll('.wd:checked')).map(c => parseInt(c.value));
        if (!days.length) { notify(__('maint.err_days'), 'error'); return; }
        const payload = {
            name, scope,
            machine_id: scope === 'machine' ? parseInt(document.getElementById('w-machine').value) : null,
            days,
            start_time: document.getElementById('w-start').value,
            end_time: document.getElementById('w-end').value,
            enabled: document.getElementById('w-enabled').checked,
        };
        const res = await api('/maintenance/windows', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok && res.body && res.body.success) { notify(__('maint.saved'), 'success'); closeForm(); load(); }
        else notify((res.body && res.body.message) || __('maint.err_save'), 'error');
    }

    function openForm() { document.getElementById('win-form').classList.remove('hidden'); }
    function closeForm() { document.getElementById('win-form').classList.add('hidden'); document.getElementById('w-name').value = ''; }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('new-win-btn').addEventListener('click', openForm);
        document.getElementById('w-cancel').addEventListener('click', closeForm);
        document.getElementById('w-save').addEventListener('click', save);
        document.getElementById('w-scope').addEventListener('change', (e) => {
            document.getElementById('w-machine-wrap').classList.toggle('hidden', e.target.value !== 'machine');
        });
        load();
    });
})();
