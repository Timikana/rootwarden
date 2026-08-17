/**
 * groups/js/main.js - UI des groupes de machines + actions de masse.
 * CRUD des groupes (dynamiques/statiques) + declenchement d'operations de masse
 * (scan derive, scan CVE) suivies dans le centre de taches.
 * Rendu sans onclick interpole (addEventListener + textContent) -> pas de DOM-XSS.
 */
(function () {
    const API = window.API_URL || '/api_proxy.php';
    function __(k) { return (window._i18n && (window._i18n['js.' + k] || window._i18n[k])) || k; }
    function escHtml(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    function notify(msg, type) { if (window.toast) window.toast(msg, type || 'info'); }

    let editingId = null; // null = creation, sinon edition

    async function api(path, opts) {
        const r = await fetch(API + path, opts || {});
        let j = null; try { j = await r.json(); } catch (e) {}
        return { ok: r.ok, status: r.status, body: j };
    }

    function filtersSummary(f) {
        if (!f || typeof f !== 'object') return '';
        const parts = [];
        for (const k of ['environment', 'criticality', 'network_type', 'lifecycle_status', 'tags']) {
            if (Array.isArray(f[k]) && f[k].length) parts.push(escHtml(f[k].join(', ')));
        }
        return parts.join(' · ');
    }

    function renderGroups(groups) {
        const wrap = document.getElementById('groups-list');
        wrap.innerHTML = '';
        if (!groups.length) {
            wrap.innerHTML = `<div class="col-span-full text-center text-gray-400 py-8">${escHtml(__('groups.empty'))}</div>`;
            return;
        }
        for (const g of groups) {
            const card = document.createElement('div');
            card.className = 'bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 flex flex-col gap-2';
            const typeLbl = g.group_type === 'static' ? __('groups.type_static') : __('groups.type_dynamic');
            card.innerHTML =
                `<div class="flex items-start justify-between gap-2">
                    <div>
                        <div class="font-semibold">${escHtml(g.name)}</div>
                        <div class="text-xs text-gray-400">${escHtml(g.description || '')}</div>
                    </div>
                    <span class="text-[10px] px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">${escHtml(typeLbl)}</span>
                 </div>
                 <div class="text-xs text-gray-500 dark:text-gray-400">${escHtml(__('groups.members'))} : <strong>${Number(g.member_count || 0)}</strong></div>
                 <div class="text-[11px] text-gray-400 min-h-[16px]">${g.group_type === 'dynamic' ? filtersSummary(g.filters) : ''}</div>`;

            const actions = document.createElement('div');
            actions.className = 'flex flex-wrap gap-2 mt-1';
            const mk = (label, cls, fn, tip) => { const b = document.createElement('button'); b.className = 'text-xs px-2.5 py-1 rounded-lg ' + cls; b.textContent = label; if (tip) b.title = tip; b.addEventListener('click', () => fn(b)); return b; };

            actions.appendChild(mk(__('groups.act_members'), 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200', () => showMembers(g.id, g.name), __('groups.tip_members')));
            actions.appendChild(mk(__('groups.act_drift'), 'bg-indigo-600 text-white hover:bg-indigo-700', (b) => runAction(g.id, 'drift_scan', b), __('groups.tip_drift')));
            actions.appendChild(mk(__('groups.act_cve'), 'bg-amber-600 text-white hover:bg-amber-700', (b) => runAction(g.id, 'cve_scan', b), __('groups.tip_cve')));
            actions.appendChild(mk(__('groups.act_delete'), 'bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300 hover:bg-rose-200', (b) => removeGroup(g.id, g.name), __('groups.tip_delete')));
            card.appendChild(actions);

            const membersBox = document.createElement('div');
            membersBox.id = 'members-' + g.id;
            membersBox.className = 'hidden text-xs text-gray-600 dark:text-gray-300 border-t border-gray-100 dark:border-gray-700 pt-2 mt-1 max-h-40 overflow-y-auto';
            card.appendChild(membersBox);

            wrap.appendChild(card);
        }
    }

    async function load() {
        const res = await api('/groups');
        if (!res.ok || !res.body || !res.body.success) { notify(__('groups.err_load'), 'error'); return; }
        renderGroups(res.body.groups || []);
    }

    async function showMembers(id, name) {
        const box = document.getElementById('members-' + id);
        if (!box) return;
        if (!box.classList.contains('hidden')) { box.classList.add('hidden'); return; }
        box.classList.remove('hidden');
        box.textContent = '…';
        const res = await api('/groups/' + id + '/members');
        if (!res.ok || !res.body || !res.body.success) { box.textContent = __('groups.err_load'); return; }
        const members = res.body.members || [];
        if (!members.length) { box.textContent = __('groups.empty_members'); return; }
        box.innerHTML = members.map(m =>
            `<div class="py-0.5 flex justify-between gap-2"><span>${escHtml(m.name)}</span>
             <span class="text-gray-400">${escHtml([m.environment, m.criticality].filter(Boolean).join(' / '))}</span></div>`
        ).join('');
    }

    async function runAction(id, action, btn) {
        const label = action === 'cve_scan' ? __('groups.act_cve') : __('groups.act_drift');
        if (!confirm(__('groups.confirm_run').replace(':action', label))) return;
        if (btn) { btn.disabled = true; }
        const res = await api('/groups/' + id + '/run', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
        });
        if (btn) { btn.disabled = false; }
        if (res.ok && res.body && res.body.success) {
            notify(__('groups.queued').replace(':n', res.body.queued || 0), 'success');
        } else {
            notify((res.body && res.body.message) || __('groups.err_run'), 'error');
        }
    }

    async function removeGroup(id, name) {
        if (!confirm(__('groups.confirm_delete').replace(':name', name))) return;
        const res = await api('/groups/' + id, { method: 'DELETE' });
        if (res.ok && res.body && res.body.success) { notify(__('groups.deleted'), 'success'); load(); }
        else notify(__('groups.err_run'), 'error');
    }

    function collectFilters() {
        const f = {};
        document.querySelectorAll('.gf:checked').forEach(cb => {
            (f[cb.dataset.col] = f[cb.dataset.col] || []).push(cb.value);
        });
        const tags = (document.getElementById('g-tags').value || '').split(',').map(s => s.trim()).filter(Boolean);
        if (tags.length) f.tags = tags;
        return f;
    }

    function toggleType() {
        const type = document.querySelector('input[name="g-type"]:checked').value;
        document.getElementById('g-dynamic').classList.toggle('hidden', type !== 'dynamic');
        document.getElementById('g-static').classList.toggle('hidden', type !== 'static');
    }

    function openForm() { document.getElementById('group-form').classList.remove('hidden'); }
    function closeForm() {
        const f = document.getElementById('group-form');
        f.classList.add('hidden');
        document.getElementById('g-name').value = '';
        document.getElementById('g-desc').value = '';
        document.getElementById('g-tags').value = '';
        f.querySelectorAll('.gf:checked, .gm:checked').forEach(cb => cb.checked = false);
        editingId = null;
    }

    async function save() {
        const name = (document.getElementById('g-name').value || '').trim();
        if (!name) { notify(__('groups.err_name'), 'error'); return; }
        const type = document.querySelector('input[name="g-type"]:checked').value;
        const payload = {
            name,
            description: document.getElementById('g-desc').value || '',
            group_type: type,
            filters: type === 'dynamic' ? collectFilters() : {},
            member_ids: type === 'static'
                ? Array.from(document.querySelectorAll('.gm:checked')).map(cb => parseInt(cb.value))
                : [],
        };
        const res = await api('/groups', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok && res.body && res.body.success) { notify(__('groups.saved'), 'success'); closeForm(); load(); }
        else notify((res.body && res.body.message) || __('groups.err_save'), 'error');
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('new-group-btn').addEventListener('click', openForm);
        document.getElementById('g-cancel').addEventListener('click', closeForm);
        document.getElementById('g-save').addEventListener('click', save);
        document.querySelectorAll('input[name="g-type"]').forEach(r => r.addEventListener('change', toggleType));
        load();
    });
})();
