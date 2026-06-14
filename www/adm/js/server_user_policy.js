/**
 * server_user_policy.js - Logique partagee des pages "Droits sudo" et "Acces SFTP/SSH".
 * Chaque page definit window.POL = { machineId, serverUserId, type, t:{...} }.
 * Appels via /api_proxy.php (la cle API n'est jamais exposee au DOM).
 */
(function () {
    const P = window.POL || {};
    const TYPE = P.type;            // 'sudo' | 'sftp'
    const M = P.machineId, U = P.serverUserId;
    const T = P.t || {};

    async function callApi(path, method, body) {
        const opts = { method, headers: { 'Content-Type': 'application/json' } };
        if (body) opts.body = JSON.stringify(body);
        const r = await fetch('/api_proxy.php' + path, opts);
        return await r.json();
    }
    function show(content, ok) {
        const el = document.getElementById('pol-output');
        if (!el) return;
        el.classList.remove('hidden');
        el.textContent = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
        el.classList.toggle('text-red-600', !ok);
    }
    function notifyToast(success, message) {
        if (typeof toast === 'function') toast(message || (success ? T.deploySuccess : T.deployFail), success ? 'success' : 'error', success ? 3000 : 6000);
    }

    function collectBody() {
        const body = { machine_id: M, server_user_id: U };
        if (TYPE === 'sudo') {
            body.preset = document.getElementById('sudo-preset').value;
            body.nopasswd = document.getElementById('sudo-nopasswd').checked;
            body.runas = document.getElementById('sudo-runas').value;
            if (body.preset === 'custom') body.custom_rules = document.getElementById('sudo-custom-rules').value;
            if (body.preset === 'systemctl_specific') body.services = (document.getElementById('sudo-services').value || '').split(/[,\s]+/).filter(Boolean);
        } else {
            body.sftp_only = document.getElementById('sftp-only').checked;
            body.chroot_dir = document.getElementById('sftp-chroot').value || null;
            body.working_dir = document.getElementById('sftp-working').value || null;
            body.allow_password_auth = document.getElementById('sftp-pw').checked;
            body.allow_tcp_forwarding = document.getElementById('sftp-tcp').checked;
            body.allow_agent_forwarding = document.getElementById('sftp-agent').checked;
            body.x11_forwarding = document.getElementById('sftp-x11').checked;
        }
        return body;
    }

    async function deployPolicy() {
        try {
            const data = await callApi('/policy/' + TYPE + '/deploy', 'POST', collectBody());
            show(data, data.success);
            notifyToast(data.success, data.success ? T.deploySuccess : (T.deployFail + ' : ' + (data.message || data.error || '?')));
            if (data.success) setTimeout(() => location.reload(), 1500);
        } catch (e) { show(T.netError + ' : ' + e, false); notifyToast(false, T.netError + ' : ' + e); }
    }
    async function auditPolicy() {
        try {
            const data = await callApi('/policy/' + TYPE + '/audit', 'POST', { machine_id: M, server_user_id: U });
            show(data.exists ? data.content : '(' + T.auditNotFound + ' - ' + (data.target_path || '?') + ')', data.success);
            notifyToast(data.success, data.exists ? T.auditFound : T.auditNotFound);
        } catch (e) { show(T.netError + ' : ' + e, false); notifyToast(false, T.netError + ' : ' + e); }
    }
    async function removePolicy() {
        if (!confirm(T.confirmRemove)) return;
        try {
            const data = await callApi('/policy/' + TYPE + '/remove', 'POST', { machine_id: M, server_user_id: U });
            show(data, data.success);
            notifyToast(data.success, data.success ? T.removeSuccess : (T.deployFail + ' : ' + (data.message || data.error || '?')));
            if (data.success) setTimeout(() => location.reload(), 1500);
        } catch (e) { show(T.netError + ' : ' + e, false); notifyToast(false, T.netError + ' : ' + e); }
    }

    function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
    async function loadHistory() {
        const params = new URLSearchParams({ machine_id: M, server_user_id: U, policy_type: TYPE });
        try {
            const data = await callApi('/policy/deployments?' + params.toString(), 'GET');
            const list = document.getElementById('history-list');
            if (!data.success || !data.deployments.length) { list.innerHTML = '<p class="text-sm text-gray-400">' + esc(T.historyEmpty) + '</p>'; return; }
            list.innerHTML = data.deployments.map(d => `
                <div class="border border-gray-200 dark:border-gray-700 rounded p-3 text-xs">
                    <div class="flex items-center justify-between mb-1">
                        <span class="font-mono">#${d.id} - ${esc(d.deployed_at)}</span>
                        <span class="px-2 py-0.5 rounded ${d.status === 'applied' ? 'bg-green-100 text-green-800' : d.status === 'rolled_back' ? 'bg-amber-100 text-amber-800' : d.status === 'failed' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'}">${esc(d.status)}</span>
                    </div>
                    <div class="text-gray-500 mb-1 font-mono">${esc(d.target_path)}</div>
                    ${d.rollback_reason ? `<div class="text-gray-400 italic mb-1">${esc(d.rollback_reason)}</div>` : ''}
                    ${(d.status === 'applied' || d.status === 'superseded') ? `<button data-rollback="${d.id}" class="text-blue-600 hover:underline">${esc(T.btnRollback)}</button>` : ''}
                </div>`).join('');
            list.querySelectorAll('[data-rollback]').forEach(b => b.addEventListener('click', () => rollbackTo(parseInt(b.dataset.rollback))));
        } catch (e) { document.getElementById('history-list').innerHTML = '<p class="text-red-600 text-sm">' + esc(T.netError + ' : ' + e) + '</p>'; }
    }
    async function rollbackTo(id) {
        const reason = prompt(T.rollbackReason + ' :');
        if (reason === null) return;
        if (!confirm(T.confirmRollback)) return;
        try {
            const data = await callApi('/policy/rollback', 'POST', { machine_id: M, deployment_id: id, reason });
            notifyToast(data.success, data.success ? T.deploySuccess : (T.deployFail + ' : ' + (data.message || data.error || '?')));
            if (data.success) setTimeout(() => location.reload(), 1500);
        } catch (e) { notifyToast(false, T.netError + ' : ' + e); }
    }

    function onPresetChange() {
        const sel = document.getElementById('sudo-preset');
        if (!sel) return;
        const v = sel.value;
        const cb = document.getElementById('custom-rules-block'); if (cb) cb.classList.toggle('hidden', v !== 'custom');
        const sb = document.getElementById('services-block'); if (sb) sb.classList.toggle('hidden', v !== 'systemctl_specific');
        const h = document.getElementById('preset-help'); if (h && P.presetHelp && P.presetHelp[v]) h.textContent = P.presetHelp[v];
    }

    document.addEventListener('DOMContentLoaded', () => {
        const byId = (id, ev, fn) => { const e = document.getElementById(id); if (e) e.addEventListener(ev, fn); };
        byId('sudo-preset', 'change', onPresetChange);
        byId('btn-deploy', 'click', deployPolicy);
        byId('btn-audit', 'click', auditPolicy);
        byId('btn-remove', 'click', removePolicy);
        byId('history-toggle', 'click', () => {
            const box = document.getElementById('history-box');
            if (!box) return;
            box.classList.toggle('hidden');
            if (!box.classList.contains('hidden')) loadHistory();
        });
        onPresetChange();
    });
})();
