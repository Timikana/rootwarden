/**
 * profiles.js - Gestion des profils de supervision (catalogue metadata).
 *
 * Chaque profil = un preset (HostMetadata, Server, ServerActive, proxy, TLS)
 * applique a une ou plusieurs machines. L'admin definit le catalogue une fois,
 * les autres admins assignent chaque serveur via un dropdown.
 *
 * Cote backend : routes /supervision/profiles (CRUD) + /supervision/machines/<id>/profile.
 */

const API = window.API_URL || '/api_proxy.php';

async function loadProfiles() {
    const platform = document.getElementById('agent-platform')?.value || 'zabbix';
    try {
        const r = await fetch(`${API}/supervision/profiles?platform=${encodeURIComponent(platform)}`);
        const d = await r.json();
        const tbody = document.getElementById('profiles-tbody');
        const empty = document.getElementById('profiles-empty');
        if (!tbody) return;
        tbody.innerHTML = '';
        const profiles = d.profiles || [];
        if (!profiles.length) {
            empty?.classList.remove('hidden');
            return;
        }
        empty?.classList.add('hidden');
        profiles.forEach(p => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/40';
            tr.innerHTML = `
                <td class="py-2 font-mono text-sm">${escapeHtml(p.name)}
                    ${p.description ? `<div class="text-xs text-gray-400">${escapeHtml(p.description)}</div>` : ''}
                </td>
                <td class="py-2 font-mono text-xs">${escapeHtml(p.host_metadata || '')}</td>
                <td class="py-2 text-xs">${escapeHtml(p.zabbix_server || '-')}</td>
                <td class="py-2 text-xs">${escapeHtml(p.zabbix_proxy || '-')}</td>
                <td class="py-2 text-center">
                    <span class="px-2 py-0.5 rounded-full text-xs ${p.machine_count > 0 ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300' : 'bg-gray-100 dark:bg-gray-700 text-gray-400'}">${p.machine_count}</span>
                </td>
                <td class="py-2 text-right">
                    <button onclick='editProfile(${JSON.stringify(p).replace(/'/g, "&apos;")})'
                            class="text-xs px-2 py-1 text-blue-600 hover:underline">Editer</button>
                    <button onclick="deleteProfile(${p.id}, '${escapeAttr(p.name)}')"
                            class="text-xs px-2 py-1 text-red-600 hover:underline">Supprimer</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('loadProfiles', e);
    }
}

function openProfileDialog() {
    document.getElementById('profile-id').value = '';
    ['name', 'description', 'host-metadata', 'server', 'server-active', 'proxy', 'listen-port', 'notes']
        .forEach(k => { const el = document.getElementById('profile-' + k); if (el) el.value = ''; });
    document.getElementById('profile-dialog-title').textContent = 'Nouveau profil';
    document.getElementById('profile-dialog').classList.remove('hidden');
}

function closeProfileDialog() {
    document.getElementById('profile-dialog').classList.add('hidden');
}

function editProfile(p) {
    document.getElementById('profile-id').value = p.id;
    document.getElementById('profile-name').value = p.name || '';
    document.getElementById('profile-description').value = p.description || '';
    document.getElementById('profile-host-metadata').value = p.host_metadata || '';
    document.getElementById('profile-server').value = p.zabbix_server || '';
    document.getElementById('profile-server-active').value = p.zabbix_server_active || '';
    document.getElementById('profile-proxy').value = p.zabbix_proxy || '';
    document.getElementById('profile-listen-port').value = p.listen_port || '';
    document.getElementById('profile-notes').value = p.notes || '';
    document.getElementById('profile-dialog-title').textContent = 'Editer profil : ' + p.name;
    document.getElementById('profile-dialog').classList.remove('hidden');
}

async function saveProfile() {
    const id = document.getElementById('profile-id').value;
    const platform = document.getElementById('agent-platform')?.value || 'zabbix';
    const payload = {
        platform,
        name: document.getElementById('profile-name').value.trim(),
        description: document.getElementById('profile-description').value.trim(),
        host_metadata: document.getElementById('profile-host-metadata').value.trim(),
        zabbix_server: document.getElementById('profile-server').value.trim(),
        zabbix_server_active: document.getElementById('profile-server-active').value.trim(),
        zabbix_proxy: document.getElementById('profile-proxy').value.trim(),
        listen_port: document.getElementById('profile-listen-port').value || null,
        notes: document.getElementById('profile-notes').value,
    };
    if (id) payload.id = parseInt(id, 10);
    if (!payload.name) { alert('Le nom est obligatoire.'); return; }
    try {
        const r = await fetch(`${API}/supervision/profiles`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const d = await r.json();
        if (!d.success) { alert(d.message || 'Erreur'); return; }
        closeProfileDialog();
        loadProfiles();
    } catch (e) { alert('Erreur reseau'); }
}

async function deleteProfile(id, name) {
    if (!confirm(`Supprimer le profil "${name}" ? Les serveurs assignes perdront leur profil.`)) return;
    try {
        const r = await fetch(`${API}/supervision/profiles/${id}`, { method: 'DELETE' });
        const d = await r.json();
        if (!d.success) { alert(d.message || 'Erreur'); return; }
        loadProfiles();
    } catch (e) { alert('Erreur reseau'); }
}

async function assignProfileToMachine(machineId, profileId) {
    const platform = document.getElementById('agent-platform')?.value || 'zabbix';
    const url = `${API}/supervision/machines/${machineId}/profile?platform=${platform}`;
    try {
        if (!profileId) {
            await fetch(url, { method: 'DELETE' });
        } else {
            await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ profile_id: parseInt(profileId, 10) }),
            });
        }
    } catch (e) { console.error(e); }
}

function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

function escapeAttr(s) { return String(s || '').replace(/'/g, "\\'"); }

// Hook onglet profiles : charge a l'activation
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tab="profiles"]').forEach(btn => {
        btn.addEventListener('click', () => setTimeout(loadProfiles, 50));
    });
    // Rafraichit sur changement de plateforme
    const sel = document.getElementById('agent-platform');
    if (sel) {
        sel.addEventListener('change', () => {
            if (document.getElementById('tab-profiles')?.classList.contains('active')) {
                loadProfiles();
            }
        });
    }
});
