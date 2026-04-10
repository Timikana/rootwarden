// fail2banManager.js — Interactions JS pour la page Fail2ban
const API = window.API_URL || '/api_proxy.php';
let _currentJail = null;
let _currentServer = null;

// ── Helpers ──────────────────────────────────────────────────────────────────

function getServer() {
    const sel = document.getElementById('server');
    if (!sel || !sel.value) {
        toast(__('select_server'), 'warning');
        return null;
    }
    try { return JSON.parse(sel.value); }
    catch { toast(__('invalid_server'), 'error'); return null; }
}

function serverPayload(srv, extra = {}) {
    return {
        machine_id: srv.id,
        ...extra
    };
}

function appendLog(msg) {
    const c = document.getElementById('logs-container');
    if (!c) return;
    const p = document.createElement('p');
    p.textContent = msg;
    c.appendChild(p);
    c.scrollTop = c.scrollHeight;
}

function clearLogs() {
    const c = document.getElementById('logs-container');
    if (c) c.innerHTML = '';
}

async function apiPost(endpoint, body) {
    const r = await fetch(`${API}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return r.json();
}

async function apiGet(endpoint) {
    const r = await fetch(`${API}${endpoint}`);
    return r.json();
}

// ── Charger le statut ────────────────────────────────────────────────────────

async function loadStatus() {
    const srv = getServer();
    if (!srv) return;
    _currentServer = srv;

    clearLogs();
    appendLog(__('f2b_loading_status', {server: srv.name}));

    try {
        const d = await apiPost('/fail2ban/status', serverPayload(srv));
        if (!d.success) { appendLog(__('error_with_msg', {msg: d.message})); return; }

        const container = document.getElementById('status-container');
        container.classList.remove('hidden');

        // Badge
        const badge = document.getElementById('f2b-badge');
        if (!d.installed) {
            badge.textContent = __('f2b_not_installed');
            badge.className = 'px-3 py-1 rounded-full text-xs font-bold bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300';
            document.getElementById('btn-install').classList.remove('hidden');
            document.getElementById('btn-install-all').classList.remove('hidden');
            document.getElementById('btn-restart').classList.add('hidden');
            document.getElementById('btn-config').classList.add('hidden');
            document.getElementById('btn-logs').classList.add('hidden');
        } else if (!d.running) {
            badge.textContent = __('f2b_stopped');
            badge.className = 'px-3 py-1 rounded-full text-xs font-bold bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300';
            document.getElementById('btn-install').classList.add('hidden');
            document.getElementById('btn-install-all').classList.add('hidden');
            document.getElementById('btn-restart').classList.remove('hidden');
            document.getElementById('btn-config').classList.remove('hidden');
            document.getElementById('btn-logs').classList.remove('hidden');
        } else {
            badge.textContent = __('f2b_active');
            badge.className = 'px-3 py-1 rounded-full text-xs font-bold bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300';
            document.getElementById('btn-install').classList.add('hidden');
            document.getElementById('btn-install-all').classList.add('hidden');
            document.getElementById('btn-restart').classList.remove('hidden');
            document.getElementById('btn-config').classList.remove('hidden');
            document.getElementById('btn-logs').classList.remove('hidden');
        }

        // Jail cards
        const grid = document.getElementById('jails-grid');
        grid.innerHTML = '';
        if (d.jails && d.jails.length > 0) {
            d.jails.forEach(j => {
                const card = document.createElement('div');
                card.className = 'bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-xl p-4 cursor-pointer hover:shadow-md transition-shadow';
                card.onclick = () => loadJailDetail(j.name);
                const banColor = j.currently_banned > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400';
                card.innerHTML = `
                    <div class="text-sm font-semibold text-gray-800 dark:text-gray-200 mb-2">${escHtml(j.name)}</div>
                    <div class="text-3xl font-bold ${banColor}">${j.currently_banned}</div>
                    <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">${__('f2b_currently_banned')}</div>
                    <div class="text-xs text-gray-400 mt-1">${__('f2b_total', {count: j.total_banned})}</div>
                `;
                grid.appendChild(card);
            });
            appendLog(__('f2b_jails_found', {jails: d.jails.length, ips: d.jails.reduce((a, j) => a + j.currently_banned, 0)}));
        } else {
            grid.innerHTML = '<p class="text-sm text-gray-400 col-span-3">' + __('f2b_no_active_jail') + '</p>';
            appendLog(__('f2b_no_active_jail'));
        }

        // Charger historique + services + whitelist + stats
        loadHistory(srv.id);
        loadStats(srv.id);
        if (d.installed) {
            loadServices();
            loadWhitelist();
        }

    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

// ── Detail d'un jail ─────────────────────────────────────────────────────────

async function loadJailDetail(jail) {
    if (!_currentServer) return;
    _currentJail = jail;

    appendLog(__('f2b_loading_jail', {jail}));

    try {
        const d = await apiPost('/fail2ban/jail', serverPayload(_currentServer, { jail }));
        if (!d.success) { appendLog(__('error_with_msg', {msg: d.message})); return; }

        const panel = document.getElementById('jail-detail');
        panel.classList.remove('hidden');
        document.getElementById('jail-name').textContent = jail;

        // Config
        if (d.config) {
            document.getElementById('cfg-maxretry').textContent = d.config.maxretry ?? '-';
            document.getElementById('cfg-bantime').textContent = d.config.bantime ?? '-';
            document.getElementById('cfg-findtime').textContent = d.config.findtime ?? '-';
        }

        // IPs bannies
        const tbody = document.getElementById('banned-ips-table');
        const noMsg = document.getElementById('no-bans-msg');
        tbody.innerHTML = '';
        if (d.banned_ips && d.banned_ips.length > 0) {
            noMsg.classList.add('hidden');
            d.banned_ips.forEach(ip => {
                const tr = document.createElement('tr');
                tr.className = 'border-b border-gray-100 dark:border-gray-700';
                tr.innerHTML = `
                    <td class="py-2 px-3 font-mono text-sm">${escHtml(ip)}</td>
                    <td class="py-2 px-3 text-xs" id="geo-${escAttr(ip)}"><span class="text-gray-400">...</span></td>
                    <td class="py-2 px-3 text-right">
                        <button onclick="unbanIp('${escAttr(jail)}', '${escAttr(ip)}')"
                                class="text-xs px-2 py-1 bg-green-600 hover:bg-green-700 text-white rounded transition-colors">
                            Unban
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
            // Lazy GeoIP lookup
            d.banned_ips.forEach(ip => loadGeoIp(ip));
        } else {
            noMsg.classList.remove('hidden');
        }

        appendLog(__('f2b_jail_summary', {jail, banned: d.currently_banned, total: d.total_banned}));

    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

// ── Actions ──────────────────────────────────────────────────────────────────

async function installFail2ban() {
    const srv = getServer();
    if (!srv) return;
    if (!confirm(__('f2b_confirm_install', {server: srv.name}))) return;

    clearLogs();
    appendLog(__('f2b_installing'));

    try {
        const d = await apiPost('/fail2ban/install', serverPayload(srv));
        if (d.output) d.output.split('\n').forEach(l => { if (l.trim()) appendLog(l); });
        appendLog(d.success ? __('f2b_install_done') : __('f2b_failure', {msg: d.message}));
        if (d.success) loadStatus();
    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

async function restartFail2ban() {
    const srv = getServer();
    if (!srv) return;

    appendLog(__('f2b_restarting'));
    try {
        const d = await apiPost('/fail2ban/restart', serverPayload(srv));
        appendLog(d.success ? __('f2b_restarted') : __('error_with_msg', {msg: d.message}));
        if (d.success) setTimeout(loadStatus, 1000);
    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

function banIpFromForm() {
    const ip = document.getElementById('ban-ip-input').value.trim();
    if (!ip) { toast(__('enter_ip'), 'warning'); return; }
    if (!_currentJail) return;
    banIp(_currentJail, ip);
}

async function banIp(jail, ip) {
    if (!_currentServer) return;
    if (!confirm(__('f2b_confirm_ban', {ip, jail, server: _currentServer.name}))) return;

    appendLog(__('f2b_banning', {ip, jail}));
    try {
        const d = await apiPost('/fail2ban/ban', serverPayload(_currentServer, { jail, ip }));
        appendLog(d.success ? d.message : __('error_with_msg', {msg: d.message}));
        if (d.success) {
            document.getElementById('ban-ip-input').value = '';
            loadJailDetail(jail);
        }
    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

async function unbanIp(jail, ip) {
    if (!_currentServer) return;
    if (!confirm(__('f2b_confirm_unban', {ip, jail, server: _currentServer.name}))) return;

    appendLog(__('f2b_unbanning', {ip, jail}));
    try {
        const d = await apiPost('/fail2ban/unban', serverPayload(_currentServer, { jail, ip }));
        appendLog(d.success ? d.message : __('error_with_msg', {msg: d.message}));
        if (d.success) loadJailDetail(jail);
    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

async function loadConfig() {
    const srv = getServer();
    if (!srv) return;

    appendLog(__('f2b_loading_config'));
    try {
        const d = await apiPost('/fail2ban/config', serverPayload(srv));
        if (!d.success) { appendLog(__('error_with_msg', {msg: d.message})); return; }
        document.getElementById('config-viewer').classList.remove('hidden');
        document.getElementById('jail-config-content').textContent = d.config;
        appendLog(__('f2b_config_loaded'));
    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

// ── Historique ───────────────────────────────────────────────────────────────

async function loadHistory(serverId) {
    if (!serverId) return;
    try {
        const d = await apiGet(`/fail2ban/history?server_id=${serverId}`);
        if (!d.success || !d.history || d.history.length === 0) return;

        document.getElementById('history-section').classList.remove('hidden');
        const tbody = document.getElementById('history-table');
        tbody.innerHTML = '';
        d.history.forEach(h => {
            const tr = document.createElement('tr');
            tr.className = 'border-b border-gray-100 dark:border-gray-700';
            const actionCls = h.action === 'ban'
                ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
                : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300';
            const date = h.created_at ? new Date(h.created_at).toLocaleString('fr-FR') : '-';
            tr.innerHTML = `
                <td class="py-2 px-3 text-xs text-gray-500">${escHtml(date)}</td>
                <td class="py-2 px-3 text-xs font-medium">${escHtml(h.jail)}</td>
                <td class="py-2 px-3 font-mono text-xs">${escHtml(h.ip_address)}</td>
                <td class="py-2 px-3"><span class="px-2 py-0.5 rounded-full text-xs font-bold ${actionCls}">${escHtml(h.action)}</span></td>
                <td class="py-2 px-3 text-xs text-gray-500">${escHtml(h.performed_by)}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (_) {}
}

// ── Services detectes & gestion jails ────────────────────────────────────────

const SERVICE_ICONS = {
    sshd: 'SSH', vsftpd: 'FTP', proftpd: 'FTP', 'pure-ftpd': 'FTP',
    apache2: 'Apache', nginx: 'Nginx', postfix: 'Mail', dovecot: 'Mail',
};

async function loadServices() {
    if (!_currentServer) return;
    appendLog(__('f2b_detecting_services'));

    try {
        const d = await apiPost('/fail2ban/services', serverPayload(_currentServer));
        if (!d.success) { appendLog(__('error_with_msg', {msg: d.message})); return; }

        document.getElementById('services-panel').classList.remove('hidden');
        const grid = document.getElementById('services-grid');
        grid.innerHTML = '';

        d.services.forEach(svc => {
            const div = document.createElement('div');
            div.className = 'flex items-center justify-between p-3 rounded-lg border ' +
                (svc.installed
                    ? 'border-gray-200 dark:border-gray-600 bg-white dark:bg-gray-700'
                    : 'border-gray-100 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 opacity-50');

            const label = SERVICE_ICONS[svc.service] || svc.service;
            let jailsHtml = '';
            svc.jails.forEach(j => {
                if (svc.installed) {
                    if (j.enabled) {
                        jailsHtml += `
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300">
                                ${escHtml(j.name)}
                                <button onclick="disableJail('${escAttr(j.name)}')" class="ml-1 text-red-500 hover:text-red-700" title="${__('f2b_disable')}">&times;</button>
                            </span>`;
                    } else {
                        jailsHtml += `
                            <button onclick="openJailModal('${escAttr(j.name)}')"
                                    class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-600 text-gray-500 dark:text-gray-300 hover:bg-green-100 hover:text-green-700 transition-colors"
                                    title="${__('f2b_click_to_enable')}">
                                ${escHtml(j.name)} +
                            </button>`;
                    }
                } else {
                    jailsHtml += `<span class="text-xs text-gray-400">${escHtml(j.name)}</span>`;
                }
            });

            div.innerHTML = `
                <div class="flex items-center gap-3">
                    <span class="text-sm font-semibold w-20 ${svc.installed ? 'text-gray-800 dark:text-gray-200' : 'text-gray-400'}">${escHtml(label)}</span>
                    <span class="text-xs ${svc.installed ? 'text-green-600' : 'text-gray-400'}">${svc.installed ? __('f2b_installed') : __('f2b_not_installed')}</span>
                </div>
                <div class="flex flex-wrap gap-1">${jailsHtml}</div>
            `;
            grid.appendChild(div);
        });

        const installed = d.services.filter(s => s.installed).length;
        const enabled = d.services.flatMap(s => s.jails).filter(j => j.enabled).length;
        appendLog(__('f2b_services_detected', {installed, enabled}));

    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

let _pendingJail = null;

function openJailModal(jail) {
    _pendingJail = jail;
    document.getElementById('modal-jail-name').textContent = jail;
    document.getElementById('modal-maxretry').value = 5;
    document.getElementById('modal-bantime').value = 3600;
    document.getElementById('modal-findtime').value = 600;
    document.getElementById('jail-config-modal').classList.remove('hidden');
}

function closeJailModal() {
    document.getElementById('jail-config-modal').classList.add('hidden');
    _pendingJail = null;
}

async function submitEnableJail() {
    if (!_pendingJail || !_currentServer) return;
    const jail = _pendingJail;
    const maxretry = parseInt(document.getElementById('modal-maxretry').value) || 5;
    const bantime = parseInt(document.getElementById('modal-bantime').value) || 3600;
    const findtime = parseInt(document.getElementById('modal-findtime').value) || 600;

    closeJailModal();
    appendLog(__('f2b_enabling_jail', {jail}));

    try {
        const d = await apiPost('/fail2ban/enable_jail', serverPayload(_currentServer, {
            jail, maxretry, bantime, findtime
        }));
        appendLog(d.success ? d.message : __('error_with_msg', {msg: d.message}));
        if (d.success) { loadStatus(); loadServices(); }
    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

async function disableJail(jail) {
    if (!_currentServer) return;
    if (!confirm(__('f2b_confirm_disable_jail', {jail, server: _currentServer.name}))) return;

    appendLog(__('f2b_disabling_jail', {jail}));
    try {
        const d = await apiPost('/fail2ban/disable_jail', serverPayload(_currentServer, { jail }));
        appendLog(d.success ? d.message : __('error_with_msg', {msg: d.message}));
        if (d.success) { loadStatus(); loadServices(); }
    } catch (e) {
        appendLog(__('exception_with_msg', {msg: e}));
    }
}

// ── Whitelist ────────────────────────────────────────────────────────────────

async function loadWhitelist() {
    if (!_currentServer) return;
    try {
        const d = await apiPost('/fail2ban/whitelist', serverPayload(_currentServer, { action: 'list' }));
        if (!d.success) return;
        document.getElementById('whitelist-section').classList.remove('hidden');
        const list = document.getElementById('whitelist-list');
        list.innerHTML = '';
        (d.ips || []).forEach(ip => {
            const span = document.createElement('span');
            span.className = 'inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300';
            span.innerHTML = `${escHtml(ip)} <button onclick="removeWhitelistIp('${escAttr(ip)}')" class="ml-1 text-red-500 hover:text-red-700">&times;</button>`;
            list.appendChild(span);
        });
    } catch (_) {}
}

async function addWhitelistIp() {
    const ip = document.getElementById('whitelist-ip-input').value.trim();
    if (!ip) { toast(__('enter_ip'), 'warning'); return; }
    if (!_currentServer) return;
    appendLog(__('f2b_whitelist_adding', {ip}));
    try {
        const d = await apiPost('/fail2ban/whitelist', serverPayload(_currentServer, { action: 'add', ip }));
        appendLog(d.success ? d.message : __('error_with_msg', {msg: d.message}));
        if (d.success) { document.getElementById('whitelist-ip-input').value = ''; loadWhitelist(); }
    } catch (e) { appendLog(__('exception_with_msg', {msg: e})); }
}

async function removeWhitelistIp(ip) {
    if (!_currentServer) return;
    if (!confirm(__('f2b_confirm_remove_whitelist', {ip, server: _currentServer.name}))) return;
    try {
        const d = await apiPost('/fail2ban/whitelist', serverPayload(_currentServer, { action: 'remove', ip }));
        appendLog(d.success ? d.message : __('error_with_msg', {msg: d.message}));
        if (d.success) loadWhitelist();
    } catch (e) { appendLog(__('exception_with_msg', {msg: e})); }
}

// ── Unban All ────────────────────────────────────────────────────────────────

async function unbanAllIps() {
    if (!_currentServer || !_currentJail) return;
    if (!confirm(__('f2b_confirm_unban_all', {jail: _currentJail, server: _currentServer.name}))) return;
    appendLog(__('f2b_unbanning_all', {jail: _currentJail}));
    try {
        const d = await apiPost('/fail2ban/unban_all', serverPayload(_currentServer, { jail: _currentJail }));
        appendLog(d.success ? d.message : __('error_with_msg', {msg: d.message}));
        if (d.success) loadJailDetail(_currentJail);
    } catch (e) { appendLog(__('exception_with_msg', {msg: e})); }
}

// ── Ban all servers ──────────────────────────────────────────────────────────

async function banIpAllServers() {
    const ip = document.getElementById('ban-ip-input').value.trim();
    if (!ip) { toast(__('enter_ip'), 'warning'); return; }
    if (!_currentJail) return;
    if (!confirm(__('f2b_confirm_ban_all_servers', {ip, jail: _currentJail}))) return;
    appendLog(__('f2b_ban_global', {ip}));
    try {
        const d = await apiPost('/fail2ban/ban_all_servers', { ip, jail: _currentJail });
        appendLog(d.message);
        if (d.results) d.results.forEach(r => {
            appendLog(`  ${r.server}: ${r.success ? 'OK' : __('failure') + ' ' + (r.error || '')}`);
        });
        document.getElementById('ban-ip-input').value = '';
    } catch (e) { appendLog(__('exception_with_msg', {msg: e})); }
}

// ── Install all ──────────────────────────────────────────────────────────────

async function installAllFail2ban() {
    if (!confirm(__('f2b_confirm_install_all'))) return;
    clearLogs();
    appendLog(__('f2b_installing_all'));
    try {
        const d = await apiPost('/fail2ban/install_all', {});
        appendLog(d.message);
        if (d.results) d.results.forEach(r => {
            appendLog(`  ${r.server}: ${r.success ? 'OK' : __('failure') + ' ' + (r.error || '')}`);
        });
    } catch (e) { appendLog(__('exception_with_msg', {msg: e})); }
}

// ── Logs viewer ──────────────────────────────────────────────────────────────

async function loadF2bLogs() {
    if (!_currentServer) return;
    appendLog(__('f2b_loading_logs'));
    try {
        const d = await apiPost('/fail2ban/logs', serverPayload(_currentServer, { lines: 100 }));
        if (!d.success) { appendLog(__('error_with_msg', {msg: d.message})); return; }
        document.getElementById('f2b-logs-viewer').classList.remove('hidden');
        document.getElementById('f2b-logs-content').textContent = d.logs;
        appendLog(__('f2b_logs_loaded'));
    } catch (e) { appendLog(__('exception_with_msg', {msg: e})); }
}

// ── Templates ────────────────────────────────────────────────────────────────

const _templates = {
    permissive: { maxretry: 10, bantime: 600,   findtime: 600 },
    moderate:   { maxretry: 5,  bantime: 3600,  findtime: 600 },
    strict:     { maxretry: 3,  bantime: 86400, findtime: 3600 },
};

function applyTemplate() {
    const sel = document.getElementById('modal-template').value;
    if (sel === 'custom') return;
    const t = _templates[sel];
    if (!t) return;
    document.getElementById('modal-maxretry').value = t.maxretry;
    document.getElementById('modal-bantime').value = t.bantime;
    document.getElementById('modal-findtime').value = t.findtime;
}

// ── Stats timeline ───────────────────────────────────────────────────────────

async function loadStats(serverId) {
    if (!serverId) return;
    try {
        const d = await apiGet(`/fail2ban/stats?server_id=${serverId}&days=30`);
        if (!d.success || !d.stats || d.stats.length === 0) return;

        document.getElementById('stats-section').classList.remove('hidden');
        const chart = document.getElementById('stats-chart');
        chart.innerHTML = '';

        // Agreger par jour
        const days = {};
        d.stats.forEach(s => {
            if (!days[s.day]) days[s.day] = { ban: 0, unban: 0 };
            days[s.day][s.action] = s.count;
        });

        const maxVal = Math.max(1, ...Object.values(days).map(d => d.ban + d.unban));
        Object.entries(days).sort().forEach(([day, counts]) => {
            const h = Math.max(4, (counts.ban / maxVal) * 100);
            const bar = document.createElement('div');
            bar.className = 'flex-1 min-w-[6px] rounded-t';
            bar.style.height = h + '%';
            bar.style.background = counts.ban > 0 ? '#ef4444' : '#22c55e';
            bar.title = `${day}: ${counts.ban} ban(s), ${counts.unban} unban(s)`;
            chart.appendChild(bar);
        });
    } catch (_) {}
}

// ── GeoIP ────────────────────────────────────────────────────────────────────

const _countryFlags = {};

async function loadGeoIp(ip) {
    try {
        const d = await apiPost('/fail2ban/geoip', { ip });
        if (!d.success) return;
        const el = document.getElementById(`geo-${ip}`);
        if (el) el.innerHTML = `<span title="${escHtml(d.country)}">${countryFlag(d.countryCode)} ${escHtml(d.country)}</span>`;
    } catch (_) {}
}

function countryFlag(code) {
    if (!code || code === '??' || code === 'LO') return '';
    return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// ── Utilitaires XSS-safe ────────────────────────────────────────────────────

function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

function escAttr(s) {
    return String(s).replace(/&/g, '&amp;').replace(/'/g, '&#39;')
                     .replace(/"/g, '&quot;').replace(/</g, '&lt;')
                     .replace(/>/g, '&gt;').replace(/\\/g, '\\\\');
}
