/**
 * supervision/js/main.js — Logique JS du module Supervision.
 *
 * Gestion des onglets, configuration globale, deploiement agents,
 * editeur de config distant, backups, streaming logs.
 *
 * Dependances : window.API_URL, window.API_KEY, escHtml(), toast(), __()
 */

/* ── Echappement XSS ──────────────────────────────────────────────────────── */
function escHtmlSuper(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

/* ── Selecteur plateforme agent ─────────────────────────────────────────── */
var currentPlatform = 'zabbix';

var PLATFORM_COLORS = {
    zabbix:     { bg: 'bg-purple-600', hover: 'hover:bg-purple-700', badge: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300', letter: 'Z' },
    centreon:   { bg: 'bg-red-600',    hover: 'hover:bg-red-700',    badge: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',          letter: 'C' },
    prometheus: { bg: 'bg-orange-500',  hover: 'hover:bg-orange-600', badge: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300', letter: 'P' },
    telegraf:   { bg: 'bg-sky-600',     hover: 'hover:bg-sky-700',    badge: 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300',          letter: 'T' },
};

var CONFIG_PATHS = {
    zabbix: '/etc/zabbix/zabbix_agent2.conf',
    centreon: '/etc/centreon-monitoring-agent/centagent.yaml',
    prometheus: '/etc/default/prometheus-node-exporter',
    telegraf: '/etc/telegraf/telegraf.conf',
};

function switchAgentPlatform(platform) {
    currentPlatform = platform;
    var colors = PLATFORM_COLORS[platform] || PLATFORM_COLORS.zabbix;

    // Toggle config forms
    ['zabbix', 'centreon', 'prometheus', 'telegraf'].forEach(function(p) {
        var el = document.getElementById('config-' + p);
        if (el) el.style.display = (p === platform ? '' : 'none');
    });

    // Badge plateforme
    var badge = document.getElementById('platform-badge');
    if (badge) {
        badge.textContent = platform.toUpperCase();
        badge.className = 'px-2 py-0.5 rounded-full text-[10px] font-bold transition-colors ' + colors.badge;
    }

    // Boutons deploy : changer couleur
    document.querySelectorAll('.deploy-action-btn').forEach(function(btn) {
        btn.className = btn.className
            .replace(/bg-\w+-[56]00/g, '')
            .replace(/hover:bg-\w+-[67]00/g, '');
        btn.classList.add(colors.bg, colors.hover);
    });

    // Chemin fichier editeur
    var pathBadge = document.getElementById('editor-file-path-badge');
    if (pathBadge) pathBadge.textContent = CONFIG_PATHS[platform] || '';

    // Compteur agents
    updateAgentCounter();

    // Load config for non-zabbix
    if (platform !== 'zabbix') {
        loadPlatformConfig(platform);
    }
}

function updateAgentCounter() {
    var counter = document.getElementById('agent-counter');
    if (!counter) return;
    var total = document.querySelectorAll('#deploy-table-body tr').length;
    var count = 0;
    document.querySelectorAll('.deploy-agents').forEach(function(cell) {
        var badges = cell.querySelectorAll('span[class*="rounded-full"]');
        badges.forEach(function(b) {
            var letter = PLATFORM_COLORS[currentPlatform] ? PLATFORM_COLORS[currentPlatform].letter : '';
            if (b.textContent.trim().startsWith(letter)) count++;
        });
    });
    counter.textContent = count + '/' + total + ' avec ' + currentPlatform;
}

function scanAllAgents() {
    var rows = document.querySelectorAll('#deploy-table-body tr[data-machine-id]');
    var ids = [];
    rows.forEach(function(r) { ids.push(parseInt(r.dataset.machineId)); });
    if (ids.length === 0) return;

    toast(__('scan_all_running') || 'Scan en cours...', 'info');
    var platforms = ['zabbix', 'centreon', 'prometheus', 'telegraf'];
    var pending = 0;

    ids.forEach(function(mid) {
        platforms.forEach(function(plat) {
            pending++;
            supervisionFetch(window.API_URL + '/supervision/' + plat + '/version', { machine_id: mid })
                .then(function(res) {
                    if (res.success && res.version) {
                        updateAgentBadge(mid, plat, res.version);
                    }
                })
                .catch(function() {})
                .finally(function() {
                    pending--;
                    if (pending === 0) {
                        toast(__('scan_all_done') || 'Scan termine', 'success');
                        updateAgentCounter();
                    }
                });
        });
    });
}

function updateAgentBadge(machineId, platform, version) {
    var cell = document.querySelector('.deploy-agents[data-machine-id="' + machineId + '"]');
    if (!cell) return;
    var colors = PLATFORM_COLORS[platform] || {};
    var letter = colors.letter || '?';

    // Chercher un badge existant pour cette plateforme
    var existing = null;
    cell.querySelectorAll('span[class*="rounded-full"]').forEach(function(b) {
        if (b.textContent.trim().startsWith(letter)) existing = b;
    });

    if (version) {
        if (existing) {
            existing.textContent = letter + ' ' + version;
        } else {
            // Supprimer le "-" placeholder
            var dash = cell.querySelector('.text-gray-400');
            if (dash && dash.textContent.trim() === '-') dash.remove();
            // Creer le wrapper si absent
            var wrap = cell.querySelector('.flex');
            if (!wrap) {
                wrap = document.createElement('div');
                wrap.className = 'flex flex-wrap gap-1 justify-center';
                cell.innerHTML = '';
                cell.appendChild(wrap);
            }
            var badge = document.createElement('span');
            badge.className = 'inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-bold ' + (colors.badge || '');
            badge.textContent = letter + ' ' + version;
            wrap.appendChild(badge);
        }
    } else if (existing) {
        existing.remove();
        // Remettre "-" si plus de badge
        if (!cell.querySelector('span[class*="rounded-full"]')) {
            cell.innerHTML = '<span class="text-xs text-gray-400">-</span>';
        }
    }
}

function loadPlatformConfig(platform) {
    supervisionGet(window.API_URL + '/supervision/config/' + platform)
        .then(function(res) {
            if (!res.success || !res.config) return;
            var cfg = res.config;
            if (platform === 'centreon') {
                if (cfg.centreon_host) document.getElementById('cfg-centreon-host').value = cfg.centreon_host;
                if (cfg.centreon_port) document.getElementById('cfg-centreon-port').value = cfg.centreon_port;
                if (cfg.hostname_pattern) document.getElementById('cfg-centreon-hostname').value = cfg.hostname_pattern;
                if (cfg.extra_config) document.getElementById('cfg-centreon-extra').value = cfg.extra_config;
            } else if (platform === 'prometheus') {
                if (cfg.prometheus_listen) document.getElementById('cfg-prometheus-listen').value = cfg.prometheus_listen;
                if (cfg.hostname_pattern) document.getElementById('cfg-prometheus-hostname').value = cfg.hostname_pattern;
                if (cfg.prometheus_collectors) document.getElementById('cfg-prometheus-collectors').value = cfg.prometheus_collectors;
                if (cfg.extra_config) document.getElementById('cfg-prometheus-extra').value = cfg.extra_config;
            } else if (platform === 'telegraf') {
                if (cfg.telegraf_output_url) document.getElementById('cfg-telegraf-url').value = cfg.telegraf_output_url;
                if (cfg.telegraf_output_org) document.getElementById('cfg-telegraf-org').value = cfg.telegraf_output_org;
                if (cfg.telegraf_output_bucket) document.getElementById('cfg-telegraf-bucket').value = cfg.telegraf_output_bucket;
                if (cfg.hostname_pattern) document.getElementById('cfg-telegraf-hostname').value = cfg.hostname_pattern;
                if (cfg.telegraf_inputs) document.getElementById('cfg-telegraf-inputs').value = cfg.telegraf_inputs;
                if (cfg.extra_config) document.getElementById('cfg-telegraf-extra').value = cfg.extra_config;
            }
        }).catch(function() {});
}

function savePlatformConfig(platform) {
    var data = { hostname_pattern: '{machine.name}', extra_config: null };

    if (platform === 'centreon') {
        data.centreon_host = document.getElementById('cfg-centreon-host').value.trim();
        data.centreon_port = parseInt(document.getElementById('cfg-centreon-port').value) || 4317;
        data.hostname_pattern = document.getElementById('cfg-centreon-hostname').value.trim() || '{machine.name}';
        data.extra_config = document.getElementById('cfg-centreon-extra').value || null;
        if (!data.centreon_host) { toast('Serveur Centreon requis', 'warning'); return; }
    } else if (platform === 'prometheus') {
        data.prometheus_listen = document.getElementById('cfg-prometheus-listen').value.trim() || ':9100';
        data.hostname_pattern = document.getElementById('cfg-prometheus-hostname').value.trim() || '{machine.name}';
        data.prometheus_collectors = document.getElementById('cfg-prometheus-collectors').value.trim() || null;
        data.extra_config = document.getElementById('cfg-prometheus-extra').value || null;
    } else if (platform === 'telegraf') {
        data.telegraf_output_url = document.getElementById('cfg-telegraf-url').value.trim() || null;
        data.telegraf_output_token = document.getElementById('cfg-telegraf-token').value || null;
        data.telegraf_output_org = document.getElementById('cfg-telegraf-org').value.trim() || null;
        data.telegraf_output_bucket = document.getElementById('cfg-telegraf-bucket').value.trim() || null;
        data.hostname_pattern = document.getElementById('cfg-telegraf-hostname').value.trim() || '{machine.name}';
        data.telegraf_inputs = document.getElementById('cfg-telegraf-inputs').value.trim() || 'cpu,mem,disk,diskio,net,system';
        data.extra_config = document.getElementById('cfg-telegraf-extra').value || null;
    }

    supervisionFetch(window.API_URL + '/supervision/config/' + platform, data)
        .then(function(res) {
            if (res.success) toast('Configuration ' + platform + ' sauvegardee', 'success');
            else toast(res.message || 'Erreur', 'error');
        })
        .catch(function(err) { toast(err.message, 'error'); });
}

/* ── Onglets ───────────────────────────────────────────────────────────────── */
document.querySelectorAll('.tab-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
        document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.remove('active'); });
        btn.classList.add('active');
        var panel = document.getElementById('tab-' + btn.dataset.tab);
        if (panel) panel.classList.add('active');
    });
});

/* ── TLS toggle PSK fields ────────────────────────────────────────────────── */
['cfg-tls-connect', 'cfg-tls-accept'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) el.addEventListener('change', togglePskFields);
});

function togglePskFields() {
    var connect = document.getElementById('cfg-tls-connect').value;
    var accept = document.getElementById('cfg-tls-accept').value;
    var pskBlock = document.getElementById('psk-fields');
    if (pskBlock) {
        if (connect === 'psk' || accept === 'psk') {
            pskBlock.classList.remove('hidden');
        } else {
            pskBlock.classList.add('hidden');
        }
    }
}

/* ── Helper : POST JSON via proxy ─────────────────────────────────────────── */
function supervisionFetch(url, body, extraHeaders) {
    return fetch(url, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json', 'X-API-KEY': window.API_KEY || '' }, extraHeaders || {}),
        body: JSON.stringify(body)
    }).then(function(res) {
        if (!res.ok) {
            return res.text().then(function(txt) { throw new Error('HTTP ' + res.status + ': ' + txt.slice(0, 200)); });
        }
        return res.json();
    });
}

function supervisionGet(url) {
    return fetch(url, {
        method: 'GET',
        headers: { 'X-API-KEY': window.API_KEY || '' }
    }).then(function(res) {
        if (!res.ok) {
            return res.text().then(function(txt) { throw new Error('HTTP ' + res.status + ': ' + txt.slice(0, 200)); });
        }
        return res.json();
    });
}

/* ══════════════════════════════════════════════════════════════════════════════
   ONGLET 1 : Configuration globale
   ══════════════════════════════════════════════════════════════════════════════ */

function saveGlobalConfig() {
    var data = {
        agent_type: document.getElementById('cfg-agent-type').value,
        agent_version: document.getElementById('cfg-agent-version').value,
        zabbix_server: document.getElementById('cfg-zabbix-server').value.trim(),
        zabbix_server_active: document.getElementById('cfg-server-active').value.trim() || null,
        listen_port: parseInt(document.getElementById('cfg-listen-port').value) || 10050,
        hostname_pattern: document.getElementById('cfg-hostname-pattern').value.trim() || '{machine.name}',
        tls_connect: document.getElementById('cfg-tls-connect').value,
        tls_accept: document.getElementById('cfg-tls-accept').value,
        tls_psk_identity: document.getElementById('cfg-psk-identity').value.trim() || null,
        tls_psk_value: document.getElementById('cfg-psk-value').value || null,
        host_metadata_template: document.getElementById('cfg-host-metadata').value.trim() || null,
        extra_config: document.getElementById('cfg-extra-config').value || null
    };

    if (!data.zabbix_server) {
        toast(__('supervision.zabbix_server') + ' requis', 'warning');
        return;
    }

    supervisionFetch(window.API_URL + '/supervision/config', data)
        .then(function(res) {
            if (res.success) {
                toast(__('config_saved') || 'Configuration sauvegardee.', 'success');
            } else {
                toast(res.message || 'Erreur', 'error');
            }
        })
        .catch(function(err) { toast(err.message, 'error'); });
}

/* ══════════════════════════════════════════════════════════════════════════════
   ONGLET 2 : Deploiement
   ══════════════════════════════════════════════════════════════════════════════ */

function selectAllDeploy(checked) {
    // Ne selectionner que les lignes visibles (non filtrees)
    document.querySelectorAll('#deploy-table-body tr:not([style*="display: none"]) input[name="deploy_machines[]"]').forEach(function(cb) {
        cb.checked = checked;
    });
    updateSelectionCount();
}

function updateSelectionCount() {
    var total = document.querySelectorAll('input[name="deploy_machines[]"]').length;
    var checked = document.querySelectorAll('input[name="deploy_machines[]"]:checked').length;
    var el = document.getElementById('deploy-selection-count');
    if (el) el.textContent = checked > 0 ? checked + '/' + total : '';
}

function filterDeployTable() {
    var query = (document.getElementById('deploy-filter').value || '').toLowerCase();
    document.querySelectorAll('#deploy-table-body tr').forEach(function(row) {
        var text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    });
}

// Compteur de selection en temps reel
document.addEventListener('change', function(e) {
    if (e.target && e.target.name === 'deploy_machines[]') updateSelectionCount();
});

// Compteur agents au chargement
document.addEventListener('DOMContentLoaded', function() { updateAgentCounter(); });

function getSelectedDeployIds() {
    var ids = [];
    document.querySelectorAll('input[name="deploy_machines[]"]:checked').forEach(function(cb) {
        ids.push(parseInt(cb.value));
    });
    return ids;
}

/* ── Logs helpers ──────────────────────────────────────────────────────────── */

function clearDeployLogs() {
    var container = document.getElementById('deploy-logs-container');
    if (container) container.innerHTML = '';
    var logs = document.getElementById('deploy-logs');
    if (logs) logs.innerHTML = '';
}

function appendDeployLog(message, type, serverName) {
    var container = document.getElementById('deploy-logs-container');
    if (!container) return;

    // Trouver ou creer la fenetre du serveur
    var windowId = 'log-' + serverName.replace(/[^a-zA-Z0-9]/g, '_');
    var win = document.getElementById(windowId);
    if (!win) {
        win = document.createElement('div');
        win.id = windowId;
        win.className = 'server-log-window';
        var title = document.createElement('h3');
        title.textContent = serverName;
        win.appendChild(title);
        container.appendChild(win);
    }

    var line = document.createElement('pre');
    line.className = 'log-line';
    if (type === 'error') line.style.color = '#ef4444';
    else if (type === 'success') line.style.color = '#22c55e';
    else if (type === 'progress') line.style.color = '#eab308';
    line.textContent = message;
    win.appendChild(line);
    win.scrollTop = win.scrollHeight;
}

/* ── Streaming reader ─────────────────────────────────────────────────────── */

function streamDeploy(url, body, autoDetect) {
    clearDeployLogs();
    var successIds = [];

    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.API_KEY || '' },
        body: JSON.stringify(body)
    }).then(function(response) {
        if (!response.ok) {
            toast('Erreur HTTP ' + response.status, 'error');
            return;
        }
        var reader = response.body.getReader();
        var decoder = new TextDecoder();

        function read() {
            return reader.read().then(function(result) {
                if (result.done) {
                    // Auto-detection des versions apres deploiement reussi
                    if (autoDetect && successIds.length > 0) {
                        successIds.forEach(function(mid) { detectVersion(mid); });
                    }
                    return;
                }
                var chunk = decoder.decode(result.value, { stream: true });
                chunk.split('\n').forEach(function(line) {
                    if (!line.trim()) return;
                    var serverName = 'Global';
                    var type = 'info';
                    var msg = line;

                    if (line.startsWith('ERROR_MACHINE::')) {
                        var parts = line.split('::');
                        serverName = getServerNameById(parts[1]) || 'Machine ' + parts[1];
                        msg = parts.slice(2).join('::');
                        type = 'error';
                    } else if (line.startsWith('SUCCESS_MACHINE::')) {
                        var parts2 = line.split('::');
                        var mid = parseInt(parts2[1]);
                        if (mid) successIds.push(mid);
                        serverName = getServerNameById(parts2[1]) || 'Machine ' + parts2[1];
                        msg = parts2.slice(2).join('::');
                        type = 'success';
                    } else if (line.startsWith('START_MACHINE::')) {
                        var parts3 = line.split('::');
                        serverName = getServerNameById(parts3[1]) || 'Machine ' + parts3[1];
                        msg = parts3.slice(2).join('::');
                        type = 'info';
                    } else if (line.match(/\d+%/)) {
                        type = 'progress';
                    }

                    appendDeployLog(msg, type, serverName);
                });
                return read();
            });
        }
        return read();
    }).catch(function(err) {
        toast(err.message, 'error');
    });
}

function getServerNameById(id) {
    var row = document.querySelector('#deploy-table-body tr[data-machine-id="' + id + '"]');
    if (row) {
        var nameCell = row.querySelector('.deploy-name');
        if (nameCell) return nameCell.textContent.trim();
    }
    return null;
}

/* ── Actions ──────────────────────────────────────────────────────────────── */

function deploySelected() {
    var ids = getSelectedDeployIds();
    if (ids.length === 0) { toast(__('select_machine') || 'Selectionnez au moins un serveur.', 'warning'); return; }
    if (!confirm(__('confirm_deploy') || 'Confirmer le deploiement ?')) return;
    streamDeploy(window.API_URL + '/supervision/' + currentPlatform + '/deploy', { machine_ids: ids }, true);
}

function deploySingle(machineId) {
    if (!confirm(__('confirm_deploy') || 'Confirmer le deploiement ?')) return;
    streamDeploy(window.API_URL + '/supervision/' + currentPlatform + '/deploy', { machine_ids: [machineId] }, true);
}

function reconfigureSelected() {
    var ids = getSelectedDeployIds();
    if (ids.length === 0) { toast(__('select_machine') || 'Selectionnez au moins un serveur.', 'warning'); return; }
    streamDeploy(window.API_URL + '/supervision/' + currentPlatform + '/reconfigure', { machine_ids: ids }, false);
}

function reconfigureSingle(machineId) {
    streamDeploy(window.API_URL + '/supervision/' + currentPlatform + '/reconfigure', { machine_ids: [machineId] }, false);
}

function uninstallAgent(machineId) {
    if (!confirm(__('confirm_uninstall') || 'Confirmer la desinstallation ?')) return;
    streamDeploy(window.API_URL + '/supervision/' + currentPlatform + '/uninstall', { machine_id: machineId }, false);
}

function detectVersionSelected() {
    var ids = getSelectedDeployIds();
    if (ids.length === 0) { toast(__('select_machine') || 'Selectionnez au moins un serveur.', 'warning'); return; }
    ids.forEach(function(id) { detectVersion(id); });
}

function detectVersion(machineId) {
    supervisionFetch(window.API_URL + '/supervision/' + currentPlatform + '/version', { machine_id: machineId })
        .then(function(res) {
            if (res.success) {
                var plat = res.platform || currentPlatform;
                updateAgentBadge(machineId, plat, res.version);
                updateAgentCounter();
                toast(res.version ? plat + ' v' + res.version : plat + ' non installe', res.version ? 'success' : 'info');
            } else {
                toast(res.message || 'Erreur', 'error');
            }
        })
        .catch(function(err) { toast(err.message, 'error'); });
}

/* ══════════════════════════════════════════════════════════════════════════════
   ONGLET 3 : Editeur de configuration
   ══════════════════════════════════════════════════════════════════════════════ */

function loadRemoteConfig() {
    var serverId = document.getElementById('editor-server').value;
    if (!serverId) { toast(__('editor_select_server') || 'Selectionnez un serveur.', 'warning'); return; }

    supervisionFetch(window.API_URL + '/supervision/' + currentPlatform + '/config/read', { machine_id: parseInt(serverId) })
        .then(function(res) {
            if (res.success) {
                document.getElementById('editor-content').value = res.config;
                document.getElementById('editor-path').textContent = res.path || '';
                toast(__('config_loaded') || 'Configuration chargee.', 'success');
            } else {
                toast(res.message || 'Erreur', 'error');
            }
        })
        .catch(function(err) { toast(err.message, 'error'); });
}

function saveRemoteConfig() {
    var serverId = document.getElementById('editor-server').value;
    if (!serverId) { toast(__('editor_select_server') || 'Selectionnez un serveur.', 'warning'); return; }

    var config = document.getElementById('editor-content').value;
    if (!config.trim()) { toast('Configuration vide', 'warning'); return; }

    supervisionFetch(window.API_URL + '/supervision/' + currentPlatform + '/config/save', {
        machine_id: parseInt(serverId),
        config: config
    }).then(function(res) {
        if (res.success) {
            toast(__('config_remote_saved') || res.message, 'success');
        } else {
            toast(res.message || 'Erreur', 'error');
        }
    }).catch(function(err) { toast(err.message, 'error'); });
}

function loadBackups() {
    var serverId = document.getElementById('editor-server').value;
    if (!serverId) { toast(__('editor_select_server') || 'Selectionnez un serveur.', 'warning'); return; }

    supervisionFetch(window.API_URL + '/supervision/' + currentPlatform + '/backups', { machine_id: parseInt(serverId) })
        .then(function(res) {
            if (!res.success) { toast(res.message || 'Erreur', 'error'); return; }
            var list = document.getElementById('backups-list');
            if (!list) return;
            list.innerHTML = '';

            if (!res.backups || res.backups.length === 0) {
                list.innerHTML = '<p class="text-sm text-gray-400 text-center py-4">' + escHtmlSuper(__('no_backups') || 'Aucun backup.') + '</p>';
            } else {
                res.backups.forEach(function(b) {
                    var row = document.createElement('div');
                    row.className = 'flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded-lg';

                    var info = document.createElement('div');
                    var fnSpan = document.createElement('span');
                    fnSpan.className = 'text-sm font-mono';
                    fnSpan.textContent = b.filename;
                    var dtSpan = document.createElement('span');
                    dtSpan.className = 'text-xs text-gray-400 ml-2';
                    dtSpan.textContent = b.date + ' — ' + b.size + ' B';
                    info.appendChild(fnSpan);
                    info.appendChild(dtSpan);

                    var btn = document.createElement('button');
                    btn.className = 'text-xs px-2 py-1 bg-orange-500 hover:bg-orange-600 text-white rounded transition-colors';
                    btn.textContent = __('btn_restore') || 'Restaurer';
                    btn.addEventListener('click', (function(fname) {
                        return function() { restoreBackup(fname); };
                    })(b.filename));

                    row.appendChild(info);
                    row.appendChild(btn);
                    list.appendChild(row);
                });
            }

            document.getElementById('backups-modal').classList.remove('hidden');
        })
        .catch(function(err) { toast(err.message, 'error'); });
}

function closeBackupsModal() {
    document.getElementById('backups-modal').classList.add('hidden');
}

function restoreBackup(filename) {
    var serverId = document.getElementById('editor-server').value;
    if (!serverId) return;

    supervisionFetch(window.API_URL + '/supervision/' + currentPlatform + '/restore', {
        machine_id: parseInt(serverId),
        backup_name: filename
    }).then(function(res) {
        if (res.success) {
            toast(__('backup_restored') || res.message, 'success');
            closeBackupsModal();
            loadRemoteConfig();
        } else {
            toast(res.message || 'Erreur', 'error');
        }
    }).catch(function(err) { toast(err.message, 'error'); });
}
