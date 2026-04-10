// apiCalls.js
// Variable globale pour stocker l'ID de la machine en cours de planification sécurité
let currentSecurityMachineId = null;

if (typeof secu === "undefined") {
    var secu = null;
}

/**
 * Effectue un fetch POST JSON et vérifie response.ok avant de parser le JSON.
 * Rejette la promesse avec un message d'erreur HTTP si le statut n'est pas 2xx.
 * @param {string} url
 * @param {object} body
 * @param {object} [extraHeaders]
 * @returns {Promise<object>}
 */
function apiFetch(url, body, extraHeaders = {}) {
    return fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-KEY": window.API_KEY || "", ...extraHeaders },
        body: JSON.stringify(body)
    }).then(res => {
        if (!res.ok) {
            return res.text().then(txt => {
                throw new Error(`HTTP ${res.status}: ${txt.slice(0, 200)}`);
            });
        }
        return res.json();
    });
}

/**
 * Sélectionner / désélectionner tous les serveurs
 * @param {boolean} select - true pour sélectionner, false pour désélectionner
 */
function selectAll(select) {
    const checkboxes = document.querySelectorAll('input[name="selected_machines[]"]');
    checkboxes.forEach(checkbox => {
        checkbox.checked = select;
    });
}

/**
 * Récupère les machines sélectionnées et renvoie un tableau d'IDs (ex: [1, 2, 3]).
 * @returns {Array<number>} - Tableau des IDs des machines sélectionnées
 */
function getSelectedMachineIds() {
    const checkboxes = document.querySelectorAll('input[name="selected_machines[]"]:checked');
    const ids = [];
    checkboxes.forEach(cb => {
        // La value du checkbox contient l'ID (machine_id)
        const machineId = cb.value;
        ids.push(parseInt(machineId, 10));
    });
    return ids;
}

/**
 * Affiche le message 'msg' dans la zone de logs (id="logs").
 * @param {string} msg - Le message à afficher
 */
function appendToLogs(msg) {
    appendLog(msg); // Utilise la fonction de domManipulation.js
}

/**
 * Vérifie les versions Linux pour les machines sélectionnées
 */
function checkLinuxVersion() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    // On vide les logs et on ajoute un message initial
    clearLog();
    appendLog(__('upd_checking_linux_versions') + "\n");

    let pendingFetches = machineIds.length;

    machineIds.forEach(id => {
        apiFetch(`${window.API_URL}/linux_version`, { machine_id: id })
        .then(data => {
            if (data.success) {
                appendLog(__('upd_machine_version', {id, version: data.version}));
                // Mise à jour immédiate du DOM
                updateMachineVersionDOM(id, data.version);
                const row = document.querySelector(`tr[data-machine-id="${id}"]`);
                if (row) {
                    const lastChecked = row.querySelector('.last-checked');
                    if (lastChecked) lastChecked.textContent = new Date().toLocaleString('sv-SE').replace('T', ' ');
                }
            } else {
                appendLog(__('upd_machine_error', {id, msg: data.message}));
            }
        })
        .catch(err => {
            appendLog(__('upd_machine_exception', {id, msg: err}));
        })
        .finally(() => {
            pendingFetches--;
            if (pendingFetches === 0) {
                appendLog(__('upd_machine_list_updated'));
            }
        });
    });
}

/**
 * Vérifie le statut (online/offline) des machines sélectionnées
 */
// Exemple de fonction pour vérifier le statut du serveur
function checkServerStatus() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    clearLog();
    appendLog(__('upd_checking_status') + "\n");

    let pendingFetches = machineIds.length;

    machineIds.forEach(id => {
        // Récupérer les IP et ports depuis la ligne correspondante
        const row = document.querySelector(`tr[data-machine-id="${id}"]`);
        if (!row) {
            appendToLogs(__('upd_machine_row_not_found', {id}));
            pendingFetches--;
            return;
        }

        const ip = row.getAttribute('data-ip');
        const port = row.getAttribute('data-port') || 22;

        apiFetch(`${window.API_URL}/server_status`, { ip, port: parseInt(port, 10) })
        .then(data => {
            if (data.success) {
                const status = data.status === 'online' ? 'ONLINE' : 'OFFLINE';
                appendLog(__('upd_machine_status', {id, status}));
                updateMachineStatusDOM(id, status);
            } else {
                // Afficher le message d'erreur du serveur
                appendLog(__('upd_machine_error', {id, msg: JSON.stringify(data.message)}));
            }
        })
        .catch(err => {
            appendLog(__('upd_machine_exception', {id, msg: err}));
        })
        .finally(() => {
            pendingFetches--;
            if (pendingFetches === 0) {
                appendLog(__('upd_status_check_done'));
            }
        });
        
    });
}


/**
 * Met à jour les machines sélectionnées via l'endpoint /update (streaming)
 */
function updateLinux() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    clearLogs();
    appendLog(__('upd_linux_updating') + "\n");

    let pendingFetches = machineIds.length;

    machineIds.forEach(id => {
        const row = document.querySelector(`tr[data-machine-id="${id}"]`);
        const serverName = row ? row.querySelector('.server-name').textContent : `Machine ${id}`;

        fetch(`${window.API_URL}/update`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-KEY": window.API_KEY
            },
            body: JSON.stringify({ machine_id: id })
        })
        .then(response => {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            function read() {
                return reader.read().then(({ done, value }) => {
                    if (done) {
                        appendLog(__('upd_stream_end'), "info", serverName);
                        pendingFetches--;
                        if (pendingFetches === 0) {
                            appendLog(__('upd_linux_update_done'));
                            refreshMachineList();
                        }
                        return;
                    }
                    const chunk = decoder.decode(value, { stream: true });
                    chunk.split("\n").forEach(line => {
                        if (line.trim()) appendLog(line, "info", serverName);
                    });
                    return read();
                });
            }
            return read();
        })
        .catch(err => {
            appendLog(__('exception_with_msg', {msg: err}), "error", serverName);
            pendingFetches--;
            if (pendingFetches === 0) refreshMachineList();
        });
    });
}

/**
 * Applique les mises à jour de sécurité sur les machines sélectionnées
 */
function applySecurityUpdates() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    clearLogs();  // Effacer toutes les fenêtres de logs
    // Message général d'information (facultatif)
    // appendLog("Application des mises à jour de sécurité...", "info");

    machineIds.forEach(id => {
        // Récupérer la ligne de la machine et son nom
        const row = document.querySelector(`tr[data-machine-id="${id}"]`);
        const serverName = row ? row.querySelector('.server-name').textContent : `Machine ${id}`;
        
        fetch(`${window.API_URL}/security_updates`, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-API-KEY":  window.API_KEY
            },
            body: JSON.stringify({ machine_id: id })
        })
        .then(response => {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            
            function read() {
                return reader.read().then(({ done, value }) => {
                    if (done) {
                        appendLog(__('upd_stream_end'), "info", serverName);
                        return;
                    }
                    const chunk = decoder.decode(value, { stream: true });

                    // Découper en lignes
                    const lines = chunk.split("\n");
                    lines.forEach(line => {
                        if (line.trim() === "") return;
                        // Si la ligne semble représenter une progression (ex. contient un pourcentage)
                        if (line.match(/\d+%/)) {
                            appendLog(line, "progress", serverName);
                        } else {
                            appendLog(line, "info", serverName);
                        }
                    });
                    
                    return read();
                });
            }
            return read();
        })
        .catch(err => {
            appendLog(__('exception_with_msg', {msg: err}), "error", serverName);
        });
    });
}

/**
 * Liste les paquets upgradables (apt list --upgradable) pour les machines selectionnees.
 * Affiche un resume dans les logs avec le nombre de paquets par serveur.
 */
function checkPendingPackages() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    clearLogs();
    appendLog(__('upd_checking_packages') + "\n");

    let completed = 0;
    const total = machineIds.length;

    machineIds.forEach(id => {
        const row = document.querySelector(`tr[data-machine-id="${id}"]`);
        const serverName = row ? row.querySelector('.server-name').textContent : `Machine ${id}`;

        fetch(`${window.API_URL}/pending_packages`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-KEY": window.API_KEY
            },
            body: JSON.stringify({ machine_id: id })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                if (data.count === 0) {
                    appendLog(`[${serverName}] ${__('upd_no_pending_packages')}`, "info", serverName);
                } else {
                    appendLog(`[${serverName}] ${__('upd_upgradable_packages', {count: data.count})}`, "info", serverName);
                    data.packages.forEach(pkg => {
                        const versions = pkg.current ? `${pkg.current} -> ${pkg.available}` : pkg.available;
                        appendLog(`  - ${pkg.name} (${versions})`, "info", serverName);
                    });
                }
            } else {
                appendLog(`[${serverName}] ${__('error_with_msg', {msg: data.message})}`, "error", serverName);
            }
            completed++;
            if (completed === total) {
                toast(__('upd_check_done', {count: total}), 'success');
            }
        })
        .catch(err => {
            appendLog(`[${serverName}] ${__('network_error_with_msg', {msg: err})}`, "error", serverName);
            completed++;
        });
    });
}

/**
 * Simule un apt upgrade (--dry-run) sans rien installer.
 * Affiche la liste des paquets qui seraient mis a jour.
 */
function dryRunUpdate() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    clearLogs();
    appendLog(__('upd_dry_run_in_progress') + "\n");

    let pendingFetches = machineIds.length;

    machineIds.forEach(id => {
        const row = document.querySelector(`tr[data-machine-id="${id}"]`);
        const serverName = row ? row.querySelector('.server-name').textContent : `Machine ${id}`;

        fetch(`${window.API_URL}/dry_run_update`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-KEY": window.API_KEY
            },
            body: JSON.stringify({ machine_id: id })
        })
        .then(response => {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            function read() {
                return reader.read().then(({ done, value }) => {
                    if (done) {
                        appendLog(__('upd_dry_run_end'), "info", serverName);
                        pendingFetches--;
                        if (pendingFetches === 0) {
                            toast(__('upd_dry_run_done'), "success");
                        }
                        return;
                    }
                    const chunk = decoder.decode(value, { stream: true });
                    chunk.split("\n").forEach(line => {
                        if (line.trim()) appendLog(line, "info", serverName);
                    });
                    return read();
                });
            }
            return read();
        })
        .catch(err => {
            appendLog(__('exception_with_msg', {msg: err}), "error", serverName);
            pendingFetches--;
        });
    });
}

/**
 * Lance la mise à jour Zabbix pour les machines sélectionnées.
 * Pour chaque machine, une requête est envoyée à l'endpoint /update_zabbix et les logs reçus en streaming
 * sont affichés dans une fenêtre dédiée identifiée par le nom du serveur.
 */
function updateZabbix() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    clearLogs(); // Effacer toutes les fenêtres de logs

    machineIds.forEach(id => {
        // Récupérer le nom du serveur depuis le DOM (la ligne du tableau)
        const row = document.querySelector(`tr[data-machine-id="${id}"]`);
        const serverName = row ? row.querySelector('.server-name').textContent : `Machine ${id}`;

        fetch(`${window.API_URL}/update_zabbix`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-KEY":  window.API_KEY
            },
            body: JSON.stringify({
                machine_ids: [id],
                zabbix_version: document.getElementById('zabbix-version').value.trim()
            })
        })
        .then(response => {
            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            function read() {
                return reader.read().then(({ done, value }) => {
                    if (done) {
                        appendLog(__('upd_stream_end'), "info", serverName);
                        return;
                    }
                    const chunk = decoder.decode(value, { stream: true });
                    const lines = chunk.split("\n");
                    lines.forEach(line => {
                        if (line.trim() === "") return;
                        // Traitement des préfixes pour distinguer les types de message.
                        if (line.startsWith("ERROR_MACHINE::")) {
                            const parts = line.split("::");
                            appendLog(parts.slice(2).join("::"), "error", serverName);
                        } else if (line.startsWith("SUCCESS_MACHINE::")) {
                            const parts = line.split("::");
                            appendLog(parts.slice(2).join("::"), "success", serverName);
                        } else if (line.startsWith("START_MACHINE::")) {
                            const parts = line.split("::");
                            appendLog(parts.slice(2).join("::"), "info", serverName);
                        } else {
                            // Détection d'une progression si un pourcentage est présent
                            if (line.match(/\d+%/)) {
                                appendLog(line, "progress", serverName);
                            } else {
                                appendLog(line, "info", serverName);
                            }
                        }
                    });
                    return read();
                });
            }
            return read();
        })
        .catch(err => {
            appendLog(__('exception_with_msg', {msg: err}), "error", serverName);
        });
    });
}

/**
 * Planifie une mise à jour pour les machines sélectionnées
 */
function scheduleUpdate() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    const intervalMinutes = document.getElementById('update-interval').value;
    if (!intervalMinutes || intervalMinutes <= 0) {
        toast(__('upd_invalid_interval'), "warning");
        return;
    }

    clearLog();
    appendLog(__('upd_scheduling') + "\n");

    let pendingFetches = machineIds.length;

    machineIds.forEach(id => {
        apiFetch(`${window.API_URL}/schedule_update`, { machine_id: id, interval_minutes: intervalMinutes })
        .then(data => {
            if (data.success) {
                appendToLogs(__('upd_machine_schedule_ok', {id, msg: data.message}));
            } else {
                appendToLogs(__('upd_machine_error', {id, msg: data.message}));
            }
        })
        .catch(err => {
            appendToLogs(__('upd_machine_exception', {id, msg: err}));
        })
        .finally(() => {
            pendingFetches--;
            if (pendingFetches === 0) {
                appendLog(__('upd_scheduling_done'));
                refreshMachineList();
            }
        });
    });
}

/**
 * Met à jour APT pour les machines sélectionnées
 */
function aptUpdate() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    const aptMethod = document.getElementById('apt-method').value;
    const specificPackages = document.getElementById('specific-packages').value.trim();
    const excludedPackages = document.getElementById('excluded-packages').value.trim();

    clearLog();
    appendLog(__('upd_apt_updating', {method: aptMethod}) + "\n");

    let pendingFetches = machineIds.length;

    machineIds.forEach(id => {
        apiFetch(`${window.API_URL}/apt_update`, {
            machine_id: id,
            method: aptMethod,
            packages: specificPackages ? specificPackages.split(' ') : [],
            exclusions: excludedPackages ? excludedPackages.split(' ') : []
        })
        .then(data => {
            if (data.success) {
                appendToLogs(__('upd_machine_apt_ok', {id, msg: data.message}));
            } else {
                appendToLogs(__('upd_machine_apt_error', {id, msg: data.message}));
            }
        })
        .catch(err => {
            appendToLogs(__('upd_machine_apt_exception', {id, msg: err}));
        })
        .finally(() => {
            pendingFetches--;
            if (pendingFetches === 0) {
                appendLog(__('upd_apt_done'));
                refreshMachineList();
            }
        });
    });
}

/**
 * Mise à jour personnalisée des machines sélectionnées
 */
function customUpdate() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    const updatePackages = document.getElementById('update-packages').value.trim();
    const excludePackages = document.getElementById('exclude-packages').value.trim();

    if (!updatePackages && !excludePackages) {
        toast(__('upd_specify_package'), "warning");
        return;
    }

    clearLog();
    appendLog(__('upd_custom_updating') + "\n");

    let pendingFetches = machineIds.length;

    machineIds.forEach(id => {
        apiFetch(`${window.API_URL}/custom_update`, {
            machine_id: id,
            selected_packages: updatePackages ? updatePackages.split(' ') : [],
            excluded_packages: excludePackages ? excludePackages.split(' ') : []
        })
        .then(data => {
            if (data.success) {
                appendToLogs(__('upd_machine_custom_ok', {id, msg: data.message}));
            } else {
                appendToLogs(__('upd_machine_custom_error', {id, msg: data.message}));
            }
        })
        .catch(err => {
            appendToLogs(__('upd_machine_custom_exception', {id, msg: err}));
        })
        .finally(() => {
            pendingFetches--;
            if (pendingFetches === 0) {
                appendLog(__('upd_custom_done'));
                refreshMachineList();
            }
        });
    });
}

/**
 * Met à jour une seule machine via l'endpoint /update (streaming)
 * @param {number} machineId - ID de la machine à mettre à jour
 */
function updateSingleMachine(machineId) {
    const row = document.querySelector(`tr[data-machine-id="${machineId}"]`);
    const serverName = row ? row.querySelector('.server-name').textContent : `Machine ${machineId}`;
    appendLog("\n" + __('upd_quick_update', {id: machineId}) + "\n", "info", serverName);

    fetch(`${window.API_URL}/update`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-API-KEY": window.API_KEY
        },
        body: JSON.stringify({ machine_id: machineId })
    })
    .then(response => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();

        function read() {
            return reader.read().then(({ done, value }) => {
                if (done) {
                    appendLog(__('upd_stream_end'), "info", serverName);
                    refreshMachineList();
                    return;
                }
                const chunk = decoder.decode(value, { stream: true });
                chunk.split("\n").forEach(line => {
                    if (line.trim()) appendLog(line, "info", serverName);
                });
                return read();
            });
        }
        return read();
    })
    .catch(err => {
        appendLog(__('exception_with_msg', {msg: err}), "error", serverName);
    });
}

/**
 * Met à jour Zabbix pour une seule machine via l'endpoint /update_zabbix.
 * La réponse est du streaming text/plain (JSON-lines) — on utilise un reader
 * plutôt que apiFetch() qui attend du JSON.
 * @param {number} machineId - ID de la machine à mettre à jour Zabbix
 */
function zabbixUpdateSingle(machineId) {
    appendLog("\n" + __('upd_zabbix_single', {id: machineId}) + "\n");

    const zabbixVersion = document.getElementById('zabbix-version').value.trim() || '7.0';
    const serverName = `Machine ${machineId}`;

    fetch(`${window.API_URL}/update_zabbix`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-API-KEY": window.API_KEY || ""
        },
        body: JSON.stringify({ machine_ids: [machineId], zabbix_version: zabbixVersion })
    })
    .then(response => {
        if (!response.ok) {
            return response.text().then(txt => {
                throw new Error(`HTTP ${response.status}: ${txt.slice(0, 200)}`);
            });
        }
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        function read() {
            return reader.read().then(({ done, value }) => {
                if (done) return;
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split("\n");
                buffer = lines.pop();
                lines.forEach(line => {
                    if (!line.trim()) return;
                    try {
                        const data = JSON.parse(line);
                        if (data.type === "log" || data.type === "info") {
                            appendLog(data.message, "info", serverName);
                        } else if (data.type === "error") {
                            appendLog(data.message, "error", serverName);
                        }
                    } catch (_) {
                        appendLog(line, "info", serverName);
                    }
                });
                return read();
            });
        }
        return read();
    })
    .catch(err => {
        appendLog(__('upd_machine_exception', {id: machineId, msg: err}), "error", serverName);
    });
}

/**
 * Filtrer les serveurs en fonction des critères sélectionnés
 */
function filterServers() {
    const environment = document.getElementById('environment').value;
    const criticality = document.getElementById('criticality').value;
    const networkType = document.getElementById('network-type').value;
    const tag = document.getElementById('tag-filter')?.value || '';

    const params = new URLSearchParams({
        environment: environment,
        criticality: criticality,
        networkType: networkType
    });
    if (tag) params.set('tag', tag);

    fetch(`${window.API_URL}/filter_servers?${params.toString()}`)
        .then(res => res.json())
        .then(data => {
            if (!data.success) {
                appendToLogs(__('upd_filter_error', {msg: data.message}));
                return;
            }
            populateMachineTable(data.servers);
            appendToLogs(__('upd_filter_applied', {count: data.servers.length}));
        })
        .catch(err => {
            console.error("filterServers error:", err);
            appendToLogs(__('upd_filter_exception', {msg: err}));
        });
}


function refreshMachineList() {
    fetch("/update/functions/list_machines.php", {
        method: "GET",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin"  // ou "include"
    })
    .then((response) => {
        if (!response.ok) throw new Error(__('network_error'));
        return response.json();
    })
    .then((data) => {
        if (!data.success) {
            appendLog(__('error_with_msg', {msg: data.message}));
            return;
        }
        populateMachineTable(data.machines);
        appendLog(__('upd_machine_list_updated'));
    })
    .catch((err) => {
        appendLog(__('upd_refresh_error', {msg: err}));
    });
}

/**
 * Ajoute une ligne de log dans la fenêtre dédiée du serveur.
 * @param {string} message - Le message à afficher.
 * @param {string} [type="info"] - Le type de message ("info", "error", "progress").
 * @param {string|null} [serverName=null] - Le nom du serveur.
 */
function appendLog(message, type = "info", serverName = null) {
    let targetContainer;
    if (serverName) {
        targetContainer = getServerLogWindow(serverName);
    } else {
        // En fallback, si aucun nom n'est fourni, on affiche dans un conteneur général
        targetContainer = document.getElementById("logs-container");
    }
    
    // Pour les messages de progression, on peut mettre à jour la dernière ligne
    if (type === "progress") {
        const lastLine = targetContainer.lastElementChild;
        if (lastLine && lastLine.classList.contains("progress")) {
            lastLine.textContent = message;
            return;
        }
    }
    
    const p = document.createElement("p");
    p.textContent = message;
    p.classList.add("log-line", type);
    targetContainer.appendChild(p);
    
    // Défilement automatique
    targetContainer.scrollTop = targetContainer.scrollHeight;
}

/**
 * Efface toutes les fenêtres de logs.
 */
function clearLogs() {
    const logsContainer = document.getElementById("logs-container");
    if (logsContainer) {
        logsContainer.innerHTML = "";
    }
}

/**
 * Retourne la fenêtre de logs dédiée au serveur (en créant la fenêtre si nécessaire).
 * Utilise textContent pour le titre afin de prévenir toute XSS.
 * @param {string} serverName - Le nom du serveur
 * @returns {HTMLElement} - L'élément qui contiendra les logs du serveur
 */
function getServerLogWindow(serverName) {
    const logsContainer = document.getElementById('logs-container');
    if (!logsContainer) return null;

    // Échapper l'attribut via une recherche par valeur exacte
    let serverLogDiv = null;
    logsContainer.querySelectorAll('[data-server-name]').forEach(el => {
        if (el.getAttribute('data-server-name') === serverName) {
            serverLogDiv = el;
        }
    });

    if (!serverLogDiv) {
        serverLogDiv = document.createElement('div');
        serverLogDiv.classList.add('server-log-window');
        serverLogDiv.setAttribute('data-server-name', serverName);

        const title = document.createElement('h3');
        title.textContent = serverName; // textContent pour éviter XSS
        serverLogDiv.appendChild(title);

        const logWindow = document.createElement('div');
        logWindow.classList.add('log-window');
        serverLogDiv.appendChild(logWindow);

        logsContainer.appendChild(serverLogDiv);
    }
    return serverLogDiv.querySelector('.log-window');
}

/**
 * Récupère la date du dernier redémarrage pour une machine donnée via l'endpoint /last_reboot
 * @param {number} machineId - L'ID de la machine
 */
function fetchLastReboot(machineId) {
    apiFetch(`${window.API_URL}/last_reboot`, { machine_id: machineId }, { "X-API-KEY": window.API_KEY })
    .then(data => {
        if(data.success) {
            const el = document.getElementById('last-reboot-' + machineId);
            if (el) {
                el.textContent = data.last_reboot;
                // Indicateur reboot required
                if (data.reboot_required) {
                    el.innerHTML += ' <span class="inline-block px-1.5 py-0.5 text-[10px] font-bold bg-red-600 text-white rounded-full ml-1 animate-pulse" title="Reboot necessaire apres mise a jour">REBOOT</span>';
                }
            }
        } else {
            console.error("Error fetching last reboot:", data.message);
        }
    })
    .catch(error => console.error("Error:", error));
}

// Appel de la fonction pour chaque machine après le chargement de la page
document.addEventListener("DOMContentLoaded", function() {
    const rows = document.querySelectorAll("[data-machine-id]");
    rows.forEach(row => {
        const machineId = row.getAttribute("data-machine-id");
        fetchLastReboot(machineId);
    });
});

/**
 * Planifie une mise à jour de sécurité avancée en utilisant les paramètres saisis.
 */
function scheduleAdvancedSecurityUpdate() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }
    
    const date = document.getElementById('sec-date').value;
    const time = document.getElementById('sec-time').value;
    const repeat = document.getElementById('sec-repeat').value;
    
    if (!date || !time) {
        toast(__('upd_enter_date_time'), "warning");
        return;
    }
    
    appendLog(__('upd_scheduling_security'));
    
    machineIds.forEach(id => {
        fetch(`${window.API_URL}/schedule_advanced_security_update`, {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                // Ajoutez la clé API si nécessaire : 
                "X-API-KEY": window.API_KEY
            },
            body: JSON.stringify({
                machine_id: id,
                date: date,
                time: time,
                repeat: repeat
            })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                appendLog(`Machine ${id}: ${data.message}`);
                refreshMachineList();
            } else {
                appendLog(__('upd_machine_error', {id, msg: data.message}), "error");
            }
        })
        .catch(err => {
            appendLog(__('upd_machine_exception', {id, msg: err}), "error");
        });
    });
}

/**
 * Ouvre le modal de planification avancée pour la mise à jour de sécurité pour une machine donnée.
 * @param {number} machineId - L'ID de la machine
 */
function openSecurityScheduleModal(machineId) {
    currentSecurityMachineId = machineId;
    document.getElementById("security-schedule-modal").classList.remove("hidden");
}

/**
 * Ferme le modal de planification avancée pour la mise à jour de sécurité.
 */
function closeSecurityScheduleModal() {
    document.getElementById("security-schedule-modal").classList.add("hidden");
    currentSecurityMachineId = null;
}

/**
 * Envoie les paramètres de planification de sécurité à l'endpoint et ferme le modal.
 */
function saveSecuritySchedule() {
    const date = document.getElementById('sec-date').value;
    const time = document.getElementById('sec-time').value;
    const repeat = document.getElementById('sec-repeat').value;

    if (!date || !time) {
        toast(__('upd_enter_date_time'), "warning");
        return;
    }
    if (!currentSecurityMachineId) {
        toast(__('upd_no_machine_selected'), "warning");
        return;
    }
    
    appendLog(__('upd_scheduling_security_single', {id: currentSecurityMachineId}));
    
    fetch(`${window.API_URL}/schedule_advanced_security_update`, {
        method: "POST",
        headers: { 
            "Content-Type": "application/json",
            "X-API-KEY": window.API_KEY  // Décommentez si vous utilisez une clé API
        },
        body: JSON.stringify({
            machine_id: currentSecurityMachineId,
            date: date,
            time: time,
            repeat: repeat
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            appendLog(`Machine ${currentSecurityMachineId}: ${data.message}`);
            refreshMachineList();
        } else {
            appendLog(__('upd_machine_error', {id: currentSecurityMachineId, msg: data.message}), "error");
        }
    })
    .catch(err => {
        appendLog(__('upd_machine_exception', {id: currentSecurityMachineId, msg: err}), "error");
    })
    .finally(() => {
        closeSecurityScheduleModal();
    });
}

/**
 * Repare dpkg sur les machines selectionnees :
 * kill apt/dpkg bloques, supprime les locks, dpkg --configure -a
 */
function dpkgRepair() {
    const machineIds = getSelectedMachineIds();
    if (machineIds.length === 0) {
        toast(__('select_machine'), 'warning');
        return;
    }

    if (!confirm(__('upd_confirm_dpkg_repair'))) return;

    clearLogs();
    appendLog(__('upd_dpkg_repairing') + "\n");

    machineIds.forEach(id => {
        const row = document.querySelector(`tr[data-machine-id="${id}"]`);
        const serverName = row ? row.querySelector('.server-name').textContent : `Machine ${id}`;

        apiFetch(`${window.API_URL}/dpkg_repair`, { machine_id: id })
        .then(data => {
            if (data.success) {
                appendLog(`${data.message}`, "info", serverName);
                if (data.output) appendLog(data.output, "info", serverName);
            } else {
                appendLog(__('error_with_msg', {msg: data.message}), "error", serverName);
            }
        })
        .catch(err => {
            appendLog(__('exception_with_msg', {msg: err}), "error", serverName);
        });
    });
}