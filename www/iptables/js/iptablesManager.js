    function _escHtml(s) {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    document.addEventListener("DOMContentLoaded", function () {
        const iptablesLogContainer = document.getElementById("iptables-logs");

        /**
         * Ajoute une entrée dans le conteneur de logs iptables.
         * Utilise textContent pour prévenir toute injection XSS dans les messages.
         * Scroll automatiquement vers le bas après chaque ajout.
         * @param {string} message - Message de log à afficher
         */
        function appendIptablesLog(message) {
            const logEntry = document.createElement("p");
            logEntry.textContent = message; // textContent = sûr contre XSS
            logEntry.className = "text-gray-200 dark:text-gray-300";
            iptablesLogContainer.appendChild(logEntry);
            iptablesLogContainer.scrollTop = iptablesLogContainer.scrollHeight;
        }

        // ── Charger les règles actives depuis le serveur ─────────────────────────
        // Appelle POST /iptables (action: 'get') avec les credentials SSH du serveur
        // sélectionné. Affiche les règles actives (current_rules_v4/v6) et les
        // fichiers persistants (file_rules_v4/v6) dans les zones dédiées.
        document.getElementById('fetch-rules').addEventListener('click', async () => {
            const serverData = document.getElementById('server').value;
            if (!serverData) {
                toast(__('select_server'), 'warning');
                return;
            }

            // Parse le JSON du serveur stocké dans la valeur de l'option <select>
            const server = JSON.parse(serverData);
            appendIptablesLog(__('ipt_loading_rules_for', {name: server.name, ip: server.ip}));

            try {
                const response = await fetch(`${window.API_URL}/iptables`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-API-KEY': window.API_KEY || '' },
                    body: JSON.stringify({
                        action: 'get',
                        machine_id: server.id
                    }),
                });

                const result = await response.json();
                if (result.success) {
                    // Vérification de l'existence des éléments avant manipulation
                    const rulesContainer = document.getElementById('rules-container');
                    const rulesV4 = document.getElementById('current-rules-v4');
                    const rulesV6 = document.getElementById('current-rules-v6');
                    const fileRulesV4 = document.getElementById('file-rules-v4');
                    const fileRulesV6 = document.getElementById('file-rules-v6');

                    if (rulesV4) {
                        rulesV4.textContent = result.current_rules_v4 || __('ipt_no_rules_v4');
                    }

                    if (rulesV6) {
                        rulesV6.textContent = result.current_rules_v6 || __('ipt_no_rules_v6');
                    }

                    if (fileRulesV4) {
                        fileRulesV4.value = result.file_rules_v4 || '';
                    }

                    if (fileRulesV6) {
                        fileRulesV6.value = result.file_rules_v6 || '';
                    }

                    if (rulesContainer) {
                        rulesContainer.classList.remove('hidden');
                    }

                    appendIptablesLog(__('ipt_rules_fetched'));
                    // Charger l'historique
                    loadHistory();
                } else {
                    appendIptablesLog(__('error_with_msg', {msg: result.message}));
                }
            } catch (error) {
                appendIptablesLog(__('network_error_with_msg', {msg: error}));
            }
        });

        // ── Valider les regles (dry-run) ─────────────────────────────────────
        document.getElementById("validate-rules").addEventListener("click", async () => {
            const serverData = document.getElementById("server").value;
            if (!serverData) { toast(__('select_server'), "warning"); return; }
            const server = JSON.parse(serverData);
            const rulesV4 = document.getElementById("file-rules-v4").value;
            if (!rulesV4.trim()) { toast(__('ipt_rules_v4_empty'), "warning"); return; }

            appendIptablesLog(__('ipt_validating'));
            try {
                const response = await fetch(`${window.API_URL}/iptables-validate`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "X-API-KEY": window.API_KEY || "" },
                    body: JSON.stringify({
                        machine_id: server.id, rules_v4: rulesV4
                    }),
                });
                const result = await response.json();
                if (result.success) {
                    toast(__('ipt_rules_valid'), "success");
                    appendIptablesLog(__('ipt_validation_ok'));
                } else {
                    toast(__('ipt_syntax_error'), "error");
                    appendIptablesLog(__('ipt_validation_error', {msg: result.message || ''}));
                    if (result.output) appendIptablesLog(result.output);
                }
            } catch (error) {
                appendIptablesLog(__('network_error_with_msg', {msg: error}));
            }
        });

        // ── Appliquer les règles éditées sur le serveur ──────────────────────────
        // Envoie le contenu des éditeurs textarea (file-rules-v4/v6) vers
        // POST /iptables-apply du backend Python pour les appliquer en live.
        document.getElementById("apply-rules").addEventListener("click", async () => {
            const serverData = document.getElementById("server").value;
            if (!serverData) {
                toast(__('select_server'), "warning");
                return;
            }

            const server = JSON.parse(serverData);
            const rulesV4 = document.getElementById("file-rules-v4").value;
            const rulesV6 = document.getElementById("file-rules-v6").value;

            try {
                const response = await fetch(`${window.API_URL}/iptables-apply`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "X-API-KEY": window.API_KEY || "" },
                    body: JSON.stringify({
                        action: "apply",
                        machine_id: server.id,
                        rules_v4: rulesV4,
                        rules_v6: rulesV6
                    }),
                });

                const result = await response.json();
                if (result.success) {
                    showNotification(__('ipt_rules_applied'), "success");
                } else {
                    showNotification(__('error_with_msg', {msg: result.message}), "error");
                }
            } catch (error) {
                console.error("Network error:", error);
                showNotification(__('ipt_apply_error'), "error");
            }
        });

        // ── Restaurer les règles BDD vers le serveur ─────────────────────────────
        // Appelle POST /iptables-restore du backend Python qui récupère les règles
        // sauvegardées en BDD et les applique directement sur le serveur distant.
        document.getElementById("restore-rules").addEventListener("click", async () => {
            const serverData = document.getElementById("server").value;
            if (!serverData) {
                toast(__('select_server'), "warning");
                return;
            }

            const server = JSON.parse(serverData);

            try {
                const response = await fetch(`${window.API_URL}/iptables-restore`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json", "X-API-KEY": window.API_KEY || "" },
                    body: JSON.stringify({
                        machine_id: server.id
                    }),
                });

                const result = await response.json();

                if (result.success) {
                    showNotification(__('ipt_rules_restored'), "success");
                } else {
                    console.error("Restore error:", result.message);
                    showNotification(__('error_with_msg', {msg: result.message}), "error");
                }
            } catch (error) {
                console.error("Network error:", error);
                showNotification(__('ipt_restore_error'), "error");
            }
        });

        // ── Sauvegarder les règles éditées dans la BDD ───────────────────────────
        // Appelle ce même fichier PHP en POST (action: save_to_db) pour stocker
        // le contenu des éditeurs dans la table iptables_rules.
        document.getElementById("save-rules").addEventListener("click", async () => {
            const serverData = document.getElementById("server").value;
            if (!serverData) {
                toast(__('select_server'), "warning");
                return;
            }

            const server = JSON.parse(serverData);
            const rulesV4 = document.getElementById("file-rules-v4").value;
            const rulesV6 = document.getElementById("file-rules-v6").value;

            try {
                const response = await fetch("index.php", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: new URLSearchParams({
                        action: "save_to_db",
                        server_id: server.id,
                        rules_v4: rulesV4,
                        rules_v6: rulesV6
                    }),
                });

                const result = await response.json();

                if (result.success) {
                    showNotification(__('ipt_rules_saved_db'), "success");
                } else {
                    showNotification(result.message, "error");
                }
            } catch (error) {
                console.error("Network error:", error);
                showNotification(__('ipt_save_db_error'), "error");
            }
        });

        // ── Charger les règles depuis la BDD (lecture seule) ─────────────────────
        // Appelle ce même fichier PHP en POST (action: load_from_db) et affiche
        // les règles dans les textarea en lecture seule (bdd-rules-v4/v6).
        document.getElementById("load-rules").addEventListener("click", async () => {
            const serverData = document.getElementById("server").value;
            if (!serverData) {
                toast(__('select_server'), "warning");
                return;
            }

            const server = JSON.parse(serverData);

            try {
                const response = await fetch("index.php", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: new URLSearchParams({
                        action: "load_from_db",
                        server_id: server.id,
                    }),
                });

                const result = await response.json();

                if (result.success) {
                    // Remplit les textarea en lecture seule avec les règles de la BDD
                    const rulesV4Textarea = document.getElementById("bdd-rules-v4");
                    const rulesV6Textarea = document.getElementById("bdd-rules-v6");

                    if (rulesV4Textarea) {
                        rulesV4Textarea.value = result.rules_v4 || __('ipt_no_rules_found_v4');
                    }

                    if (rulesV6Textarea) {
                        rulesV6Textarea.value = result.rules_v6 || __('ipt_no_rules_found_v6');
                    }

                    showNotification(__('ipt_rules_loaded_db'), "success");
                } else {
                    console.error("Server error:", result.message);
                    showNotification(result.message, "error");
                }
            } catch (error) {
                console.error("Network error:", error);
                showNotification(__('ipt_load_db_error'), "error");
            }
        });

        /**
         * Affiche une notification toast en bas à droite de l'écran.
         * La notification disparaît automatiquement après 5 secondes.
         * @param {string} message - Message à afficher dans la notification
         * @param {string} type    - Type parmi 'success', 'error', 'info' (défaut: 'success')
         */
        function showNotification(message, type = 'success') {
            const notifications = document.getElementById('notifications');
            let bgColor, textColor;

            switch(type) {
                case 'success':
                    bgColor = 'bg-green-100 dark:bg-green-700';
                    textColor = 'text-green-700 dark:text-green-100';
                    break;
                case 'error':
                    bgColor = 'bg-red-100 dark:bg-red-700';
                    textColor = 'text-red-700 dark:text-red-100';
                    break;
                case 'info':
                    bgColor = 'bg-blue-100 dark:bg-blue-700';
                    textColor = 'text-blue-700 dark:text-blue-100';
                    break;
                default:
                    bgColor = 'bg-gray-100 dark:bg-gray-700';
                    textColor = 'text-gray-700 dark:text-gray-100';
            }

            notifications.innerHTML = `
                <div class="flex items-center justify-between ${bgColor} ${textColor} px-4 py-3 rounded-lg shadow-md mb-4">
                    <span>${_escHtml(message)}</span>
                    <button onclick="this.parentElement.parentElement.innerHTML = ''" class="text-xl font-bold">&times;</button>
                </div>
            `;
            // Auto-hide après 5 secondes
            setTimeout(() => {
                notifications.innerHTML = "";
            }, 5000);
        }
    });

    /**
     * Ouvre un flux SSE vers /iptables-logs du backend Python et affiche
     * chaque message reçu dans le conteneur de logs (#iptables-logs).
     * Le bouton "Charger les règles" déclenche aussi cette fonction pour
     * afficher les logs temps réel associés à la récupération des règles.
     * Utilise textContent pour chaque entrée (protection XSS).
     * Ferme la connexion SSE en cas d'erreur.
     */
    function fetchLogs() {
        const logWindow = document.getElementById('iptables-logs');

        // Réinitialise la zone de logs avant d'ouvrir le nouveau flux
        logWindow.innerHTML = "";

        // Connexion SSE vers le backend Python
        const eventSource = new EventSource(`${window.API_URL}/iptables-logs`);

        eventSource.onmessage = function (event) {
            // Chaque message SSE = une ligne de log ; textContent protège contre XSS
            const logEntry = document.createElement("p");
            logEntry.textContent = event.data;
            logEntry.className = "text-gray-200 dark:text-gray-300";
            logWindow.appendChild(logEntry);
            logWindow.scrollTop = logWindow.scrollHeight; // Auto-scroll vers le bas
        };

        // Ferme la connexion pour éviter les reconnexions automatiques en boucle
        eventSource.onerror = function () {
            console.error("Error connecting to iptables-logs stream.");
            eventSource.close();
        };
    }
    // ── Templates iptables ──────────────────────────────────────────────────
    const IPTABLES_TEMPLATES = {
        web: `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
# Loopback
-A INPUT -i lo -j ACCEPT
# Connexions etablies
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# SSH
-A INPUT -p tcp --dport 22 -j ACCEPT
# HTTP + HTTPS
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
# ICMP ping
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
COMMIT`,
        db: `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# SSH
-A INPUT -p tcp --dport 22 -j ACCEPT
# MySQL (reseau interne uniquement)
-A INPUT -p tcp --dport 3306 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p tcp --dport 3306 -s 172.16.0.0/12 -j ACCEPT
-A INPUT -p tcp --dport 3306 -s 192.168.0.0/16 -j ACCEPT
# PostgreSQL
-A INPUT -p tcp --dport 5432 -s 10.0.0.0/8 -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
COMMIT`,
        ssh_only: `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# SSH uniquement
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
COMMIT`,
        deny_all: `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# ATTENTION: seul SSH est ouvert pour ne pas perdre l'acces
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT`,
        docker: `*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# SSH
-A INPUT -p tcp --dport 22 -j ACCEPT
# HTTP + HTTPS (reverse proxy)
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
# Docker bridge
-A INPUT -i docker0 -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
COMMIT`
    };

    // ── Historique iptables ─────────────────────────────────────────────────
    async function loadHistory() {
        const serverData = document.getElementById("server").value;
        if (!serverData) return;
        const server = JSON.parse(serverData);
        const container = document.getElementById('iptables-history');
        container.innerHTML = '<p class="text-xs text-gray-400">' + __('loading') + '</p>';

        try {
            // On a besoin du server_id, pas de l'IP — recupérons-le via une query
            const r = await fetch(`${window.API_URL}/iptables-history?server_id=${server.id || ''}`);
            const d = await r.json();
            if (!d.success || !d.history || d.history.length === 0) {
                container.innerHTML = '<p class="text-xs text-gray-400">' + __('ipt_no_history') + '</p>';
                return;
            }
            container.innerHTML = '';
            d.history.forEach(function(h) {
                const date = new Date(h.created_at).toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
                const reason = h.change_reason ? ' — ' + h.change_reason : '';
                const row = document.createElement('div');
                row.className = 'flex items-center justify-between gap-2 py-1.5 border-b border-gray-100 dark:border-gray-700 last:border-0';
                const info = document.createElement('div');
                info.className = 'flex-1 min-w-0';
                const dateSpan = document.createElement('span');
                dateSpan.className = 'text-xs font-mono text-gray-500';
                dateSpan.textContent = date;
                const bySpan = document.createElement('span');
                bySpan.className = 'text-xs text-gray-400 ml-2';
                bySpan.textContent = (h.changed_by || 'admin') + reason;
                info.appendChild(dateSpan);
                info.appendChild(bySpan);
                const btn = document.createElement('button');
                btn.className = 'text-[10px] px-2 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300 hover:bg-orange-200 flex-shrink-0';
                btn.textContent = __('restore');
                btn.addEventListener('click', (function(id) { return function() { rollbackRules(id); }; })(parseInt(h.id)));
                row.appendChild(info);
                row.appendChild(btn);
                container.appendChild(row);
            });
        } catch(e) {
            container.innerHTML = '<p class="text-xs text-red-400">' + __('error_with_msg', {msg: _escHtml(e.message)}) + '</p>';
        }
    }

    async function rollbackRules(historyId) {
        if (!confirm(__('ipt_confirm_rollback'))) return;
        try {
            const r = await fetch(`${window.API_URL}/iptables-rollback`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-API-KEY': window.API_KEY || ''},
                body: JSON.stringify({history_id: historyId})
            });
            const d = await r.json();
            if (d.success) {
                toast(__('ipt_rollback_success'), 'success');
                appendIptablesLog(__('ipt_rollback_log', {id: historyId}));
            } else {
                toast(d.message || __('error'), 'error');
            }
        } catch(e) {
            toast(__('network_error'), 'error');
        }
    }

    function loadTemplate(name) {
        const tpl = IPTABLES_TEMPLATES[name];
        if (!tpl) return;
        const editor = document.getElementById('file-rules-v4');
        if (!editor) return;
        if (editor.value.trim() && !confirm(__('ipt_confirm_template'))) return;
        editor.value = tpl;
        toast(__('ipt_template_loaded', {name}), 'info');
        appendIptablesLog(__('ipt_template_loaded', {name}));
    }
