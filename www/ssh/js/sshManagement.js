function _escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// Liste complète des machines injectée depuis PHP, utilisée pour la validation côté client

// --------------------------------------------------------------------
// Sélection/dé-sélection de toutes les cases
// --------------------------------------------------------------------
/**
 * Coche ou décoche toutes les cases à cocher du tableau de machines.
 * @param {boolean} select - true pour tout cocher, false pour tout décocher
 */
function selectAll(select) {
    const checkboxes = document.querySelectorAll('input[name="selected_machines[]"]');
    checkboxes.forEach(checkbox => {
        checkbox.checked = select;
    });
}

function filterMachines() {
    const tagFilter = (document.getElementById('filter-tag')?.value || '').toLowerCase();
    const envFilter = (document.getElementById('filter-env')?.value || '').toUpperCase();
    document.querySelectorAll('.machine-item').forEach(item => {
        const tags = (item.dataset.tags || '').toLowerCase();
        const env = (item.dataset.env || '').toUpperCase();
        const matchTag = !tagFilter || tags.split(',').includes(tagFilter);
        const matchEnv = !envFilter || env === envFilter;
        item.style.display = (matchTag && matchEnv) ? '' : 'none';
    });
}

function selectFiltered(select) {
    document.querySelectorAll('.machine-item').forEach(item => {
        if (item.style.display !== 'none') {
            const cb = item.querySelector('input[type="checkbox"]');
            if (cb) cb.checked = select;
        }
    });
}

// --------------------------------------------------------------------
// Récupère la liste des machines sélectionnées
// --------------------------------------------------------------------
/**
 * Retourne les identifiants numériques des machines dont la case est cochée.
 * Filtre les valeurs non-numériques (parseInt retourne NaN).
 * @returns {number[]} Tableau des IDs de machines sélectionnées
 */
function getSelectedMachines() {
    const checkboxes = document.querySelectorAll('input[name="selected_machines[]"]:checked');
    const machines = [];
    checkboxes.forEach(cb => {
        const machineId = parseInt(cb.value, 10);
        if (!isNaN(machineId)) {
            machines.push(machineId);
        }
    });
    return machines;
}

// --------------------------------------------------------------------
// Valide la sélection des machines
// --------------------------------------------------------------------
/**
 * Vérifie que tous les IDs sélectionnés appartiennent bien à la liste des
 * machines autorisées (injectée depuis PHP). Protège contre la manipulation
 * côté client des valeurs de checkbox.
 * @param {number[]} selectedMachines   - IDs sélectionnés par l'utilisateur
 * @param {Object[]} availableMachines  - Machines autorisées (depuis availableMachines)
 * @returns {boolean} true si tous les IDs sont valides, false sinon
 */
function validateMachineSelection(selectedMachines, availableMachines) {
    // Extrait uniquement les IDs de la liste de référence serveur
    const availableIds = availableMachines.map(machine => machine.id);
    return selectedMachines.every(machineId => availableIds.includes(machineId));
}

// --------------------------------------------------------------------
// Lance la requête de déploiement SSH sur notre API Python
// --------------------------------------------------------------------
/**
 * Orchestre le déploiement des clés SSH :
 *   1. Récupère et valide la sélection de machines
 *   2. Envoie une requête POST /deploy au backend Python avec X-API-KEY
 *   3. En cas de succès, démarre la récupération des logs SSE via fetchLogs()
 *   4. En cas d'erreur réseau ou serveur, affiche une alerte à l'utilisateur
 */
function deploySSH() {
    const machines = getSelectedMachines();
    if (!validateMachineSelection(machines, availableMachines)) {
        toast("Machines selectionnees invalides", "error");
        return;
    }
    if (machines.length === 0) {
        toast("Selectionnez au moins une machine", "warning");
        return;
    }

    const btn = document.getElementById('deploy-btn');
    const spinner = document.getElementById('deploy-spinner');
    const label = document.getElementById('deploy-label');
    const logWindow = document.getElementById('logs');

    // Pre-flight check d'abord
    btn.disabled = true;
    spinner.classList.remove('hidden');
    document.getElementById('deploy-icon')?.classList.add('hidden');
    label.textContent = 'Verification pre-deploiement...';
    logWindow.innerHTML = '== Pre-flight checks ==\n';

    fetch(`${window.API_URL}/preflight_check`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-API-KEY": window.API_KEY || "" },
        body: JSON.stringify({ machines: machines })
    })
    .then(r => r.json())
    .then(data => {
        if (!data.success) {
            toast(data.message || "Erreur preflight", "error");
            resetDeployBtn();
            return;
        }

        const results = data.results || [];
        let allOk = true;
        let failedNames = [];

        results.forEach(r => {
            const auth = r.auth_method ? ` [${r.auth_method}]` : '';
            const disk = r.disk_free ? ` | Disque: ${r.disk_free}` : '';
            const os = r.os_version ? ` | ${r.os_version}` : '';
            logWindow.innerHTML += `[${r.ssh_ok ? 'OK' : 'FAIL'}] ${_escHtml(r.name)} (${_escHtml(r.ip)})${_escHtml(auth)}${_escHtml(os)}${_escHtml(disk)}\n`;
            if (r.errors && r.errors.length > 0) {
                r.errors.forEach(e => { logWindow.innerHTML += `     \u274c ${_escHtml(e)}\n`; });
                allOk = false;
                failedNames.push(r.name);
            }
            if (r.warnings && r.warnings.length > 0) {
                r.warnings.forEach(w => { logWindow.innerHTML += `     \u26a0 ${_escHtml(w)}\n`; });
            }
        });

        if (data.users_with_keys === 0) {
            logWindow.innerHTML += '\n\u26a0 ATTENTION: Aucun utilisateur actif avec une cle SSH !\n';
            allOk = false;
        } else {
            logWindow.innerHTML += `\n${data.users_with_keys} utilisateur(s) avec cle SSH.\n`;
        }

        if (!allOk) {
            logWindow.innerHTML += `\n\u274c Pre-flight echoue pour: ${failedNames.join(', ')}\n`;
            logWindow.innerHTML += 'Corrigez les erreurs ci-dessus ou decochez les machines en echec.\n';
            toast(`Pre-flight echoue (${failedNames.length} serveur${failedNames.length > 1 ? 's' : ''})`, 'error');
            resetDeployBtn();
            return;
        }

        // Tout est OK — lancer le deploiement
        logWindow.innerHTML += '\n\u2705 Tous les checks OK — Deploiement en cours...\n\n';
        label.textContent = 'Deploiement en cours...';

        fetch(`${window.API_URL}/deploy`, {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-API-KEY": window.API_KEY || "" },
            body: JSON.stringify({ machines: machines })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                fetchLogs();
            } else {
                toast(data.message, "error");
                resetDeployBtn();
            }
        })
        .catch(error => {
            toast("Erreur reseau", "error");
            resetDeployBtn();
        });
    })
    .catch(error => {
        toast("Erreur pre-flight", "error");
        resetDeployBtn();
    });
}

function resetDeployBtn() {
    const btn = document.getElementById('deploy-btn');
    if (btn) {
        btn.disabled = false;
        document.getElementById('deploy-spinner').classList.add('hidden');
        document.getElementById('deploy-icon')?.classList.remove('hidden');
        document.getElementById('deploy-label').textContent = 'Deployer les cles';
    }
}

// --------------------------------------------------------------------
// Connexion SSE au flux des logs (endpoint /logs du backend Python)
// --------------------------------------------------------------------
/**
 * Ouvre une connexion Server-Sent Events vers /logs et affiche chaque
 * message reçu dans la zone de logs (#logs) en temps réel.
 * Ferme la connexion SSE en cas d'erreur pour éviter les reconnexions infinies.
 * Note : innerHTML est utilisé ici car les messages de log sont concaténés
 *        sous forme de texte brut (pas de données utilisateur non maîtrisées).
 */
function fetchLogs() {
    const logWindow = document.getElementById('logs');
    if (!logWindow) {
        console.error("Erreur : élément #logs introuvable !");
        return;
    }

    logWindow.innerHTML = "Connexion aux logs...\n";

    // Ouvre la connexion SSE via le proxy PHP générique (évite CORS avec Hypercorn)
    const eventSource = new EventSource(`${window.API_URL}/logs`);

    // Chaque événement SSE contient une ligne de log brute
    eventSource.onmessage = function(event) {
        if (event.data === '[Fin du flux de logs]') {
            logWindow.innerHTML += "\n--- Deploiement termine ---\n";
            eventSource.close();
            toast('Deploiement termine avec succes', 'success');
            const btn = document.getElementById('deploy-btn');
            if (btn) { btn.disabled = false; document.getElementById('deploy-spinner').classList.add('hidden'); document.getElementById('deploy-icon')?.classList.remove('hidden'); document.getElementById('deploy-label').textContent = 'Deployer les cles'; }
            return;
        }
        logWindow.innerHTML += event.data + "\n";
        logWindow.scrollTop = logWindow.scrollHeight; // Auto-scroll vers le bas
    };

    // Ferme la connexion pour éviter les tentatives de reconnexion automatiques
    eventSource.onerror = function() {
        logWindow.innerHTML += "\n[Fin du flux]\n";
        eventSource.close();
        const btn = document.getElementById('deploy-btn');
        if (btn) { btn.disabled = false; document.getElementById('deploy-spinner').classList.add('hidden'); document.getElementById('deploy-label').textContent = 'Lancer le Deploiement'; }
    };
}
