/**
 * @file domManipulation.js
 * @description Fonctions de manipulation DOM pour l'interface de mises à jour Linux.
 *
 * Responsabilités :
 *   - Affichage et réinitialisation de la zone de logs globale (#logs)
 *   - Mise à jour en temps réel des cellules du tableau (statut, version…)
 *   - Construction dynamique des lignes de tableau <tr> (filtrage AJAX)
 *   - Gestion des modals de planification (planning normal et sécurité)
 *
 * Conventions de sécurité :
 *   - textContent est systématiquement utilisé pour insérer des données
 *     provenant du serveur ou de l'utilisateur (protection XSS).
 *   - Les attributs HTML (data-*, value, id) sont définis via setAttribute()
 *     plutôt que par concaténation de chaînes dans innerHTML.
 *   - Les IDs de machines sont convertis en entiers (parseInt) avant usage
 *     dans des sélecteurs ou des appels d'API.
 *
 * Dépendances :
 *   - window.API_URL  : URL de base du backend Python (définie dans head.php)
 *   - apiCalls.js     : fonctions updateSingleMachine(),
 *                       openScheduleModal() appelées depuis les boutons d'action
 */

/**
 * Ajoute un message dans la zone de logs globale (#logs) et fait défiler
 * automatiquement vers le bas pour afficher le dernier message.
 * Utilise textContent (et non innerHTML) pour prévenir toute injection XSS,
 * car les messages peuvent contenir des sorties de commandes SSH non filtrées.
 *
 * @param {string} message - Le message à afficher dans le log
 * @returns {void}
 */
function appendLog(message) {
    const logWindow = document.getElementById('logs');
    if (!logWindow) return;

    // Crée un <span> avec textContent pour isoler chaque ligne de log
    const line = document.createElement('span');
    line.textContent = message + "\n";
    logWindow.appendChild(line);
    logWindow.scrollTop = logWindow.scrollHeight; // Auto-scroll vers le bas
}

/**
 * Vide intégralement la zone de logs globale (#logs).
 * À appeler avant de démarrer une nouvelle opération pour éviter
 * l'accumulation de logs d'opérations précédentes.
 *
 * @returns {void}
 */
function clearLog() {
    const logWindow = document.getElementById('logs');
    if (!logWindow) return;
    logWindow.innerHTML = ""; // innerHTML est sûr ici car on assigne une chaîne vide
}

/**
 * Met à jour la cellule "statut en ligne" d'une machine dans le tableau principal.
 * Sélectionne la ligne par l'attribut data-machine-id (défini côté PHP/populateMachineTable).
 * La cellule cible porte la classe CSS 'online-status' comme convention.
 *
 * @param {number} machineId - Identifiant de la machine (attribut data-machine-id)
 * @param {string} status    - Libellé du statut à afficher (ex. 'Online', 'Offline')
 * @returns {void}
 */
function updateMachineStatusDOM(machineId, status) {
    // Recherche la ligne <tr> correspondant à cette machine
    const row = document.querySelector(`tr[data-machine-id="${machineId}"]`);
    if (!row) return;

    // Sélectionne la cellule de statut par sa classe fonctionnelle
    const statusCell = row.querySelector('.online-status');
    if (statusCell) {
        statusCell.textContent = status; // textContent = pas de risque XSS
    }
}

/**
 * Met à jour la cellule "version Linux" d'une machine dans le tableau principal.
 * Affiche 'Non vérifiée' si la version fournie est vide ou nulle.
 * La cellule cible porte la classe CSS 'linux-version'.
 *
 * @param {number} machineId    - Identifiant de la machine (attribut data-machine-id)
 * @param {string} linuxVersion - Version Linux détectée (ex. 'Ubuntu 22.04.3 LTS')
 * @returns {void}
 */
function updateMachineVersionDOM(machineId, linuxVersion) {
    const row = document.querySelector(`tr[data-machine-id="${machineId}"]`);
    if (!row) return;

    // La cellule est identifiée par sa classe fonctionnelle 'linux-version'
    const versionCell = row.querySelector('.linux-version');
    if (versionCell) {
        versionCell.textContent = linuxVersion || __('not_checked');
    }
}

/**
 * Crée une ligne de tableau <tr> complète pour un serveur.
 * Utilisée lors du filtrage AJAX pour reconstruire les lignes du tableau
 * sans rechargement de page. Toutes les données sont insérées via textContent
 * ou setAttribute pour prévenir toute injection XSS.
 * Les boutons d'action dans la colonne "Actions" utilisent addEventListener
 * (et non onclick inline) pour les mêmes raisons de sécurité.
 *
 * @param {Object} serverData - Objet machine contenant les propriétés :
 *   id, name, ip, port, linux_version, last_checked, online_status,
 *   environment, criticality, network_type
 * @returns {HTMLTableRowElement} La ligne <tr> prête à être insérée dans le DOM
 */
function createMachineRow(serverData) {
    const tr = document.createElement('tr');
    tr.setAttribute('data-machine-id', serverData.id);
    tr.classList.add('border-b');

    // 1) Cellule de sélection (checkbox)
    const tdCheck = document.createElement('td');
    tdCheck.classList.add('p-2', 'text-center');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.name = 'selected_machines[]';
    checkbox.value = serverData.id;
    tdCheck.appendChild(checkbox);
    tr.appendChild(tdCheck);

    // 2) Nom
    const tdName = document.createElement('td');
    tdName.classList.add('p-2', 'server-name', 'font-semibold');
    tdName.textContent = serverData.name;
    tr.appendChild(tdName);

    // 3) Version Linux
    const tdVersion = document.createElement('td');
    tdVersion.classList.add('p-2', 'linux-version');
    tdVersion.textContent = serverData.linux_version || __('not_checked');
    tr.appendChild(tdVersion);

    // 4) Date de Vérification
    const tdLastChecked = document.createElement('td');
    tdLastChecked.classList.add('p-2', 'last-checked');
    tdLastChecked.textContent = serverData.last_checked || __('not_checked');
    tr.appendChild(tdLastChecked);

    // 5) IP:PORT
    const tdIpPort = document.createElement('td');
    tdIpPort.classList.add('p-2');
    tdIpPort.textContent = `${serverData.ip}:${serverData.port}`;
    tr.appendChild(tdIpPort);

    // 6) Statut en ligne
    const tdStatus = document.createElement('td');
    tdStatus.classList.add('p-2', 'online-status');
    tdStatus.textContent = serverData.online_status || __('unknown');
    tr.appendChild(tdStatus);

    // 7) MàJ sécurité - Planifier
    tr.appendChild(createTd(serverData.maj_secu_date || 'N/A', ['maj-secu-date', 'text-center']));

    // 9) Data de dernière exécution
    tr.appendChild(createTd(serverData.maj_secu_last_exec_date || 'N/A', ['maj-secu-lastexec-date', 'text-center']));

    // 10) Dernier Redémarrage
    const tdReboot = createTd(serverData.last_reboot || 'N/A', ['last-reboot']);
    tdReboot.id = 'last-reboot-' + id;
    tr.appendChild(tdReboot);

    // 11) Environnement
    tr.appendChild(createTd(serverData.environment || 'OTHER', ['environment', 'text-center']));

    // 12) Criticité
    tr.appendChild(createTd(serverData.criticality || 'NON CRITIQUE', ['criticality', 'text-center']));

    // 13) Type de réseau
    tr.appendChild(createTd(serverData.network_type || 'INTERNE', ['network-type', 'text-center']));

    // 11) Actions
    const tdActions = document.createElement('td');
    tdActions.classList.add('p-2', 'space-y-1', 'text-xs');

    // Bouton Mise à jour
    const btnUpdate = document.createElement('button');
    btnUpdate.type = 'button';
    btnUpdate.classList.add('bg-orange-400', 'text-white', 'px-2', 'py-1', 'rounded', 'block');
    btnUpdate.textContent = __('update_btn');
    btnUpdate.onclick = () => updateSingleMachine(serverData.id);
    tdActions.appendChild(btnUpdate);

    // Bouton Planifier
    const btnSchedule = document.createElement('button');
    btnSchedule.type = 'button';
    btnSchedule.classList.add('bg-gray-500', 'text-white', 'px-2', 'py-1', 'rounded', 'block');
    btnSchedule.textContent = __('schedule_btn');
    btnSchedule.onclick = () => openScheduleModal(serverData.id);
    tdActions.appendChild(btnSchedule);

    tr.appendChild(tdActions);

    return tr;
}

/**
 * Crée une cellule de tableau <td> avec du texte sûr et des classes CSS.
 * La classe 'p-2' est systématiquement ajoutée pour respecter le padding
 * standard du tableau. textContent garantit l'absence d'injection XSS.
 *
 * @param {string}   text    - Texte brut à afficher dans la cellule
 * @param {string[]} classes - Classes CSS supplémentaires à appliquer (ex. ['font-semibold'])
 * @returns {HTMLTableCellElement} La cellule <td> créée
 */
function createTd(text, classes = []) {
    const td = document.createElement('td');
    td.classList.add('p-2', ...classes);
    td.textContent = text;
    return td;
}

/**
 * Reconstruit intégralement le corps du tableau des machines (#server-table-body)
 * à partir d'une liste de machines reçue en JSON (typiquement après un filtrage AJAX).
 * Vide le tableau avant d'insérer les nouvelles lignes.
 * Utilise createTd() et textContent/setAttribute pour prévenir toute injection XSS.
 * Les IDs sont parsés en entiers et les entrées avec ID invalide sont ignorées.
 *
 * @param {Object[]} machines - Tableau d'objets machine (propriétés : id, name, ip, port,
 *   linux_version, last_checked, online_status,
 *   maj_secu_date, maj_secu_last_exec_date, last_reboot,
 *   environment, criticality, network_type)
 * @returns {void}
 */
function populateMachineTable(machines) {
    const serverTableBody = document.getElementById("server-table-body");
    if (!serverTableBody) return;

    // Vide le tableau existant avant de le reconstruire
    serverTableBody.innerHTML = "";

    machines.forEach(m => {
        // Parse l'ID en entier ; ignore les entrées avec ID manquant ou non numérique
        const id = parseInt(m.id, 10);
        if (!id) return;

        const tr = document.createElement("tr");
        tr.classList.add("border-b", "border-gray-200", "dark:border-gray-700");
        tr.setAttribute("data-machine-id", id);
        tr.setAttribute("data-ip", m.ip ?? "");
        tr.setAttribute("data-port", m.port ?? "22");

        // Checkbox
        const tdCheck = document.createElement('td');
        tdCheck.classList.add('p-2', 'text-center');
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.name = 'selected_machines[]';
        cb.value = id;
        cb.classList.add('form-checkbox', 'h-4', 'w-4', 'text-blue-600', 'dark:text-blue-400');
        tdCheck.appendChild(cb);
        tr.appendChild(tdCheck);

        tr.appendChild(createTd(m.name ?? "", ['font-semibold', 'server-name']));
        tr.appendChild(createTd(m.linux_version ?? __('not_checked'), ['linux-version']));
        tr.appendChild(createTd(m.last_checked ?? __('not_checked'), ['last-checked']));
        tr.appendChild(createTd(`${m.ip ?? ""}:${m.port ?? ""}`, []));
        tr.appendChild(createTd(m.online_status ?? __('unknown'), ['online-status']));
        tr.appendChild(createTd(m.maj_secu_date ?? "N/A", ['maj-secu-date', 'text-center']));
        tr.appendChild(createTd(m.maj_secu_last_exec_date ?? "N/A", ['maj-secu-lastexec-date', 'text-center']));

        const tdReboot = createTd(m.last_reboot ?? "N/A", ['last-reboot', 'text-center']);
        tdReboot.id = `last-reboot-${id}`;
        tr.appendChild(tdReboot);

        tr.appendChild(createTd(m.environment ?? "OTHER", ['environment', 'text-center']));
        tr.appendChild(createTd(m.criticality ?? "NON CRITIQUE", ['criticality', 'text-center']));
        tr.appendChild(createTd(m.network_type ?? "INTERNE", ['network-type', 'text-center']));

        // Actions - IDs sont des entiers validés ci-dessus (pas de données utilisateur brutes)
        // addEventListener est utilisé (pas d'onclick inline) pour éviter les injections CSP
        const tdActions = document.createElement('td');
        tdActions.classList.add('p-2', 'space-y-1', 'text-xs');

        // Bouton "Planifier" : ouvre le modal de planification générale
        const btnSchedule = document.createElement('button');
        btnSchedule.type = 'button';
        btnSchedule.classList.add('bg-gray-500', 'dark:bg-gray-600', 'text-white', 'px-2', 'py-1', 'rounded', 'block', 'hover:bg-gray-600');
        btnSchedule.textContent = __('schedule_btn');
        btnSchedule.addEventListener('click', () => openScheduleModal(id));
        tdActions.appendChild(btnSchedule);

        // Bouton "Planifier Sécurité" : ouvre le modal dédié aux mises à jour de sécurité
        const btnSecu = document.createElement('button');
        btnSecu.type = 'button';
        btnSecu.classList.add('bg-red-500', 'dark:bg-red-600', 'text-white', 'px-2', 'py-1', 'rounded', 'block', 'hover:bg-red-600');
        btnSecu.textContent = __('schedule_security_btn');
        btnSecu.addEventListener('click', () => openSecurityScheduleModal(id));
        tdActions.appendChild(btnSecu);

        tr.appendChild(tdActions);
        serverTableBody.appendChild(tr);
    });
}



// ── Gestion du modal de planification avancée ──────────────────────────────
// Variable module-level pour mémoriser la machine en cours de planification
// entre l'ouverture du modal et la validation.
let currentMachineIdForSchedule = null;

/**
 * Ouvre le modal de planification générale et mémorise l'ID de la machine cible.
 * Le modal (#schedule-modal) est affiché en flex pour centrer son contenu.
 *
 * @param {number} machineId - Identifiant de la machine à planifier
 * @returns {void}
 */
function openScheduleModal(machineId) {
    currentMachineIdForSchedule = machineId;
    const modal = document.getElementById('schedule-modal');
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

/**
 * Ferme le modal de planification et réinitialise la machine mémorisée.
 *
 * @returns {void}
 */
function closeScheduleModal() {
    currentMachineIdForSchedule = null;
    const modal = document.getElementById('schedule-modal');
    modal.classList.add('hidden');
    modal.classList.remove('flex');
}

/**
 * Valide et envoie la planification avancée au backend.
 * Collecte la date (#sched-date), l'heure (#sched-time) et la récurrence
 * (#sched-repeat) du formulaire du modal, puis appelle POST /schedule_update.
 * Ferme le modal après envoi (succès ou échec réseau).
 * Les résultats sont journalisés dans la zone de logs globale (#logs).
 *
 * @returns {void}
 */
function saveAdvancedSchedule() {
    // Lecture des champs du formulaire de planification
    const dateVal   = document.getElementById('sched-date').value;
    const timeVal   = document.getElementById('sched-time').value;
    const repeatVal = document.getElementById('sched-repeat').value;

    if (!dateVal || !timeVal) {
        toast(__('upd_enter_date_time'), 'warning');
        return;
    }

    console.log("Planification avancée : machine=", currentMachineIdForSchedule, dateVal, timeVal, repeatVal);

    // Appel POST /schedule_update vers le backend Python
    fetch(`${window.API_URL}/schedule_update`, {
       method: "POST",
       headers: { "Content-Type": "application/json" },
       body: JSON.stringify({
         machine_id: currentMachineIdForSchedule,
         date: dateVal,
         time: timeVal,
         repeat: repeatVal
       })
    })
    .then(r => r.json())
    .then(data => {
       if(data.success) {
           appendLog(__('upd_machine_scheduled', {id: currentMachineIdForSchedule}));
           appendLog(__('upd_details', {msg: data.message}));
       } else {
           appendLog(__('upd_machine_error', {id: currentMachineIdForSchedule, msg: data.message}));
       }
    })
    .catch(err => {
        // Erreur réseau ou parsing JSON
        appendLog(__('upd_machine_exception', {id: currentMachineIdForSchedule, msg: err}));
    });

    // Ferme le modal immédiatement (l'appel API est asynchrone)
    closeScheduleModal();
}
