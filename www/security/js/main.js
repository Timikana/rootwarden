// URL du backend Python (via proxy PHP)
const API_URL = window.API_URL || '/api_proxy.php';
const API_KEY = window.API_KEY || '';

// Config injectee depuis PHP (window._cveConfig)
const _cfg = window._cveConfig || {};

// Charge les derniers resultats au chargement + restore seuils localStorage
document.addEventListener('DOMContentLoaded', () => {
    (_cfg.machineIds || []).forEach(id => {
        loadLastResults(id);
        // Restaurer le seuil par serveur depuis localStorage
        const saved = localStorage.getItem(`cve-cvss-${id}`);
        const sel = document.getElementById(`cvss-${id}`);
        if (saved && sel) sel.value = saved;
    });

    // Synchro : seuil global → tous les seuils par serveur
    const globalSel = document.getElementById('global-min-cvss');
    if (globalSel) {
        globalSel.addEventListener('change', () => {
            (_cfg.machineIds || []).forEach(id => {
                const sel = document.getElementById(`cvss-${id}`);
                if (sel) sel.value = globalSel.value;
            });
        });
    }

    // Persistance localStorage quand on change un seuil par serveur
    (_cfg.machineIds || []).forEach(id => {
        const sel = document.getElementById(`cvss-${id}`);
        if (sel) sel.addEventListener('change', () => localStorage.setItem(`cve-cvss-${id}`, sel.value));
    });
});

// Styles Tailwind associés à chaque niveau de sévérité CVE (badge + ligne de tableau)
const SEV_STYLES = {
    CRITICAL: { badge: 'bg-red-600 text-white',    row: 'bg-red-50 dark:bg-red-900/20' },
    HIGH:     { badge: 'bg-orange-500 text-white',  row: 'bg-orange-50 dark:bg-orange-900/20' },
    MEDIUM:   { badge: 'bg-yellow-500 text-white',  row: 'bg-yellow-50 dark:bg-yellow-900/20' },
    LOW:      { badge: 'bg-green-600 text-white',   row: 'bg-green-50 dark:bg-green-900/20' },
    NONE:     { badge: 'bg-gray-400 text-white',    row: 'bg-gray-50 dark:bg-gray-800' },
};

// ── Test connexion OpenCVE ────────────────────────────────────────────────
// Le test est désormais fait côté PHP (server-side) pour éviter les problèmes
// CORS entre le navigateur et le backend Python via Hypercorn.

// ── Charge les derniers résultats stockés au chargement ───────────────────
// Boucle PHP : génère un appel loadLastResults(id) pour chaque serveur affiché
// afin de pré-remplir les cartes avec l'historique du dernier scan.

/**
 * Récupère le dernier scan CVE stocké en base pour un serveur donné.
 * Si un scan existe, appelle renderResults() pour afficher les résultats.
 * Les erreurs réseau sont silencieusement ignorées (catch vide).
 * @param {number} id - Identifiant de la machine en base
 */
async function loadLastResults(id) {
    try {
        const r = await fetch(`${API_URL}/cve_results?machine_id=${id}`);
        if (!r.ok) {
            console.error(`[CVE] loadLastResults machine ${id}: HTTP ${r.status}`);
            return;
        }
        const d = await r.json();
        if (d.success && d.scan) renderResults(id, d.findings, d.scan);
        else if (!d.success) console.warn(`[CVE] loadLastResults machine ${id}:`, d.message);
    } catch (e) {
        console.error(`[CVE] loadLastResults machine ${id}:`, e);
    }
}

// ── Scan individuel ───────────────────────────────────────────────────────
/**
 * Lance un scan CVE sur un seul serveur.
 * Lit le seuil CVSS depuis le sélecteur global avant d'appeler runScan().
 * @param {number} id - Identifiant de la machine à scanner
 */
function scanServer(id) {
    // Seuil par serveur (dropdown inline) sinon seuil global
    const perSelect = document.getElementById(`cvss-${id}`);
    const globalSelect = document.getElementById('global-min-cvss');
    const minCvss = parseFloat(perSelect ? perSelect.value : globalSelect.value);
    runScan('scan', { machine_id: id, min_cvss: minCvss }, [id]);
}

// ── Scan global ───────────────────────────────────────────────────────────
/**
 * Lance un scan CVE sur tous les serveurs disponibles, séquentiellement.
 * Affiche la barre de progression globale (#global-progress) pendant le scan
 * et la masque automatiquement 4 secondes après la fin.
 */
async function scanAll() {
    const globalCvss = parseFloat(document.getElementById('global-min-cvss').value);
    const allIds = _cfg.machineIds || [];

    const btnAll = document.getElementById('btn-scan-all');
    if (btnAll) btnAll.disabled = true;
    document.getElementById('global-progress').classList.remove('hidden');

    let done = 0;
    for (const id of allIds) {
        // Seuil par serveur si disponible, sinon global
        const perSelect = document.getElementById(`cvss-${id}`);
        const minCvss = parseFloat(perSelect ? perSelect.value : globalCvss);
        await runScan('scan', { machine_id: id, min_cvss: minCvss }, [id]);
        done++;
        const pct = Math.round((done / allIds.length) * 100);
        const name = document.querySelector(`#server-card-${id} .font-semibold`)?.textContent || `#${id}`;
        document.getElementById('global-progress-label').textContent = `Terminé : ${name}`;
        document.getElementById('global-progress-pct').textContent   = `${pct} %`;
        document.getElementById('global-progress-bar').style.width   = `${pct}%`;
    }

    if (btnAll) btnAll.disabled = false;
    setTimeout(() => document.getElementById('global-progress').classList.add('hidden'), 4000);
}

// ── Moteur de scan (streaming JSON-lines) ────────────────────────────────
/**
 * Effectue un scan CVE en streaming via l'API backend.
 * Le backend envoie une ligne JSON par événement (start, progress, finding, done, error).
 * Chaque ligne est parsée et routée vers handleEvent().
 * Un buffer `buf` accumule les octets reçus entre deux lectures pour gérer
 * les lignes découpées à cheval sur plusieurs chunks réseau.
 *
 * @param {string}   endpoint   - Chemin de l'endpoint (ex. '/cve_scan')
 * @param {Object}   body       - Corps JSON envoyé au backend (machine_id, min_cvss)
 * @param {number[]} machineIds - Liste des IDs machines à mettre à jour dans l'UI
 */
async function runScan(endpoint, body, machineIds) {
    // Passe les boutons en état "en cours" et masque les anciens résultats
    for (const id of machineIds) {
        setScanning(id, true);
        document.getElementById(`results-${id}`)?.classList.add('hidden');
    }

    // findingsMap : { machineId => [CVE findings] }
    // metaMap     : { machineId => metadata de l'événement 'done' }
    const findingsMap = {}, metaMap = {};

    try {
        const resp = await fetch(`${API_URL}/cve_${endpoint}`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(body),
        });

        // Lecture du flux en streaming avec ReadableStream
        const reader = resp.body.getReader();
        const dec    = new TextDecoder();
        let   buf    = ''; // Buffer partiel entre deux chunks

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            // Décode le chunk binaire en texte et l'ajoute au buffer
            buf += dec.decode(value, { stream: true });

            // Découpe le buffer en lignes complètes ; la dernière (incomplète) reste dans buf
            const lines = buf.split('\n');
            buf = lines.pop();

            for (const line of lines) {
                if (!line.trim()) continue; // Ignore les lignes vides (keep-alive)
                try { handleEvent(JSON.parse(line), findingsMap, metaMap); } catch (_) {}
            }
        }
    } catch (e) {
        console.error('Scan error:', e);
    }

    // Rétablit les boutons et affiche les résultats finaux
    for (const id of machineIds) {
        setScanning(id, false);
        if (findingsMap[id] !== undefined) renderResults(id, findingsMap[id], metaMap[id]);
    }
}

/**
 * Traite un événement JSON reçu du stream et met à jour l'UI.
 * Types d'événements attendus :
 *   - 'start'    : initialise le tableau de findings pour la machine
 *   - 'progress' : met à jour la barre de progression (package en cours)
 *   - 'finding'  : ajoute une CVE au tableau local de la machine
 *   - 'done'     : masque la progression, passe le point en vert, stocke les métadonnées
 *   - 'error'    : masque la progression, passe le point en rouge, affiche le message
 *
 * @param {Object} ev          - Objet JSON parsé depuis une ligne du stream
 * @param {Object} findingsMap - Accumulateur des CVE par machine_id
 * @param {Object} metaMap     - Accumulateur des métadonnées de fin par machine_id
 */
function handleEvent(ev, findingsMap, metaMap) {
    const id = ev.machine_id;
    if (!id) return; // Ignore les événements sans identifiant de machine
    switch (ev.type) {
        case 'start':
            // Initialise le tableau vide pour cette machine et indique le scan en bleu
            findingsMap[id] = [];
            dotColor(id, 'blue');
            break;
        case 'progress': {
            show(`progress-${id}`);
            if (ev.step === 'detect_os' || ev.step === 'packages') {
                // Etapes initiales (pas encore de barre)
                setText(`progress-label-${id}`, ev.message || 'Initialisation...');
                setText(`progress-pct-${id}`, '');
                setWidth(`progress-bar-${id}`, 0);
            } else if (ev.current && ev.total) {
                // Scan des paquets : barre de progression
                const pct = ev.percent || (ev.total > 0 ? Math.round(ev.current / ev.total * 100) : 0);
                const cveInfo = ev.total_cve_found !== undefined ? ` - ${ev.total_cve_found} CVE` : '';
                setText(`progress-label-${id}`, `${ev.package} (${ev.current}/${ev.total})${cveInfo}`);
                setText(`progress-pct-${id}`, `${pct} %`);
                setWidth(`progress-bar-${id}`, pct);
            } else if (ev.message) {
                setText(`progress-label-${id}`, ev.message);
            }
            break;
        }
        case 'finding':
            // Ajoute la CVE à la liste (opérateur ||= crée le tableau si absent)
            (findingsMap[id] ||= []).push(ev);
            break;
        case 'done': {
            metaMap[id] = ev;
            hide(`progress-${id}`);
            dotColor(id, 'green');
            // Affiche un résumé dans la barre de progression
            const stats = [];
            stats.push(`${ev.packages_scanned} paquets`);
            if (ev.packages_queried !== undefined) stats.push(`${ev.packages_queried} interroges`);
            if (ev.packages_skipped > 0) stats.push(`${ev.packages_skipped} ignores`);
            stats.push(`${ev.total_findings} CVE`);
            setText(`last-scan-${id}`, `Scan termine : ${stats.join(', ')}`);
            break;
        }
        case 'error':
            // Erreur pendant le scan : affiche le message d'erreur dans la carte
            hide(`progress-${id}`);
            dotColor(id, 'red');
            showError(id, ev.message);
            break;
    }
}

// ── Rendu du tableau ──────────────────────────────────────────────────────
/**
 * Génère et injecte le tableau HTML des CVE pour un serveur donné.
 * Met également à jour les badges de résumé (CRITICAL/HIGH/MEDIUM/LOW)
 * et la date du dernier scan dans l'en-tête de la carte serveur.
 * Si aucune CVE n'est trouvée, affiche un message "Aucune vulnérabilité".
 *
 * @param {number}   machineId - Identifiant de la machine
 * @param {Object[]} findings  - Tableau d'objets CVE (cve_id, package, version, severity, cvss, summary)
 * @param {Object}   meta      - Métadonnées du scan (critical_count, high_count, medium_count, low_count, scan_date)
 */
function renderResults(machineId, findings, meta) {
    const container = document.getElementById(`results-${machineId}`);
    if (!container) return;

    // Mise à jour des badges résumé (compteurs par sévérité dans l'en-tête de carte)
    const badgesEl = document.getElementById(`badges-${machineId}`);
    if (badgesEl && meta) {
        const map = { CRITICAL: meta.critical_count||0, HIGH: meta.high_count||0,
                      MEDIUM: meta.medium_count||0,     LOW:  meta.low_count||0 };
        badgesEl.innerHTML = Object.entries(map)
            .filter(([,c]) => c > 0)
            .map(([s,c]) => `<span class="px-2 py-0.5 rounded-full text-xs font-bold ${SEV_STYLES[s].badge}">${c}&nbsp;${s}</span>`)
            .join('');
    }

    // Date dernier scan
    if (meta?.scan_date) {
        const el = document.getElementById(`last-scan-${machineId}`);
        if (el) el.textContent = 'Scan : ' + new Date(meta.scan_date).toLocaleString('fr-FR');
    }

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="px-5 py-4 text-sm text-green-600 dark:text-green-400 flex items-center gap-2">
                <svg class="w-4 h-4 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
                </svg>
                Aucune vulnérabilité détectée au-dessus du seuil configuré.
            </div>`;
        show(`results-${machineId}`);
        return;
    }

    // Boutons de filtre par sévérité : déduplique les niveaux présents dans les findings
    const _mid = parseInt(machineId) || 0;
    const sevs = [...new Set(findings.map(f => f.severity||'NONE'))];
    const filterBtns = [
        `<button onclick="filterFindings(${_mid},'ALL')" data-sev="ALL"
                 class="sev-btn text-xs font-bold px-2.5 py-1 rounded-full
                        bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200">
             Tout (${findings.length})
         </button>`,
        ...sevs.map(s => {
            const cnt = findings.filter(f=>(f.severity||'NONE')===s).length;
            const safeSev = String(s).replace(/[^A-Z_-]/g, '');
            return `<button onclick="filterFindings(${_mid},'${safeSev}')" data-sev="${safeSev}"
                            class="sev-btn text-xs font-bold px-2.5 py-1 rounded-full ${SEV_STYLES[s]?.badge || ''}">
                        ${safeSev} (${cnt})
                    </button>`;
        })
    ].join('');

    // Trier par année (plus récent d'abord) puis par CVSS
    findings.sort((a, b) => {
        const ya = parseInt((a.cve_id||'').replace('CVE-','')) || 0;
        const yb = parseInt((b.cve_id||'').replace('CVE-','')) || 0;
        if (yb !== ya) return yb - ya;
        return (b.cvss||b.cvss_score||0) - (a.cvss||a.cvss_score||0);
    });

    // Compteurs par année
    const yearCounts = {};
    findings.forEach(f => {
        const y = (f.cve_id||'').match(/CVE-(\d{4})/)?.[1] || '?';
        yearCounts[y] = (yearCounts[y]||0) + 1;
    });
    const yearBtns = Object.entries(yearCounts)
        .sort(([a],[b]) => b.localeCompare(a))
        .map(([y,c]) => { const safeY = String(y).replace(/[^0-9?]/g, ''); return `<button onclick="filterFindings(${_mid},'YEAR-${safeY}')" class="sev-btn text-[10px] px-2 py-0.5 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-blue-100 dark:hover:bg-blue-900">${safeY} (${c})</button>`; })
        .join('');

    // Stocker les findings pour la pagination
    window._cveFindings = window._cveFindings || {};
    window._cveFindings[machineId] = findings;
    window._cvePage = window._cvePage || {};
    window._cvePage[machineId] = 1;
    const PER_PAGE = 50;

    function buildRows(list, page) {
        const start = 0;
        const end = page * PER_PAGE;
        const visible = list.slice(start, end);
        return visible.map(f => {
            const sev = f.severity || 'NONE';
            const st  = SEV_STYLES[sev] || SEV_STYLES.NONE;
            const year = (f.cve_id||'').match(/CVE-(\d{4})/)?.[1] || '';
            return `<tr class="finding-row ${st.row}" data-severity="${sev}" data-year="${year}">
                <td class="px-4 py-2 font-mono text-xs whitespace-nowrap">
                    <a href="https://www.cve.org/CVERecord?id=${esc(f.cve_id)}" target="_blank"
                       class="text-blue-600 dark:text-blue-400 hover:underline">${esc(f.cve_id)}</a>
                </td>
                <td class="px-4 py-2 text-xs font-medium">${esc(f.package||f.package_name||'')}</td>
                <td class="px-4 py-2 font-mono text-xs text-gray-500">${esc(f.version||f.package_version||'')}</td>
                <td class="px-4 py-2 whitespace-nowrap">
                    <span class="inline-block text-[10px] font-bold px-1.5 py-0.5 rounded-full ${st.badge}">${sev} ${f.cvss||f.cvss_score||''}</span>
                </td>
                <td class="px-4 py-2 text-[11px] text-gray-600 dark:text-gray-300 max-w-xs truncate" title="${esc(f.summary||'')}">${esc((f.summary||'').slice(0,120))}</td>
                <td class="px-3 py-2 whitespace-nowrap">
                    <select onchange="setCveRemediation('${esc(f.cve_id)}', ${machineId}, this.value)" class="text-[10px] border border-gray-300 dark:border-gray-600 rounded px-1 py-0.5 bg-white dark:bg-gray-700">
                        <option value="">-</option>
                        <option value="open">Open</option>
                        <option value="in_progress">En cours</option>
                        <option value="accepted">Accepte</option>
                        <option value="wont_fix">Won't fix</option>
                    </select>
                </td>
            </tr>`;
        }).join('');
    }

    const hasMore = findings.length > PER_PAGE;

    // Résumé cliquable (toujours visible)
    container.innerHTML = `
        <div class="px-4 py-2 flex items-center justify-between cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors"
             onclick="toggleCveDetail(${_mid})">
            <div class="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                <svg id="cve-chevron-${_mid}" class="w-4 h-4 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
                <span>${findings.length} CVE</span>
                <span class="text-gray-300 dark:text-gray-600">|</span>
                ${Object.entries(yearCounts).sort(([a],[b]) => b.localeCompare(a)).slice(0,5).map(([y,c]) => `<span>${y}: ${c}</span>`).join(' · ')}
            </div>
            <span class="text-[10px] text-gray-400">Cliquer pour voir les details</span>
        </div>`;
    show(`results-${machineId}`);

    // Détail (masqué par défaut)
    const detailEl = document.getElementById(`results-detail-${machineId}`);
    if (!detailEl) return;
    detailEl.innerHTML = `
        <div class="px-4 py-2 border-t border-gray-100 dark:border-gray-700 space-y-2">
            <div class="flex flex-wrap gap-1.5 items-center">
                <span class="text-xs text-gray-500 mr-1">Severite :</span>
                ${filterBtns}
            </div>
            <div class="flex flex-wrap gap-1 items-center">
                <span class="text-xs text-gray-500 mr-1">Annee :</span>
                <button onclick="filterFindings(${machineId},'ALL')" class="sev-btn text-[10px] px-2 py-0.5 rounded-full bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200">Toutes</button>
                ${yearBtns}
            </div>
            <div>
                <input type="text" placeholder="Rechercher un CVE ou paquet..." class="w-full sm:w-64 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500"
                       oninput="searchFindings(${machineId}, this.value)">
            </div>
        </div>
        <div class="overflow-x-auto max-h-[500px] overflow-y-auto">
            <table class="w-full text-left border-collapse" id="findings-table-${machineId}">
                <thead>
                    <tr class="text-xs uppercase tracking-wide text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-gray-700/50 sticky top-0">
                        <th class="px-4 py-2">CVE</th>
                        <th class="px-4 py-2">Package</th>
                        <th class="px-4 py-2">Version</th>
                        <th class="px-4 py-2">Severite</th>
                        <th class="px-4 py-2">Resume</th>
                        <th class="px-3 py-2">Suivi</th>
                    </tr>
                </thead>
                <tbody id="findings-body-${machineId}">${buildRows(findings, 1)}</tbody>
            </table>
        </div>
        ${hasMore ? `<div class="px-4 py-3 border-t border-gray-100 dark:border-gray-700 flex items-center justify-between">
            <span class="text-xs text-gray-400" id="findings-count-${machineId}">Affiche ${Math.min(PER_PAGE, findings.length)} / ${findings.length}</span>
            <button onclick="loadMoreFindings(${machineId})" id="load-more-${machineId}" class="text-xs px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors">Voir plus</button>
        </div>` : ''}`;
}

/**
 * Filtre les lignes du tableau CVE par niveau de sévérité.
 * Masque les lignes ne correspondant pas au filtre sélectionné via display:none.
 * Passer 'ALL' réaffiche toutes les lignes.
 *
 * @param {number} machineId - Identifiant de la machine (préfixe du tableau)
 * @param {string} sev       - Sévérité à afficher ('ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')
 */
/** Toggle l'affichage des détails CVE d'un serveur */
function toggleCveDetail(machineId) {
    const detail = document.getElementById(`results-detail-${machineId}`);
    const chevron = document.getElementById(`cve-chevron-${machineId}`);
    if (!detail) return;
    const isHidden = detail.classList.contains('hidden');
    detail.classList.toggle('hidden');
    if (chevron) chevron.style.transform = isHidden ? 'rotate(90deg)' : '';
}

/** Charge plus de résultats (pagination côté client) */
function loadMoreFindings(machineId) {
    const findings = window._cveFindings?.[machineId] || [];
    window._cvePage[machineId] = (window._cvePage[machineId] || 1) + 1;
    const page = window._cvePage[machineId];
    const PER_PAGE = 50;
    const end = page * PER_PAGE;
    const tbody = document.getElementById(`findings-body-${machineId}`);
    if (!tbody) return;

    // Ajouter les nouvelles lignes
    const newFindings = findings.slice((page-1)*PER_PAGE, end);
    newFindings.forEach(f => {
        const sev = f.severity || 'NONE';
        const st = SEV_STYLES[sev] || SEV_STYLES.NONE;
        const year = (f.cve_id||'').match(/CVE-(\d{4})/)?.[1] || '';
        const tr = document.createElement('tr');
        tr.className = `finding-row ${st.row}`;
        tr.dataset.severity = sev;
        tr.dataset.year = year;
        tr.innerHTML = `<td class="px-4 py-2 font-mono text-xs whitespace-nowrap"><a href="https://www.cve.org/CVERecord?id=${esc(f.cve_id)}" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline">${esc(f.cve_id)}</a></td><td class="px-4 py-2 text-xs font-medium">${esc(f.package||f.package_name||'')}</td><td class="px-4 py-2 font-mono text-xs text-gray-500">${esc(f.version||f.package_version||'')}</td><td class="px-4 py-2 whitespace-nowrap"><span class="inline-block text-[10px] font-bold px-1.5 py-0.5 rounded-full ${st.badge}">${sev} ${f.cvss||f.cvss_score||''}</span></td><td class="px-4 py-2 text-[11px] text-gray-600 dark:text-gray-300 max-w-md truncate">${esc((f.summary||'').slice(0,150))}</td>`;
        tbody.appendChild(tr);
    });

    const countEl = document.getElementById(`findings-count-${machineId}`);
    if (countEl) countEl.textContent = `Affiche ${Math.min(end, findings.length)} / ${findings.length}`;
    if (end >= findings.length) {
        const btn = document.getElementById(`load-more-${machineId}`);
        if (btn) btn.style.display = 'none';
    }
}

/** Recherche dans les CVE (reconstruit depuis les findings en mémoire) */
function searchFindings(machineId, query) {
    const q = query.toLowerCase().trim();
    if (!q) { filterFindings(machineId, 'ALL'); return; }
    const all = window._cveFindings?.[machineId] || [];
    const filtered = all.filter(f =>
        (f.cve_id || '').toLowerCase().includes(q) ||
        (f.package || f.package_name || '').toLowerCase().includes(q) ||
        (f.summary || '').toLowerCase().includes(q)
    );
    // Réutilise filterFindings en injectant temporairement
    window._cveFindings[machineId + '_search'] = filtered;
    const tbody = document.getElementById(`findings-body-${machineId}`);
    if (!tbody) return;
    const limit = Math.min(filtered.length, 100);
    tbody.innerHTML = filtered.slice(0, limit).map(f => {
        const sev = f.severity || 'NONE';
        const st = SEV_STYLES[sev] || SEV_STYLES.NONE;
        return `<tr class="finding-row ${st.row}">
            <td class="px-4 py-2 font-mono text-xs whitespace-nowrap"><a href="https://www.cve.org/CVERecord?id=${esc(f.cve_id)}" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline">${esc(f.cve_id)}</a></td>
            <td class="px-4 py-2 text-xs font-medium">${esc(f.package || f.package_name || '')}</td>
            <td class="px-4 py-2 font-mono text-xs text-gray-500">${esc(f.version || f.package_version || '')}</td>
            <td class="px-4 py-2 whitespace-nowrap"><span class="inline-block text-[10px] font-bold px-1.5 py-0.5 rounded-full ${st.badge}">${sev} ${f.cvss || f.cvss_score || ''}</span></td>
            <td class="px-4 py-2 text-[11px] text-gray-600 dark:text-gray-300 max-w-md truncate">${esc((f.summary || '').slice(0, 150))}</td>
        </tr>`;
    }).join('');
    const countEl = document.getElementById(`findings-count-${machineId}`);
    if (countEl) countEl.textContent = `${limit} / ${filtered.length} CVE (recherche: "${q}")`;
}

function filterFindings(machineId, filter) {
    const all = window._cveFindings?.[machineId] || [];
    if (!all.length) return;

    // Filtre les findings en mémoire
    let filtered;
    if (filter === 'ALL') {
        filtered = all;
    } else if (filter.startsWith('YEAR-')) {
        const year = filter.replace('YEAR-', '');
        filtered = all.filter(f => (f.cve_id || '').includes('CVE-' + year));
    } else {
        filtered = all.filter(f => (f.severity || 'NONE') === filter);
    }

    // Reconstruit le tbody avec les résultats filtrés (max 100)
    const tbody = document.getElementById(`findings-body-${machineId}`);
    if (!tbody) return;
    const limit = Math.min(filtered.length, 100);
    tbody.innerHTML = filtered.slice(0, limit).map(f => {
        const sev = f.severity || 'NONE';
        const st = SEV_STYLES[sev] || SEV_STYLES.NONE;
        const year = (f.cve_id || '').match(/CVE-(\d{4})/)?.[1] || '';
        return `<tr class="finding-row ${st.row}" data-severity="${sev}" data-year="${year}">
            <td class="px-4 py-2 font-mono text-xs whitespace-nowrap"><a href="https://www.cve.org/CVERecord?id=${esc(f.cve_id)}" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline">${esc(f.cve_id)}</a></td>
            <td class="px-4 py-2 text-xs font-medium">${esc(f.package || f.package_name || '')}</td>
            <td class="px-4 py-2 font-mono text-xs text-gray-500">${esc(f.version || f.package_version || '')}</td>
            <td class="px-4 py-2 whitespace-nowrap"><span class="inline-block text-[10px] font-bold px-1.5 py-0.5 rounded-full ${st.badge}">${sev} ${f.cvss || f.cvss_score || ''}</span></td>
            <td class="px-4 py-2 text-[11px] text-gray-600 dark:text-gray-300 max-w-md truncate" title="${esc(f.summary || '')}">${esc((f.summary || '').slice(0, 150))}</td>
        </tr>`;
    }).join('');

    // Met à jour le compteur
    const countEl = document.getElementById(`findings-count-${machineId}`);
    if (countEl) countEl.textContent = `${limit} / ${filtered.length} CVE` + (filter !== 'ALL' ? ` (${filter})` : '');

    // Masque "Voir plus" quand on filtre
    const btn = document.getElementById(`load-more-${machineId}`);
    if (btn) btn.style.display = (filter === 'ALL' && all.length > limit) ? '' : 'none';
}

// ── Helpers ───────────────────────────────────────────────────────────────
/**
 * Active ou désactive visuellement le bouton "Scanner" d'une carte serveur.
 * En état actif, remplace le label par une icône spinner animée.
 * @param {number}  id     - Identifiant de la machine
 * @param {boolean} active - true = scan en cours, false = scan terminé
 */
function setScanning(id, active) {
    const btn = document.getElementById(`btn-${id}`);
    if (!btn) return;
    btn.disabled = active;
    btn.innerHTML = active
        ? '<svg class="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg> En cours…'
        : '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Scanner';
}

/**
 * Affiche un message d'erreur dans la zone de résultats d'une carte serveur.
 * Utilise esc() pour éviter toute injection XSS dans le message.
 * @param {number} id  - Identifiant de la machine
 * @param {string} msg - Message d'erreur à afficher
 */
function showError(id, msg) {
    const el = document.getElementById(`results-${id}`);
    if (!el) return;
    el.innerHTML = `<div class="px-5 py-3 text-sm text-red-600 dark:text-red-400 flex gap-2 items-center">
        <svg class="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
        </svg>
        Erreur : ${esc(msg)}</div>`;
    el.classList.remove('hidden');
}

/**
 * Change la couleur du point de statut d'une carte serveur.
 * @param {number} id    - Identifiant de la machine
 * @param {string} color - 'blue' (scan en cours), 'green' (succès), 'red' (erreur)
 */
function dotColor(id, color) {
    const dot = document.getElementById(`status-dot-${id}`);
    if (!dot) return;
    dot.className = `w-2.5 h-2.5 rounded-full flex-shrink-0 bg-${color}-${color==='blue'?400:color==='green'?500:500}`;
}
/** Rend visible un élément en retirant la classe Tailwind 'hidden'. @param {string} id */
function show(id)  { document.getElementById(id)?.classList.remove('hidden'); }
/** Masque un élément en ajoutant la classe Tailwind 'hidden'. @param {string} id */
function hide(id)  { document.getElementById(id)?.classList.add('hidden'); }
/** Définit le textContent d'un élément (sûr contre XSS). @param {string} id @param {string} t */
function setText(id, t) { const el = document.getElementById(id); if (el) el.textContent = t; }
/** Définit la largeur CSS d'un élément (barre de progression). @param {string} id @param {number} pct */
function setWidth(id, pct) { const el = document.getElementById(id); if (el) el.style.width = pct + '%'; }
/**
 * Échappe les caractères HTML spéciaux pour une insertion sûre dans innerHTML.
 * Traite &, <, >, " afin d'éviter toute injection XSS via les données CVE.
 * @param {*} s - Valeur à échapper (convertie en string si besoin)
 * @returns {string} Chaîne HTML-encodée
 */
function esc(s)    { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── Gestion des scans planifies ──────────────────────────────────────────
async function loadSchedules() {
    try {
        const r = await fetch(`${window.API_URL}/cve_schedules`);
        const d = await r.json();
        if (!d.success) return;
        const list = document.getElementById('schedules-list');
        const count = document.getElementById('schedule-count');
        if (!list) return;
        const active = d.schedules.filter(s => s.enabled);
        if (count) count.textContent = active.length > 0 ? `${active.length} actif${active.length > 1 ? 's' : ''}` : '';
        if (d.schedules.length === 0) {
            list.innerHTML = '<p class="text-xs text-gray-400">Aucun scan planifie.</p>';
            return;
        }
        list.innerHTML = d.schedules.map(s => {
            const enabled = s.enabled == 1;
            const lastRun = s.last_run ? new Date(s.last_run).toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}) : 'Jamais';
            const nextRun = s.next_run ? new Date(s.next_run).toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}) : '-';
            let target = 'Tous';
            if (s.target_type === 'tag') {
                target = 'Tag: ' + esc(s.target_value);
            } else if (s.target_type === 'machines') {
                try {
                    const ids = JSON.parse(s.target_value || '[]');
                    const names = ids.map(id => (window._machinesById?.[id]?.name) || `#${id}`);
                    target = names.length === 1 ? 'Serveur: ' + esc(names[0]) : `${names.length} serveurs`;
                } catch { target = 'Selection'; }
            }
            return `<div class="flex items-center justify-between gap-3 px-3 py-2 rounded-lg ${enabled ? 'bg-blue-50 dark:bg-blue-900/20' : 'bg-gray-50 dark:bg-gray-700/30 opacity-60'}">
                <div class="flex-1 min-w-0">
                    <span class="text-sm font-medium">${esc(s.name)}</span>
                    <span class="text-xs text-gray-400 ml-2 font-mono">${esc(s.cron_expression)}</span>
                    <span class="text-xs text-gray-400 ml-2">${target}</span>
                    <span class="text-xs text-gray-400 ml-2">CVSS &ge; ${s.min_cvss}</span>
                </div>
                <div class="flex items-center gap-3 flex-shrink-0 text-xs text-gray-500">
                    <span>Dernier: ${lastRun}</span>
                    <span>Prochain: ${nextRun}</span>
                    <button onclick="toggleSchedule(${s.id}, ${enabled ? 0 : 1})" class="px-2 py-0.5 rounded text-xs font-medium ${enabled ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' : 'bg-gray-200 text-gray-500'}">${enabled ? 'ON' : 'OFF'}</button>
                    <button onclick="deleteSchedule(${s.id})" class="text-red-400 hover:text-red-600">&times;</button>
                </div>
            </div>`;
        }).join('');
    } catch(e) { console.error('loadSchedules:', e); }
}

async function addSchedule() {
    const name = document.getElementById('sched-name')?.value.trim();
    const cron = document.getElementById('sched-cron')?.value.trim();
    const cvss = document.getElementById('sched-cvss')?.value || '7';
    const targetRaw = document.getElementById('sched-target')?.value || 'all';
    if (!name) { toast('Nom requis', 'warning'); return; }

    let target_type = 'all', target_value = '';
    if (targetRaw.startsWith('tag:')) {
        target_type = 'tag';
        target_value = targetRaw.substring(4);
    } else if (targetRaw.startsWith('machine:')) {
        target_type = 'machines';
        // Le backend attend un JSON array d'IDs (supporte le multi-select futur)
        target_value = JSON.stringify([parseInt(targetRaw.substring(8), 10)]);
    }

    const r = await fetch(`${window.API_URL}/cve_schedules`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name, cron_expression: cron, min_cvss: parseFloat(cvss), target_type, target_value})
    });
    const d = await r.json();
    if (d.success) { toast('Planification ajoutee', 'success'); loadSchedules(); document.getElementById('sched-name').value = ''; }
    else toast(d.message || 'Erreur', 'error');
}

async function toggleSchedule(id, enabled) {
    await fetch(`${window.API_URL}/cve_schedules/${id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled})
    });
    loadSchedules();
}

async function deleteSchedule(id) {
    if (!confirm('Supprimer cette planification ?')) return;
    await fetch(`${window.API_URL}/cve_schedules/${id}`, {method: 'DELETE'});
    toast('Planification supprimee', 'success');
    loadSchedules();
}

// ── Comparaison de scans CVE ──────────────────────────────────────────────
async function compareCveScans(machineId) {
    try {
        const r = await fetch(`${window.API_URL}/cve_compare?machine_id=${machineId}`);
        const d = await r.json();
        if (!d.success) { toast(d.message || 'Impossible de comparer', 'warning'); return; }

        const date1 = d.scan1?.scan_date ? new Date(d.scan1.scan_date).toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}) : '?';
        const date2 = d.scan2?.scan_date ? new Date(d.scan2.scan_date).toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}) : '?';

        let html = `<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onclick="if(event.target===this)this.remove()">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-hidden flex flex-col">
                <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between flex-shrink-0">
                    <h3 class="text-lg font-bold text-gray-800 dark:text-gray-200">Comparaison CVE</h3>
                    <button onclick="this.closest('.fixed').remove()" class="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
                </div>
                <div class="p-6 overflow-y-auto">
                    <div class="flex items-center justify-between mb-4 text-sm">
                        <span class="text-gray-500">Scan ${date1}</span>
                        <span class="text-gray-400">&rarr;</span>
                        <span class="text-gray-500">Scan ${date2}</span>
                    </div>
                    <div class="grid grid-cols-3 gap-3 mb-4 text-center">
                        <div class="p-3 rounded-lg bg-green-50 dark:bg-green-900/20">
                            <div class="text-xl font-bold text-green-600">-${d.removed_count}</div>
                            <div class="text-[10px] text-green-500">Corrigees</div>
                        </div>
                        <div class="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                            <div class="text-xl font-bold text-gray-600 dark:text-gray-300">${d.unchanged}</div>
                            <div class="text-[10px] text-gray-400">Inchangees</div>
                        </div>
                        <div class="p-3 rounded-lg bg-red-50 dark:bg-red-900/20">
                            <div class="text-xl font-bold text-red-600">+${d.added_count}</div>
                            <div class="text-[10px] text-red-500">Nouvelles</div>
                        </div>
                    </div>`;

        if (d.added.length > 0) {
            html += `<h4 class="text-sm font-semibold text-red-600 mb-2">+ ${d.added.length} nouvelle(s) CVE</h4>
                <div class="space-y-1 mb-4">`;
            d.added.forEach(c => {
                html += `<div class="flex items-center gap-2 text-xs px-2 py-1 rounded bg-red-50 dark:bg-red-900/20">
                    <span class="font-mono font-bold text-red-600">${esc(c.cve_id)}</span>
                    <span class="text-gray-500">${esc(c.package_name)}</span>
                    <span class="ml-auto text-[10px] px-1.5 py-0.5 rounded-full ${c.severity === 'CRITICAL' ? 'bg-red-600 text-white' : 'bg-orange-500 text-white'}">${c.severity} ${c.cvss_score}</span>
                </div>`;
            });
            html += '</div>';
        }

        if (d.removed.length > 0) {
            html += `<h4 class="text-sm font-semibold text-green-600 mb-2">- ${d.removed.length} CVE corrigee(s)</h4>
                <div class="space-y-1 mb-4">`;
            d.removed.forEach(c => {
                html += `<div class="flex items-center gap-2 text-xs px-2 py-1 rounded bg-green-50 dark:bg-green-900/20 line-through opacity-70">
                    <span class="font-mono text-green-700">${esc(c.cve_id)}</span>
                    <span class="text-gray-400">${esc(c.package_name)}</span>
                    <span class="ml-auto text-[10px]">${c.severity}</span>
                </div>`;
            });
            html += '</div>';
        }

        if (d.added.length === 0 && d.removed.length === 0) {
            html += '<p class="text-center text-sm text-gray-400 py-4">Aucune difference entre les deux scans.</p>';
        }

        html += '</div></div></div>';
        document.body.insertAdjacentHTML('beforeend', html);
    } catch(e) { toast('Erreur comparaison : ' + e.message, 'error'); }
}

// Charger les planifications au chargement de la page
document.addEventListener('DOMContentLoaded', loadSchedules);

// ── Remediation CVE ──────────────────────────────────────────────────────
async function setCveRemediation(cveId, machineId, status) {
    if (!status) return;
    try {
        const r = await fetch(`${window.API_URL}/cve_remediation`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({cve_id: cveId, machine_id: machineId, status: status})
        });
        const d = await r.json();
        if (d.success) {
            const labels = {open:'Ouverte', in_progress:'En cours', accepted:'Acceptee', wont_fix:"Won't fix"};
            toast(`${cveId} → ${labels[status] || status}`, 'success');
        } else {
            toast(d.message || 'Erreur', 'error');
        }
    } catch(e) { toast('Erreur reseau', 'error'); }
}

// ── Whitelist CVE ────────────────────────────────────────────────────────
async function whitelistCve(cveId, machineId) {
    const reason = prompt(`Raison de la whitelist pour ${cveId} :`);
    if (!reason) return;
    try {
        const r = await fetch(`${window.API_URL}/cve_whitelist`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({cve_id: cveId, machine_id: machineId, reason: reason, whitelisted_by: _cfg.username || 'admin'})
        });
        const d = await r.json();
        if (d.success) toast(`${cveId} ajoutee a la whitelist`, 'info');
        else toast(d.message || 'Erreur', 'error');
    } catch(e) { toast('Erreur reseau', 'error'); }
}
